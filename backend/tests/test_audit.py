"""Tests for the audit trail on the write endpoints.

Two layers:
  * unit tests on the entry itself -- its fields, its timestamp, and the fact
    that it is emitted as one parseable JSON line;
  * route tests proving each of the four writes records exactly one entry with
    the right endpoint, case id, client IP, authentication flag and actor (the
    operator key's fingerprint, the owner's hash prefix, or none) -- and that
    nothing which did not change anything (a 401, a 429, a 404, any read)
    records one at all.

The last class is the one that matters most: it asserts what must NEVER reach
the log. Key material, raw_alert text, analyst notes, note bodies and
resolution text are all absent by construction, and these tests keep them that
way if somebody adds a field later.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import audit
import auth
import limits
from conftest import SESSION_TOKEN_A, TEST_API_KEY, TEST_SESSION_TOKEN
from database import CaseRow, SessionLocal
from main import app
from models import IOCType, Severity
from routes import triage as triage_route


@pytest.fixture
def audit_log():
    """Capture the lines the audit logger emits, as parsed JSON objects.

    A handler attached straight to the audit logger rather than pytest's
    caplog: the logger sets ``propagate = False`` so its records never reach
    the root logger caplog listens on, which is exactly the behaviour that
    keeps the line from being emitted twice in production.
    """
    entries: list[dict] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            entries.append(json.loads(self.format(record)))

    handler = _Capture()
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit.logger.addHandler(handler)
    try:
        yield entries
    finally:
        audit.logger.removeHandler(handler)


@pytest.fixture
def raw_audit_log():
    """The audit lines as raw text, for asserting what is *not* in them."""
    lines: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(self.format(record))

    handler = _Capture()
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit.logger.addHandler(handler)
    try:
        yield lines
    finally:
        audit.logger.removeHandler(handler)


def _seed_case(manager, make_enrichment, make_report):
    return manager.open_case(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        severity=Severity.LOW,
        enrichment=make_enrichment(),
        report=make_report(),
    )


def _stub_triage_externals(monkeypatch, make_enrichment, make_report):
    async def fake_enrich(ioc, ioc_type):
        return make_enrichment(ioc=ioc)

    async def fake_generate(enrichment, alert):
        return make_report(ioc=enrichment.ioc)

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)


# -- The entry ----------------------------------------------------------------


class TestBuildEntry:
    def test_fields_are_exactly_the_allowed_set(self) -> None:
        """No field may be added without this test being changed deliberately.

        The point of the assertion is the direction nobody wants: a free-text
        field appearing in the audit record by accident.
        """
        entry = audit.build_entry(
            endpoint="POST /api/triage", case_id="4FA22FE3",
            ip="203.0.113.7", authenticated=False, actor="none", actor_id=None,
        )

        assert set(entry) == set(audit.ENTRY_FIELDS)

    def test_records_the_values_it_is_given(self) -> None:
        entry = audit.build_entry(
            endpoint="PATCH /api/cases/{case_id}/note", case_id="4FA22FE3",
            ip="203.0.113.7", authenticated=True,
            actor="operator", actor_id="0123abcd",
        )

        assert entry["event"] == "write"
        assert entry["endpoint"] == "PATCH /api/cases/{case_id}/note"
        assert entry["case_id"] == "4FA22FE3"
        assert entry["ip"] == "203.0.113.7"
        assert entry["authenticated"] is True
        assert entry["actor"] == "operator"
        assert entry["actor_id"] == "0123abcd"

    def test_timestamp_is_an_iso_8601_instant_in_utc(self) -> None:
        moment = datetime(2026, 9, 19, 12, 34, 56, tzinfo=UTC)

        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="203.0.113.7",
            authenticated=False, actor="none", actor_id=None, now=moment,
        )

        assert entry["ts"] == "2026-09-19T12:34:56+00:00"
        parsed = datetime.fromisoformat(str(entry["ts"]))
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0

    def test_timestamp_defaults_to_now_in_utc(self) -> None:
        before = datetime.now(UTC)
        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="203.0.113.7", authenticated=False,
            actor="none", actor_id=None,
        )
        after = datetime.now(UTC)

        assert before <= datetime.fromisoformat(str(entry["ts"])) <= after

    def test_case_id_is_optional(self) -> None:
        """Every write today supplies one; the field still tolerates its absence."""
        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="203.0.113.7", authenticated=False,
            actor="none", actor_id=None,
        )

        assert entry["case_id"] is None


class TestRecord:
    def test_emits_one_parseable_json_line(self, raw_audit_log) -> None:
        audit.record(
            endpoint="POST /api/triage", case_id="4FA22FE3",
            ip="203.0.113.7", authenticated=False, actor="none", actor_id=None,
        )

        assert len(raw_audit_log) == 1
        line = raw_audit_log[0]
        assert "\n" not in line  # one event, one line, for line-based ingest
        assert json.loads(line)["case_id"] == "4FA22FE3"

    def test_the_line_is_the_json_and_nothing_else(self, raw_audit_log) -> None:
        """No level prefix or logger name in front of the object."""
        audit.record(
            endpoint="POST /api/triage", ip="203.0.113.7", authenticated=True,
            actor="operator", actor_id="0123abcd",
        )

        assert raw_audit_log[0].startswith("{")
        assert raw_audit_log[0].endswith("}")

    def test_logger_does_not_propagate(self) -> None:
        """Otherwise uvicorn's root handlers emit every entry a second time."""
        assert audit.logger.propagate is False


# -- The four writes ----------------------------------------------------------


class TestTriageIsAudited:
    def test_records_the_case_it_opened(
        self, owner_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        response = owner_client(SESSION_TOKEN_A).post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip"},
            headers={"x-forwarded-for": "203.0.113.7"},
        )

        assert len(audit_log) == 1
        entry = audit_log[0]
        assert entry["endpoint"] == "POST /api/triage"
        assert entry["case_id"] == response.json()["case_id"]
        assert entry["ip"] == "203.0.113.7"

    def test_a_token_only_triage_is_recorded_as_unauthenticated(
        self, owner_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """A session token identifies a browser, not an operator."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        owner_client(SESSION_TOKEN_A).post("/api/triage", json={"ioc": "8.8.8.8"})

        assert audit_log[0]["authenticated"] is False

    def test_a_keyed_triage_is_recorded_as_authenticated(
        self, client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """The route needs no key, but the trail notes one that identified itself."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert audit_log[0]["authenticated"] is True

    def test_a_wrong_key_is_recorded_as_unauthenticated(
        self, owner_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """Presenting a key is not identifying yourself; the key has to be valid."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        owner_client(SESSION_TOKEN_A).post(
            "/api/triage",
            json={"ioc": "8.8.8.8"},
            headers={auth.API_KEY_HEADER: "not-the-key"},
        )

        assert audit_log[0]["authenticated"] is False

    def test_uses_the_leftmost_forwarded_for_entry(
        self, owner_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """The IP is the client behind the proxy, not the proxy's own hop."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        owner_client(SESSION_TOKEN_A).post(
            "/api/triage",
            json={"ioc": "8.8.8.8"},
            headers={"x-forwarded-for": "203.0.113.7, 70.41.3.18, 150.172.238.178"},
        )

        assert audit_log[0]["ip"] == "203.0.113.7"


class TestCaseWritesAreAudited:
    @pytest.mark.parametrize(
        ("suffix", "body", "endpoint"),
        [
            ("status", {"status": "in_progress"},
             "PATCH /api/cases/{case_id}/status"),
            ("note", {"note": "confirmed false positive"},
             "PATCH /api/cases/{case_id}/note"),
            ("close", {"resolution": "contained"},
             "PATCH /api/cases/{case_id}/close"),
        ],
    )
    def test_each_patch_records_one_authenticated_entry(
        self, client, audit_log, manager, make_enrichment, make_report,
        suffix: str, body: dict, endpoint: str,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = client.patch(
            f"/api/cases/{case.case_id}/{suffix}",
            json=body,
            headers={"x-forwarded-for": "198.51.100.4"},
        )

        assert response.status_code == 200
        assert len(audit_log) == 1
        entry = audit_log[0]
        # The route template, not the concrete path, so entries group cleanly.
        assert entry["endpoint"] == endpoint
        assert entry["case_id"] == case.case_id
        assert entry["ip"] == "198.51.100.4"
        assert entry["authenticated"] is True

    def test_several_writes_record_several_entries_in_order(
        self, client, audit_log, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        client.patch(f"/api/cases/{case.case_id}/status",
                     json={"status": "in_progress"})
        client.patch(f"/api/cases/{case.case_id}/note", json={"note": "looked"})
        client.patch(f"/api/cases/{case.case_id}/close", json={"resolution": "done"})

        assert [e["endpoint"].rsplit("/", 1)[-1] for e in audit_log] == [
            "status", "note", "close",
        ]

    def test_falls_back_to_the_socket_peer_without_a_proxy_header(
        self, client, audit_log, manager, make_enrichment, make_report
    ) -> None:
        """Local and direct-connection use still records an address."""
        case = _seed_case(manager, make_enrichment, make_report)

        client.patch(f"/api/cases/{case.case_id}/status",
                     json={"status": "escalated"})

        assert audit_log[0]["ip"]  # whatever TestClient's peer is, not blank


# -- Who made the change ------------------------------------------------------

# The expected ids come from fixed SHA-256 known-answer values of the test
# credentials, not from the auth.py helpers the code under test uses. Fixed
# rather than computed, so the test hashes nothing itself. The digests sit on
# lines of their own, apart from the credential names, because gitleaks'
# generic-api-key rule reads a long hex value next to a name like *_KEY as a key.
OPERATOR_KEY_B = "second-operator-key-not-a-real-secret"

_SHA256 = dict(
    zip(
        (TEST_API_KEY, OPERATOR_KEY_B, SESSION_TOKEN_A, TEST_SESSION_TOKEN),
        (
            "dc9301d03df111e45f84bf33d8e141617883ca1965ff0b1067ff721a9de94b54",
            "b366079ca70a6bce75a07e32169862feb330a8571b4c3eff2a52e815ad26f465",
            "303617b9730210ef3c86c52dc2aecc4dce54aaca6af8c8b0f4ceec9ecc54e57e",
            "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98",
        ),
        strict=True,
    )
)


def _sha256(value: str) -> str:
    """The SHA-256 hex digest of a test credential, from the table above."""
    return _SHA256[value]


def _key_only_client(key: str = TEST_API_KEY) -> TestClient:
    return TestClient(app, headers={auth.API_KEY_HEADER: key})


def _seed_owned_case(manager, make_enrichment, make_report, token: str):
    return manager.open_case(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        severity=Severity.LOW,
        enrichment=make_enrichment(),
        report=make_report(),
        owner_hash=_sha256(token),
    )


def _stored_owner_hash(case_id: str) -> str | None:
    with SessionLocal() as session:
        row = session.scalars(select(CaseRow).where(CaseRow.case_id == case_id)).one()
        return row.owner_hash


class _HeaderRequest:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class TestCallerActor:
    def test_a_keyed_caller_is_the_operator_named_by_key_fingerprint(self) -> None:
        caller = auth.resolve_caller(_HeaderRequest({auth.API_KEY_HEADER: TEST_API_KEY}))

        assert caller.audit_actor() == ("operator", _sha256(TEST_API_KEY)[:8])

    def test_a_token_caller_is_the_owner_named_by_hash_prefix(self) -> None:
        caller = auth.resolve_caller(
            _HeaderRequest({auth.SESSION_TOKEN_HEADER: SESSION_TOKEN_A})
        )

        assert caller.audit_actor() == ("owner", _sha256(SESSION_TOKEN_A)[:12])

    def test_a_caller_with_neither_is_none(self) -> None:
        caller = auth.resolve_caller(_HeaderRequest({}))

        assert caller.audit_actor() == ("none", None)

    def test_the_key_wins_when_both_are_present(self) -> None:
        """A keyed caller is scoped to every case, so the key is the authority."""
        caller = auth.resolve_caller(
            _HeaderRequest(
                {auth.API_KEY_HEADER: TEST_API_KEY, auth.SESSION_TOKEN_HEADER: SESSION_TOKEN_A}
            )
        )

        assert caller.audit_actor() == ("operator", _sha256(TEST_API_KEY)[:8])

    def test_a_wrong_key_carries_no_fingerprint(self) -> None:
        caller = auth.resolve_caller(_HeaderRequest({auth.API_KEY_HEADER: "not-the-key"}))

        assert caller.is_admin is False
        assert caller.key_fingerprint is None
        assert caller.audit_actor() == ("none", None)

    def test_no_key_configured_carries_no_fingerprint(self, monkeypatch) -> None:
        """Fail closed: with no key configured, nobody is the operator."""
        monkeypatch.delenv("SOCTRIAGE_API_KEYS")

        caller = auth.resolve_caller(_HeaderRequest({auth.API_KEY_HEADER: TEST_API_KEY}))

        assert caller.audit_actor() == ("none", None)

    def test_each_configured_key_has_its_own_fingerprint(self, monkeypatch) -> None:
        """With two keys configured during a rotation, the trail tells them apart."""
        monkeypatch.setenv("SOCTRIAGE_API_KEYS", f"{TEST_API_KEY},{OPERATOR_KEY_B}")

        first = auth.resolve_caller(_HeaderRequest({auth.API_KEY_HEADER: TEST_API_KEY}))
        second = auth.resolve_caller(_HeaderRequest({auth.API_KEY_HEADER: OPERATOR_KEY_B}))

        assert first.audit_actor() == ("operator", _sha256(TEST_API_KEY)[:8])
        assert second.audit_actor() == ("operator", _sha256(OPERATOR_KEY_B)[:8])


class TestActorIsRecorded:
    @pytest.mark.parametrize(
        ("suffix", "body"),
        [
            ("status", {"status": "in_progress"}),
            ("note", {"note": "looked"}),
            ("close", {"resolution": "done"}),
        ],
    )
    def test_an_operator_patch_records_the_key_fingerprint(
        self, audit_log, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = _key_only_client().patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        assert response.status_code == 200
        assert audit_log[0]["actor"] == "operator"
        assert audit_log[0]["actor_id"] == _sha256(TEST_API_KEY)[:8]
        assert audit_log[0]["authenticated"] is True

    @pytest.mark.parametrize(
        ("suffix", "body"),
        [
            ("status", {"status": "in_progress"}),
            ("note", {"note": "looked"}),
            ("close", {"resolution": "done"}),
        ],
    )
    def test_an_owner_patch_records_the_cases_owner_hash_prefix(
        self, owner_client, audit_log, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_owned_case(manager, make_enrichment, make_report, SESSION_TOKEN_A)

        response = owner_client(SESSION_TOKEN_A).patch(
            f"/api/cases/{case.case_id}/{suffix}", json=body
        )

        assert response.status_code == 200
        stored = _stored_owner_hash(case.case_id)
        assert stored is not None
        assert audit_log[0]["actor"] == "owner"
        assert audit_log[0]["actor_id"] == stored[:12]
        assert audit_log[0]["authenticated"] is False

    def test_an_owner_triage_records_the_new_cases_owner_hash_prefix(
        self, owner_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        response = owner_client(SESSION_TOKEN_A).post("/api/triage", json={"ioc": "8.8.8.8"})

        stored = _stored_owner_hash(response.json()["case_id"])
        assert stored is not None
        assert audit_log[0]["actor"] == "owner"
        assert audit_log[0]["actor_id"] == stored[:12]

    def test_a_keyed_triage_records_the_operator(
        self, client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """Key and token together: the key is what the trail names."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert audit_log[0]["actor"] == "operator"
        assert audit_log[0]["actor_id"] == _sha256(TEST_API_KEY)[:8]

    def test_a_rotated_key_is_told_apart_from_the_old_one(
        self, monkeypatch, audit_log, manager, make_enrichment, make_report
    ) -> None:
        monkeypatch.setenv("SOCTRIAGE_API_KEYS", f"{TEST_API_KEY},{OPERATOR_KEY_B}")
        case = _seed_case(manager, make_enrichment, make_report)

        _key_only_client(OPERATOR_KEY_B).patch(
            f"/api/cases/{case.case_id}/note", json={"note": "new key"}
        )
        _key_only_client().patch(f"/api/cases/{case.case_id}/note", json={"note": "old key"})

        assert [e["actor_id"] for e in audit_log] == [
            _sha256(OPERATOR_KEY_B)[:8], _sha256(TEST_API_KEY)[:8],
        ]

    def test_no_actor_is_recorded_as_none(self, raw_audit_log) -> None:
        """Every write route answers 401 to a caller with neither credential (see
        TestNothingIsRecordedWhenNothingChanged), so no route can produce this
        entry today. It is exercised at the record level."""
        audit.record(
            endpoint="POST /api/triage", case_id="4FA22FE3", ip="203.0.113.7",
            authenticated=False, actor="none", actor_id=None,
        )

        entry = json.loads(raw_audit_log[0])
        assert entry["actor"] == "none"
        assert entry["actor_id"] is None


class TestActorIdShapeIsEnforced:
    """build_entry refuses anything that is not a short hex fingerprint."""

    @pytest.mark.parametrize(
        ("actor", "actor_id"),
        [
            ("operator", TEST_API_KEY),                 # a raw key
            ("owner", SESSION_TOKEN_A),                 # a raw token
            ("owner", _sha256(SESSION_TOKEN_A)),        # the whole owner hash
            ("operator", _sha256(TEST_API_KEY)),        # the whole key hash
            ("operator", _sha256(TEST_API_KEY)[:12]),   # wrong length
            ("owner", _sha256(SESSION_TOKEN_A)[:8]),    # wrong length
            ("operator", _sha256(TEST_API_KEY)[:8].upper()),
            ("operator", None),
            ("owner", None),
            ("none", "0123abcd"),
            ("admin", "0123abcd"),                      # unknown actor
        ],
    )
    def test_rejects_a_value_of_the_wrong_shape(self, actor, actor_id) -> None:
        with pytest.raises(ValueError) as raised:
            audit.build_entry(
                endpoint="POST /api/triage", ip="203.0.113.7",
                authenticated=False, actor=actor, actor_id=actor_id,
            )

        # The error must not become a second place the value gets logged.
        if actor_id:
            assert actor_id not in str(raised.value)


# -- What must never be recorded ----------------------------------------------


class TestSensitiveValuesAreNeverLogged:
    """Key material and free text stay out of the trail, whatever the payload."""

    def test_the_api_key_never_appears(
        self, client, raw_audit_log, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        client.patch(f"/api/cases/{case.case_id}/note", json={"note": "checked"})

        assert raw_audit_log
        assert all(TEST_API_KEY not in line for line in raw_audit_log)
        assert all("x-api-key" not in line.lower() for line in raw_audit_log)

    def test_the_note_text_never_appears(
        self, client, raw_audit_log, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        secret = "victim ssn 123-45-6789 found in the payload"

        client.patch(f"/api/cases/{case.case_id}/note", json={"note": secret})

        assert raw_audit_log
        assert all(secret not in line for line in raw_audit_log)

    def test_the_resolution_text_never_appears(
        self, client, raw_audit_log, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        secret = "closed after the CEO confirmed the wire transfer"

        client.patch(f"/api/cases/{case.case_id}/close", json={"resolution": secret})

        assert raw_audit_log
        assert all(secret not in line for line in raw_audit_log)

    def test_the_raw_alert_and_analyst_notes_never_appear(
        self, client, monkeypatch, raw_audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)
        alert_text = "CrowdStrike: outbound to 185.220.101.45 from WS-042 at 0200"
        note_text = "user says they were asleep, escalating to the IR lead"

        client.post(
            "/api/triage",
            json={
                "ioc": "8.8.8.8",
                "ioc_type": "ip",
                "raw_alert": alert_text,
                "analyst_notes": note_text,
            },
        )

        assert raw_audit_log
        for line in raw_audit_log:
            assert alert_text not in line
            assert note_text not in line

    def test_the_entry_only_ever_carries_the_declared_fields(
        self, client, audit_log, manager, make_enrichment, make_report
    ) -> None:
        """Belt and braces on the two tests above, for any future free text."""
        case = _seed_case(manager, make_enrichment, make_report)

        client.patch(f"/api/cases/{case.case_id}/note", json={"note": "anything"})

        assert set(audit_log[0]) == set(audit.ENTRY_FIELDS)

    @pytest.mark.parametrize(
        "credentials",
        [
            {"key": TEST_API_KEY},
            {"key": OPERATOR_KEY_B},
            {"token": SESSION_TOKEN_A},
            {"key": TEST_API_KEY, "token": SESSION_TOKEN_A},
            {"key": "a-wrong-key-not-configured", "token": SESSION_TOKEN_A},
        ],
        ids=["key", "second-key", "token", "key-and-token", "wrong-key-and-token"],
    )
    def test_no_raw_key_or_token_appears_in_any_entry(
        self, monkeypatch, raw_audit_log, manager, make_enrichment, make_report,
        credentials: dict,
    ) -> None:
        """Every write, under every way of being let in: the trail carries
        fingerprints only, never a key, a token, or a whole hash of either."""
        monkeypatch.setenv("SOCTRIAGE_API_KEYS", f"{TEST_API_KEY},{OPERATOR_KEY_B}")
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)
        headers = {}
        if "key" in credentials:
            headers[auth.API_KEY_HEADER] = credentials["key"]
        if "token" in credentials:
            headers[auth.SESSION_TOKEN_HEADER] = credentials["token"]
        caller = TestClient(app, headers=headers)
        # A case the caller can write: its own if it has a token, else any.
        token = credentials.get("token")
        case = (
            _seed_owned_case(manager, make_enrichment, make_report, token)
            if token else _seed_case(manager, make_enrichment, make_report)
        )

        responses = [
            caller.patch(f"/api/cases/{case.case_id}/status", json={"status": "in_progress"}),
            caller.patch(f"/api/cases/{case.case_id}/note", json={"note": "checked"}),
            caller.patch(f"/api/cases/{case.case_id}/close", json={"resolution": "done"}),
        ]
        if token:  # triage requires a token
            responses.append(caller.post("/api/triage", json={"ioc": "8.8.8.8"}))

        assert all(r.status_code == 200 for r in responses)
        assert len(raw_audit_log) == len(responses)
        forbidden = [
            TEST_API_KEY, OPERATOR_KEY_B, "a-wrong-key-not-configured",
            SESSION_TOKEN_A, TEST_SESSION_TOKEN,
            _sha256(TEST_API_KEY), _sha256(OPERATOR_KEY_B), _sha256(SESSION_TOKEN_A),
        ]
        for line in raw_audit_log:
            for value in forbidden:
                assert value not in line
            # Nothing longer than a fingerprint that looks like a digest either.
            assert not re.search(r"[0-9a-f]{13,}", line)


# -- What must not be recorded at all -----------------------------------------


class TestNothingIsRecordedWhenNothingChanged:
    """The trail is of writes that happened, not of requests that were made."""

    @pytest.mark.parametrize(
        ("suffix", "body"),
        [
            ("status", {"status": "in_progress"}),
            ("note", {"note": "hi"}),
            ("close", {"resolution": "done"}),
        ],
    )
    def test_a_401_records_nothing(
        self, anon_client, audit_log, manager, make_enrichment, make_report,
        suffix: str, body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = anon_client.patch(f"/api/cases/{case.case_id}/{suffix}", json=body)

        assert response.status_code == 401
        assert audit_log == []

    def test_a_404_records_nothing(self, client, audit_log) -> None:
        response = client.patch(
            "/api/cases/DOESNOTEX/status", json={"status": "closed"}
        )

        assert response.status_code == 404
        assert audit_log == []

    def test_a_429_records_nothing(
        self, client, monkeypatch, audit_log, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        limiter = limits.Limiter(ip_rate=1)
        monkeypatch.setattr(triage_route, "limiter", limiter)
        limiter.check_case_write(ip="203.0.113.9")  # spend the allowance

        response = client.patch(
            f"/api/cases/{case.case_id}/status",
            json={"status": "closed"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 429
        assert audit_log == []

    def test_a_rejected_triage_records_nothing(
        self, owner_client, monkeypatch, audit_log
    ) -> None:
        """A triage turned away by the length cap never opened a case."""
        monkeypatch.setattr(
            triage_route, "limiter", limits.Limiter(max_raw_alert_chars=10)
        )

        response = owner_client(SESSION_TOKEN_A).post(
            "/api/triage", json={"ioc": "8.8.8.8", "raw_alert": "x" * 11}
        )

        assert response.status_code == 400
        assert audit_log == []

    def test_a_triage_without_a_token_records_nothing(
        self, anon_client, audit_log
    ) -> None:
        response = anon_client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert response.status_code == 401
        assert audit_log == []

    @pytest.mark.parametrize(
        "path", ["/health", "/api/cases", "/api/dashboard", "/api/cases/DOESNOTEX"]
    )
    def test_reads_record_nothing(self, client, audit_log, path: str) -> None:
        client.get(path)

        assert audit_log == []

"""Tests for the audit trail on the write endpoints.

Two layers:
  * unit tests on the entry itself -- its fields, its timestamp, and the fact
    that it is emitted as one parseable JSON line;
  * route tests proving each of the four writes records exactly one entry with
    the right endpoint, case id, client IP and authentication flag -- and that
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
from datetime import UTC, datetime

import pytest

import audit
import auth
import limits
from conftest import TEST_API_KEY
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
            ip="203.0.113.7", authenticated=False,
        )

        assert set(entry) == set(audit.ENTRY_FIELDS)

    def test_records_the_values_it_is_given(self) -> None:
        entry = audit.build_entry(
            endpoint="PATCH /api/cases/{case_id}/note", case_id="4FA22FE3",
            ip="203.0.113.7", authenticated=True,
        )

        assert entry["event"] == "write"
        assert entry["endpoint"] == "PATCH /api/cases/{case_id}/note"
        assert entry["case_id"] == "4FA22FE3"
        assert entry["ip"] == "203.0.113.7"
        assert entry["authenticated"] is True

    def test_timestamp_is_an_iso_8601_instant_in_utc(self) -> None:
        moment = datetime(2026, 9, 19, 12, 34, 56, tzinfo=UTC)

        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="203.0.113.7",
            authenticated=False, now=moment,
        )

        assert entry["ts"] == "2026-09-19T12:34:56+00:00"
        parsed = datetime.fromisoformat(str(entry["ts"]))
        assert parsed.tzinfo is not None
        assert parsed.utcoffset().total_seconds() == 0

    def test_timestamp_defaults_to_now_in_utc(self) -> None:
        before = datetime.now(UTC)
        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="1.1.1.1", authenticated=False
        )
        after = datetime.now(UTC)

        assert before <= datetime.fromisoformat(str(entry["ts"])) <= after

    def test_case_id_is_optional(self) -> None:
        """Every write today supplies one; the field still tolerates its absence."""
        entry = audit.build_entry(
            endpoint="POST /api/triage", ip="1.1.1.1", authenticated=False
        )

        assert entry["case_id"] is None


class TestRecord:
    def test_emits_one_parseable_json_line(self, raw_audit_log) -> None:
        audit.record(
            endpoint="POST /api/triage", case_id="4FA22FE3",
            ip="203.0.113.7", authenticated=False,
        )

        assert len(raw_audit_log) == 1
        line = raw_audit_log[0]
        assert "\n" not in line  # one event, one line, for line-based ingest
        assert json.loads(line)["case_id"] == "4FA22FE3"

    def test_the_line_is_the_json_and_nothing_else(self, raw_audit_log) -> None:
        """No level prefix or logger name in front of the object."""
        audit.record(endpoint="POST /api/triage", ip="1.1.1.1", authenticated=True)

        assert raw_audit_log[0].startswith("{")
        assert raw_audit_log[0].endswith("}")

    def test_logger_does_not_propagate(self) -> None:
        """Otherwise uvicorn's root handlers emit every entry a second time."""
        assert audit.logger.propagate is False


# -- The four writes ----------------------------------------------------------


class TestTriageIsAudited:
    def test_records_the_case_it_opened(
        self, anon_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        response = anon_client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip"},
            headers={"x-forwarded-for": "203.0.113.7"},
        )

        assert len(audit_log) == 1
        entry = audit_log[0]
        assert entry["endpoint"] == "POST /api/triage"
        assert entry["case_id"] == response.json()["case_id"]
        assert entry["ip"] == "203.0.113.7"

    def test_an_anonymous_triage_is_recorded_as_unauthenticated(
        self, anon_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        anon_client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert audit_log[0]["authenticated"] is False

    def test_a_keyed_triage_is_recorded_as_authenticated(
        self, client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """The route needs no key, but the trail notes one that identified itself."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert audit_log[0]["authenticated"] is True

    def test_a_wrong_key_is_recorded_as_unauthenticated(
        self, anon_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """Presenting a key is not identifying yourself; the key has to be valid."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        anon_client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8"},
            headers={auth.API_KEY_HEADER: "not-the-key"},
        )

        assert audit_log[0]["authenticated"] is False

    def test_uses_the_leftmost_forwarded_for_entry(
        self, anon_client, monkeypatch, audit_log, make_enrichment, make_report
    ) -> None:
        """The IP is the client behind the proxy, not the proxy's own hop."""
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)

        anon_client.post(
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
        self, anon_client, monkeypatch, raw_audit_log, make_enrichment, make_report
    ) -> None:
        _stub_triage_externals(monkeypatch, make_enrichment, make_report)
        alert_text = "CrowdStrike: outbound to 185.220.101.45 from WS-042 at 0200"
        note_text = "user says they were asleep, escalating to the IR lead"

        anon_client.post(
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
        self, anon_client, monkeypatch, audit_log
    ) -> None:
        """A triage turned away by the length cap never opened a case."""
        monkeypatch.setattr(
            triage_route, "limiter", limits.Limiter(max_raw_alert_chars=10)
        )

        response = anon_client.post(
            "/api/triage", json={"ioc": "8.8.8.8", "raw_alert": "x" * 11}
        )

        assert response.status_code == 400
        assert audit_log == []

    @pytest.mark.parametrize(
        "path", ["/health", "/api/cases", "/api/dashboard", "/api/cases/DOESNOTEX"]
    )
    def test_reads_record_nothing(self, client, audit_log, path: str) -> None:
        client.get(path)

        assert audit_log == []

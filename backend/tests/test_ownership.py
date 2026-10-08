"""Tests for case ownership through the visitor session token.

The rules under test (auth.py has the reasoning):

  * POST /api/triage requires an X-Session-Token and stores its SHA-256 as the
    case's owner_hash.
  * The reads (list, get, dashboard) show a token only its own cases; a valid
    API key sees every case.
  * The writes (status, note, close) accept a token for its own cases and the
    key for any case.
  * Another owner's case answers the same 404 as a case that does not exist.
  * Cases from before ownership have no owner and are visible to the key only.
  * No token and no key: the reads answer as if there were no cases, the
    writes answer 401.

Two visitors, A and B, each open one case through the API, and one legacy case
is seeded straight through the CaseManager with no owner. Every route is then
driven as A, as B, as nobody and as the key.
"""
from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

import audit
import auth
import limits
from conftest import SESSION_TOKEN_A, SESSION_TOKEN_B, TEST_API_KEY, TEST_SESSION_TOKEN
from database import CaseRow, SessionLocal
from models import IOCType, Severity
from routes import triage as triage_route

WRITE_ROUTES = [
    ("status", {"status": "escalated"}),
    ("note", {"note": "looked at this"}),
    ("close", {"resolution": "contained"}),
]


class _StubRequest:
    def __init__(self, token: str | None) -> None:
        self.headers = {} if token is None else {auth.SESSION_TOKEN_HEADER: token}


@pytest.fixture
def stub_externals(monkeypatch, make_enrichment, make_report):
    """Stub out the outbound enrichment + AI calls of POST /api/triage."""
    async def fake_enrich(ioc, ioc_type):
        return make_enrichment(ioc=ioc)

    async def fake_generate(enrichment, alert):
        return make_report(ioc=enrichment.ioc)

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)


@pytest.fixture
def visitors(owner_client, stub_externals, manager, make_enrichment, make_report):
    """A and B each open a case; one legacy case exists with no owner."""
    a = owner_client(SESSION_TOKEN_A)
    b = owner_client(SESSION_TOKEN_B)
    case_a = a.post("/api/triage", json={"ioc": "10.0.0.1"}).json()["case_id"]
    case_b = b.post("/api/triage", json={"ioc": "10.0.0.2"}).json()["case_id"]
    legacy = manager.open_case(
        ioc="10.0.0.3",
        ioc_type=IOCType.IP,
        severity=Severity.HIGH,
        enrichment=make_enrichment(ioc="10.0.0.3"),
        report=make_report(ioc="10.0.0.3", severity=Severity.HIGH),
    ).case_id
    return {"a": a, "b": b, "case_a": case_a, "case_b": case_b, "legacy": legacy}


def _ids(response) -> set[str]:
    assert response.status_code == 200
    return {case["case_id"] for case in response.json()}


# -- The token itself ---------------------------------------------------------


class TestSessionToken:
    def test_owner_hash_is_the_sha256_hex_of_the_token(self) -> None:
        expected = hashlib.sha256(SESSION_TOKEN_A.encode()).hexdigest()
        assert auth.owner_hash(SESSION_TOKEN_A) == expected

    def test_a_uuid_is_accepted(self) -> None:
        assert auth.session_owner_hash(_StubRequest(SESSION_TOKEN_A)) == auth.owner_hash(
            SESSION_TOKEN_A
        )

    def test_surrounding_whitespace_is_ignored(self) -> None:
        padded = _StubRequest(f"  {SESSION_TOKEN_A} ")
        assert auth.session_owner_hash(padded) == auth.owner_hash(SESSION_TOKEN_A)

    @pytest.mark.parametrize(
        "token",
        [
            None,
            "",
            "short",
            "x" * (auth.SESSION_TOKEN_MIN_LENGTH - 1),
            "x" * (auth.SESSION_TOKEN_MAX_LENGTH + 1),
            "has a space inside it, so no",
            "café-0000-0000-0000-000000000000",
        ],
    )
    def test_unusable_tokens_own_nothing(self, token: str | None) -> None:
        assert auth.session_owner_hash(_StubRequest(token)) is None

    def test_length_bounds_are_inclusive(self) -> None:
        for length in (auth.SESSION_TOKEN_MIN_LENGTH, auth.SESSION_TOKEN_MAX_LENGTH):
            assert auth.session_owner_hash(_StubRequest("x" * length)) is not None


# -- Opening a case -----------------------------------------------------------


class TestTriageRequiresAToken:
    def test_no_token_is_401(self, anon_client, stub_externals) -> None:
        response = anon_client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert response.status_code == 401
        assert response.json() == {"detail": auth.SESSION_TOKEN_MESSAGE}

    def test_a_malformed_token_is_401(self, owner_client, stub_externals) -> None:
        response = owner_client("short").post("/api/triage", json={"ioc": "8.8.8.8"})

        assert response.status_code == 401

    def test_the_key_alone_does_not_open_a_case(
        self, anon_client, stub_externals
    ) -> None:
        """Every new case gets an owner, the operator's included."""
        response = anon_client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8"},
            headers={auth.API_KEY_HEADER: TEST_API_KEY},
        )

        assert response.status_code == 401

    def test_no_case_is_opened_on_a_401(self, anon_client, client, stub_externals) -> None:
        anon_client.post("/api/triage", json={"ioc": "8.8.8.8"})

        assert client.get("/api/cases").json() == []

    def test_stores_the_hash_and_never_the_token(
        self, owner_client, stub_externals
    ) -> None:
        case_id = owner_client(SESSION_TOKEN_A).post(
            "/api/triage", json={"ioc": "8.8.8.8"}
        ).json()["case_id"]

        with SessionLocal() as session:
            row = session.get(CaseRow, case_id)
            assert row is not None
            assert row.owner_hash == auth.owner_hash(SESSION_TOKEN_A)
            stored = " ".join(str(v) for v in row.__dict__.values())
        assert SESSION_TOKEN_A not in stored

    def test_the_token_check_comes_before_the_limiter(
        self, anon_client, owner_client, monkeypatch, stub_externals
    ) -> None:
        """A refused triage spends none of the caller's allowance."""
        monkeypatch.setattr(triage_route, "limiter", limits.Limiter(ip_rate=1))
        headers = {"x-forwarded-for": "203.0.113.9"}

        for _ in range(3):
            refused = anon_client.post("/api/triage", json={"ioc": "8.8.8.8"}, headers=headers)
            assert refused.status_code == 401

        allowed = owner_client(SESSION_TOKEN_A).post(
            "/api/triage", json={"ioc": "8.8.8.8"}, headers=headers
        )
        assert allowed.status_code == 200


# -- Reads --------------------------------------------------------------------


class TestReadIsolation:
    def test_each_token_lists_only_its_own_cases(self, visitors) -> None:
        assert _ids(visitors["a"].get("/api/cases")) == {visitors["case_a"]}
        assert _ids(visitors["b"].get("/api/cases")) == {visitors["case_b"]}

    def test_each_token_gets_its_own_case(self, visitors) -> None:
        assert visitors["a"].get(f"/api/cases/{visitors['case_a']}").status_code == 200
        assert visitors["b"].get(f"/api/cases/{visitors['case_b']}").status_code == 200

    def test_another_owners_case_is_the_same_404_as_a_missing_one(self, visitors) -> None:
        foreign = visitors["b"].get(f"/api/cases/{visitors['case_a']}")
        missing = visitors["b"].get("/api/cases/DOESNOTEX")

        assert foreign.status_code == missing.status_code == 404
        assert foreign.json() == missing.json()

    def test_each_token_has_its_own_dashboard(self, visitors) -> None:
        for who in ("a", "b"):
            stats = visitors[who].get("/api/dashboard").json()
            assert stats["total"] == 1
            assert stats["by_status"]["open"] == 1
            assert sum(stats["by_severity"].values()) == 1

    def test_a_malformed_token_reads_nothing(self, visitors, owner_client) -> None:
        bad = owner_client("short")

        assert _ids(bad.get("/api/cases")) == set()
        assert bad.get(f"/api/cases/{visitors['case_a']}").status_code == 404
        assert bad.get("/api/dashboard").json()["total"] == 0


class TestNoToken:
    def test_lists_no_cases(self, visitors, anon_client) -> None:
        assert _ids(anon_client.get("/api/cases")) == set()

    def test_gets_no_case(self, visitors, anon_client) -> None:
        for case_id in (visitors["case_a"], visitors["case_b"], visitors["legacy"]):
            assert anon_client.get(f"/api/cases/{case_id}").status_code == 404

    def test_dashboard_is_all_zero(self, visitors, anon_client) -> None:
        stats = anon_client.get("/api/dashboard").json()

        assert stats["total"] == 0
        assert set(stats["by_status"].values()) == {0}
        assert set(stats["by_severity"].values()) == {0}

    @pytest.mark.parametrize(("suffix", "body"), WRITE_ROUTES)
    def test_writes_are_401(self, visitors, anon_client, suffix: str, body: dict) -> None:
        response = anon_client.patch(f"/api/cases/{visitors['case_a']}/{suffix}", json=body)

        assert response.status_code == 401


class TestLegacyCases:
    """Cases from before ownership have owner_hash NULL: the key's alone."""

    def test_hidden_from_every_token_in_the_list(self, visitors) -> None:
        for who in ("a", "b"):
            assert visitors["legacy"] not in _ids(visitors[who].get("/api/cases"))

    def test_404_for_every_token(self, visitors) -> None:
        for who in ("a", "b"):
            assert visitors[who].get(f"/api/cases/{visitors['legacy']}").status_code == 404

    def test_left_out_of_every_token_dashboard(self, visitors) -> None:
        """The legacy case is HIGH; neither visitor's dashboard counts it."""
        for who in ("a", "b"):
            assert visitors[who].get("/api/dashboard").json()["by_severity"]["high"] == 0

    @pytest.mark.parametrize(("suffix", "body"), WRITE_ROUTES)
    def test_no_token_can_write_to_one(
        self, visitors, client, suffix: str, body: dict
    ) -> None:
        before = client.get(f"/api/cases/{visitors['legacy']}").json()

        response = visitors["a"].patch(f"/api/cases/{visitors['legacy']}/{suffix}", json=body)

        assert response.status_code == 404
        assert client.get(f"/api/cases/{visitors['legacy']}").json() == before


# -- Writes -------------------------------------------------------------------


class TestWriteIsolation:
    @pytest.mark.parametrize(("suffix", "body"), WRITE_ROUTES)
    def test_an_owner_can_write_to_their_own_case(
        self, visitors, suffix: str, body: dict
    ) -> None:
        response = visitors["a"].patch(f"/api/cases/{visitors['case_a']}/{suffix}", json=body)

        assert response.status_code == 200
        assert response.json()["timeline"][-1]["action"]

    @pytest.mark.parametrize(("suffix", "body"), WRITE_ROUTES)
    def test_another_owners_case_is_404_and_unchanged(
        self, visitors, client, suffix: str, body: dict
    ) -> None:
        before = client.get(f"/api/cases/{visitors['case_a']}").json()

        foreign = visitors["b"].patch(f"/api/cases/{visitors['case_a']}/{suffix}", json=body)
        missing = visitors["b"].patch(f"/api/cases/DOESNOTEX/{suffix}", json=body)

        assert foreign.status_code == missing.status_code == 404
        assert foreign.json() == missing.json()
        assert client.get(f"/api/cases/{visitors['case_a']}").json() == before

    def test_an_owner_write_is_audited_as_unauthenticated(self, visitors, monkeypatch) -> None:
        recorded: list[dict] = []
        monkeypatch.setattr(audit, "record", lambda **entry: recorded.append(entry))

        visitors["a"].patch(
            f"/api/cases/{visitors['case_a']}/status", json={"status": "closed"}
        )

        assert recorded == [
            {
                "endpoint": "PATCH /api/cases/{case_id}/status",
                "case_id": visitors["case_a"],
                "ip": "testclient",
                "authenticated": False,
                # Named by its hash prefix, never by the token itself.
                "actor": "owner",
                "actor_id": auth.owner_hash(SESSION_TOKEN_A)[:12],
            }
        ]


# -- The key ------------------------------------------------------------------


class TestTheKeySeesEverything:
    def test_lists_every_case(self, visitors, client) -> None:
        assert _ids(client.get("/api/cases")) == {
            visitors["case_a"], visitors["case_b"], visitors["legacy"],
        }

    def test_gets_every_case(self, visitors, client) -> None:
        for case_id in (visitors["case_a"], visitors["case_b"], visitors["legacy"]):
            assert client.get(f"/api/cases/{case_id}").status_code == 200

    def test_dashboard_counts_every_case(self, visitors, client) -> None:
        assert client.get("/api/dashboard").json()["total"] == 3

    @pytest.mark.parametrize(("suffix", "body"), WRITE_ROUTES)
    def test_writes_to_every_case(
        self, visitors, client, suffix: str, body: dict
    ) -> None:
        for case_id in (visitors["case_a"], visitors["case_b"], visitors["legacy"]):
            response = client.patch(f"/api/cases/{case_id}/{suffix}", json=body)
            assert response.status_code == 200

    def test_a_wrong_key_with_a_token_is_just_that_token(
        self, visitors, owner_client
    ) -> None:
        a_with_bad_key = owner_client(SESSION_TOKEN_A)
        a_with_bad_key.headers[auth.API_KEY_HEADER] = "not-the-key"

        assert _ids(a_with_bad_key.get("/api/cases")) == {visitors["case_a"]}

    def test_cases_opened_with_the_key_still_belong_to_the_token(
        self, visitors, client
    ) -> None:
        """The ``client`` fixture sends the key and a token; its case is that token's."""
        case_id = client.post("/api/triage", json={"ioc": "10.0.0.4"}).json()["case_id"]

        with SessionLocal() as session:
            owner = session.scalar(
                select(CaseRow.owner_hash).where(CaseRow.case_id == case_id)
            )
        assert owner == auth.owner_hash(TEST_SESSION_TOKEN)

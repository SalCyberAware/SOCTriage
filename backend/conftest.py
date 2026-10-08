"""Pytest configuration and shared fixtures for the SOCTriage backend tests.

database.py builds the SQLAlchemy engine at import time from the DATABASE_URL
environment variable. To keep the tests off the real database, this file points
DATABASE_URL at a throwaway SQLite file *before* any application module is
imported. Every test then runs against empty tables.

The schema comes from the Alembic migrations, the same way it does in
production, not from Base.metadata.create_all(): the session starts by
migrating to head, so a migration that drifts from the models fails the suite.

SOCTRIAGE_TEST_DATABASE_URL, when set, is used instead of the SQLite file. CI
points it at a Postgres service so the suite also runs against the production
engine. Every table's rows are deleted between tests, so never point it at a
database whose data matters.
"""
import os
import tempfile
from datetime import UTC, datetime

# Point the app at a throwaway SQLite database BEFORE importing anything that
# reads DATABASE_URL -- database.py resolves it at import time.
_TEST_DB = os.path.join(tempfile.gettempdir(), "soctriage_pytest.db")
_EXTERNAL_TEST_DB_URL = os.getenv("SOCTRIAGE_TEST_DATABASE_URL", "").strip()
if _EXTERNAL_TEST_DB_URL:
    os.environ["DATABASE_URL"] = _EXTERNAL_TEST_DB_URL
else:
    # Start from an empty file so a schema left by an earlier run, possibly
    # from a different migration history, never leaks into this one.
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)
    os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.replace(os.sep, "/")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from auth import API_KEY_HEADER, SESSION_TOKEN_HEADER  # noqa: E402
from database import Base, engine, init_db  # noqa: E402
from main import app  # noqa: E402
from models import (  # noqa: E402
    EngineResult,
    EnrichmentResult,
    IncidentReport,
    MITRETechnique,
    Severity,
)
from services.case_manager import CaseManager  # noqa: E402

# The key the suite presents on authenticated requests. Configured for every
# test by the autouse fixture below, so a test that cares about the
# unconfigured (fail-closed) case has to delete the variable deliberately.
TEST_API_KEY = "test-api-key-not-a-real-secret"

# The session token the ``client`` fixture presents, so its triage requests
# open cases (POST /api/triage requires a token). Two more for the ownership
# tests, which need distinct visitors.
TEST_SESSION_TOKEN = "00000000-0000-4000-8000-000000000000"
SESSION_TOKEN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SESSION_TOKEN_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def _configured_api_key(monkeypatch):
    """Configure one accepted API key for the duration of each test.

    auth.py reads the environment per call, so setting it here is enough; no
    application object has to be rebuilt.
    """
    monkeypatch.setenv("SOCTRIAGE_API_KEYS", TEST_API_KEY)


@pytest.fixture(autouse=True)
def _development_env(monkeypatch):
    """Run each test as development unless it opts into production.

    Production keys the rate limit on X-Real-IP (see limits.client_ip). The
    suite drives distinct clients through X-Forwarded-For, the development key,
    so it runs as development by default. Tests of the production key set
    SOCTRIAGE_ENV themselves.
    """
    monkeypatch.setenv("SOCTRIAGE_ENV", "development")


@pytest.fixture
def client(_configured_api_key) -> TestClient:
    """A TestClient that presents a valid API key and a session token.

    The default for the suite: the gated routes are a detail most tests should
    not have to restate. The key makes every case visible to it whoever owns
    the case; the token is there because opening a case requires one. httpx
    merges these defaults with per-request headers, so a test can still add
    its own (x-forwarded-for, a different key) freely.
    Tests that exercise the unauthenticated paths use ``anon_client``.
    """
    return TestClient(
        app,
        headers={API_KEY_HEADER: TEST_API_KEY, SESSION_TOKEN_HEADER: TEST_SESSION_TOKEN},
    )


@pytest.fixture
def anon_client() -> TestClient:
    """A TestClient that presents neither an API key nor a session token."""
    return TestClient(app)


@pytest.fixture
def owner_client():
    """Factory for a TestClient that presents only the given session token."""
    def _make(token: str) -> TestClient:
        return TestClient(app, headers={SESSION_TOKEN_HEADER: token})

    return _make


@pytest.fixture(scope="session", autouse=True)
def _migrated_db():
    """Bring the test database to the newest migration, once per session."""
    init_db()
    yield
    engine.dispose()


def _delete_all_rows() -> None:
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())


@pytest.fixture(autouse=True)
def clean_db(_migrated_db):
    """Give every test empty tables, on the migrated schema."""
    _delete_all_rows()
    yield
    _delete_all_rows()


@pytest.fixture
def manager() -> CaseManager:
    """A CaseManager wired to the throwaway test database."""
    return CaseManager()


@pytest.fixture
def make_enrichment():
    """Factory for a minimal valid EnrichmentResult.

    Call with overrides, e.g. make_enrichment(score=83, verdict="malicious").
    """
    def _make(ioc="8.8.8.8", ioc_type="ip", verdict="clean", score=0):
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            verdict=verdict,
            score=score,
            engines=[
                EngineResult(
                    id="virustotal", verdict=verdict,
                    detail="0/90 engines flagged this", score=0.0,
                ),
            ],
        )

    return _make


@pytest.fixture
def make_report():
    """Factory for a minimal valid IncidentReport.

    Call with overrides, e.g. make_report(severity=Severity.HIGH).
    """
    def _make(ioc="8.8.8.8", ioc_type="ip", severity=Severity.LOW,
              verdict="clean", score=0):
        return IncidentReport(
            title=f"Triage of {ioc}",
            severity=severity,
            summary="Generated incident report for tests.",
            affected_assets=["WS-001"],
            threat_type="reconnaissance",
            ioc=ioc,
            ioc_type=ioc_type,
            verdict=verdict,
            score=score,
            mitre_techniques=[
                MITRETechnique(
                    technique_id="T1071",
                    technique_name="Application Layer Protocol",
                    tactic="Command and Control",
                    description="Adversary communication over common protocols.",
                    mitre_url="https://attack.mitre.org/techniques/T1071/",
                ),
            ],
            recommended_actions=["Isolate the affected host."],
            playbook=["Verify the alert", "Contain", "Eradicate"],
            generated_at=datetime.now(UTC),
        )

    return _make


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    """Give each test a fresh limiter so per-IP/daily state never leaks across tests.

    The limiter holds in-memory counters for the process lifetime, which in a test
    run means "for the whole suite" -- one test's writes would otherwise eat into
    the next test's allowance. Limit-specific tests replace this with their own
    configured limiter.
    """
    import limits
    from routes import triage as triage_route

    monkeypatch.setattr(triage_route, "limiter", limits.Limiter())

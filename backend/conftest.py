"""Pytest configuration and shared fixtures for the SOCTriage backend tests.

database.py builds the SQLAlchemy engine at import time from the DATABASE_URL
environment variable. To keep the tests off the real database, this file points
DATABASE_URL at a throwaway SQLite file *before* any application module is
imported. Every test then runs against freshly created, empty tables.
"""
import os
import tempfile
from datetime import UTC, datetime

# Point the app at a throwaway SQLite database BEFORE importing anything that
# reads DATABASE_URL -- database.py resolves it at import time.
_TEST_DB = os.path.join(tempfile.gettempdir(), "soctriage_pytest.db")
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.replace(os.sep, "/")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from auth import API_KEY_HEADER  # noqa: E402
from database import Base, engine  # noqa: E402
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


@pytest.fixture(autouse=True)
def _configured_api_key(monkeypatch):
    """Configure one accepted API key for the duration of each test.

    auth.py reads the environment per call, so setting it here is enough; no
    application object has to be rebuilt.
    """
    monkeypatch.setenv("SOCTRIAGE_API_KEYS", TEST_API_KEY)


@pytest.fixture
def client(_configured_api_key) -> TestClient:
    """A TestClient that presents a valid API key on every request.

    The default for the suite: the gated routes are a detail most tests should
    not have to restate. httpx merges these defaults with per-request headers,
    so a test can still add its own (x-forwarded-for, a different key) freely.
    Tests that exercise the unauthenticated paths use ``anon_client``.
    """
    return TestClient(app, headers={API_KEY_HEADER: TEST_API_KEY})


@pytest.fixture
def anon_client() -> TestClient:
    """A TestClient that presents no API key at all."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    """Give every test a fresh, empty set of tables."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


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

"""Pytest configuration and shared fixtures for the SOCTriage backend tests.

database.py builds the SQLAlchemy engine at import time from the DATABASE_URL
environment variable. To keep the tests off the real database, this file points
DATABASE_URL at a throwaway SQLite file *before* any application module is
imported. Every test then runs against freshly created, empty tables.
"""
import os
import tempfile
from datetime import datetime, timezone

# Point the app at a throwaway SQLite database BEFORE importing anything that
# reads DATABASE_URL -- database.py resolves it at import time.
_TEST_DB = os.path.join(tempfile.gettempdir(), "soctriage_pytest.db")
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.replace(os.sep, "/")

import pytest  # noqa: E402

from database import Base, engine  # noqa: E402
from models import (  # noqa: E402
    EngineResult,
    EnrichmentResult,
    IncidentReport,
    MITRETechnique,
    Severity,
)
from services.case_manager import CaseManager  # noqa: E402


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
            generated_at=datetime.now(timezone.utc),
        )

    return _make

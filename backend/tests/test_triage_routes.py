"""API-level tests for the routes defined in routes/triage.py.

These tests drive the FastAPI app through TestClient, so they cover the HTTP
layer (status codes, JSON shapes, error responses) on top of the persistence
layer. They reuse the shared test-database harness in backend/conftest.py:
the autouse ``clean_db`` fixture gives every test a fresh, empty SQLite
database, and ``manager`` / ``make_enrichment`` / ``make_report`` seed cases
through the same CaseManager the routes use.

POST /api/triage is covered here too, with the outbound enrichment + AI
calls monkeypatched so the route exercises end-to-end without touching
ThreatScan or Anthropic.
"""
from fastapi.testclient import TestClient

import pytest

from main import app
from models import CaseStatus, IOCType, Severity
from routes import triage as triage_route


@pytest.fixture
def client() -> TestClient:
    """A TestClient bound to the real FastAPI app."""
    return TestClient(app)


def _open_case(manager, make_enrichment, make_report, *, ioc="8.8.8.8",
               severity=Severity.LOW, analyst_notes=None):
    """Seed a case through the CaseManager and return it."""
    return manager.open_case(
        ioc=ioc,
        ioc_type=IOCType.IP,
        severity=severity,
        enrichment=make_enrichment(ioc=ioc),
        report=make_report(ioc=ioc, severity=severity),
        analyst_notes=analyst_notes,
    )


# ── GET /health ──────────────────────────────────────────────────────────────


def test_health_returns_ok_payload(client):
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "SOC Triage Assistant"
    assert body["version"] == "1.0.0"


# ── GET /api/cases ───────────────────────────────────────────────────────────


def test_list_cases_empty(client):
    response = client.get("/api/cases")

    assert response.status_code == 200
    assert response.json() == []


def test_list_cases_returns_seeded_cases(
    client, manager, make_enrichment, make_report
):
    _open_case(manager, make_enrichment, make_report, ioc="10.0.0.1")
    _open_case(manager, make_enrichment, make_report, ioc="10.0.0.2",
               severity=Severity.HIGH)

    response = client.get("/api/cases")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert {c["ioc"] for c in body} == {"10.0.0.1", "10.0.0.2"}


# ── GET /api/cases/{case_id} ─────────────────────────────────────────────────


def test_get_case_returns_full_payload(
    client, manager, make_enrichment, make_report
):
    case = _open_case(
        manager, make_enrichment, make_report,
        ioc="1.2.3.4", severity=Severity.CRITICAL,
        analyst_notes="check this",
    )

    response = client.get(f"/api/cases/{case.case_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["case_id"] == case.case_id
    assert body["ioc"] == "1.2.3.4"
    assert body["severity"] == "critical"
    assert body["status"] == "open"
    assert body["analyst_notes"] == "check this"
    assert body["enrichment"]["ioc"] == "1.2.3.4"
    assert body["report"]["title"] == "Triage of 1.2.3.4"
    assert len(body["timeline"]) >= 1


def test_get_case_returns_404_for_unknown_id(client):
    response = client.get("/api/cases/DOESNOTEX")

    assert response.status_code == 404
    assert response.json() == {"detail": "Case not found"}


# ── GET /api/dashboard ───────────────────────────────────────────────────────


def test_dashboard_empty_database(client):
    response = client.get("/api/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    for status in CaseStatus:
        assert body["by_status"][status.value] == 0
    for severity in Severity:
        assert body["by_severity"][severity.value] == 0


def test_dashboard_reflects_seeded_cases(
    client, manager, make_enrichment, make_report
):
    _open_case(manager, make_enrichment, make_report, ioc="1.1.1.1")
    high = _open_case(manager, make_enrichment, make_report,
                      ioc="2.2.2.2", severity=Severity.HIGH)
    manager.update_status(high.case_id, CaseStatus.ESCALATED)

    response = client.get("/api/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["by_status"]["open"] == 1
    assert body["by_status"]["escalated"] == 1
    assert body["by_severity"]["low"] == 1
    assert body["by_severity"]["high"] == 1


# ── PATCH /api/cases/{case_id}/status ────────────────────────────────────────


def test_update_status_changes_status_and_appends_timeline(
    client, manager, make_enrichment, make_report
):
    case = _open_case(manager, make_enrichment, make_report)
    timeline_before = len(case.timeline)

    response = client.patch(
        f"/api/cases/{case.case_id}/status",
        json={"status": "in_progress"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "in_progress"
    assert len(body["timeline"]) == timeline_before + 1
    assert body["timeline"][-1]["action"] == "Status updated to in_progress"


def test_update_status_returns_404_for_unknown_id(client):
    response = client.patch(
        "/api/cases/DOESNOTEX/status",
        json={"status": "in_progress"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Case not found"}


def test_update_status_rejects_invalid_status(
    client, manager, make_enrichment, make_report
):
    case = _open_case(manager, make_enrichment, make_report)

    response = client.patch(
        f"/api/cases/{case.case_id}/status",
        json={"status": "not_a_real_status"},
    )

    # Pydantic enum validation kicks in before the route runs.
    assert response.status_code == 422


# ── PATCH /api/cases/{case_id}/note ──────────────────────────────────────────


def test_add_note_appends_timeline_event(
    client, manager, make_enrichment, make_report
):
    case = _open_case(manager, make_enrichment, make_report)
    timeline_before = len(case.timeline)

    response = client.patch(
        f"/api/cases/{case.case_id}/note",
        json={"note": "Confirmed false positive"},
    )

    assert response.status_code == 200
    body = response.json()
    # Adding a note must not change the case status.
    assert body["status"] == "open"
    assert len(body["timeline"]) == timeline_before + 1
    last = body["timeline"][-1]
    assert last["action"] == "Note added"
    assert last["notes"] == "Confirmed false positive"


def test_add_note_returns_404_for_unknown_id(client):
    response = client.patch(
        "/api/cases/DOESNOTEX/note",
        json={"note": "anything"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Case not found"}


# ── PATCH /api/cases/{case_id}/close ─────────────────────────────────────────


def test_close_case_sets_status_and_records_resolution(
    client, manager, make_enrichment, make_report
):
    case = _open_case(manager, make_enrichment, make_report)

    response = client.patch(
        f"/api/cases/{case.case_id}/close",
        json={"resolution": "False positive: legitimate scan"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "closed"
    assert body["timeline"][-1]["action"] == "Case closed"
    assert body["timeline"][-1]["notes"] == "False positive: legitimate scan"


def test_close_case_persists_through_subsequent_get(
    client, manager, make_enrichment, make_report
):
    case = _open_case(manager, make_enrichment, make_report)

    client.patch(
        f"/api/cases/{case.case_id}/close",
        json={"resolution": "contained"},
    )

    fetched = client.get(f"/api/cases/{case.case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "closed"


def test_close_case_returns_404_for_unknown_id(client):
    response = client.patch(
        "/api/cases/DOESNOTEX/close",
        json={"resolution": "resolved"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Case not found"}


# ── POST /api/triage ─────────────────────────────────────────────────────────


def _patch_triage_externals(monkeypatch, enrichment, report):
    """Replace the route's enrichment + AI calls with async stubs.

    The route imports ``enrich_ioc`` and ``generate_report`` into its own
    namespace, so the patches must target ``routes.triage`` -- not the
    underlying service modules.
    """
    captured = {}

    async def fake_enrich(ioc, ioc_type):
        captured["enrich_args"] = (ioc, ioc_type)
        return enrichment

    async def fake_generate(enr, alert):
        captured["generate_args"] = (enr, alert)
        return report

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)
    return captured


def test_triage_endpoint_returns_triage_response_and_persists_case(
    client, monkeypatch, make_enrichment, make_report
):
    enrichment = make_enrichment(
        ioc="185.220.101.45", ioc_type="ip", verdict="malicious", score=87,
    )
    report = make_report(
        ioc="185.220.101.45", ioc_type="ip", verdict="malicious", score=87,
        severity=Severity.HIGH,
    )
    captured = _patch_triage_externals(monkeypatch, enrichment, report)

    response = client.post(
        "/api/triage",
        json={
            "raw_alert": "CrowdStrike: suspicious outbound connection",
            "ioc": "185.220.101.45",
            "ioc_type": "ip",
            "analyst_notes": "Triggered on WS-042",
        },
    )

    assert response.status_code == 200
    body = response.json()

    # The TriageResponse shape: case_id + enrichment + report + status.
    assert body["status"] == "success"
    assert body["case_id"]
    assert body["enrichment"]["ioc"] == "185.220.101.45"
    assert body["enrichment"]["verdict"] == "malicious"
    assert body["enrichment"]["score"] == 87
    assert body["report"]["title"] == "Triage of 185.220.101.45"
    assert body["report"]["severity"] == "high"

    # The stubs were invoked with the alert's IOC/type, not random values.
    assert captured["enrich_args"][0] == "185.220.101.45"
    assert captured["enrich_args"][1] == IOCType.IP

    # The case persisted -- it shows up in GET /api/cases and is fetchable
    # by id, with the analyst notes the intake supplied.
    listed = client.get("/api/cases").json()
    assert len(listed) == 1
    assert listed[0]["case_id"] == body["case_id"]
    assert listed[0]["ioc"] == "185.220.101.45"
    assert listed[0]["status"] == "open"
    assert listed[0]["severity"] == "high"

    fetched = client.get(f"/api/cases/{body['case_id']}").json()
    assert fetched["analyst_notes"] == "Triggered on WS-042"
    assert fetched["enrichment"]["verdict"] == "malicious"
    assert fetched["report"]["title"] == "Triage of 185.220.101.45"


def test_triage_endpoint_applies_severity_override(
    client, monkeypatch, make_enrichment, make_report
):
    """severity_override on the alert wins over the AI engine's severity."""
    enrichment = make_enrichment(verdict="suspicious", score=42)
    # AI engine says medium, but the analyst overrides to critical.
    report = make_report(severity=Severity.MEDIUM, verdict="suspicious", score=42)
    _patch_triage_externals(monkeypatch, enrichment, report)

    response = client.post(
        "/api/triage",
        json={
            "ioc": "8.8.8.8",
            "ioc_type": "ip",
            "severity_override": "critical",
        },
    )

    assert response.status_code == 200
    case_id = response.json()["case_id"]
    fetched = client.get(f"/api/cases/{case_id}").json()
    assert fetched["severity"] == "critical"


def test_triage_endpoint_returns_422_when_ioc_missing(client):
    """ioc is the only required field on AlertIntake; omitting it is a 422."""
    response = client.post("/api/triage", json={"ioc_type": "ip"})

    assert response.status_code == 422
    body = response.json()
    # FastAPI/Pydantic surfaces a "detail" list naming the bad field.
    assert "detail" in body
    assert any("ioc" in str(err.get("loc", [])) for err in body["detail"])


def test_triage_endpoint_returns_422_for_invalid_ioc_type(client):
    """ioc_type is an enum; an unknown value must fail validation."""
    response = client.post(
        "/api/triage",
        json={"ioc": "8.8.8.8", "ioc_type": "not_a_real_type"},
    )

    assert response.status_code == 422

from fastapi import APIRouter, HTTPException
from models import (
    AlertIntake, TriageResponse, Case,
    CaseStatus
)
from services.enrichment import enrich_ioc
from services.ai_engine import generate_report
from services.case_manager import (
    create_case, get_case, get_all_cases,
    update_case_status, add_note,
    close_case, get_dashboard_stats
)
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/api", tags=["triage"])


# ── Triage — main endpoint ────────────────────────────────────────────────────

@router.post("/triage", response_model=TriageResponse)
async def triage_alert(intake: AlertIntake):
    """
    Main endpoint — takes raw alert or IOC, enriches it,
    generates AI incident report, opens a case.
    """
    # 1. Determine IOC type
    ioc_type = intake.ioc_type.value if intake.ioc_type else "url"

    # 2. Enrich via ThreatScan
    enrichment = await enrich_ioc(intake.ioc, ioc_type)

    # 3. Generate AI report
    report = await generate_report(
        ioc            = intake.ioc,
        ioc_type       = ioc_type,
        enrichment     = enrichment,
        raw_alert      = intake.raw_alert,
        analyst_notes  = intake.analyst_notes,
        severity_override = intake.severity_override,
    )

    # 4. Open case
    case = create_case(
        ioc           = intake.ioc,
        ioc_type      = ioc_type,
        severity      = report.severity,
        enrichment    = enrichment,
        report        = report,
        analyst_notes = intake.analyst_notes,
    )

    return TriageResponse(
        case_id    = case.case_id,
        enrichment = enrichment,
        report     = report,
    )


# ── Cases ─────────────────────────────────────────────────────────────────────

@router.get("/cases", response_model=List[Case])
def list_cases():
    """Return all cases sorted by status and severity."""
    return get_all_cases()


@router.get("/cases/{case_id}", response_model=Case)
def get_single_case(case_id: str):
    """Return a single case by ID."""
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


# ── Case Actions ──────────────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status:  CaseStatus
    analyst: Optional[str] = "analyst"
    notes:   Optional[str] = None

class NoteUpdate(BaseModel):
    note:    str
    analyst: Optional[str] = "analyst"

class CloseCase(BaseModel):
    resolution: str
    analyst:    Optional[str] = "analyst"


@router.patch("/cases/{case_id}/status")
def update_status(case_id: str, body: StatusUpdate):
    """Update case status — open, in_progress, escalated, closed."""
    case = update_case_status(
        case_id  = case_id,
        status   = body.status,
        analyst  = body.analyst,
        notes    = body.notes,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


@router.patch("/cases/{case_id}/note")
def update_note(case_id: str, body: NoteUpdate):
    """Add or update analyst note on a case."""
    case = add_note(
        case_id  = case_id,
        note     = body.note,
        analyst  = body.analyst,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


@router.patch("/cases/{case_id}/close")
def close(case_id: str, body: CloseCase):
    """Close a case with resolution notes."""
    case = close_case(
        case_id    = case_id,
        resolution = body.resolution,
        analyst    = body.analyst,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


# ── Dashboard ─────────────────────────────────────────────────────────────────

@router.get("/dashboard")
def dashboard():
    """Return dashboard stats — case counts by status and severity."""
    return get_dashboard_stats()


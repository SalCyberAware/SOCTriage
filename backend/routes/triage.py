from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models import AlertIntake, CaseStatus
from services.enrichment import enrich_ioc
from services.ai_engine import generate_report
from services.case_manager import case_manager

router = APIRouter(prefix="/api")


class StatusUpdate(BaseModel):
    status: CaseStatus


class NoteUpdate(BaseModel):
    note: str


class CloseRequest(BaseModel):
    resolution: str


@router.post("/triage")
async def triage_alert(alert: AlertIntake):
    enrichment = await enrich_ioc(alert.ioc, alert.ioc_type)
    report = await generate_report(enrichment, alert)
    severity = alert.severity_override or report.severity
    case = case_manager.open_case(
        ioc=alert.ioc,
        ioc_type=alert.ioc_type,
        severity=severity,
        enrichment=enrichment,
        report=report,
        analyst_notes=alert.analyst_notes,
    )
    return case


@router.get("/cases")
async def list_cases():
    return case_manager.list_cases()


@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    case = case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/status")
async def update_status(case_id: str, body: StatusUpdate):
    case = case_manager.update_status(case_id, body.status)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/note")
async def add_note(case_id: str, body: NoteUpdate):
    case = case_manager.add_note(case_id, body.note)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/close")
async def close_case(case_id: str, body: CloseRequest):
    case = case_manager.close_case(case_id, body.resolution)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.get("/dashboard")
async def dashboard():
    return case_manager.get_stats()

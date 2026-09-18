from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from limits import LimitRejectedError, build_limiter, client_ip
from models import AlertIntake, CaseStatus, TriageResponse
from services.enrichment import enrich_ioc
from services.ai_engine import generate_report
from services.case_manager import case_manager

router = APIRouter(prefix="/api")

# Single shared limiter for this instance. In-memory state; see limits.py.
limiter = build_limiter()


def _enforce(check, **kwargs) -> None:
    """Run one limiter check, translating a rejection into an HTTP error.

    Called at the top of every write route, before any database write and before
    any model or third-party call, so a rejected request spends nothing.
    """
    try:
        check(**kwargs)
    except LimitRejectedError as rejected:
        raise HTTPException(
            status_code=rejected.status_code,
            detail=rejected.message,
            headers=rejected.headers,
        ) from rejected


class StatusUpdate(BaseModel):
    status: CaseStatus


class NoteUpdate(BaseModel):
    note: str


class CloseRequest(BaseModel):
    resolution: str


@router.post("/triage", response_model=TriageResponse)
async def triage_alert(alert: AlertIntake, request: Request):
    # Gated before enrichment and the AI call: this is the endpoint that spends
    # Anthropic and ThreatScan quota, and the only one under the daily cap.
    _enforce(
        limiter.check_triage,
        raw_alert=alert.raw_alert,
        ioc=alert.ioc,
        analyst_notes=alert.analyst_notes,
        ip=client_ip(request),
    )

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
    return TriageResponse(case_id=case.case_id, enrichment=enrichment, report=report)


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
async def update_status(case_id: str, body: StatusUpdate, request: Request):
    # No free text to cap: the body is a CaseStatus enum.
    _enforce(limiter.check_case_write, ip=client_ip(request))

    case = case_manager.update_status(case_id, body.status)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/note")
async def add_note(case_id: str, body: NoteUpdate, request: Request):
    _enforce(
        limiter.check_case_write,
        ip=client_ip(request),
        field="note",
        text=body.note,
    )

    case = case_manager.add_note(case_id, body.note)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/close")
async def close_case(case_id: str, body: CloseRequest, request: Request):
    _enforce(
        limiter.check_case_write,
        ip=client_ip(request),
        field="resolution",
        text=body.resolution,
    )

    case = case_manager.close_case(case_id, body.resolution)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.get("/dashboard")
async def dashboard():
    return case_manager.get_stats()

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import audit
from auth import AuthRejectedError, is_authenticated, require_api_key
from limits import LimitRejectedError, build_limiter, client_ip
from models import AlertIntake, CaseStatus, TriageResponse
from services.ai_engine import generate_report
from services.case_manager import case_manager
from services.enrichment import enrich_ioc

router = APIRouter(prefix="/api")

# Single shared limiter for this instance. In-memory state; see limits.py.
limiter = build_limiter()


def _require_key(request: Request) -> None:
    """Gate a write route on the API key, translating a rejection into a 401.

    Called as the FIRST statement of every gated route, ahead of the limiter
    and ahead of the case lookup. Ahead of the lookup because an unauthenticated
    caller must not be able to tell a case id that exists from one that does
    not: if the 404 came first, the route would be an oracle for enumerating
    case ids eight hex characters at a time.

    Ahead of the limiter because a 401 is the cheapest answer the service can
    give -- one constant-time string compare, no shared state, no database --
    so a rejected request touches nothing, not even the caller's rate-limit
    allowance. That does leave key guessing unthrottled, which is a deliberate
    trade: the guessing is bounded by the key's entropy (use a long random one;
    see .env.example), and spending limiter state on requests that are already
    refused would let an unauthenticated client push an authenticated one out
    of its allowance.
    """
    try:
        require_api_key(request)
    except AuthRejectedError as rejected:
        raise HTTPException(
            status_code=rejected.status_code,
            detail=rejected.message,
        ) from rejected


def _audit_case_write(endpoint: str, case_id: str, ip: str) -> None:
    """Record a completed write to an existing case.

    ``authenticated=True`` without asking: every route that calls this is
    behind :func:`_require_key`, so there is no other way to have reached it.
    """
    audit.record(endpoint=endpoint, case_id=case_id, ip=ip, authenticated=True)


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
    ip = client_ip(request)
    # Gated before enrichment and the AI call: this is the endpoint that spends
    # Anthropic and ThreatScan quota, and the only one under the daily cap.
    _enforce(
        limiter.check_triage,
        raw_alert=alert.raw_alert,
        ioc=alert.ioc,
        analyst_notes=alert.analyst_notes,
        ip=ip,
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
    # This route needs no key, but it can be given one, and the trail records
    # which it was. Neither the raw_alert nor the analyst notes are logged --
    # only that a case was opened, and by whom.
    audit.record(
        endpoint="POST /api/triage",
        case_id=case.case_id,
        ip=ip,
        authenticated=is_authenticated(request),
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
    _require_key(request)
    ip = client_ip(request)
    # No free text to cap: the body is a CaseStatus enum.
    _enforce(limiter.check_case_write, ip=ip)

    case = case_manager.update_status(case_id, body.status)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # After the write, so the trail records changes that happened. A 401, 429
    # or 404 above leaves no entry, because none of them changed anything.
    # authenticated is unconditionally True: _require_key is the only way here.
    _audit_case_write("PATCH /api/cases/{case_id}/status", case_id, ip)
    return case


@router.patch("/cases/{case_id}/note")
async def add_note(case_id: str, body: NoteUpdate, request: Request):
    _require_key(request)
    ip = client_ip(request)
    _enforce(
        limiter.check_case_write,
        ip=ip,
        field="note",
        text=body.note,
    )

    case = case_manager.add_note(case_id, body.note)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # The note text is deliberately absent from the entry: that a note was
    # added is auditable, what it said is the case timeline's business.
    _audit_case_write("PATCH /api/cases/{case_id}/note", case_id, ip)
    return case


@router.patch("/cases/{case_id}/close")
async def close_case(case_id: str, body: CloseRequest, request: Request):
    _require_key(request)
    ip = client_ip(request)
    _enforce(
        limiter.check_case_write,
        ip=ip,
        field="resolution",
        text=body.resolution,
    )

    case = case_manager.close_case(case_id, body.resolution)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # The resolution text is left out for the same reason as the note text.
    _audit_case_write("PATCH /api/cases/{case_id}/close", case_id, ip)
    return case


@router.get("/dashboard")
async def dashboard():
    return case_manager.get_stats()

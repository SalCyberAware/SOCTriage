from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import audit
from auth import (
    AuthRejectedError,
    Caller,
    require_case_writer,
    require_session_owner,
    resolve_caller,
)
from limits import LimitRejectedError, build_limiter, client_ip
from models import AlertIntake, CaseStatus, TriageResponse
from services.ai_engine import generate_report
from services.case_manager import ALL_CASES, CaseScope, case_manager
from services.enrichment import enrich_ioc

router = APIRouter(prefix="/api")

# Single shared limiter for this instance. In-memory state; see limits.py.
limiter = build_limiter()


def _scope(caller: Caller) -> CaseScope:
    """The cases a caller may see and change: all of them with the key, else
    only those its session token opened (none, without a token)."""
    if caller.is_admin:
        return ALL_CASES
    return CaseScope(owner_hash=caller.owner_hash)


def _require_writer(request: Request) -> Caller:
    """Gate a write route on the API key or a session token; 401 otherwise.

    A token gets through this gate whether or not it owns the case. Ownership
    is checked by the scoped lookup afterwards, and a case the token does not
    own answers the same 404 as one that does not exist, so a token cannot be
    used to tell taken case ids from free ones either.

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
        return require_case_writer(request)
    except AuthRejectedError as rejected:
        raise HTTPException(
            status_code=rejected.status_code,
            detail=rejected.message,
        ) from rejected


def _require_owner_token(request: Request) -> str:
    """The session token's owner hash, or a 401 if the request has none."""
    try:
        return require_session_owner(request)
    except AuthRejectedError as rejected:
        raise HTTPException(
            status_code=rejected.status_code,
            detail=rejected.message,
        ) from rejected


def _audit_case_write(endpoint: str, case_id: str, ip: str, caller: Caller) -> None:
    """Record a completed write to an existing case.

    ``authenticated`` means the API key, as it does everywhere in the trail. An
    owner changing their own case through a session token is recorded as
    unauthenticated: the token identifies a browser, not an operator.
    """
    audit.record(
        endpoint=endpoint, case_id=case_id, ip=ip, authenticated=caller.is_admin
    )


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
    # The token comes first, ahead of the limiter, for the same reason the key
    # does on the PATCH routes: a refusal that costs nothing should spend
    # nothing, not even the caller's rate-limit allowance.
    owner = _require_owner_token(request)
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
        owner_hash=owner,
    )
    # This route needs no key, but it can be given one, and the trail records
    # which it was. Neither the raw_alert nor the analyst notes are logged --
    # only that a case was opened, and by whom.
    audit.record(
        endpoint="POST /api/triage",
        case_id=case.case_id,
        ip=ip,
        authenticated=resolve_caller(request).is_admin,
    )
    return TriageResponse(case_id=case.case_id, enrichment=enrichment, report=report)


# The reads never answer 401. Without a key or a token they answer as if there
# were no cases at all, because for that caller there are none.


@router.get("/cases")
async def list_cases(request: Request):
    return case_manager.list_cases(_scope(resolve_caller(request)))


@router.get("/cases/{case_id}")
async def get_case(case_id: str, request: Request):
    # Another owner's case and a missing one are the same 404.
    case = case_manager.get_case(case_id, _scope(resolve_caller(request)))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/cases/{case_id}/status")
async def update_status(case_id: str, body: StatusUpdate, request: Request):
    caller = _require_writer(request)
    ip = client_ip(request)
    # No free text to cap: the body is a CaseStatus enum.
    _enforce(limiter.check_case_write, ip=ip)

    case = case_manager.update_status(case_id, body.status, _scope(caller))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # After the write, so the trail records changes that happened. A 401, 429
    # or 404 above leaves no entry, because none of them changed anything.
    _audit_case_write("PATCH /api/cases/{case_id}/status", case_id, ip, caller)
    return case


@router.patch("/cases/{case_id}/note")
async def add_note(case_id: str, body: NoteUpdate, request: Request):
    caller = _require_writer(request)
    ip = client_ip(request)
    _enforce(
        limiter.check_case_write,
        ip=ip,
        field="note",
        text=body.note,
    )

    case = case_manager.add_note(case_id, body.note, _scope(caller))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # The note text is deliberately absent from the entry: that a note was
    # added is auditable, what it said is the case timeline's business.
    _audit_case_write("PATCH /api/cases/{case_id}/note", case_id, ip, caller)
    return case


@router.patch("/cases/{case_id}/close")
async def close_case(case_id: str, body: CloseRequest, request: Request):
    caller = _require_writer(request)
    ip = client_ip(request)
    _enforce(
        limiter.check_case_write,
        ip=ip,
        field="resolution",
        text=body.resolution,
    )

    case = case_manager.close_case(case_id, body.resolution, _scope(caller))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    # The resolution text is left out for the same reason as the note text.
    _audit_case_write("PATCH /api/cases/{case_id}/close", case_id, ip, caller)
    return case


@router.get("/dashboard")
async def dashboard(request: Request):
    return case_manager.get_stats(_scope(resolve_caller(request)))

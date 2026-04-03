import uuid
from datetime import datetime
from typing import Dict, Optional, List
from models import (
    Case, CaseStatus, Severity, TimelineEvent,
    EnrichmentResult, IncidentReport
)

# In-memory store — will upgrade to PostgreSQL in Phase 2
_cases: Dict[str, Case] = {}


def create_case(
    ioc: str,
    ioc_type: str,
    severity: Severity,
    enrichment: EnrichmentResult,
    report: IncidentReport,
    analyst_notes: Optional[str] = None,
) -> Case:
    """Open a new investigation case."""
    case_id = f"CASE-{str(uuid.uuid4())[:8].upper()}"
    now     = datetime.utcnow()

    case = Case(
        case_id       = case_id,
        ioc           = ioc,
        ioc_type      = ioc_type,
        status        = CaseStatus.OPEN,
        severity      = severity,
        created_at    = now,
        updated_at    = now,
        enrichment    = enrichment,
        report        = report,
        analyst_notes = analyst_notes,
        timeline      = [
            TimelineEvent(
                timestamp = now,
                action    = "Case opened",
                analyst   = "system",
                notes     = f"IOC: {ioc} | Verdict: {enrichment.verdict} | Score: {enrichment.score}/100",
            )
        ],
    )

    _cases[case_id] = case
    return case


def get_case(case_id: str) -> Optional[Case]:
    """Retrieve a case by ID."""
    return _cases.get(case_id)


def get_all_cases() -> List[Case]:
    """Return all cases sorted by severity then created_at."""
    severity_order = {
        CaseStatus.OPEN:        0,
        CaseStatus.IN_PROGRESS: 1,
        CaseStatus.ESCALATED:   2,
        CaseStatus.CLOSED:      3,
    }
    return sorted(
        _cases.values(),
        key=lambda c: (severity_order.get(c.status, 9), c.created_at),
        reverse=False,
    )


def update_case_status(
    case_id: str,
    status: CaseStatus,
    analyst: str = "analyst",
    notes: Optional[str] = None,
) -> Optional[Case]:
    """Update case status and log to timeline."""
    case = _cases.get(case_id)
    if not case:
        return None

    old_status  = case.status
    case.status = status
    case.updated_at = datetime.utcnow()

    case.timeline.append(TimelineEvent(
        timestamp = datetime.utcnow(),
        action    = f"Status changed: {old_status} → {status}",
        analyst   = analyst,
        notes     = notes,
    ))

    _cases[case_id] = case
    return case


def add_note(
    case_id: str,
    note: str,
    analyst: str = "analyst",
) -> Optional[Case]:
    """Add analyst note and log to timeline."""
    case = _cases.get(case_id)
    if not case:
        return None

    case.analyst_notes = note
    case.updated_at    = datetime.utcnow()

    case.timeline.append(TimelineEvent(
        timestamp = datetime.utcnow(),
        action    = "Analyst note added",
        analyst   = analyst,
        notes     = note,
    ))

    _cases[case_id] = case
    return case


def close_case(
    case_id: str,
    resolution: str,
    analyst: str = "analyst",
) -> Optional[Case]:
    """Close a case with resolution notes."""
    case = _cases.get(case_id)
    if not case:
        return None

    case.status     = CaseStatus.CLOSED
    case.updated_at = datetime.utcnow()

    case.timeline.append(TimelineEvent(
        timestamp = datetime.utcnow(),
        action    = "Case closed",
        analyst   = analyst,
        notes     = resolution,
    ))

    _cases[case_id] = case
    return case


def get_dashboard_stats() -> dict:
    """Return summary stats for the dashboard."""
    all_cases = list(_cases.values())
    return {
        "total":       len(all_cases),
        "open":        sum(1 for c in all_cases if c.status == CaseStatus.OPEN),
        "in_progress": sum(1 for c in all_cases if c.status == CaseStatus.IN_PROGRESS),
        "escalated":   sum(1 for c in all_cases if c.status == CaseStatus.ESCALATED),
        "closed":      sum(1 for c in all_cases if c.status == CaseStatus.CLOSED),
        "critical":    sum(1 for c in all_cases if c.severity == Severity.CRITICAL),
        "high":        sum(1 for c in all_cases if c.severity == Severity.HIGH),
        "medium":      sum(1 for c in all_cases if c.severity == Severity.MEDIUM),
        "low":         sum(1 for c in all_cases if c.severity == Severity.LOW),
    }


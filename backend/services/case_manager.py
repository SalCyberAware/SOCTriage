"""Case persistence for SOCTriage.

Cases are stored in a relational database (see database.py) rather than in
memory, so they survive restarts. This module is the only place that bridges
the database rows and the Pydantic models used by the API: every public
method still accepts and returns the same Pydantic types as before, so the
routes did not have to change.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import func, select

from database import CaseRow, SessionLocal
from models import (
    Case,
    CaseStatus,
    EnrichmentResult,
    IncidentReport,
    IOCType,
    Severity,
    TimelineEvent,
)


def _ioc_type_str(ioc_type, enrichment: EnrichmentResult) -> str:
    """Resolve the IOC type to a plain string.

    Falls back to the type the enrichment engine detected when the caller did
    not supply one (AlertIntake.ioc_type is optional).
    """
    if isinstance(ioc_type, IOCType):
        return ioc_type.value
    if ioc_type:
        return str(ioc_type)
    return enrichment.ioc_type


def _event(action: str, analyst: str, notes: str, when: datetime) -> dict:
    """Build a JSON-ready timeline event for storage in the timeline column."""
    return TimelineEvent(
        timestamp=when, action=action, analyst=analyst, notes=notes
    ).model_dump(mode="json")


def _row_to_case(row: CaseRow) -> Case:
    """Rebuild the Pydantic Case (the API's type) from a database row."""
    return Case(
        case_id=row.case_id,
        ioc=row.ioc,
        ioc_type=row.ioc_type,
        status=CaseStatus(row.status),
        severity=Severity(row.severity),
        created_at=row.created_at,
        updated_at=row.updated_at,
        enrichment=(
            EnrichmentResult.model_validate(row.enrichment) if row.enrichment else None
        ),
        report=IncidentReport.model_validate(row.report) if row.report else None,
        timeline=[TimelineEvent.model_validate(ev) for ev in (row.timeline or [])],
        analyst_notes=row.analyst_notes,
    )


class CaseManager:
    """Reads and writes triage cases through the database."""

    def open_case(self, ioc: str, ioc_type, severity: Severity,
                  enrichment: EnrichmentResult, report: IncidentReport,
                  analyst_notes: Optional[str] = None) -> Case:
        case_id = str(uuid.uuid4())[:8].upper()
        now = datetime.now(timezone.utc)

        timeline = [
            _event(
                "Case opened",
                "system",
                f"IOC: {ioc} | Score: {enrichment.score} | Verdict: {enrichment.verdict}",
                now,
            )
        ]
        if analyst_notes:
            timeline.append(_event("Analyst note added", "analyst", analyst_notes, now))

        severity_str = severity.value if isinstance(severity, Severity) else str(severity)

        with SessionLocal() as session:
            row = CaseRow(
                case_id=case_id,
                ioc=ioc,
                ioc_type=_ioc_type_str(ioc_type, enrichment),
                status=CaseStatus.OPEN.value,
                severity=severity_str,
                created_at=now,
                updated_at=now,
                analyst_notes=analyst_notes,
                enrichment=enrichment.model_dump(mode="json"),
                report=report.model_dump(mode="json"),
                timeline=timeline,
            )
            session.add(row)
            session.commit()
            return _row_to_case(row)

    def list_cases(self) -> List[Case]:
        with SessionLocal() as session:
            rows = session.scalars(select(CaseRow).order_by(CaseRow.created_at)).all()
            return [_row_to_case(row) for row in rows]

    def get_case(self, case_id: str) -> Optional[Case]:
        with SessionLocal() as session:
            row = session.get(CaseRow, case_id)
            return _row_to_case(row) if row else None

    def update_status(self, case_id: str, status: CaseStatus) -> Optional[Case]:
        with SessionLocal() as session:
            row = session.get(CaseRow, case_id)
            if row is None:
                return None
            now = datetime.now(timezone.utc)
            row.status = status.value if isinstance(status, CaseStatus) else str(status)
            row.updated_at = now
            row.timeline = row.timeline + [
                _event(f"Status updated to {status.value}", "analyst", "", now)
            ]
            session.commit()
            return _row_to_case(row)

    def add_note(self, case_id: str, note: str) -> Optional[Case]:
        with SessionLocal() as session:
            row = session.get(CaseRow, case_id)
            if row is None:
                return None
            now = datetime.now(timezone.utc)
            row.updated_at = now
            row.timeline = row.timeline + [_event("Note added", "analyst", note, now)]
            session.commit()
            return _row_to_case(row)

    def close_case(self, case_id: str, resolution: str) -> Optional[Case]:
        with SessionLocal() as session:
            row = session.get(CaseRow, case_id)
            if row is None:
                return None
            now = datetime.now(timezone.utc)
            row.status = CaseStatus.CLOSED.value
            row.updated_at = now
            row.timeline = row.timeline + [
                _event("Case closed", "analyst", resolution, now)
            ]
            session.commit()
            return _row_to_case(row)

    def get_stats(self) -> dict:
        with SessionLocal() as session:
            total = session.scalar(select(func.count()).select_from(CaseRow)) or 0
            status_counts = dict(
                session.execute(
                    select(CaseRow.status, func.count()).group_by(CaseRow.status)
                ).all()
            )
            severity_counts = dict(
                session.execute(
                    select(CaseRow.severity, func.count()).group_by(CaseRow.severity)
                ).all()
            )

        return {
            "total": total,
            "by_status": {s.value: status_counts.get(s.value, 0) for s in CaseStatus},
            "by_severity": {s.value: severity_counts.get(s.value, 0) for s in Severity},
        }


case_manager = CaseManager()

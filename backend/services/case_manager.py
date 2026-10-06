"""Case persistence for SOCTriage.

Cases are stored in a relational database (see database.py) rather than in
memory, so they survive restarts. This module is the only place that bridges
the database rows and the Pydantic models used by the API: every public
method still accepts and returns the same Pydantic types as before.

Every read and every write takes a CaseScope saying whose cases the caller may
touch. A case outside the scope is reported exactly like a missing one (None),
so the routes cannot accidentally answer differently for the two. The default
scope is ALL_CASES, which is what the API key gets and what internal callers
that are not acting for a visitor want.
"""
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Select, false, func, select

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


@dataclass(frozen=True)
class CaseScope:
    """Which cases a caller may see and change.

    ``everything`` is the API key. Otherwise only rows whose owner_hash equals
    ``owner_hash``; with no owner_hash that is no rows at all, and in
    particular not the legacy rows whose owner_hash is NULL.
    """

    owner_hash: str | None = None
    everything: bool = False

    def allows(self, row: CaseRow) -> bool:
        if self.everything:
            return True
        return self.owner_hash is not None and row.owner_hash == self.owner_hash

    def apply(self, statement: Select) -> Select:
        """Restrict a SELECT over cases to this scope."""
        if self.everything:
            return statement
        # owner_hash None compiles to "owner_hash IS NULL", which would match
        # exactly the legacy rows this scope must not see; match nothing.
        if self.owner_hash is None:
            return statement.where(false())
        return statement.where(CaseRow.owner_hash == self.owner_hash)


ALL_CASES = CaseScope(everything=True)


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


def _load(session, case_id: str, scope: CaseScope) -> CaseRow | None:
    """The row for ``case_id`` if it exists AND is in scope, else None."""
    row = session.get(CaseRow, case_id)
    return row if row is not None and scope.allows(row) else None


class CaseManager:
    """Reads and writes triage cases through the database."""

    def open_case(self, ioc: str, ioc_type, severity: Severity,
                  enrichment: EnrichmentResult, report: IncidentReport,
                  analyst_notes: str | None = None,
                  owner_hash: str | None = None) -> Case:
        case_id = str(uuid.uuid4())[:8].upper()
        now = datetime.now(UTC)

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
                owner_hash=owner_hash,
            )
            session.add(row)
            session.commit()
            return _row_to_case(row)

    def list_cases(self, scope: CaseScope = ALL_CASES) -> list[Case]:
        with SessionLocal() as session:
            statement = scope.apply(select(CaseRow).order_by(CaseRow.created_at))
            rows = session.scalars(statement).all()
            return [_row_to_case(row) for row in rows]

    def get_case(self, case_id: str, scope: CaseScope = ALL_CASES) -> Case | None:
        with SessionLocal() as session:
            row = _load(session, case_id, scope)
            return _row_to_case(row) if row else None

    def update_status(self, case_id: str, status: CaseStatus,
                      scope: CaseScope = ALL_CASES) -> Case | None:
        with SessionLocal() as session:
            row = _load(session, case_id, scope)
            if row is None:
                return None
            now = datetime.now(UTC)
            row.status = status.value if isinstance(status, CaseStatus) else str(status)
            row.updated_at = now
            row.timeline = row.timeline + [
                _event(f"Status updated to {status.value}", "analyst", "", now)
            ]
            session.commit()
            return _row_to_case(row)

    def add_note(self, case_id: str, note: str,
                 scope: CaseScope = ALL_CASES) -> Case | None:
        with SessionLocal() as session:
            row = _load(session, case_id, scope)
            if row is None:
                return None
            now = datetime.now(UTC)
            row.updated_at = now
            row.timeline = row.timeline + [_event("Note added", "analyst", note, now)]
            session.commit()
            return _row_to_case(row)

    def close_case(self, case_id: str, resolution: str,
                   scope: CaseScope = ALL_CASES) -> Case | None:
        with SessionLocal() as session:
            row = _load(session, case_id, scope)
            if row is None:
                return None
            now = datetime.now(UTC)
            row.status = CaseStatus.CLOSED.value
            row.updated_at = now
            row.timeline = row.timeline + [
                _event("Case closed", "analyst", resolution, now)
            ]
            session.commit()
            return _row_to_case(row)

    def get_stats(self, scope: CaseScope = ALL_CASES) -> dict:
        with SessionLocal() as session:
            total = session.scalar(
                scope.apply(select(func.count()).select_from(CaseRow))
            ) or 0
            # Unpacked per row rather than dict(rows): a SQLAlchemy Row is
            # iterable but is not typed as a 2-tuple, so dict() over it has no
            # inferable key/value type.
            status_counts: dict[str, int] = {
                status: count
                for status, count in session.execute(
                    scope.apply(select(CaseRow.status, func.count())).group_by(CaseRow.status)
                ).all()
            }
            severity_counts: dict[str, int] = {
                severity: count
                for severity, count in session.execute(
                    scope.apply(select(CaseRow.severity, func.count())).group_by(CaseRow.severity)
                ).all()
            }

        return {
            "total": total,
            "by_status": {s.value: status_counts.get(s.value, 0) for s in CaseStatus},
            "by_severity": {s.value: severity_counts.get(s.value, 0) for s in Severity},
        }


case_manager = CaseManager()

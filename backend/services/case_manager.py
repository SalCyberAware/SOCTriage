import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from models import Case, CaseStatus, EnrichmentResult, IOCType, IncidentReport, Severity, TimelineEvent


class CaseManager:
    def __init__(self):
        self.cases: Dict[str, Case] = {}

    def open_case(self, ioc: str, ioc_type: IOCType, severity: Severity,
                  enrichment: EnrichmentResult, report: IncidentReport,
                  analyst_notes: Optional[str] = None) -> Case:
        case_id = str(uuid.uuid4())[:8].upper()
        now = datetime.now(timezone.utc)

        timeline = [
            TimelineEvent(
                timestamp=now,
                action="Case opened",
                analyst="system",
                notes=f"IOC: {ioc} | Score: {enrichment.score} | Verdict: {enrichment.verdict}",
            )
        ]
        if analyst_notes:
            timeline.append(TimelineEvent(
                timestamp=now, action="Analyst note added",
                analyst="analyst", notes=analyst_notes,
            ))

        case = Case(
            case_id=case_id,
            ioc=ioc,
            ioc_type=ioc_type,
            status=CaseStatus.OPEN,
            severity=severity,
            created_at=now,
            updated_at=now,
            timeline=timeline,
            report=report,
            enrichment=enrichment,
            analyst_notes=analyst_notes,
        )
        self.cases[case_id] = case
        return case

    def list_cases(self) -> List[Case]:
        return list(self.cases.values())

    def get_case(self, case_id: str) -> Optional[Case]:
        return self.cases.get(case_id)

    def update_status(self, case_id: str, status: CaseStatus) -> Optional[Case]:
        case = self.cases.get(case_id)
        if not case:
            return None
        case.status = status
        case.updated_at = datetime.now(timezone.utc)
        case.timeline.append(TimelineEvent(
            timestamp=datetime.now(timezone.utc),
            action=f"Status updated to {status.value}",
            analyst="analyst", notes="",
        ))
        return case

    def add_note(self, case_id: str, note: str) -> Optional[Case]:
        case = self.cases.get(case_id)
        if not case:
            return None
        case.updated_at = datetime.now(timezone.utc)
        case.timeline.append(TimelineEvent(
            timestamp=datetime.now(timezone.utc),
            action="Note added", analyst="analyst", notes=note,
        ))
        return case

    def close_case(self, case_id: str, resolution: str) -> Optional[Case]:
        case = self.cases.get(case_id)
        if not case:
            return None
        case.status = CaseStatus.CLOSED
        case.updated_at = datetime.now(timezone.utc)
        case.timeline.append(TimelineEvent(
            timestamp=datetime.now(timezone.utc),
            action="Case closed", analyst="analyst", notes=resolution,
        ))
        return case

    def get_stats(self) -> dict:
        cases = list(self.cases.values())
        stats: dict = {"total": len(cases), "by_status": {}, "by_severity": {}}
        for s in CaseStatus:
            stats["by_status"][s.value] = sum(1 for c in cases if c.status == s)
        for s in Severity:
            stats["by_severity"][s.value] = sum(1 for c in cases if c.severity == s)
        return stats


case_manager = CaseManager()

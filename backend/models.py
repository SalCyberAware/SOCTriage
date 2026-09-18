from datetime import datetime
from enum import Enum

from pydantic import BaseModel

# ── Enums ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class CaseStatus(str, Enum):
    OPEN        = "open"
    IN_PROGRESS = "in_progress"
    ESCALATED   = "escalated"
    CLOSED      = "closed"

class IOCType(str, Enum):
    IP     = "ip"
    URL    = "url"
    DOMAIN = "domain"
    HASH   = "hash"


# ── Alert Intake ──────────────────────────────────────────────────────────────

class AlertIntake(BaseModel):
    raw_alert:        str | None = None   # Raw alert text from SIEM
    ioc:              str                    # IP, URL, domain, or hash
    ioc_type:         IOCType | None = None
    analyst_notes:    str | None = None
    severity_override: Severity | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "raw_alert": "CrowdStrike alert: suspicious outbound connection detected",
                "ioc": "185.220.101.45",
                "ioc_type": "ip",
                "analyst_notes": "Triggered on workstation WS-042 at 14:32 UTC",
                "severity_override": None
            }
        }


# ── Enrichment ────────────────────────────────────────────────────────────────

class EngineResult(BaseModel):
    id:      str
    verdict: str
    detail:  str | None = None
    score:   float | None = None

class EnrichmentResult(BaseModel):
    ioc:      str
    ioc_type: str
    verdict:  str
    score:    int
    engines:  list[EngineResult]


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

class MITRETechnique(BaseModel):
    technique_id:   str    # e.g. T1071
    technique_name: str    # e.g. Application Layer Protocol
    tactic:         str    # e.g. Command and Control
    description:    str
    mitre_url:      str


# ── Incident Report ───────────────────────────────────────────────────────────

class IncidentReport(BaseModel):
    title:           str
    severity:        Severity
    summary:         str
    affected_assets: list[str]
    threat_type:     str
    ioc:             str
    ioc_type:        str
    verdict:         str
    score:           int
    mitre_techniques: list[MITRETechnique]
    recommended_actions: list[str]
    playbook:        list[str]
    generated_at:    datetime


# ── Case ──────────────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: datetime
    action:    str
    analyst:   str | None = "analyst"
    notes:     str | None = None

class Case(BaseModel):
    case_id:        str
    ioc:            str
    ioc_type:       str
    status:         CaseStatus
    severity:       Severity
    created_at:     datetime
    updated_at:     datetime
    enrichment:     EnrichmentResult | None = None
    report:         IncidentReport | None = None
    timeline:       list[TimelineEvent] = []
    analyst_notes:  str | None = None


# ── API Responses ─────────────────────────────────────────────────────────────

class TriageResponse(BaseModel):
    case_id:    str
    enrichment: EnrichmentResult
    report:     IncidentReport
    status:     str = "success"

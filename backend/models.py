from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

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


# ── Schema ceilings on free text ──────────────────────────────────────────────
#
# A hard backstop, not the limit a user normally meets. limits.py enforces the
# real caps (10,000 / 256 / 2,000 characters by default, tunable by env) and
# answers with a plain 400 that names the field and the cap. These ceilings sit
# ten times or more above those defaults, so normal oversize input still gets
# that friendly 400; only something absurd is refused here, with a 422, before
# any handler code runs. If a SOCTRIAGE_MAX_* cap is ever raised past one of
# these, the ceiling wins, so raise both together.
MAX_RAW_ALERT_SCHEMA_CHARS = 100_000
MAX_IOC_SCHEMA_CHARS = 4_096
MAX_NOTE_SCHEMA_CHARS = 20_000


# ── Alert Intake ──────────────────────────────────────────────────────────────

class AlertIntake(BaseModel):
    # Raw alert text from SIEM
    raw_alert:        str | None = Field(default=None, max_length=MAX_RAW_ALERT_SCHEMA_CHARS)
    ioc:              str = Field(max_length=MAX_IOC_SCHEMA_CHARS)  # IP, URL, domain, or hash
    ioc_type:         IOCType | None = None
    analyst_notes:    str | None = Field(default=None, max_length=MAX_NOTE_SCHEMA_CHARS)
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

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


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
    raw_alert:        Optional[str] = None   # Raw alert text from SIEM
    ioc:              str                    # IP, URL, domain, or hash
    ioc_type:         Optional[IOCType] = None
    analyst_notes:    Optional[str] = None
    severity_override: Optional[Severity] = None

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
    detail:  Optional[str] = None
    score:   Optional[float] = None

class EnrichmentResult(BaseModel):
    ioc:      str
    ioc_type: str
    verdict:  str
    score:    int
    engines:  List[EngineResult]


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
    affected_assets: List[str]
    threat_type:     str
    ioc:             str
    ioc_type:        str
    verdict:         str
    score:           int
    mitre_techniques: List[MITRETechnique]
    recommended_actions: List[str]
    playbook:        List[str]
    generated_at:    datetime


# ── Case ──────────────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: datetime
    action:    str
    analyst:   Optional[str] = "analyst"
    notes:     Optional[str] = None

class Case(BaseModel):
    case_id:        str
    ioc:            str
    ioc_type:       str
    status:         CaseStatus
    severity:       Severity
    created_at:     datetime
    updated_at:     datetime
    enrichment:     Optional[EnrichmentResult] = None
    report:         Optional[IncidentReport] = None
    timeline:       List[TimelineEvent] = []
    analyst_notes:  Optional[str] = None


# ── API Responses ─────────────────────────────────────────────────────────────

class TriageResponse(BaseModel):
    case_id:    str
    enrichment: EnrichmentResult
    report:     IncidentReport
    status:     str = "success"

import os
import json
import anthropic
from datetime import datetime
from models import (
    IncidentReport, MITRETechnique, Severity,
    EnrichmentResult
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def _severity_from_score(score: int) -> Severity:
    if score >= 75: return Severity.CRITICAL
    if score >= 50: return Severity.HIGH
    if score >= 25: return Severity.MEDIUM
    return Severity.LOW


def _build_prompt(ioc: str, ioc_type: str, enrichment: EnrichmentResult,
                  raw_alert: str = None, analyst_notes: str = None) -> str:
    engine_summary = []
    for e in enrichment.engines:
        if e.verdict not in ["info", "skipped", "error"]:
            engine_summary.append(f"- {e.id}: {e.verdict} {f'({e.detail})' if e.detail else ''}")

    engines_text = "\n".join(engine_summary) if engine_summary else "No malicious detections"

    raw_alert_text = f"\nRAW ALERT:\n{raw_alert}" if raw_alert else ""
    notes_text     = f"\nANALYST NOTES:\n{analyst_notes}" if analyst_notes else ""

    return f"""You are a senior SOC analyst writing a professional incident report.

IOC: {ioc}
TYPE: {ioc_type}
THREAT SCORE: {enrichment.score}/100
VERDICT: {enrichment.verdict}
{raw_alert_text}
{notes_text}

THREAT INTELLIGENCE FINDINGS:
{engines_text}

Generate a complete incident report as a JSON object with exactly this structure:
{{
  "title": "Brief incident title (max 10 words)",
  "threat_type": "One of: Malware, Phishing, C2, Data Exfiltration, Brute Force, Insider Threat, Reconnaissance, Ransomware, Unknown",
  "summary": "3-4 sentence professional incident summary explaining what was detected, why it is concerning, and immediate impact",
  "affected_assets": ["list", "of", "affected", "systems", "or", "users"],
  "recommended_actions": [
    "Immediate action 1",
    "Immediate action 2",
    "Immediate action 3",
    "Immediate action 4",
    "Immediate action 5"
  ],
  "mitre_techniques": [
    {{
      "technique_id": "T1234",
      "technique_name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "Why this technique applies to this incident",
      "mitre_url": "https://attack.mitre.org/techniques/T1234/"
    }}
  ],
  "playbook": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ...",
    "Step 4: ...",
    "Step 5: ...",
    "Step 6: ..."
  ]
}}

Return ONLY valid JSON. No markdown, no explanation, no code blocks."""


async def generate_report(
    ioc: str,
    ioc_type: str,
    enrichment: EnrichmentResult,
    raw_alert: str = None,
    analyst_notes: str = None,
    severity_override: Severity = None,
) -> IncidentReport:
    """
    Call Claude API to generate a complete incident report
    from enrichment data.
    """
    prompt = _build_prompt(ioc, ioc_type, enrichment, raw_alert, analyst_notes)

    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    data = json.loads(raw)

    # Build MITRE techniques
    mitre_techniques = []
    for t in data.get("mitre_techniques", []):
        mitre_techniques.append(MITRETechnique(
            technique_id   = t.get("technique_id", "T0000"),
            technique_name = t.get("technique_name", "Unknown"),
            tactic         = t.get("tactic", "Unknown"),
            description    = t.get("description", ""),
            mitre_url      = t.get("mitre_url",
                f"https://attack.mitre.org/techniques/{t.get('technique_id','T0000')}/")
        ))

    severity = severity_override or _severity_from_score(enrichment.score)

    return IncidentReport(
        title            = data.get("title", f"Incident — {ioc}"),
        severity         = severity,
        summary          = data.get("summary", ""),
        affected_assets  = data.get("affected_assets", []),
        threat_type      = data.get("threat_type", "Unknown"),
        ioc              = ioc,
        ioc_type         = ioc_type,
        verdict          = enrichment.verdict,
        score            = enrichment.score,
        mitre_techniques = mitre_techniques,
        recommended_actions = data.get("recommended_actions", []),
        playbook         = data.get("playbook", []),
        generated_at     = datetime.utcnow(),
    )
```

---

**COMMIT MESSAGE:**
```
Add AI engine service — Claude generates incident report, MITRE mapping, playbook

import json
import os
from datetime import UTC, datetime

from anthropic import AsyncAnthropic

from models import AlertIntake, EnrichmentResult, IncidentReport, MITRETechnique, Severity

client = AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Output ceiling for one incident report.
#
# Sized against measured output, not guessed. A live report for a malicious IP
# with 5 MITRE techniques, 7 recommended actions and 7 playbook steps -- a
# richly populated one, not a minimal one -- came back at 1,500 output tokens.
# Estimating a pathological case from the same shape (10 techniques with
# descriptions, 10 actions, 10 playbook steps, a long summary and several
# affected assets) lands around 2,500.
#
# 8,000 is therefore >5x observed and ~3x that pathological case. The old value
# of 2,000 left 500 tokens of headroom over a normal report, which is how a
# slightly longer incident would have been cut off mid-JSON.
#
# Raising the ceiling is free: max_tokens caps what the model MAY generate, and
# billing is for tokens actually generated, so a report that still takes 1,500
# costs exactly what it did before. The reason not to simply set it enormous is
# latency -- this call blocks an analyst watching the triage form, and the
# request is not streamed, so the ceiling also bounds the worst-case wait.
MAX_TOKENS = 8000


async def generate_report(enrichment: EnrichmentResult, alert: AlertIntake) -> IncidentReport:
    prompt = f"""You are a senior SOC analyst. Analyze this threat intelligence and generate a structured incident report.

IOC: {enrichment.ioc}
Type: {enrichment.ioc_type}
Verdict: {enrichment.verdict}
Threat Score: {enrichment.score}/100
Raw Alert: {alert.raw_alert or 'Not provided'}
Analyst Notes: {alert.analyst_notes or 'None'}

Respond ONLY with a JSON object (no markdown, no backticks) with this exact structure:
{{
  "title": "brief incident title",
  "severity": "low|medium|high|critical",
  "summary": "2-3 sentence executive summary",
  "affected_assets": ["list of potentially affected assets"],
  "threat_type": "e.g. Malware, C2, Phishing, Scanning",
  "mitre_techniques": [
    {{
      "technique_id": "T1234",
      "technique_name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "How this technique applies",
      "mitre_url": "https://attack.mitre.org/techniques/T1234/"
    }}
  ],
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "playbook": ["step 1", "step 2", "step 3"]
}}"""

    message = await client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )

    # Checked before the content is touched, because a truncated response still
    # arrives as a perfectly ordinary text block -- just one holding incomplete
    # JSON. Without this, hitting the cap surfaced as a bare JSONDecodeError
    # from the parse below, which says nothing about the actual cause and
    # reaches the caller as a 500 with no usable message. Naming the cap here
    # turns that into something the operator can act on.
    if message.stop_reason == "max_tokens":
        raise ValueError(
            f"Claude hit the {MAX_TOKENS}-token output cap before finishing the "
            f"incident report, so the JSON is truncated and cannot be parsed. "
            f"Raise MAX_TOKENS in services/ai_engine.py."
        )

    # content[0] is a text block for this request -- no tools are declared and
    # thinking is off -- but the SDK types it as a union of block kinds, so read
    # the text defensively. A non-text block now fails with a clear message
    # instead of an AttributeError deep in the parse.
    block = message.content[0]
    raw_text = getattr(block, "text", None)
    if not isinstance(raw_text, str):
        raise ValueError(
            f"Expected a text block from Claude, got {type(block).__name__}"
        )
    text = raw_text.replace("```json", "").replace("```", "").strip()
    data = json.loads(text)

    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    severity = severity_map.get(data.get("severity", "medium").lower(), Severity.MEDIUM)
    mitre_techniques = [MITRETechnique(**t) for t in data.get("mitre_techniques", [])]

    playbook = data.get("playbook", [])
    if isinstance(playbook, str):
        playbook = [step.strip() for step in playbook.split("\n") if step.strip()]

    return IncidentReport(
        title=data.get("title", "Untitled Incident"),
        severity=severity,
        summary=data.get("summary", ""),
        affected_assets=data.get("affected_assets", []),
        threat_type=data.get("threat_type", "Unknown"),
        ioc=enrichment.ioc,
        ioc_type=enrichment.ioc_type,
        verdict=enrichment.verdict,
        score=enrichment.score,
        mitre_techniques=mitre_techniques,
        recommended_actions=data.get("recommended_actions", []),
        playbook=playbook,
        generated_at=datetime.now(UTC),
    )

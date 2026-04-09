import os
import json
from datetime import datetime, timezone
from anthropic import AsyncAnthropic
from models import AlertIntake, EnrichmentResult, IncidentReport, MITRETechnique, Severity

client = AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


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
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    text = message.content[0].text
    text = text.replace("```json", "").replace("```", "").strip()
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
        generated_at=datetime.now(timezone.utc),
    )

"""Tests for services/ai_engine.py.

``generate_report`` calls the Anthropic API. These tests never hit the network
(and never spend API credits) -- the module-level ``client`` is swapped for a
fake whose ``messages.create`` returns whatever payload the test wants. That
lets us exercise:

* the success path -- a normal Claude JSON response is parsed into an
  IncidentReport with the correct MITRE techniques, severity mapping, and
  carried-over enrichment fields,
* the cosmetic-formatting paths Claude actually exhibits (markdown fences,
  string-shaped playbooks, missing/invalid severity), and
* the failure paths -- the API raising, or returning a malformed response --
  which must propagate to the caller rather than producing a fake report.
"""
import json
from types import SimpleNamespace

import pytest

from models import AlertIntake, IOCType, Severity
from services import ai_engine
from services.ai_engine import generate_report


# ── test helpers ─────────────────────────────────────────────────────────────


def _fake_message(text: str) -> SimpleNamespace:
    """Build the minimum shape ai_engine reads: ``message.content[0].text``."""
    return SimpleNamespace(content=[SimpleNamespace(text=text)])


def _install_client(monkeypatch, handler):
    """Replace ai_engine.client with a fake whose messages.create runs ``handler``.

    ``handler`` is called with the kwargs ai_engine passed to
    ``client.messages.create`` and may return a fake message OR raise.
    """
    captured = {}

    async def fake_create(**kwargs):
        captured["kwargs"] = kwargs
        result = handler(**kwargs)
        return result

    fake_client = SimpleNamespace(messages=SimpleNamespace(create=fake_create))
    monkeypatch.setattr(ai_engine, "client", fake_client)
    return captured


def _alert(**overrides) -> AlertIntake:
    base = {
        "raw_alert": "CrowdStrike: suspicious outbound connection",
        "ioc": "185.220.101.45",
        "ioc_type": IOCType.IP,
        "analyst_notes": "Triggered on WS-042 at 14:32 UTC",
    }
    base.update(overrides)
    return AlertIntake(**base)


def _claude_payload(**overrides) -> dict:
    """A well-formed Claude response body that maps to a valid IncidentReport."""
    payload = {
        "title": "Suspicious outbound to known malicious IP",
        "severity": "high",
        "summary": "Endpoint contacted a known-malicious IP. Likely C2 beacon.",
        "affected_assets": ["WS-042"],
        "threat_type": "C2",
        "mitre_techniques": [
            {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversary communication over HTTPS.",
                "mitre_url": "https://attack.mitre.org/techniques/T1071/",
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Suspicious PowerShell observed.",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/",
            },
        ],
        "recommended_actions": [
            "Isolate WS-042",
            "Collect memory image",
            "Block IP at perimeter",
        ],
        "playbook": ["Verify the alert", "Contain", "Eradicate", "Recover"],
    }
    payload.update(overrides)
    return payload


# ── success path ─────────────────────────────────────────────────────────────


def test_generate_report_parses_full_claude_response(monkeypatch, make_enrichment):
    payload = _claude_payload()

    def handler(**_):
        return _fake_message(json.dumps(payload))

    captured = _install_client(monkeypatch, handler)

    enrichment = make_enrichment(
        ioc="185.220.101.45", ioc_type="ip", verdict="malicious", score=87,
    )

    import asyncio
    report = asyncio.run(generate_report(enrichment, _alert()))

    # Enrichment fields are carried straight through onto the report.
    assert report.ioc == "185.220.101.45"
    assert report.ioc_type == "ip"
    assert report.verdict == "malicious"
    assert report.score == 87

    # Claude-supplied fields are parsed and mapped.
    assert report.title == payload["title"]
    assert report.severity == Severity.HIGH
    assert report.summary == payload["summary"]
    assert report.affected_assets == ["WS-042"]
    assert report.threat_type == "C2"
    assert report.recommended_actions == payload["recommended_actions"]
    assert report.playbook == payload["playbook"]
    assert report.generated_at.tzinfo is not None

    # MITRE techniques are fully parsed.
    assert len(report.mitre_techniques) == 2
    first = report.mitre_techniques[0]
    assert first.technique_id == "T1071"
    assert first.technique_name == "Application Layer Protocol"
    assert first.tactic == "Command and Control"
    assert first.mitre_url == "https://attack.mitre.org/techniques/T1071/"

    # The Claude call was issued with the model we expect.
    assert captured["kwargs"]["model"] == "claude-sonnet-4-6"
    # The prompt embeds the IOC so Claude can reason about it.
    prompt = captured["kwargs"]["messages"][0]["content"]
    assert "185.220.101.45" in prompt
    assert "malicious" in prompt


def test_generate_report_strips_markdown_fences(monkeypatch, make_enrichment):
    """Claude sometimes wraps JSON in ```json fences; ai_engine strips them."""
    payload = _claude_payload(severity="critical")
    fenced = "```json\n" + json.dumps(payload) + "\n```"

    _install_client(monkeypatch, lambda **_: _fake_message(fenced))

    import asyncio
    report = asyncio.run(
        generate_report(make_enrichment(verdict="malicious", score=95), _alert())
    )

    assert report.severity == Severity.CRITICAL
    assert report.title == payload["title"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("low", Severity.LOW),
        ("medium", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("critical", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("Critical", Severity.CRITICAL),
    ],
)
def test_generate_report_maps_severity(monkeypatch, make_enrichment, raw, expected):
    payload = _claude_payload(severity=raw)
    _install_client(monkeypatch, lambda **_: _fake_message(json.dumps(payload)))

    import asyncio
    report = asyncio.run(generate_report(make_enrichment(), _alert()))

    assert report.severity == expected


def test_generate_report_defaults_unknown_severity_to_medium(
    monkeypatch, make_enrichment
):
    payload = _claude_payload(severity="catastrophic")
    _install_client(monkeypatch, lambda **_: _fake_message(json.dumps(payload)))

    import asyncio
    report = asyncio.run(generate_report(make_enrichment(), _alert()))

    assert report.severity == Severity.MEDIUM


def test_generate_report_splits_string_playbook(monkeypatch, make_enrichment):
    """Claude occasionally returns the playbook as a newline-joined string."""
    payload = _claude_payload(
        playbook="Verify the alert\nContain\n\nEradicate\nRecover",
    )
    _install_client(monkeypatch, lambda **_: _fake_message(json.dumps(payload)))

    import asyncio
    report = asyncio.run(generate_report(make_enrichment(), _alert()))

    assert report.playbook == ["Verify the alert", "Contain", "Eradicate", "Recover"]


def test_generate_report_fills_defaults_for_missing_fields(
    monkeypatch, make_enrichment
):
    """A minimal Claude response shouldn't crash -- defaults fill the gaps."""
    minimal = {
        "severity": "low",
        "summary": "Looks benign.",
        "affected_assets": [],
        "threat_type": "Recon",
        # title, mitre_techniques, recommended_actions, playbook omitted
    }
    _install_client(monkeypatch, lambda **_: _fake_message(json.dumps(minimal)))

    import asyncio
    report = asyncio.run(
        generate_report(make_enrichment(verdict="clean", score=0), _alert())
    )

    assert report.title == "Untitled Incident"
    assert report.severity == Severity.LOW
    assert report.mitre_techniques == []
    assert report.recommended_actions == []
    assert report.playbook == []


# ── failure paths ────────────────────────────────────────────────────────────


def test_generate_report_propagates_api_errors(monkeypatch, make_enrichment):
    """If the Anthropic SDK raises, the route layer should see the exception."""
    class FakeAPIError(RuntimeError):
        pass

    def handler(**_):
        raise FakeAPIError("upstream 500")

    _install_client(monkeypatch, handler)

    import asyncio
    with pytest.raises(FakeAPIError, match="upstream 500"):
        asyncio.run(generate_report(make_enrichment(), _alert()))


def test_generate_report_raises_on_non_json_response(monkeypatch, make_enrichment):
    """Claude returning prose instead of JSON must not silently succeed."""
    _install_client(
        monkeypatch,
        lambda **_: _fake_message("Sorry, I cannot help with that request."),
    )

    import asyncio
    with pytest.raises(json.JSONDecodeError):
        asyncio.run(generate_report(make_enrichment(), _alert()))


def test_generate_report_raises_on_empty_content(monkeypatch, make_enrichment):
    """An Anthropic message with no content blocks is unrecoverable."""
    _install_client(
        monkeypatch,
        lambda **_: SimpleNamespace(content=[]),
    )

    import asyncio
    with pytest.raises(IndexError):
        asyncio.run(generate_report(make_enrichment(), _alert()))


def test_generate_report_raises_on_malformed_mitre_technique(
    monkeypatch, make_enrichment
):
    """A MITRE block missing required fields surfaces as a validation error."""
    from pydantic import ValidationError

    payload = _claude_payload(
        mitre_techniques=[{"technique_id": "T1071"}],  # missing required fields
    )
    _install_client(monkeypatch, lambda **_: _fake_message(json.dumps(payload)))

    import asyncio
    with pytest.raises(ValidationError):
        asyncio.run(generate_report(make_enrichment(), _alert()))

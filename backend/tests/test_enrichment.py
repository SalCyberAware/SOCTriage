"""Tests for services/enrichment.py.

The enrichment service calls the external ThreatScan API over HTTPS. These
tests never hit the network -- they monkeypatch ``httpx.AsyncClient.post`` to
control exactly what the function sees. This keeps the suite fast and
deterministic, and exercises both the success path and every failure mode the
service is meant to swallow (HTTP errors, network failures, malformed
responses) so the route layer always receives a well-formed EnrichmentResult.
"""
import asyncio

import httpx
import pytest

from models import EnrichmentResult, IOCType
from services import enrichment
from services.enrichment import enrich_ioc


def _run(coro):
    """Drive an async coroutine to completion from a sync test."""
    return asyncio.run(coro)


# ── helpers ──────────────────────────────────────────────────────────────────


def _install_post(monkeypatch, handler):
    """Replace httpx.AsyncClient.post with ``handler`` for one test.

    ``handler`` is called as ``handler(url, json)`` and must return either an
    ``httpx.Response`` (which is returned to the caller) or raise to simulate
    a network failure.
    """
    async def fake_post(self, url, json=None, **kwargs):
        result = handler(url, json)
        if isinstance(result, httpx.Response):
            # Give the response a request so raise_for_status() can build the
            # error message without blowing up.
            result.request = httpx.Request("POST", url)
        return result

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


# ── success path ─────────────────────────────────────────────────────────────


def test_enrich_ioc_success_returns_populated_result(monkeypatch):
    captured = {}

    def handler(url, json):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(
            200,
            json={
                "verdict": "malicious",
                "score": 87,
                "engines": [
                    {
                        "id": "virustotal",
                        "verdict": "malicious",
                        "detail": "45/90 engines flagged this",
                        "score": 0.5,
                    },
                    {
                        "id": "abuseipdb",
                        "verdict": "suspicious",
                        "detail": "Reported 12 times",
                        "score": 0.3,
                    },
                ],
            },
        )

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("185.220.101.45", IOCType.IP))

    assert isinstance(result, EnrichmentResult)
    assert result.ioc == "185.220.101.45"
    assert result.ioc_type == "ip"
    assert result.verdict == "malicious"
    assert result.score == 87
    assert len(result.engines) == 2
    assert result.engines[0].id == "virustotal"
    assert result.engines[0].verdict == "malicious"
    assert result.engines[1].id == "abuseipdb"
    # The IOC was passed through to ThreatScan as the "query" field.
    assert captured["json"] == {"query": "185.220.101.45"}
    assert captured["url"].endswith("/scan")


def test_enrich_ioc_uses_configured_threatscan_url(monkeypatch):
    """The base URL comes from ``THREATSCAN_API_URL`` (resolved at import time)."""
    seen = {}

    def handler(url, json):
        seen["url"] = url
        return httpx.Response(200, json={"verdict": "clean", "score": 0, "engines": []})

    _install_post(monkeypatch, handler)

    _run(enrich_ioc("8.8.8.8", IOCType.IP))

    assert seen["url"] == f"{enrichment.THREATSCAN_API_URL}/scan"


def test_enrich_ioc_defaults_when_threatscan_omits_fields(monkeypatch):
    """ThreatScan can return a sparse body; missing fields fall back to defaults."""
    def handler(url, json):
        return httpx.Response(200, json={})

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("example.com", IOCType.DOMAIN))

    assert result.verdict == "unknown"
    assert result.score == 0
    assert result.engines == []
    assert result.ioc == "example.com"
    assert result.ioc_type == "domain"


def test_enrich_ioc_preserves_clean_verdict(monkeypatch):
    def handler(url, json):
        return httpx.Response(
            200,
            json={
                "verdict": "clean",
                "score": 0,
                "engines": [
                    {"id": "virustotal", "verdict": "clean", "score": 0.0},
                ],
            },
        )

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("1.1.1.1", IOCType.IP))

    assert result.verdict == "clean"
    assert result.score == 0
    assert result.engines[0].verdict == "clean"


# ── failure paths ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("status_code", [400, 404, 500, 502, 503])
def test_enrich_ioc_returns_error_result_when_threatscan_errors(
    monkeypatch, status_code
):
    """Any non-2xx status collapses into an ``verdict='error'`` result."""
    def handler(url, json):
        return httpx.Response(status_code, json={"detail": "boom"})

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("8.8.8.8", IOCType.IP))

    assert isinstance(result, EnrichmentResult)
    assert result.ioc == "8.8.8.8"
    assert result.ioc_type == "ip"
    assert result.verdict == "error"
    assert result.score == 0
    assert result.engines == []


def test_enrich_ioc_returns_error_result_on_connection_failure(monkeypatch):
    """A network-level failure must not bubble up to the caller."""
    def handler(url, json):
        raise httpx.ConnectError("connection refused")

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("8.8.8.8", IOCType.IP))

    assert result.verdict == "error"
    assert result.score == 0
    assert result.engines == []
    assert result.ioc == "8.8.8.8"
    assert result.ioc_type == "ip"


def test_enrich_ioc_returns_error_result_on_timeout(monkeypatch):
    def handler(url, json):
        raise httpx.ReadTimeout("read timed out")

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("8.8.8.8", IOCType.IP))

    assert result.verdict == "error"
    assert result.score == 0
    assert result.engines == []


def test_enrich_ioc_returns_error_result_on_malformed_json(monkeypatch):
    """A 2xx response with a non-JSON body must not crash the service."""
    def handler(url, json):
        return httpx.Response(200, content=b"<html>oops</html>")

    _install_post(monkeypatch, handler)

    result = _run(enrich_ioc("8.8.8.8", IOCType.IP))

    assert result.verdict == "error"
    assert result.score == 0
    assert result.engines == []

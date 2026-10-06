"""Tests for the web hardening layer.

  * security headers on every backend response, and the same four in
    frontend/vercel.json, which also carries a Report-Only CSP;
  * /docs, /redoc and /openapi.json off unless SOCTRIAGE_ENABLE_API_DOCS is set;
  * schema ceilings on every free-text field that sit above the limits.py caps,
    so normal oversize input still gets the limiter's friendly 400;
  * a stated ioc_type has to match the IOC, or the triage is a 400.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import limits
import main
import models
from conftest import SESSION_TOKEN_A
from models import IOCType, Severity
from routes import triage as triage_route
from security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware
from services.enrichment import detect_ioc_type, ioc_matches_type

REPO_ROOT = Path(__file__).resolve().parents[2]
VERCEL_JSON = REPO_ROOT / "frontend" / "vercel.json"
RAILWAY_API = "https://soctriage-production.up.railway.app"


@pytest.fixture
def stub_externals(monkeypatch, make_enrichment, make_report):
    """Stub the outbound enrichment + AI calls and count how often they run."""
    calls = {"enrich": 0}

    async def fake_enrich(ioc, ioc_type):
        calls["enrich"] += 1
        return make_enrichment(ioc=ioc)

    async def fake_generate(enrichment, alert):
        return make_report(ioc=enrichment.ioc)

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)
    return calls


def _seed_case(manager, make_enrichment, make_report):
    return manager.open_case(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        severity=Severity.LOW,
        enrichment=make_enrichment(),
        report=make_report(),
    )


def _assert_security_headers(response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


# -- Security headers ---------------------------------------------------------


class TestSecurityHeaders:
    def test_the_set(self) -> None:
        assert SECURITY_HEADERS == {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }

    @pytest.mark.parametrize("path", ["/health", "/api/cases", "/api/dashboard"])
    def test_on_successful_reads(self, anon_client, path: str) -> None:
        response = anon_client.get(path)

        assert response.status_code == 200
        _assert_security_headers(response)

    def test_on_a_404(self, anon_client) -> None:
        response = anon_client.get("/no/such/route")

        assert response.status_code == 404
        _assert_security_headers(response)

    def test_on_a_401(self, anon_client) -> None:
        response = anon_client.patch("/api/cases/ANY/status", json={"status": "closed"})

        assert response.status_code == 401
        _assert_security_headers(response)

    def test_on_a_422(self, client) -> None:
        response = client.post("/api/triage", json={})

        assert response.status_code == 422
        _assert_security_headers(response)

    def test_on_a_successful_write(
        self, client, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)

        response = client.patch(f"/api/cases/{case.case_id}/note", json={"note": "ok"})

        assert response.status_code == 200
        _assert_security_headers(response)

    def test_on_a_cors_preflight(self, anon_client) -> None:
        """The preflight is answered by CORSMiddleware itself, inside this layer."""
        response = anon_client.options(
            "/api/cases",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )

        _assert_security_headers(response)

    def test_the_middleware_is_outside_cors(self) -> None:
        """Starlette runs the last-added middleware first, i.e. outermost."""
        classes = [m.cls for m in main.app.user_middleware]
        assert classes.index(SecurityHeadersMiddleware) == 0

    def test_a_header_the_route_set_is_kept(self) -> None:
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/framed")
        def framed():
            from fastapi import Response

            return Response("ok", headers={"X-Frame-Options": "SAMEORIGIN"})

        response = TestClient(app).get("/framed")

        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert response.headers.get_list("X-Frame-Options") == ["SAMEORIGIN"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_non_http_scopes_pass_straight_through(self) -> None:
        seen = []

        async def inner(scope, receive, send):
            seen.append(scope["type"])
            await send({"type": "lifespan.startup.complete"})

        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {}

        asyncio.run(SecurityHeadersMiddleware(inner)({"type": "lifespan"}, receive, send))

        assert seen == ["lifespan"]
        assert sent == [{"type": "lifespan.startup.complete"}]


# -- API docs -----------------------------------------------------------------


class TestApiDocs:
    @pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
    def test_off_by_default(self, anon_client, path: str) -> None:
        assert anon_client.get(path).status_code == 404

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", " yes "])
    def test_explicit_true_values_enable(self, monkeypatch, value: str) -> None:
        monkeypatch.setenv(main.API_DOCS_FLAG, value)
        assert main.api_docs_enabled() is True

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "development", "on"])
    def test_anything_else_does_not(self, monkeypatch, value: str) -> None:
        monkeypatch.setenv(main.API_DOCS_FLAG, value)
        assert main.api_docs_enabled() is False

    def test_env_development_is_not_the_flag(self, monkeypatch) -> None:
        monkeypatch.delenv(main.API_DOCS_FLAG, raising=False)
        monkeypatch.setenv("ENV", "development")
        assert main.api_docs_enabled() is False

    def test_with_the_flag_the_docs_are_served(self, monkeypatch) -> None:
        """main.app is built at import, so build one the same way with the flag."""
        monkeypatch.setenv(main.API_DOCS_FLAG, "true")
        app = FastAPI(**main.api_docs_urls())
        client = TestClient(app)

        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        assert client.get("/openapi.json").status_code == 200

    def test_the_running_app_has_them_off(self) -> None:
        assert main.app.docs_url is None
        assert main.app.redoc_url is None
        assert main.app.openapi_url is None


# -- Schema ceilings ----------------------------------------------------------


class TestSchemaCeilings:
    @pytest.mark.parametrize(
        ("ceiling", "cap"),
        [
            (models.MAX_RAW_ALERT_SCHEMA_CHARS, limits.DEFAULT_MAX_RAW_ALERT_CHARS),
            (models.MAX_IOC_SCHEMA_CHARS, limits.DEFAULT_MAX_IOC_CHARS),
            (models.MAX_NOTE_SCHEMA_CHARS, limits.DEFAULT_MAX_NOTE_CHARS),
        ],
    )
    def test_ceilings_sit_well_above_the_caps(self, ceiling: int, cap: int) -> None:
        assert ceiling >= 10 * cap

    @pytest.mark.parametrize(
        ("field", "cap", "ceiling"),
        [
            ("raw_alert", limits.DEFAULT_MAX_RAW_ALERT_CHARS, models.MAX_RAW_ALERT_SCHEMA_CHARS),
            ("analyst_notes", limits.DEFAULT_MAX_NOTE_CHARS, models.MAX_NOTE_SCHEMA_CHARS),
        ],
    )
    def test_triage_text_fields(
        self, client, stub_externals, field: str, cap: int, ceiling: int
    ) -> None:
        just_over_cap = client.post(
            "/api/triage", json={"ioc": "8.8.8.8", field: "x" * (cap + 1)}
        )
        at_ceiling = client.post(
            "/api/triage", json={"ioc": "8.8.8.8", field: "x" * ceiling}
        )
        over_ceiling = client.post(
            "/api/triage", json={"ioc": "8.8.8.8", field: "x" * (ceiling + 1)}
        )

        # The limiter's friendly 400 still answers normal oversize input...
        assert just_over_cap.status_code == 400
        assert field in just_over_cap.json()["detail"]
        assert at_ceiling.status_code == 400
        # ...and the schema only refuses the absurd.
        assert over_ceiling.status_code == 422
        assert stub_externals["enrich"] == 0

    def test_ioc(self, client, stub_externals) -> None:
        cap, ceiling = limits.DEFAULT_MAX_IOC_CHARS, models.MAX_IOC_SCHEMA_CHARS

        assert client.post("/api/triage", json={"ioc": "a" * (cap + 1)}).status_code == 400
        assert client.post("/api/triage", json={"ioc": "a" * (ceiling + 1)}).status_code == 422

    @pytest.mark.parametrize(("suffix", "field"), [("note", "note"), ("close", "resolution")])
    def test_case_write_text_fields(
        self, client, manager, make_enrichment, make_report, suffix: str, field: str
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        url = f"/api/cases/{case.case_id}/{suffix}"

        just_over_cap = client.patch(url, json={field: "x" * (limits.DEFAULT_MAX_NOTE_CHARS + 1)})
        over_ceiling = client.patch(url, json={field: "x" * (models.MAX_NOTE_SCHEMA_CHARS + 1)})

        assert just_over_cap.status_code == 400
        assert field in just_over_cap.json()["detail"]
        assert over_ceiling.status_code == 422
        assert client.get(f"/api/cases/{case.case_id}").json()["timeline"] == [
            event.model_dump(mode="json") for event in case.timeline
        ]

    def test_the_openapi_schema_carries_the_ceilings(self) -> None:
        schema = models.AlertIntake.model_json_schema()["properties"]

        assert schema["ioc"]["maxLength"] == models.MAX_IOC_SCHEMA_CHARS
        raw_alert = next(s for s in schema["raw_alert"]["anyOf"] if s.get("type") == "string")
        assert raw_alert["maxLength"] == models.MAX_RAW_ALERT_SCHEMA_CHARS
        notes = next(s for s in schema["analyst_notes"]["anyOf"] if s.get("type") == "string")
        assert notes["maxLength"] == models.MAX_NOTE_SCHEMA_CHARS


# -- IOC type validation ------------------------------------------------------


VALID = [
    (IOCType.IP, "8.8.8.8"),
    (IOCType.IP, "185.220.101.45"),
    (IOCType.IP, "2001:4860:4860::8888"),
    (IOCType.HASH, "d41d8cd98f00b204e9800998ecf8427e"),
    (IOCType.HASH, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (IOCType.HASH, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
    (IOCType.URL, "http://malware.example.com/payload.exe"),
    (IOCType.URL, "HTTPS://203.0.113.5:8443/c2?id=1"),
    (IOCType.DOMAIN, "malware.example.com"),
    (IOCType.DOMAIN, "a-b.c_d.example.co.uk."),
    (IOCType.DOMAIN, "xn--80ak6aa92e.xn--p1ai"),
]

INVALID = [
    (IOCType.IP, "8.8.8"),
    (IOCType.IP, "999.1.1.1"),
    (IOCType.IP, "malware.example.com"),
    (IOCType.IP, " 8.8.8.8"),
    (IOCType.HASH, "d41d8cd98f00b204e9800998ecf8427"),
    (IOCType.HASH, "z41d8cd98f00b204e9800998ecf8427e"),
    (IOCType.HASH, "a" * 50),
    (IOCType.HASH, "8.8.8.8"),
    (IOCType.URL, "malware.example.com/payload"),
    (IOCType.URL, "ftp://malware.example.com/"),
    (IOCType.URL, "http://"),
    (IOCType.URL, "http://exa mple.com/"),
    (IOCType.URL, "http://[::1/"),
    (IOCType.DOMAIN, "localhost"),
    (IOCType.DOMAIN, "8.8.8.8"),
    (IOCType.DOMAIN, "-bad.example.com"),
    (IOCType.DOMAIN, "bad-.example.com"),
    (IOCType.DOMAIN, "http://malware.example.com"),
    (IOCType.DOMAIN, "exa mple.com"),
    (IOCType.DOMAIN, "a" * 64 + ".com"),
    (IOCType.DOMAIN, ("a" * 60 + ".") * 5 + "com"),
    (IOCType.DOMAIN, "example.c0m"),
]


class TestIocMatchesType:
    @pytest.mark.parametrize(("ioc_type", "ioc"), VALID)
    def test_accepts(self, ioc_type: IOCType, ioc: str) -> None:
        assert ioc_matches_type(ioc, ioc_type) is True

    @pytest.mark.parametrize(("ioc_type", "ioc"), INVALID)
    def test_rejects(self, ioc_type: IOCType, ioc: str) -> None:
        assert ioc_matches_type(ioc, ioc_type) is False


class TestDetectionAgreesWithValidation:
    """Detection must never pick a type that validation then rejects."""

    @pytest.mark.parametrize(("ioc_type", "ioc"), VALID)
    def test_detected_type_validates(self, ioc_type: IOCType, ioc: str) -> None:
        detected = detect_ioc_type(ioc)
        if detected is ioc_type:
            assert ioc_matches_type(ioc, detected)

    @pytest.mark.parametrize("ioc", ["2001:4860:4860::8888", "::1", "::ffff:192.0.2.1"])
    def test_ipv6_is_detected_as_ip(self, ioc: str) -> None:
        assert detect_ioc_type(ioc) is IOCType.IP
        assert ioc_matches_type(ioc, IOCType.IP)


class TestTriageChecksTheStatedType:
    def test_a_mismatch_is_400_and_opens_nothing(self, client, stub_externals) -> None:
        response = client.post(
            "/api/triage", json={"ioc": "malware.example.com", "ioc_type": "ip"}
        )

        assert response.status_code == 400
        assert "valid ip" in response.json()["detail"]
        assert stub_externals["enrich"] == 0
        assert client.get("/api/cases").json() == []

    @pytest.mark.parametrize(("ioc_type", "ioc"), VALID)
    def test_a_match_goes_through(
        self, client, stub_externals, ioc_type: IOCType, ioc: str
    ) -> None:
        response = client.post("/api/triage", json={"ioc": ioc, "ioc_type": ioc_type.value})

        assert response.status_code == 200

    def test_no_type_is_not_checked(self, client, stub_externals) -> None:
        """Without a stated type there is nothing to contradict; enrichment detects one."""
        response = client.post("/api/triage", json={"ioc": "something odd"})

        assert response.status_code == 200

    def test_a_mismatch_spends_no_rate_allowance(
        self, owner_client, monkeypatch, stub_externals
    ) -> None:
        monkeypatch.setattr(triage_route, "limiter", limits.Limiter(ip_rate=1))
        visitor = owner_client(SESSION_TOKEN_A)
        headers = {"x-forwarded-for": "203.0.113.9"}

        for _ in range(3):
            refused = visitor.post(
                "/api/triage", json={"ioc": "nope", "ioc_type": "hash"}, headers=headers
            )
            assert refused.status_code == 400

        allowed = visitor.post(
            "/api/triage", json={"ioc": "8.8.8.8", "ioc_type": "ip"}, headers=headers
        )
        assert allowed.status_code == 200

    def test_the_token_is_still_checked_first(self, anon_client, stub_externals) -> None:
        response = anon_client.post("/api/triage", json={"ioc": "nope", "ioc_type": "ip"})

        assert response.status_code == 401


# -- frontend/vercel.json -----------------------------------------------------


def _vercel_headers() -> dict[str, str]:
    config = json.loads(VERCEL_JSON.read_text(encoding="utf-8"))
    (rule,) = config["headers"]
    assert rule["source"] == "/(.*)"
    return {h["key"]: h["value"] for h in rule["headers"]}


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives = {}
    for part in policy.split(";"):
        name, *values = part.split()
        directives[name] = values
    return directives


class TestVercelJson:
    def test_sends_the_same_security_headers_as_the_backend(self) -> None:
        headers = _vercel_headers()

        for name, value in SECURITY_HEADERS.items():
            assert headers[name] == value

    def test_the_csp_is_report_only(self) -> None:
        headers = _vercel_headers()

        assert "Content-Security-Policy-Report-Only" in headers
        assert "Content-Security-Policy" not in headers

    def test_the_csp_allows_what_the_app_uses_and_little_else(self) -> None:
        csp = _csp_directives(_vercel_headers()["Content-Security-Policy-Report-Only"])

        assert csp["default-src"] == ["'self'"]
        assert csp["script-src"] == ["'self'"]
        assert csp["connect-src"] == ["'self'", RAILWAY_API]
        assert "https://fonts.googleapis.com" in csp["style-src"]
        assert csp["font-src"] == ["'self'", "https://fonts.gstatic.com"]
        assert csp["object-src"] == ["'none'"]
        assert csp["frame-ancestors"] == ["'none'"]

    def test_the_csp_names_the_api_the_frontend_calls(self) -> None:
        app_source = (REPO_ROOT / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        assert f'"{RAILWAY_API}"' in app_source

    @pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
    def test_it_is_not_gitignored(self) -> None:
        result = subprocess.run(
            ["git", "check-ignore", "-q", str(VERCEL_JSON)],
            cwd=REPO_ROOT,
            check=False,
        )
        # 1 means "not ignored"; 0 would mean a .gitignore pattern swallows it.
        assert result.returncode == 1

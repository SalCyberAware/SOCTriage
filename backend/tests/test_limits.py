"""Tests for the abuse-control Limiter and its wiring into the write routes.

Two layers:
  * unit tests drive the Limiter directly with an injected clock, so the
    rate-limit window and the UTC day rollover are exercised with no real
    waiting;
  * route tests drive the FastAPI app through TestClient and assert that a
    rejected request is turned away before it reaches enrichment or the AI
    engine -- the property that makes these limits worth anything.
"""
from __future__ import annotations

import pytest

from limits import (
    DEFAULT_DAILY_TRIAGE_CAP,
    DEFAULT_IP_RATE,
    DEFAULT_IP_WINDOW_SECONDS,
    DEFAULT_MAX_IOC_CHARS,
    DEFAULT_MAX_NOTE_CHARS,
    DEFAULT_MAX_RAW_ALERT_CHARS,
    Limiter,
    LimitRejectedError,
    build_limiter,
    client_ip,
)
from models import IOCType, Severity
from routes import triage as triage_route

_ENV_VARS = (
    "SOCTRIAGE_MAX_RAW_ALERT_CHARS",
    "SOCTRIAGE_MAX_IOC_CHARS",
    "SOCTRIAGE_MAX_NOTE_CHARS",
    "SOCTRIAGE_IP_RATE",
    "SOCTRIAGE_IP_WINDOW_SECONDS",
    "SOCTRIAGE_DAILY_TRIAGE_CAP",
)


class _Clock:
    """A controllable clock for the time_fn the Limiter reads."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _triage(limiter: Limiter, ip: str = "1.1.1.1", **overrides) -> None:
    """Run a minimal valid triage check against ``limiter``."""
    kwargs = {"raw_alert": None, "ioc": "8.8.8.8", "analyst_notes": None, "ip": ip}
    kwargs.update(overrides)
    limiter.check_triage(**kwargs)


# -- Length caps --------------------------------------------------------------


class TestLengthCaps:
    def test_oversized_raw_alert_rejected_400(self) -> None:
        limiter = Limiter(max_raw_alert_chars=10)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter, raw_alert="x" * 11)
        assert info.value.status_code == 400
        assert "raw_alert" in info.value.message
        assert "too long" in info.value.message

    def test_oversized_ioc_rejected_400(self) -> None:
        limiter = Limiter(max_ioc_chars=8)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter, ioc="x" * 9)
        assert info.value.status_code == 400
        assert "ioc" in info.value.message

    def test_oversized_analyst_notes_rejected_400(self) -> None:
        limiter = Limiter(max_note_chars=5)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter, analyst_notes="x" * 6)
        assert info.value.status_code == 400
        assert "analyst_notes" in info.value.message

    @pytest.mark.parametrize("field", ["note", "resolution"])
    def test_oversized_case_write_text_rejected_400(self, field: str) -> None:
        limiter = Limiter(max_note_chars=5)
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_case_write(ip="1.1.1.1", field=field, text="x" * 6)
        assert info.value.status_code == 400
        assert field in info.value.message

    def test_at_limit_is_allowed(self) -> None:
        limiter = Limiter(max_raw_alert_chars=10, max_ioc_chars=4, max_note_chars=3)
        # Exactly at each limit: no raise.
        _triage(limiter, raw_alert="x" * 10, ioc="y" * 4, analyst_notes="z" * 3)

    def test_absent_optional_fields_are_not_capped(self) -> None:
        limiter = Limiter(max_raw_alert_chars=1, max_note_chars=1)
        _triage(limiter, raw_alert=None, analyst_notes=None)  # no raise

    def test_status_write_has_no_text_to_cap(self) -> None:
        limiter = Limiter(max_note_chars=1)
        limiter.check_case_write(ip="1.1.1.1")  # no field/text: no raise

    def test_rejected_oversized_consumes_nothing(self) -> None:
        limiter = Limiter(max_raw_alert_chars=5, daily_triage_cap=1, ip_rate=1)
        with pytest.raises(LimitRejectedError):
            _triage(limiter, raw_alert="toolong")
        # Neither the daily slot nor the per-IP slot was taken.
        _triage(limiter)


# -- Per-IP rate limit --------------------------------------------------------


class TestIpRateLimit:
    def test_rejects_n_plus_1_in_window(self) -> None:
        clock = _Clock()
        limiter = Limiter(
            ip_rate=3, ip_window_seconds=300, daily_triage_cap=100, time_fn=clock
        )
        for _ in range(3):
            _triage(limiter)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter)
        assert info.value.status_code == 429
        assert "Retry-After" in info.value.headers
        assert int(info.value.headers["Retry-After"]) >= 1

    def test_retry_after_counts_down_as_the_window_slides(self) -> None:
        clock = _Clock()
        limiter = Limiter(ip_rate=1, ip_window_seconds=300, time_fn=clock)
        _triage(limiter)
        clock.advance(100)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter)
        # 300s window, 100s elapsed since the only hit: 200s left.
        assert int(info.value.headers["Retry-After"]) == 200

    def test_other_ip_unaffected(self) -> None:
        limiter = Limiter(ip_rate=1, daily_triage_cap=100)
        _triage(limiter, ip="1.1.1.1")
        with pytest.raises(LimitRejectedError):
            _triage(limiter, ip="1.1.1.1")
        _triage(limiter, ip="2.2.2.2")  # different IP, allowed

    def test_recovers_after_window(self) -> None:
        clock = _Clock()
        limiter = Limiter(
            ip_rate=1, ip_window_seconds=300, daily_triage_cap=100, time_fn=clock
        )
        _triage(limiter)
        with pytest.raises(LimitRejectedError):
            _triage(limiter)
        clock.advance(301)
        _triage(limiter)  # window passed, allowed again

    def test_bucket_is_shared_across_all_write_endpoints(self) -> None:
        """Patching a case eats the same allowance as triaging -- by design."""
        limiter = Limiter(ip_rate=3, daily_triage_cap=100)
        limiter.check_case_write(ip="1.1.1.1")
        limiter.check_case_write(ip="1.1.1.1", field="note", text="ok")
        _triage(limiter, ip="1.1.1.1")
        with pytest.raises(LimitRejectedError) as info:
            limiter.check_case_write(ip="1.1.1.1", field="resolution", text="done")
        assert info.value.status_code == 429

    def test_rejected_rate_consumes_no_daily_slot(self) -> None:
        limiter = Limiter(ip_rate=1, daily_triage_cap=5)
        _triage(limiter, ip="1.1.1.1")  # daily = 1
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter, ip="1.1.1.1")  # 429, must not bump daily
        assert info.value.status_code == 429
        # Four more IPs can still run: the daily count is at 1, not 2.
        for i in range(4):
            _triage(limiter, ip=f"9.9.9.{i}")
        with pytest.raises(LimitRejectedError) as info2:
            _triage(limiter, ip="8.8.8.8")
        assert info2.value.status_code == 503  # the 6th overall hits the cap of 5


# -- Daily global cap ---------------------------------------------------------


class TestDailyCap:
    def test_rejects_triage_past_global_ceiling(self) -> None:
        limiter = Limiter(daily_triage_cap=2, ip_rate=100)
        _triage(limiter)
        _triage(limiter)
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter)
        assert info.value.status_code == 503
        assert "capacity" in info.value.message
        assert "tomorrow" in info.value.message

    def test_case_writes_do_not_consume_the_daily_cap(self) -> None:
        """Only POST /api/triage has money attached, so only it is capped."""
        limiter = Limiter(daily_triage_cap=1, ip_rate=100)
        for _ in range(10):
            limiter.check_case_write(ip="1.1.1.1", field="note", text="ok")
        _triage(limiter)  # the single daily slot is still free

    def test_case_writes_still_work_once_the_daily_cap_is_spent(self) -> None:
        """An analyst can keep working open cases after triage is exhausted."""
        limiter = Limiter(daily_triage_cap=1, ip_rate=100)
        _triage(limiter)
        with pytest.raises(LimitRejectedError):
            _triage(limiter)
        limiter.check_case_write(ip="1.1.1.1", field="note", text="still fine")

    def test_resets_next_utc_day(self) -> None:
        clock = _Clock()
        limiter = Limiter(daily_triage_cap=1, ip_rate=100, time_fn=clock)
        _triage(limiter)
        with pytest.raises(LimitRejectedError):
            _triage(limiter)
        clock.advance(86_400)  # next UTC day
        _triage(limiter)  # counter reset, allowed

    def test_does_not_reset_within_the_same_utc_day(self) -> None:
        clock = _Clock(start=86_400.0)  # midnight UTC
        limiter = Limiter(daily_triage_cap=1, ip_rate=100, time_fn=clock)
        _triage(limiter)
        clock.advance(86_399)  # 23:59:59 the same day
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter)
        assert info.value.status_code == 503


# -- Check ordering -----------------------------------------------------------


class TestCheckOrder:
    def test_length_checked_before_daily_cap(self) -> None:
        # Daily cap already exhausted, but an oversized alert still gets the 400.
        limiter = Limiter(max_raw_alert_chars=3, daily_triage_cap=1, ip_rate=100)
        _triage(limiter)  # fills the daily cap
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter, raw_alert="toolong")
        assert info.value.status_code == 400  # length wins, cheapest first

    def test_daily_cap_checked_before_ip_rate(self) -> None:
        """At capacity, telling the caller to try tomorrow beats slow down."""
        limiter = Limiter(daily_triage_cap=1, ip_rate=1)
        _triage(limiter)  # fills both the daily cap and this IP allowance
        with pytest.raises(LimitRejectedError) as info:
            _triage(limiter)
        assert info.value.status_code == 503


# -- Client IP extraction -----------------------------------------------------


class _StubClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _StubRequest:
    """Duck-types the bits of a Starlette Request that client_ip reads."""

    def __init__(self, headers: dict | None = None, peer: str | None = None) -> None:
        self.headers = headers or {}
        self.client = _StubClient(peer) if peer else None


class TestClientIp:
    def test_uses_leftmost_forwarded_for(self) -> None:
        request = _StubRequest(
            {"x-forwarded-for": "203.0.113.7, 70.41.3.18, 150.172.238.178"},
            peer="10.0.0.1",
        )
        assert client_ip(request) == "203.0.113.7"

    def test_strips_whitespace(self) -> None:
        request = _StubRequest({"x-forwarded-for": "  203.0.113.7 "})
        assert client_ip(request) == "203.0.113.7"

    def test_falls_back_to_socket_peer(self) -> None:
        assert client_ip(_StubRequest(peer="10.0.0.1")) == "10.0.0.1"

    def test_unknown_when_no_header_and_no_peer(self) -> None:
        assert client_ip(_StubRequest()) == "unknown"


# -- build_limiter / env configuration ----------------------------------------


class TestBuildLimiter:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in _ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        limiter = build_limiter()
        assert limiter.max_raw_alert_chars == DEFAULT_MAX_RAW_ALERT_CHARS
        assert limiter.max_ioc_chars == DEFAULT_MAX_IOC_CHARS
        assert limiter.max_note_chars == DEFAULT_MAX_NOTE_CHARS
        assert limiter.ip_rate == DEFAULT_IP_RATE
        assert limiter.ip_window_seconds == DEFAULT_IP_WINDOW_SECONDS
        assert limiter.daily_triage_cap == DEFAULT_DAILY_TRIAGE_CAP

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOCTRIAGE_MAX_RAW_ALERT_CHARS", "1234")
        monkeypatch.setenv("SOCTRIAGE_MAX_IOC_CHARS", "64")
        monkeypatch.setenv("SOCTRIAGE_MAX_NOTE_CHARS", "99")
        monkeypatch.setenv("SOCTRIAGE_IP_RATE", "9")
        monkeypatch.setenv("SOCTRIAGE_IP_WINDOW_SECONDS", "60")
        monkeypatch.setenv("SOCTRIAGE_DAILY_TRIAGE_CAP", "42")
        limiter = build_limiter()
        assert limiter.max_raw_alert_chars == 1234
        assert limiter.max_ioc_chars == 64
        assert limiter.max_note_chars == 99
        assert limiter.ip_rate == 9
        assert limiter.ip_window_seconds == 60
        assert limiter.daily_triage_cap == 42

    @pytest.mark.parametrize("bad", ["not-a-number", "-3", "0", "", "   "])
    def test_invalid_env_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch, bad: str
    ) -> None:
        """A junk or non-positive value must not disable the cap."""
        monkeypatch.setenv("SOCTRIAGE_DAILY_TRIAGE_CAP", bad)
        assert build_limiter().daily_triage_cap == DEFAULT_DAILY_TRIAGE_CAP


# -- Route wiring -------------------------------------------------------------


@pytest.fixture
def spy_externals(monkeypatch):
    """Replace the outbound calls of the route with spies that record invocation.

    A limiter rejection must never reach either of these. The route imports both
    names into its own namespace, so the patches target ``routes.triage``.
    """
    calls = {"enrich": 0, "generate": 0}

    async def fake_enrich(ioc, ioc_type):
        calls["enrich"] += 1
        raise AssertionError("enrich_ioc was called on a rejected request")

    async def fake_generate(enrichment, alert):
        calls["generate"] += 1
        raise AssertionError("generate_report was called on a rejected request")

    monkeypatch.setattr(triage_route, "enrich_ioc", fake_enrich)
    monkeypatch.setattr(triage_route, "generate_report", fake_generate)
    return calls


def _use_limiter(monkeypatch, **kwargs) -> Limiter:
    """Install a purpose-built limiter on the triage router."""
    limiter = Limiter(**kwargs)
    monkeypatch.setattr(triage_route, "limiter", limiter)
    return limiter


def _seed_case(manager, make_enrichment, make_report):
    return manager.open_case(
        ioc="8.8.8.8",
        ioc_type=IOCType.IP,
        severity=Severity.LOW,
        enrichment=make_enrichment(),
        report=make_report(),
    )


class TestTriageRouteRejectionsSpendNothing:
    """The point of the whole module: a rejected request costs nothing."""

    def test_oversized_raw_alert_returns_400_without_calling_out(
        self, client, monkeypatch, spy_externals
    ) -> None:
        _use_limiter(monkeypatch, max_raw_alert_chars=100)

        response = client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip", "raw_alert": "x" * 101},
        )

        assert response.status_code == 400
        assert "too long" in response.json()["detail"]
        assert spy_externals == {"enrich": 0, "generate": 0}

    def test_rate_limited_returns_429_without_calling_out(
        self, client, monkeypatch, spy_externals
    ) -> None:
        limiter = _use_limiter(monkeypatch, ip_rate=1, daily_triage_cap=100)
        # Spend the single allowance on a cheap case write, not a triage, so the
        # spies stay untouched for the assertion below.
        limiter.check_case_write(ip="203.0.113.9")

        response = client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 429
        assert int(response.headers["retry-after"]) >= 1
        assert spy_externals == {"enrich": 0, "generate": 0}

    def test_daily_cap_returns_503_without_calling_out(
        self, client, monkeypatch, spy_externals
    ) -> None:
        limiter = _use_limiter(monkeypatch, daily_triage_cap=1, ip_rate=100)
        limiter.check_triage(
            raw_alert=None, ioc="1.1.1.1", analyst_notes=None, ip="9.9.9.9"
        )  # fills the day

        response = client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 503
        assert "tomorrow" in response.json()["detail"]
        assert spy_externals == {"enrich": 0, "generate": 0}

    def test_no_case_is_persisted_by_a_rejected_triage(
        self, client, monkeypatch, spy_externals
    ) -> None:
        _use_limiter(
            monkeypatch, daily_triage_cap=1, ip_rate=100, max_raw_alert_chars=10
        )

        client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8", "ioc_type": "ip", "raw_alert": "x" * 11},
        )

        assert client.get("/api/cases").json() == []

    def test_forwarded_for_separates_clients(
        self, client, monkeypatch, spy_externals
    ) -> None:
        """One noisy IP must not lock out everybody behind the same proxy."""
        limiter = _use_limiter(monkeypatch, ip_rate=1, daily_triage_cap=100)
        limiter.check_case_write(ip="203.0.113.9")

        blocked = client.post(
            "/api/triage",
            json={"ioc": "8.8.8.8"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )
        assert blocked.status_code == 429

        # A different client address is still inside its own allowance, so it
        # gets past the limiter -- and trips the spy, proving it got through.
        with pytest.raises(AssertionError, match="enrich_ioc was called"):
            client.post(
                "/api/triage",
                json={"ioc": "8.8.8.8"},
                headers={"x-forwarded-for": "198.51.100.4"},
            )
        assert spy_externals["enrich"] == 1


class TestCaseWriteRoutes:
    def test_oversized_note_returns_400(
        self, client, monkeypatch, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        _use_limiter(monkeypatch, max_note_chars=10)

        response = client.patch(
            f"/api/cases/{case.case_id}/note", json={"note": "x" * 11}
        )

        assert response.status_code == 400
        assert "note" in response.json()["detail"]
        # The rejected note was not appended to the timeline.
        fetched = client.get(f"/api/cases/{case.case_id}").json()
        assert all(event["notes"] != "x" * 11 for event in fetched["timeline"])

    def test_oversized_resolution_returns_400_and_case_stays_open(
        self, client, monkeypatch, manager, make_enrichment, make_report
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        _use_limiter(monkeypatch, max_note_chars=10)

        response = client.patch(
            f"/api/cases/{case.case_id}/close", json={"resolution": "x" * 11}
        )

        assert response.status_code == 400
        assert client.get(f"/api/cases/{case.case_id}").json()["status"] == "open"

    @pytest.mark.parametrize(
        ("suffix", "body"),
        [
            ("status", {"status": "in_progress"}),
            ("note", {"note": "hi"}),
            ("close", {"resolution": "done"}),
        ],
    )
    def test_each_patch_route_is_rate_limited(
        self,
        client,
        monkeypatch,
        manager,
        make_enrichment,
        make_report,
        suffix: str,
        body: dict,
    ) -> None:
        case = _seed_case(manager, make_enrichment, make_report)
        limiter = _use_limiter(monkeypatch, ip_rate=1)
        limiter.check_case_write(ip="203.0.113.9")  # spend the allowance

        response = client.patch(
            f"/api/cases/{case.case_id}/{suffix}",
            json=body,
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 429
        assert int(response.headers["retry-after"]) >= 1

    def test_rate_limit_is_checked_before_the_case_lookup(
        self, client, monkeypatch
    ) -> None:
        """A blocked client gets 429, not 404, for a case that never existed."""
        limiter = _use_limiter(monkeypatch, ip_rate=1)
        limiter.check_case_write(ip="203.0.113.9")

        response = client.patch(
            "/api/cases/DOESNOTEX/note",
            json={"note": "hi"},
            headers={"x-forwarded-for": "203.0.113.9"},
        )

        assert response.status_code == 429


class TestReadsStayOpen:
    """Reads and /health cost nothing per call, so they are deliberately ungated."""

    @pytest.mark.parametrize(
        "path", ["/health", "/api/cases", "/api/dashboard", "/api/cases/DOESNOTEX"]
    )
    def test_reads_are_not_rate_limited(self, client, monkeypatch, path: str) -> None:
        limiter = _use_limiter(monkeypatch, ip_rate=1)
        limiter.check_case_write(ip="203.0.113.9")  # this IP is out of writes

        for _ in range(5):
            response = client.get(path, headers={"x-forwarded-for": "203.0.113.9"})
            assert response.status_code in (200, 404)  # never 429

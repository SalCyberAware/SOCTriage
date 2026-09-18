"""Abuse controls for the public SOCTriage API.

Three protections, all applied before any third-party call so a rejected request
spends nothing:
  1. free-text length caps (bound the per-request cost and the payload size),
  2. per-IP rate limit on every write endpoint (bounds a single client),
  3. daily global cap on POST /api/triage (the backstop against total cost blow-up).

Only the writes are protected. The reads (GET /api/cases, /api/cases/{id},
/api/dashboard) and /health stay open: they touch nothing but the local database
and cost nothing per call.

The daily cap covers POST /api/triage alone, because that is the only endpoint
with money attached: each call spends one Anthropic completion AND one ThreatScan
scan, which itself fans out to the third-party engines behind their own free-tier
quotas. The three PATCH routes only write local rows, so they get the per-IP limit
(which stops a hammering client) but no global ceiling.

State is in-memory. This assumes a SINGLE instance and resets on restart. The
daily cap in particular resets if the process restarts mid-day, so it is a soft
backstop, not an accountant. A shared store like Redis would be the multi-instance
upgrade. All limits are env-configurable with conservative defaults.
"""
from __future__ import annotations

import math
import os
import time
from collections.abc import Callable, Sequence
from typing import Any

# Conservative defaults. Tune for deploy.
DEFAULT_MAX_RAW_ALERT_CHARS = 10_000  # a pasted SIEM alert, generously
DEFAULT_MAX_IOC_CHARS = 256  # an IP, domain, URL or hash
DEFAULT_MAX_NOTE_CHARS = 2_000  # analyst_notes, note, resolution
DEFAULT_IP_RATE = 10  # writes per IP ...
DEFAULT_IP_WINDOW_SECONDS = 300  # ... per 5 minutes
DEFAULT_DAILY_TRIAGE_CAP = 50  # triages per UTC day across all users

_SECONDS_PER_DAY = 86400


class LimitRejectedError(Exception):
    """A request was rejected by an abuse control.

    Carries the HTTP status, a plain client-facing message, and any extra response
    headers (e.g. ``Retry-After``). The web layer maps this to an HTTP error.
    """

    def __init__(
        self, status_code: int, message: str, headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self.message = message
        self.headers = headers or {}
        super().__init__(message)


def _env_int(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back to ``default``."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def client_ip(request: Any) -> str:
    """Resolve the client IP behind a proxy.

    Behind Railway's proxy the real client is the leftmost entry of
    ``X-Forwarded-For``; this trusts the platform to set and sanitize that header.
    A client that sets the header itself, reaching the app directly, could spoof
    its identity here -- the trust is in Railway terminating every inbound
    connection. Falls back to the direct socket peer for local/dev use.

    Takes anything with ``.headers`` and ``.client`` (a Starlette ``Request``),
    so this module stays independent of the web framework and easy to unit test.
    """
    forwarded: str | None = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    peer: str | None = request.client.host if request.client else None
    return peer or "unknown"


class Limiter:
    """In-memory abuse controls. Single-instance only (see module docstring).

    ``time_fn`` is injectable so tests can drive the clock with no real waiting.
    """

    def __init__(
        self,
        *,
        max_raw_alert_chars: int = DEFAULT_MAX_RAW_ALERT_CHARS,
        max_ioc_chars: int = DEFAULT_MAX_IOC_CHARS,
        max_note_chars: int = DEFAULT_MAX_NOTE_CHARS,
        ip_rate: int = DEFAULT_IP_RATE,
        ip_window_seconds: int = DEFAULT_IP_WINDOW_SECONDS,
        daily_triage_cap: int = DEFAULT_DAILY_TRIAGE_CAP,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self.max_raw_alert_chars = max_raw_alert_chars
        self.max_ioc_chars = max_ioc_chars
        self.max_note_chars = max_note_chars
        self.ip_rate = ip_rate
        self.ip_window_seconds = ip_window_seconds
        self.daily_triage_cap = daily_triage_cap
        self._time_fn = time_fn
        # One bucket per IP, shared by all four write endpoints: the limit bounds
        # what a single client can do to the service, not what it can do to one
        # route. Patching notes in a loop therefore eats into the same allowance
        # as triaging, which is the intent.
        self._ip_hits: dict[str, list[float]] = {}
        self._day_index: int | None = None
        self._day_count = 0

    # ── individual checks ────────────────────────────────────────────────────

    def _check_lengths(self, fields: Sequence[tuple[str, str | None, int]]) -> None:
        """Reject the first over-long field. Cheapest check: no state needed."""
        for name, value, limit in fields:
            if value is not None and len(value) > limit:
                raise LimitRejectedError(
                    400,
                    f"Your {name} is too long. The limit is {limit} characters.",
                )

    def _roll_day(self, now: float) -> None:
        """Reset the daily counter when the UTC day changes."""
        index = int(now // _SECONDS_PER_DAY)  # UTC day index
        if index != self._day_index:
            self._day_index = index
            self._day_count = 0

    def _check_daily_cap(self, now: float) -> None:
        """Reject once the global ceiling for the UTC day is reached."""
        self._roll_day(now)
        if self._day_count >= self.daily_triage_cap:
            raise LimitRejectedError(
                503,
                "The public demo is at capacity for today. Please try again "
                "tomorrow.",
            )

    def _check_ip_rate(self, ip: str, now: float) -> list[float]:
        """Reject a client past its allowance; return its surviving hit times."""
        recent = [
            t for t in self._ip_hits.get(ip, []) if now - t < self.ip_window_seconds
        ]
        if len(recent) >= self.ip_rate:
            retry_after = max(1, math.ceil(self.ip_window_seconds - (now - recent[0])))
            raise LimitRejectedError(
                429,
                "You are sending requests too fast. Try again shortly.",
                {"Retry-After": str(retry_after)},
            )
        return recent

    # ── endpoint entry points ────────────────────────────────────────────────

    def check_triage(
        self,
        *,
        raw_alert: str | None,
        ioc: str,
        analyst_notes: str | None,
        ip: str,
    ) -> None:
        """Gate POST /api/triage: lengths, daily cap, per-IP rate.

        Runs the checks cheapest-first and consumes a slot only if all pass, so a
        rejected request costs neither an Anthropic completion nor a ThreatScan
        scan. Raises :class:`LimitRejectedError` on the first failed check.
        """
        self._check_lengths(
            [
                ("raw_alert", raw_alert, self.max_raw_alert_chars),
                ("ioc", ioc, self.max_ioc_chars),
                ("analyst_notes", analyst_notes, self.max_note_chars),
            ]
        )

        now = self._time_fn()
        self._check_daily_cap(now)
        recent = self._check_ip_rate(ip, now)

        # All clear: consume one slot against both counters.
        recent.append(now)
        self._ip_hits[ip] = recent
        self._day_count += 1

    def check_case_write(
        self,
        *,
        ip: str,
        field: str | None = None,
        text: str | None = None,
    ) -> None:
        """Gate a PATCH on a case: length (when the route carries free text), rate.

        No daily cap: these endpoints write local rows only. ``field``/``text`` are
        omitted for the status route, whose body is an enum with nothing free-form
        to cap.
        """
        if field is not None:
            self._check_lengths([(field, text, self.max_note_chars)])

        now = self._time_fn()
        recent = self._check_ip_rate(ip, now)

        recent.append(now)
        self._ip_hits[ip] = recent


def build_limiter() -> Limiter:
    """Build a :class:`Limiter` from environment variables with safe defaults."""
    return Limiter(
        max_raw_alert_chars=_env_int(
            "SOCTRIAGE_MAX_RAW_ALERT_CHARS", DEFAULT_MAX_RAW_ALERT_CHARS
        ),
        max_ioc_chars=_env_int("SOCTRIAGE_MAX_IOC_CHARS", DEFAULT_MAX_IOC_CHARS),
        max_note_chars=_env_int("SOCTRIAGE_MAX_NOTE_CHARS", DEFAULT_MAX_NOTE_CHARS),
        ip_rate=_env_int("SOCTRIAGE_IP_RATE", DEFAULT_IP_RATE),
        ip_window_seconds=_env_int(
            "SOCTRIAGE_IP_WINDOW_SECONDS", DEFAULT_IP_WINDOW_SECONDS
        ),
        daily_triage_cap=_env_int(
            "SOCTRIAGE_DAILY_TRIAGE_CAP", DEFAULT_DAILY_TRIAGE_CAP
        ),
    )

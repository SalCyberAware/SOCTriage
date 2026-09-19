"""API key authentication for the SOCTriage write endpoints.

What is gated, and what is not:

  * The three PATCH routes on a case (status, note, close) require a key. They
    mutate somebody else's investigation record, and a case id is eight hex
    characters -- guessable enough that "you need the id" is not a control.
  * POST /api/triage stays open. It is the public demo, and the abuse controls
    in limits.py already bound what it can cost: a per-IP rate limit and a
    global daily cap on the one endpoint that spends Anthropic and ThreatScan
    quota. Putting a key on it would close the demo to close nothing else.
  * The reads (GET /api/cases, /api/cases/{id}, /api/dashboard) and /health
    stay open, unchanged.

The key travels in the ``X-API-Key`` request header and is compared against the
comma-separated list in ``SOCTRIAGE_API_KEYS``. A list rather than a single
value so a key can be rotated without a window where no key works: add the new
one, move clients over, drop the old one.

Comparison is ``hmac.compare_digest``, not ``==``. Python's ``==`` on strings
returns as soon as two bytes differ, which leaks the length of the matching
prefix through response timing; over enough samples that recovers a key one
byte at a time. ``compare_digest`` takes the same time whatever matches. For
the same reason the loop over several configured keys does not short-circuit on
the first match: it ORs every result together and always compares them all.

FAIL CLOSED: with no key configured, every gated route answers 401 -- it does
not quietly fall back to letting anybody write. The convenient choice is the
other one, so here is the argument against it. An auth check that disappears
when its configuration disappears is not a control, because the case it has to
survive is exactly a missing or misspelled variable: a service moved between
Railway projects, a variable dropped in a redeploy, ``SOCTRIAGE_API_KEY``
typed for ``SOCTRIAGE_API_KEYS``. Fail-open turns each of those into a silently
world-writable API that still returns 200 and still looks healthy -- the same
class of failure as the September 2026 stale deploy, where every signal was
green and the thing itself was broken. Fail-closed turns them into a 401 on the
first write attempt, which is loud, immediate, and honest about what happened.
The cost is real but bounded and recoverable: a fresh clone cannot PATCH until
it sets the variable, and .env.example plus the README say so. Nothing that
makes the demo work -- triage, the reads, /health -- is affected either way.

Environment is read per call rather than captured at import, so a key can be
rotated by restarting the process with a new value and so tests can vary it.
The read is a ``getenv`` and a ``split``; it is not worth caching.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

# The header clients send the key in. Case-insensitive on the wire; Starlette's
# header mapping already normalizes it.
API_KEY_HEADER = "X-API-Key"

# Comma-separated list of accepted keys. Plural: see the rotation note above.
API_KEY_ENV = "SOCTRIAGE_API_KEYS"

# One message for a missing key and for a wrong one. Which of the two it was is
# something the caller already knows, and telling them apart is free help for
# anyone probing.
MISSING_OR_INVALID_MESSAGE = "Missing or invalid API key."

# A distinct message for the fail-closed case. This does tell a caller that no
# key will ever work here, which is not worth hiding: it is not exploitable,
# and without it a self-hoster who forgot the variable sees a 401 for a key
# they are certain is correct and has nothing to go on.
NOT_CONFIGURED_MESSAGE = (
    "This deployment has no API key configured, so the endpoints that require "
    "one are disabled."
)


class AuthRejectedError(Exception):
    """A request failed the API key check.

    Carries the HTTP status and a plain client-facing message, mirroring
    :class:`limits.LimitRejectedError`, so the web layer translates both the
    same way. Never carries the presented key.
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def configured_keys() -> tuple[str, ...]:
    """The accepted keys, in the order configured.

    Blank entries are dropped, so a trailing comma or a value of ``","`` leaves
    no keys configured rather than accepting the empty string as a key.
    """
    raw = os.getenv(API_KEY_ENV, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def key_is_valid(presented: str | None) -> bool:
    """Whether ``presented`` matches a configured key, in constant time.

    ``False`` when no key is configured (fail closed) and when ``presented`` is
    ``None`` or empty -- an absent header is not a match for anything.
    """
    keys = configured_keys()
    if not keys or not presented:
        return False

    supplied = presented.encode("utf-8")
    # Deliberately not `any(...)`: that would stop at the first match and make
    # the response time depend on which key was used. `|=` compares them all.
    matched = False
    for key in keys:
        matched |= hmac.compare_digest(supplied, key.encode("utf-8"))
    return matched


def require_api_key(request: Any) -> None:
    """Gate a request. Raises :class:`AuthRejectedError` if it may not proceed.

    Takes anything with a ``.headers`` mapping (a Starlette ``Request``), so
    this module stays independent of the web framework, the same way
    :func:`limits.client_ip` does.
    """
    if not configured_keys():
        raise AuthRejectedError(401, NOT_CONFIGURED_MESSAGE)
    if not key_is_valid(request.headers.get(API_KEY_HEADER)):
        raise AuthRejectedError(401, MISSING_OR_INVALID_MESSAGE)


def is_authenticated(request: Any) -> bool:
    """Whether a request carries a valid key, without requiring that it does.

    For the ungated routes, which record in the audit trail whether the caller
    identified itself. Defined in terms of :func:`require_api_key` so the flag
    means exactly "would have passed the gate" and cannot drift away from it.
    """
    try:
        require_api_key(request)
    except AuthRejectedError:
        return False
    return True

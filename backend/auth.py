"""Authentication for SOCTriage: the admin API key and the visitor session token.

Two credentials, two scopes:

  * The SESSION TOKEN (``X-Session-Token``) is how a visitor owns cases. The
    browser makes a random one on first load and sends it on every call. POST
    /api/triage requires one and stores its SHA-256 next to the case; after
    that, the reads (list, get, dashboard) show only the cases with the same
    hash, and the three PATCH routes (status, note, close) accept it for those
    cases. Another owner's case answers 404, exactly like a case that does not
    exist, so a token is no help in finding out which ids are taken.
  * The API KEY (``X-API-Key``) is the operator's. A valid key sees and changes
    every case, including the ones created before ownership existed, which
    have no owner at all and so are visible to the key and to nobody else.

Why the hash and not the token: the database never holds anything a reader
could replay. A leaked dump gives hashes, and a hash sent as a token is just
another token that owns nothing. The token is a 122-bit random UUID, so a
plain SHA-256 is enough; there is no low-entropy secret here for a slow hash
to protect.

What a token is not: an account. It lives in one browser's localStorage, so
clearing site data or switching browsers loses access to those cases (the key
still reaches them). It is not a secret from the person holding it, and it
does not need to be: it only ever unlocks cases that the same token created.

Why POST /api/triage is still not behind the key: it is the public demo, and
the abuse controls in limits.py already bound what it can cost (a per-IP rate
limit and a global daily cap on the one endpoint that spends Anthropic and
ThreatScan quota). Requiring a token closes nothing there either; it just
gives the new case an owner. /health stays open.

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

FAIL CLOSED: with no key configured, no request is ever treated as the
operator. A write without a matching session token answers 401; it does not
quietly fall back to letting anybody write. The convenient choice is the
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
makes the demo work -- triage, the reads, an owner changing their own case,
/health -- is affected either way.

Environment is read per call rather than captured at import, so a key can be
rotated by restarting the process with a new value and so tests can vary it.
The read is a ``getenv`` and a ``split``; it is not worth caching.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
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
    "This deployment has no API key configured, so a case can only be changed "
    "with the session token that created it."
)

# The header the browser sends its session token in.
SESSION_TOKEN_HEADER = "X-Session-Token"

# Bounds on an acceptable token. The frontend sends crypto.randomUUID() (36
# characters). The floor keeps out tokens short enough to guess, such as "a",
# which would make a shared mailbox of whatever cases they own; the ceiling
# keeps an attacker from making the server hash megabytes per request.
SESSION_TOKEN_MIN_LENGTH = 16
SESSION_TOKEN_MAX_LENGTH = 128

# One message for a missing token and a malformed one, for the same reason as
# MISSING_OR_INVALID_MESSAGE.
SESSION_TOKEN_MESSAGE = (
    "Missing or invalid session token. Send a random X-Session-Token of "
    f"{SESSION_TOKEN_MIN_LENGTH} to {SESSION_TOKEN_MAX_LENGTH} printable characters."
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


def owner_hash(token: str) -> str:
    """The SHA-256 of a session token, as stored in ``cases.owner_hash``."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_owner_hash(request: Any) -> str | None:
    """The owner hash for the request's session token, or ``None``.

    ``None`` both when the header is absent and when it is malformed: too
    short, too long, or containing anything but printable ASCII. A request
    with no usable token owns nothing, rather than owning the cases of
    whoever else sent the same malformed value.
    """
    token = (request.headers.get(SESSION_TOKEN_HEADER) or "").strip()
    if not SESSION_TOKEN_MIN_LENGTH <= len(token) <= SESSION_TOKEN_MAX_LENGTH:
        return None
    if not all("!" <= ch <= "~" for ch in token):
        return None
    return owner_hash(token)


@dataclass(frozen=True)
class Caller:
    """Who a request is, as far as case access goes.

    ``is_admin`` when it carries a valid API key; ``owner_hash`` when it
    carries a usable session token. Both can be set. Neither set is an
    anonymous caller, who owns nothing and sees nothing.
    """

    is_admin: bool
    owner_hash: str | None


def resolve_caller(request: Any) -> Caller:
    """Identify a request without requiring anything of it."""
    return Caller(
        is_admin=is_authenticated(request),
        owner_hash=session_owner_hash(request),
    )


def require_case_writer(request: Any) -> Caller:
    """Gate a case write: a valid API key, or a session token. Else raise.

    Whether the token actually owns the case is the route's question, answered
    with a 404 after the lookup. This check only refuses callers who could not
    own anything, and refuses them with the API key's own messages, so a
    deployment with no key configured still says so.
    """
    caller = resolve_caller(request)
    if caller.is_admin or caller.owner_hash is not None:
        return caller
    require_api_key(request)  # raises; the key it was given did not pass
    raise AuthRejectedError(401, MISSING_OR_INVALID_MESSAGE)  # pragma: no cover


def require_session_owner(request: Any) -> str:
    """The owner hash for a request that must have a session token."""
    hashed = session_owner_hash(request)
    if hashed is None:
        raise AuthRejectedError(401, SESSION_TOKEN_MESSAGE)
    return hashed

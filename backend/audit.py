"""Audit trail for every write the SOCTriage API performs.

One line per successful write, recording who did what: when, which endpoint,
which case, the client IP as resolved behind Railway's proxy, whether the
caller presented a valid API key, and which actor made the change. All four
writes are covered, including the keyless POST /api/triage -- "an anonymous caller from 203.0.113.7
opened case 4FA22FE3" is exactly the sort of thing the trail exists to answer.


WHERE THIS LIVES: structured application logs, not the database.

The tempting alternative is an ``audit_events`` table next to ``cases``. Three
reasons it is the wrong home here.

1. The database already has a durable record of what changed, and it is the
   case timeline. Every one of these writes appends a timeline event that
   says what happened and persists with the case. A table would re-record the
   same facts a second time, and two stores that are supposed to agree about
   the same events will eventually disagree about them.

2. What the audit trail adds over the timeline is the *operational* half --
   client IP and whether the request was authenticated -- and that half must
   not go in the cases table. The timeline is served verbatim by
   GET /api/cases/{id}, which is open to anyone. Putting a client IP there
   publishes it. It would be a privacy leak introduced by the feature meant
   to improve accountability.

3. A table nobody can read is not an audit trail. Making it useful means a
   query endpoint, which itself needs authorization and a retention policy
   for the IP addresses it stores. Railway already captures stdout, with
   search and retention handled by the platform, for zero new surface area.

So: JSON to stdout, one object per line, at INFO. Machine-readable for
``railway logs`` or anything that ingests them later, and cheap enough that a
write path is not measurably slower for having been recorded.

The trade accepted along with that: log retention is the platform's, not ours
(a few days on Railway's smaller plans), and the trail cannot be joined to the
cases table in SQL. If the trail ever needs to outlive the platform's window,
the upgrade is to ship these lines to a log store, not to add a table -- the
shape of the record does not change either way.


WHAT IS NEVER RECORDED, and how that is kept true:

  * No key material. Nothing in this module takes a key, a header or a
    request; the caller passes a resolved boolean and an actor. The actor is
    "operator" with the first 8 hex characters of the SHA-256 of the key that
    was used, "owner" with the first 12 characters of the case's owner hash
    (itself the SHA-256 of the session token), or "none". :func:`build_entry`
    refuses an ``actor_id`` that is not lowercase hex of exactly that length,
    so a raw key or token cannot be passed through by mistake.
  * No ``raw_alert``, no ``analyst_notes``, no note or resolution text. The
    entry records THAT a change happened, never its content. Again
    structural: :func:`build_entry` has no parameter such a string could
    arrive through, so logging one would take a deliberate code change rather
    than an accident. A test asserts the emitted keys are exactly the allowed
    set.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime

LOGGER_NAME = "soctriage.audit"

# The exact keys of an audit entry. Exported so the tests can assert that no
# extra field -- above all no free text -- ever sneaks into the record.
ENTRY_FIELDS = frozenset(
    {"ts", "event", "endpoint", "case_id", "ip", "authenticated", "actor", "actor_id"}
)

# What an ``actor_id`` must look like for each actor: lowercase hex of a fixed
# length, or nothing. Mirrors auth.key_fingerprint and auth.OWNER_ID_CHARS.
_ACTOR_ID_PATTERNS: dict[str, re.Pattern[str] | None] = {
    "operator": re.compile(r"[0-9a-f]{8}"),
    "owner": re.compile(r"[0-9a-f]{12}"),
    "none": None,
}

logger = logging.getLogger(LOGGER_NAME)

# Its own stdout handler with a bare "%(message)s" format, so the emitted line
# is the JSON object and nothing else: no level prefix, no logger name, no
# timestamp of its own (the entry carries one). propagate=False keeps it from
# being re-emitted through uvicorn's root handlers in its format as well.
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def build_entry(
    *,
    endpoint: str,
    ip: str,
    authenticated: bool,
    actor: str,
    actor_id: str | None,
    case_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Build one audit entry.

    Separate from :func:`record` so the shape of the record can be asserted
    without going through the logging machinery.

    ``endpoint`` is the route template, e.g. ``"PATCH /api/cases/{case_id}/note"``
    -- the route, not the concrete path, so entries group cleanly. ``case_id``
    carries the concrete case; every write today has one (POST /api/triage
    reports the case it just opened), and it stays optional for a future write
    that does not.

    ``ip`` comes from :func:`limits.client_ip`, i.e. the rate-limit key: in
    production the X-Real-IP Railway's edge sets (an IPv6 client as its /56),
    falling back to the socket peer. ``now`` is injectable for tests;
    production passes nothing.

    ``actor`` and ``actor_id`` come from :meth:`auth.Caller.audit_actor`. A
    value that does not fit the actor's shape raises ``ValueError`` rather
    than being logged: an unknown actor, an id on "none", or an id that is not
    a short hex fingerprint (which a raw key or token never is).
    """
    if actor not in _ACTOR_ID_PATTERNS:
        raise ValueError(f"unknown audit actor {actor!r}")
    pattern = _ACTOR_ID_PATTERNS[actor]
    if pattern is None:
        if actor_id is not None:
            raise ValueError(f"actor {actor!r} carries no id")
    elif actor_id is None or not pattern.fullmatch(actor_id):
        # The value is deliberately left out of the message: if it is a key
        # that arrived here by mistake, the error must not log it instead.
        raise ValueError(f"actor_id is not a valid {actor} fingerprint")
    return {
        "ts": (now or datetime.now(UTC)).isoformat(),
        "event": "write",
        "endpoint": endpoint,
        "case_id": case_id,
        "ip": ip,
        "authenticated": authenticated,
        "actor": actor,
        "actor_id": actor_id,
    }


def record(
    *,
    endpoint: str,
    ip: str,
    authenticated: bool,
    actor: str,
    actor_id: str | None,
    case_id: str | None = None,
) -> None:
    """Emit one audit entry as a JSON line on stdout.

    Called after the write has succeeded, so the trail records writes that
    happened rather than writes that were attempted: a 401, a 429 or a 404
    leaves no entry, because none of them changed anything.
    """
    entry = build_entry(
        endpoint=endpoint,
        ip=ip,
        authenticated=authenticated,
        actor=actor,
        actor_id=actor_id,
        case_id=case_id,
    )
    logger.info(json.dumps(entry, separators=(",", ":")))

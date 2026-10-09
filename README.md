# SOCTriage

**AI-powered SOC alert triage assistant. A free, open-source alternative to enterprise SOAR platforms.**

[![Backend quality](https://img.shields.io/github/actions/workflow/status/SalCyberAware/SOCTriage/backend-quality.yml?branch=main&label=backend%20quality&style=flat-square)](https://github.com/SalCyberAware/SOCTriage/actions/workflows/backend-quality.yml)
[![Backend tests](https://img.shields.io/github/actions/workflow/status/SalCyberAware/SOCTriage/backend-tests.yml?branch=main&label=backend%20tests&style=flat-square)](https://github.com/SalCyberAware/SOCTriage/actions/workflows/backend-tests.yml)
[![Frontend](https://img.shields.io/github/actions/workflow/status/SalCyberAware/SOCTriage/frontend.yml?branch=main&label=frontend&style=flat-square)](https://github.com/SalCyberAware/SOCTriage/actions/workflows/frontend.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/SalCyberAware/SOCTriage/security.yml?branch=main&label=security&style=flat-square)](https://github.com/SalCyberAware/SOCTriage/actions/workflows/security.yml)
[![Deploy verification](https://img.shields.io/github/actions/workflow/status/SalCyberAware/SOCTriage/deploy-verify.yml?branch=main&label=deploy%20verification&style=flat-square)](https://github.com/SalCyberAware/SOCTriage/actions/workflows/deploy-verify.yml)
[![codecov](https://img.shields.io/codecov/c/github/SalCyberAware/SOCTriage?style=flat-square&label=coverage&logo=codecov&logoColor=white)](https://codecov.io/gh/SalCyberAware/SOCTriage)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-soctriage.vercel.app-00d4aa?style=flat-square)](https://soctriage.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Railway-6366f1?style=flat-square)](https://soctriage-production.up.railway.app/health)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-3b82f6?style=flat-square)](https://python.org)

---

## What It Does

SOCTriage automates the first 30 minutes of SOC alert triage. Paste an IP, domain, URL, or file hash. SOCTriage enriches it across **11 threat intelligence engines** simultaneously and generates a full **AI-powered incident report** with MITRE ATT&CK mapping, severity scoring, recommended actions, and a step-by-step response playbook.

Enterprise SOAR platforms (Splunk SOAR, Palo Alto XSOAR) cost **$100,000+ per year**. SOCTriage is free.

<div align="center">

![SOCTriage Incident Report](soctriage-report.png)

![MITRE Techniques and Engine Verdicts](soctriage-techniques.png)

</div>

---

## Live Demo

**Frontend:** https://soctriage.vercel.app  
**Backend Health:** https://soctriage-production.up.railway.app/health

Note that the hosted demo ships no API key, so the Cases tab is read-only there. See [The frontend and the hosted demo](#the-frontend-and-the-hosted-demo).

---

## Features

- **IOC Enrichment.** Queries 11 threat intelligence engines via [ThreatScan](https://github.com/SalCyberAware/ThreatScan) and returns aggregated verdicts and threat scores
- **AI Incident Reports.** Claude AI generates executive summaries, threat classifications, affected asset identification, and recommended actions
- **MITRE ATT&CK Mapping.** Every IOC is automatically mapped to relevant ATT&CK techniques and tactics with direct links to attack.mitre.org
- **Severity Scoring.** LOW / MEDIUM / HIGH / CRITICAL based on weighted engine results, on a 0 to 100 scale
- **Response Playbook.** Step-by-step containment, investigation, eradication, and recovery guidance tailored to the specific threat
- **Case Management.** Cases are opened automatically with full timeline logging; status can be updated (OPEN, IN_PROGRESS, ESCALATED, CLOSED)
- **Persistent storage.** Cases live in PostgreSQL in production and in a local SQLite file for development, so they survive restarts. The schema is managed by Alembic migrations, applied automatically on startup. See [docs/MIGRATIONS.md](docs/MIGRATIONS.md)
- **Dashboard.** Live stats by case status and severity
- **Per-visitor case isolation.** Each browser gets a random session token, and sees and changes only the cases it opened. An operator API key reaches every case. See [Authentication](#authentication)
- **Audit logging.** Every write records who did what, as one structured line per event. See [Audit Logging](#audit-logging)
- **Abuse controls.** Per-IP rate limiting, a global daily cap on the one endpoint that spends money, and length caps on every free-text input
- **Web hardening.** Security headers on the API and the site, a Report-Only Content-Security-Policy, API docs off in production, and IOC validation against the stated type. See [Web Hardening](#web-hardening)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React + Vite, deployed to Vercel |
| Backend | Python FastAPI, deployed to Railway |
| AI Engine | Anthropic Claude API |
| Enrichment | ThreatScan API (11 engines) |
| Data Models | Pydantic v2 |
| Database | PostgreSQL in production, SQLite locally, via SQLAlchemy 2.x, schema versioned with Alembic |
| Backend tests | pytest, 241 tests, 99% line coverage |
| Frontend tests | vitest + React Testing Library, 18 specs |
| CI | GitHub Actions: tests, lint, types, security scanning, deploy verification |

---

## Threat Intelligence Engines

SOCTriage enriches IOCs through ThreatScan, which queries:

1. VirusTotal
2. AbuseIPDB
3. URLScan.io
4. AlienVault OTX
5. GreyNoise
6. MalwareBazaar
7. URLhaus (abuse.ch)
8. ThreatFox
9. Google Safe Browsing
10. IPInfo
11. WHOIS / DNS

---

## How SOCTriage compares

SOCTriage is a fast first-pass triage layer: paste an IOC, get enriched intel from 11 sources, an AI-generated incident report mapped to MITRE ATT&CK, and a tracked case with timeline in under a minute. It is **not** a full SOAR platform. It is the layer that compresses the 15 to 30 minutes of manual tab-switching and report-writing that usually happens **before** a SOAR playbook fires, or in place of one, for teams without SOAR budget. Honest comparison:

| Tool | Category | Cost | Strengths | Where SOCTriage differs |
|------|----------|------|-----------|--------------------------|
| Cortex XSOAR / Splunk SOAR / Tines | Enterprise SOAR | ~$100k+/yr | Massive integration libraries, playbook automation across hundreds of tools, mature case management, SLA dashboards | SOCTriage is zero-install (one Vercel + one Railway deploy), free, and AI-first, with no playbook authoring required. Meant to slot in **before** these for first-pass triage, not replace them |
| TheHive + Cortex | Open-source SOC platform | Free, self-hosted | Mature case management, observable enrichment via Cortex analyzers, MISP integration, active community | SOCTriage is hosted (no Elasticsearch/Cassandra ops burden); ships LLM-generated narrative reports + auto-derived ATT&CK techniques instead of raw analyzer output you compose yourself |
| Manual workflow (SIEM + tabs + ticketing) | What most small SOC teams actually do | "Free," burns analyst time | Full flexibility, familiar tools, no new platform to learn | SOCTriage compresses paste-IOC, 11-engine enrich, ATT&CK mapping, AI report and tracked case into one request; the manual equivalent is 15 to 30 min per alert across many tabs |

**A note on the AI-generated MITRE mapping:** technique IDs, tactics, and `attack.mitre.org` URLs are produced by Claude per-triage from the enriched intel and alert context, not from a static mapping table. That makes them context-aware (the same IOC in a different alert context can map to different techniques), but reviewers should sanity-check the techniques on high-stakes incidents the same way they would any LLM output.

**A note on the enrichment layer:** SOCTriage delegates the 11-engine fan-out to its sister project [ThreatScan](https://github.com/SalCyberAware/ThreatScan) via an HTTP call. The intel work is not reinvented. SOCTriage adds the AI report, ATT&CK mapping, and case lifecycle on top.

### When to use what

- **Use enterprise SOAR (Cortex XSOAR, Splunk SOAR, Tines)** when you have a team of analysts, dozens of integrations to orchestrate, complex playbooks, and the budget for the licenses.
- **Use TheHive + Cortex** when you want full self-hosted control over case data, have the ops capacity to run Elasticsearch/Cassandra, and prefer composing analyzers yourself.
- **Use SOCTriage** when you are a small or mid-size SOC team that needs fast first-pass triage without enterprise overhead, especially for the AI-generated incident report and ATT&CK mapping out of the box.

---

## API Endpoints

```
POST   /api/triage              Submit IOC for enrichment + AI report + case creation   [token]
GET    /api/cases               List the caller's cases                                [scoped]
GET    /api/cases/{id}          Get single case with full timeline                     [scoped]
PATCH  /api/cases/{id}/status   Update case status                                     [owner or key]
PATCH  /api/cases/{id}/note     Add analyst note                                       [owner or key]
PATCH  /api/cases/{id}/close    Close case with resolution                             [owner or key]
GET    /api/dashboard           Stats by status and severity                           [scoped]
GET    /health                  Health check, reports the running commit
```

`[token]` needs an `X-Session-Token`. `[scoped]` returns only the cases that
token opened, or every case with a valid `X-API-Key`. `[owner or key]` needs
the token that opened the case, or the key. See
[Authentication](#authentication) below.

### Example Request

```bash
curl -X POST https://soctriage-production.up.railway.app/api/triage \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": "185.220.101.45",
    "ioc_type": "ip",
    "raw_alert": "CrowdStrike: suspicious outbound connection from WS-042 at 2:00 AM",
    "analyst_notes": "User reported no activity at that time"
  }'
```

`ioc_type` is optional. When it is omitted, the type is detected from the
indicator itself. When it is given, the IOC has to fit it, or the request is a
`400`; see [Web Hardening](#web-hardening).

### Example Response

```json
{
  "case_id": "4FA22FE3",
  "status": "success",
  "report": {
    "title": "Suspicious Outbound C2 Connection from WS-042 to Malicious IP 185.220.101.45",
    "severity": "high",
    "threat_type": "C2 (Command and Control)",
    "summary": "Workstation WS-042 initiated a suspicious outbound connection...",
    "mitre_techniques": [
      {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/001/"
      }
    ],
    "recommended_actions": [
      "Immediately isolate WS-042 from the network",
      "Block 185.220.101.45 at perimeter firewall",
      "Conduct full forensic image of WS-042"
    ],
    "playbook": [
      "STEP 1 - CONTAINMENT: Isolate WS-042 immediately via NAC or VLAN quarantine...",
      "STEP 2 - IDENTIFICATION: Pull CrowdStrike process tree and network telemetry..."
    ]
  },
  "enrichment": {
    "verdict": "malicious",
    "score": 83
  }
}
```

---

## Authentication

SOCTriage has two credentials. A **session token** makes a visitor the owner of
the cases they open. The operator's **API key** reaches every case.

| Endpoint | Session token (`X-Session-Token`) | API key (`X-API-Key`) | Neither |
|----------|-----------------------------------|-----------------------|---------|
| `POST /api/triage` | **Required.** The new case is owned by this token | Not enough on its own: a token is still required | `401` |
| `GET /api/cases` | Only this token's cases | Every case | `[]` |
| `GET /api/cases/{id}` | This token's case; any other id is `404` | Any case | `404` |
| `GET /api/dashboard` | Counts this token's cases only | Counts every case | All zero |
| `PATCH /api/cases/{id}/status`, `/note`, `/close` | This token's case; any other id is `404` | Any case | `401` |
| `GET /health` | Not needed | Not needed | Open |

### Session tokens: visitors see only their own cases

On first load the frontend makes a random token with `crypto.randomUUID()`,
keeps it in `localStorage`, and sends it as `X-Session-Token` on every API
call. `POST /api/triage` stores the token's **SHA-256** next to the new case,
never the token itself. After that:

- The reads return only the cases whose hash matches the caller's token.
- The owner can change their own cases (status, note, close) with the same
  token and no key.
- **Another owner's case returns `404`, the same status and body as a case
  that does not exist.** A token cannot be used to find out which case ids are
  taken.
- A request with no token sees no cases at all, and cannot open or change one.

A token is not an account. It belongs to one browser, so clearing site data or
switching browsers starts a new token, and cases opened under the old one are
then reachable only with the API key. The app says so next to the triage form
and on the Cases tab.

A token must be 16 to 128 printable ASCII characters; anything else is treated
as no token. Hashing means a leaked database holds nothing that can be replayed
as a token. A plain SHA-256 is enough because the token is a 122-bit random
UUID, not a password.

Cases opened **before** ownership existed have no owner (`owner_hash` is
`NULL`). No token matches them, so only the API key sees or changes them.

```bash
TOKEN=$(python -c "import uuid; print(uuid.uuid4())")

curl -X POST https://soctriage-production.up.railway.app/api/triage \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: $TOKEN" \
  -d '{"ioc": "8.8.8.8"}'

curl https://soctriage-production.up.railway.app/api/cases \
  -H "X-Session-Token: $TOKEN"
```

### The API key: the operator sees everything

Send it in the `X-API-Key` header:

```bash
curl -X PATCH https://soctriage-production.up.railway.app/api/cases/4FA22FE3/status \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SOCTRIAGE_API_KEY" \
  -d '{"status": "in_progress"}'
```

A valid key lists, reads, counts and changes every case, whoever owns it,
including the ownerless legacy ones. A wrong key is ignored rather than
rejected outright: the request is then judged on its session token alone.

On the write routes, a request with neither a valid key nor a token returns
`401` with a plain `detail` message and changes nothing. The check runs
**before** the case lookup, so such a caller gets the same 401 for a case id
that exists and one that does not, and it runs before the rate limiter, so a
refused request does not eat into anyone's allowance.

### Configuring keys

Set `SOCTRIAGE_API_KEYS` on the backend to one key, or to several separated by
commas. Several exist so a key can be rotated with no window where none works:
add the new one, move clients across, drop the old one.

```bash
# generate something worth having
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keys are compared with `hmac.compare_digest`, not `==`. String equality returns
as soon as two bytes differ, which leaks the length of the matching prefix
through response timing; over enough samples that recovers a key one byte at a
time. The comparison loop also does not stop at the first matching key, so the
response time does not depend on which key was used.

### It fails closed

**With `SOCTRIAGE_API_KEYS` unset, no request is ever treated as the
operator.** Owners can still open, read and change their own cases with their
session token, but nothing reaches anyone else's cases or the legacy ones, and
a write without a token returns `401` saying the deployment has no key.

That is the inconvenient choice and it is deliberate. An auth check that
disappears along with its configuration is not a control, because the case it
has to survive is precisely a missing variable: a service moved between Railway
projects, a variable dropped in a redeploy, `SOCTRIAGE_API_KEY` typed for
`SOCTRIAGE_API_KEYS`. Fail-open turns every one of those into a silently
world-writable API that still returns 200 and still looks healthy, the same
shape of failure as the stale deploy that
[deploy verification](.github/workflows/deploy-verify.yml) exists to catch,
where every signal was green and the thing itself was broken. Fail-closed turns
them into a 401 on the first write, which is loud, immediate, and honest.

### The frontend and the hosted demo

[soctriage.vercel.app](https://soctriage.vercel.app) has **no API key built
in, and no build can have one**. There is no `VITE_API_KEY` any more: whatever
Vite compiles into a bundle is readable by anyone who opens devtools, so a key
there would be a published key.

Visitors need no key. Their session token lets them see and change the cases
they opened, so the Cases tab shows the status buttons on every case it lists.

An operator who needs every case types the key into the **Admin API key** field
at the bottom of the page. It is held in the page's memory only: never written
to `localStorage` or any other storage, sent only as `X-API-Key`, and forgotten
on reload or with **Forget key**. Treat any browser you type it into as one
that has seen it.

---

## Web Hardening

**Security headers.** Every backend response, errors and CORS preflights
included, carries:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |

The frontend sends the same four from [`frontend/vercel.json`](frontend/vercel.json),
plus a **Content-Security-Policy in Report-Only mode**. It allows scripts only
from the site itself, API calls only to the site and
`https://soctriage-production.up.railway.app`, stylesheets from the site and
Google Fonts (`fonts.googleapis.com`), font files from `fonts.gstatic.com`, and
no plugins or framing. Report-Only means a browser logs a violation to the
console instead of blocking anything, so the policy can be checked against the
live site before it is enforced. If you self-host against a different API
origin, add it to `connect-src` there.

**No API docs in production.** `/docs`, `/redoc` and `/openapi.json` return
`404` unless `SOCTRIAGE_ENABLE_API_DOCS` is set to `1`, `true` or `yes`. They
are a full map of every route and header, which helps on a laptop and only
helps an attacker on a public deployment. It is a dedicated flag rather than
`ENV=development`, so a stale `ENV` value cannot turn them on.

**Schema ceilings.** Every free-text field has a `max_length` in the request
schema: `raw_alert` 100,000 characters, `ioc` 4,096, and `analyst_notes`,
`note` and `resolution` 20,000. These sit ten times or more above the
[abuse-control caps](backend/limits.py), so normal oversize input still gets
the plain `400` naming the field and the cap; only something absurd is refused
earlier with a `422`. If you raise a `SOCTRIAGE_MAX_*` cap, keep it below its
ceiling.

**A stated `ioc_type` must fit the IOC.** When `ioc_type` is given,
`POST /api/triage` checks the indicator against it and answers `400` on a
mismatch, before enrichment, the AI call or the rate limiter:

| `ioc_type` | Accepted |
|------------|----------|
| `ip` | An IPv4 or IPv6 address |
| `hash` | MD5, SHA-1 or SHA-256 in hex (32, 40 or 64 characters) |
| `url` | An `http` or `https` URL with a host, no whitespace |
| `domain` | Two or more dot-separated labels and an alphabetic or `xn--` TLD |

Leave `ioc_type` out and the type is detected instead, as before.

---

## Audit Logging

Every write records who did what. All four of them, including the
unauthenticated `POST /api/triage`, because "an anonymous caller from
203.0.113.7 opened case 4FA22FE3" is exactly the kind of thing the trail exists
to answer.

One JSON object per line on stdout, at INFO:

```json
{"ts":"2026-09-19T12:34:56.789012+00:00","event":"write","endpoint":"PATCH /api/cases/{case_id}/status","case_id":"4FA22FE3","ip":"203.0.113.7","authenticated":true,"actor":"operator","actor_id":"9f86d081"}
```

| Field | Meaning |
|-------|---------|
| `ts` | ISO 8601 instant, UTC |
| `event` | Always `write` |
| `endpoint` | The route template, not the concrete path, so entries group cleanly |
| `case_id` | The case written. For `POST /api/triage`, the case it just opened |
| `ip` | The client behind the proxy: leftmost `X-Forwarded-For`, else the socket peer |
| `authenticated` | Whether the caller presented a valid API key |
| `actor` | Who made the change: `operator` (a valid API key), `owner` (the case's session token) or `none`. With both a key and a token, the key is named |
| `actor_id` | For `operator`, the first 8 hex characters of the SHA-256 of the key that was used, so rotated keys can be told apart. For `owner`, the first 12 characters of the case's `owner_hash`. `null` for `none` |

Entries are written **after** the write succeeds, so the trail is of changes
that happened, not requests that were made. A 401, a 429, a 404 and every read
record nothing at all.

### What is never logged

No key material, and no free text: not `raw_alert`, not analyst notes, not
note bodies, not resolution text. The actor is named by a short hash prefix,
never by the key or the session token, and `audit.build_entry` refuses an
`actor_id` that is not lowercase hex of exactly that length. The entry records **that** a change happened.
**What** it said belongs to the case timeline, which is already persisted and
already served by `GET /api/cases/{id}`.

That is structural rather than a matter of care. `audit.build_entry` has no
parameter such a string could arrive through, and a test asserts the emitted
keys are exactly the eight above.

### Why logs and not a database table

An `audit_events` table next to `cases` was the obvious alternative. Three
reasons against it here:

1. **The database already records what changed.** Every one of these writes
   appends a case timeline event that persists with the case. A table would
   re-record the same facts a second time, and two stores meant to agree about
   the same events eventually disagree about them.
2. **What the trail adds is the operational half, client IP and whether the
   caller was authenticated, and that half must not go in the cases table.**
   The timeline is served verbatim by an open endpoint. Putting a client IP
   there publishes it: a privacy leak introduced by the feature meant to
   improve accountability.
3. **A table nobody can read is not an audit trail.** Making it useful means a
   query endpoint, which needs its own authorization and a retention policy for
   the addresses it stores. Railway already captures stdout, with search and
   retention handled by the platform, for no new surface area.

The trade accepted along with that: retention is the platform's, not ours (a
few days on Railway's smaller plans), and the trail cannot be joined to the
cases table in SQL. If it ever needs to outlive the platform's window, the
upgrade is to ship these lines to a log store. The shape of the record does
not change either way.

Read them with `railway logs`, or filter to the trail alone:

```bash
railway logs | grep '"event":"write"'
```

No configuration: there is nothing to set, and nothing to turn off.

---

## Self-Hosting

### Prerequisites

- Python 3.11+ (CI pins 3.11.9, see [`backend/runtime.txt`](backend/runtime.txt))
- Node.js 20+ and npm, for the frontend
- Anthropic API key (console.anthropic.com)
- ThreatScan running locally, or use the live instance
- PostgreSQL 16+ is optional. Without `DATABASE_URL` the backend uses a local SQLite file.

### Backend Setup

```bash
git clone https://github.com/SalCyberAware/SOCTriage.git
cd SOCTriage/backend

python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install -r requirements.txt        # to run the service (hash-checked lock)
pip install -r requirements-dev.txt    # to run the tests too (adds pytest, ruff, mypy)

cp .env.example .env
# Edit .env with your API keys

uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

`requirements.txt` holds runtime dependencies only. Installing it alone is
enough to serve the API but not to run the test suite, which is why
`requirements-dev.txt` exists and is what the test jobs install.

### Dependencies and the lock

Production installs exact, hash-checked versions:

| File | What it is |
|------|------------|
| `requirements.in` | The runtime dependency ranges. Edit this one. |
| `requirements.txt` | The lock compiled from it: every package, transitives included, pinned with sha256 hashes. Railway and CI install this. |
| `requirements-dev.in` | Dev tools (pytest, ruff, mypy), constrained to the lock. |
| `requirements-dev.txt` | The dev lock compiled from it. |

pip checks hashes automatically for a file that has them. The lock is
universal, so the same file installs on Railway's Linux and on Windows or
macOS. After editing a `.in` file, regenerate from `backend/` with
[uv](https://docs.astral.sh/uv/) 0.12.18, the version CI pins:

```bash
uv pip compile requirements.in --universal --python-version 3.11 --generate-hashes -o requirements.txt
uv pip compile requirements-dev.in --universal --python-version 3.11 --generate-hashes -o requirements-dev.txt
```

CI's **Hashed production install** job fails if a lock no longer matches its
`.in` file, and `/health` reports `dependencies_locked: true` only when the
running process has exactly the lock's versions. Dependabot (the `uv`
ecosystem) regenerates the locks itself on its update PRs.

### Environment Variables

The full annotated list lives in
[`backend/.env.example`](backend/.env.example). The short version:

```env
# Required
ANTHROPIC_API_KEY=your_anthropic_api_key
THREATSCAN_API_URL=https://threatscan-production.up.railway.app/api

# The operator key: sees and changes every case. Without it, nobody can reach
# another visitor's cases or the pre-ownership ones. Comma-separate several
# values to rotate keys. See "Authentication" above.
SOCTRIAGE_API_KEYS=generate_one_with_secrets.token_urlsafe

# Recommended: CORS allowlist origin
FRONTEND_URL=http://localhost:5173

# Optional
ENV=development
PORT=8080

# Optional. PostgreSQL connection URL. When unset the backend uses a local
# SQLite file at backend/soctriage.db. Railway injects this automatically
# when a PostgreSQL service is attached.
DATABASE_URL=postgresql://user:password@host:5432/dbname

# Optional abuse controls. Each falls back to a conservative default when
# unset, and a junk or non-positive value falls back too, so a typo cannot
# disable a cap.
SOCTRIAGE_IP_RATE=10
SOCTRIAGE_IP_WINDOW_SECONDS=300
SOCTRIAGE_DAILY_TRIAGE_CAP=50
SOCTRIAGE_MAX_RAW_ALERT_CHARS=10000
SOCTRIAGE_MAX_IOC_CHARS=256
SOCTRIAGE_MAX_NOTE_CHARS=2000

# Optional, development only. Serves /docs, /redoc and /openapi.json.
# Leave unset in production. See "Web Hardening" above.
# SOCTRIAGE_ENABLE_API_DOCS=true
```

### Frontend Setup

```bash
cd SOCTriage/frontend
npm install

echo "VITE_API_URL=http://localhost:8080" > .env

# No key goes in .env: the frontend has no build-time key. To act as the
# operator, type the key into the Admin API key field at the bottom of the page.

npm run dev
```

### Running the checks

The same five things CI runs:

```bash
cd backend
pytest                                      # 241 tests
pytest --cov=. --cov-report=term-missing    # with coverage, as CI runs it
ruff check .
mypy

cd ../frontend
npm run lint
npm test                                    # 18 specs
npm run build
```

---

## Project Structure

```
SOCTriage/
├── docs/
│   └── MIGRATIONS.md              # Creating and applying schema migrations
├── .github/
│   ├── dependabot.yml             # Dependency update proposals
│   └── workflows/
│       ├── backend-tests.yml      # pytest + Codecov; migrations and tests on Postgres
│       ├── backend-quality.yml    # ruff and mypy
│       ├── frontend.yml           # eslint, vite build, vitest
│       ├── security.yml           # pip-audit, npm audit, gitleaks, CodeQL
│       └── deploy-verify.yml      # Confirms both surfaces serve the pushed commit
├── backend/
│   ├── main.py                    # FastAPI app, CORS, route registration, /health
│   ├── database.py                # SQLAlchemy engine, cases table, init_db() (migrates to head)
│   ├── alembic.ini                # Alembic config; the URL comes from database.py
│   ├── alembic/
│   │   ├── env.py                 # Reads DATABASE_URL the way the app does
│   │   └── versions/              # One file per migration, 0001 is the baseline
│   ├── models.py                  # Pydantic data models
│   ├── auth.py                    # API key gate on the three PATCH routes
│   ├── audit.py                   # Structured audit trail for every write
│   ├── limits.py                  # Per-IP rate limit, daily cap, length caps
│   ├── conftest.py                # Shared pytest fixtures, throwaway test database
│   ├── routes/
│   │   └── triage.py              # All API endpoints
│   ├── services/
│   │   ├── enrichment.py          # ThreatScan integration, IOC type detection
│   │   ├── ai_engine.py           # Claude incident report generation
│   │   └── case_manager.py        # Case persistence and timeline, via SQLAlchemy
│   ├── tests/                     # 241 tests
│   │   ├── test_ai_engine.py
│   │   ├── test_audit.py
│   │   ├── test_auth.py
│   │   ├── test_case_manager.py
│   │   ├── test_enrichment.py
│   │   ├── test_limits.py
│   │   ├── test_migrations.py
│   │   └── test_triage_routes.py
│   ├── requirements.in            # Runtime dependency ranges (edit this)
│   ├── requirements.txt           # Hashed lock compiled from requirements.in
│   ├── requirements-dev.in        # pytest, pytest-cov, ruff, mypy ranges
│   ├── requirements-dev.txt       # Hashed dev lock
│   ├── pytest.ini
│   ├── ruff.toml
│   ├── mypy.ini
│   ├── .env.example               # Annotated list of every variable
│   ├── Procfile                   # Railway start command
│   └── runtime.txt                # Python 3.11.9
└── frontend/
    ├── src/
    │   ├── App.jsx                # React UI (single file)
    │   ├── App.test.jsx           # vitest + React Testing Library, 18 specs
    │   ├── main.jsx
    │   ├── index.css
    │   └── test/setup.js
    ├── index.html                  # Gets <meta name="build-commit"> at build time
    ├── vite.config.js              # Vite + vitest config, bakes the build commit in
    ├── eslint.config.js
    └── package.json
```

---

## Roadmap

### Shipped since 1.0.0

- [x] **PostgreSQL persistence**, replacing the in-memory case store
- [x] **Alembic migrations**: the schema is versioned, applied on startup, and exercised on Postgres in CI
- [x] **Abuse controls** on the write endpoints: per-IP rate limit, daily cap on triage, length caps
- [x] **API key authentication** on the three case-mutating PATCH routes
- [x] **Audit logging** of every write
- [x] **Build identity and deploy verification**: `/health` and `index.html` report the commit they are running, and CI confirms after every push that both surfaces actually serve it
- [x] **CI beyond tests**: ruff, mypy, a frontend job (eslint, build, vitest), security scanning, and Dependabot

### Phase 2, Enterprise Foundation

- [ ] Full case management UI. The timeline renders today, but adding a note or closing a case still requires the API
- [ ] Evidence upload and attachment
- [ ] PDF export of incident reports
- [ ] Dashboard with charts

### Phase 3, Enterprise Ready

- [ ] JWT authentication and multi-analyst accounts. Today's auth is a shared API key, not per-user identity
- [ ] SIEM webhook integration
- [ ] Splunk integration
- [ ] Jira / ServiceNow ticket creation

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the environment variable
reference, how to extend each part of the backend, and the pull request
process. Security reports go through [SECURITY.md](SECURITY.md), and
[CHANGELOG.md](CHANGELOG.md) tracks what has shipped.

---

## Author

**Salah-Adin Mozeb**  
CompTIA Security+ | Network+ | A+ | Cisco CCNA  
M.S. Cybersecurity, Georgia Tech (in progress)  
GitHub: [@SalCyberAware](https://github.com/SalCyberAware)

---

## License

MIT. Free to use, modify, and distribute.

---

_Status (September 2026): the backend is database-backed, with a 241-test pytest suite at 99% line coverage plus ruff and mypy, and an 18-spec vitest suite on the frontend, all running on GitHub Actions. The write endpoints are API-key authenticated and audit-logged. The frontend auto-deploys to Vercel, and every push is checked to confirm both surfaces are actually serving the pushed commit._

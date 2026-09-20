# Contributing to SOCTriage

SOCTriage is an AI-powered SOC alert triage assistant. Paste an IOC, get enriched threat intelligence, a Claude-generated incident report with MITRE ATT&CK mapping, and a full response playbook, all backed by persistent case management.

## Prerequisites

- **Python 3.11+** (CI pins 3.11.9, see [`backend/runtime.txt`](backend/runtime.txt))
- **Node.js 20+** and **npm**, for the frontend
- **PostgreSQL 16+** *(optional locally)*. The backend falls back to SQLite if `DATABASE_URL` is unset; Railway provides Postgres in production
- An **Anthropic API key** for the AI incident-report generation
- A reachable **ThreatScan API** for IOC enrichment (the live instance is fine, or run [ThreatScan](https://github.com/SalCyberAware/ThreatScan) locally)

## Setup

```bash
git clone https://github.com/SalCyberAware/SOCTriage.git
cd SOCTriage

# Backend
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt    # runtime deps + pytest, pytest-cov, ruff, mypy

# Frontend
cd ../frontend
npm install
```

`requirements.txt` holds runtime dependencies only. Install
`requirements-dev.txt` for development: it pulls in `requirements.txt` and adds
the test and lint tooling, and it is what every CI job installs.

## Environment Variables

Copy the template and fill in your keys. [`backend/.env.example`](backend/.env.example)
is the annotated reference and always lists every variable.

```bash
cd backend
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | Claude API key for incident-report generation |
| `THREATSCAN_API_URL` | yes | Base URL of the enrichment service (e.g. `https://threatscan-production.up.railway.app/api`) |
| `SOCTRIAGE_API_KEYS` | yes, for the PATCH routes | Comma-separated list of accepted API keys for the three case-mutating routes. **Unset means those routes return 401 to everyone**, by design. See the README's [Authentication](README.md#authentication) section |
| `FRONTEND_URL` | recommended | CORS allowlist origin; set to `https://your-frontend.vercel.app` in production |
| `ENV` | optional | `development` / `production` |
| `PORT` | optional | Defaults to `8080` |
| `DATABASE_URL` | optional | PostgreSQL URL. If unset, the backend uses a local SQLite file (`backend/soctriage.db`). Railway injects this automatically when a Postgres service is attached. |
| `SOCTRIAGE_IP_RATE` | optional | Writes allowed per IP per window. Default `10` |
| `SOCTRIAGE_IP_WINDOW_SECONDS` | optional | Length of that window. Default `300` |
| `SOCTRIAGE_DAILY_TRIAGE_CAP` | optional | Global cap on `POST /api/triage` per UTC day. Default `50` |
| `SOCTRIAGE_MAX_RAW_ALERT_CHARS` | optional | Length cap on `raw_alert`. Default `10000` |
| `SOCTRIAGE_MAX_IOC_CHARS` | optional | Length cap on `ioc`. Default `256` |
| `SOCTRIAGE_MAX_NOTE_CHARS` | optional | Length cap on `analyst_notes`, `note`, `resolution`. Default `2000` |

Every `SOCTRIAGE_*` limit falls back to its default when unset, and also when
the value is junk or non-positive, so a typo cannot silently disable a cap.

For the frontend, create `frontend/.env`:

```dotenv
VITE_API_URL=http://localhost:8080

# Optional. Enables the Cases tab status buttons by sending X-API-Key.
# A browser bundle cannot hold a secret: whatever is set here is inlined at
# build time and readable in devtools. Only set it where the bundle is not
# public, and treat the value as disclosed. Empty or whitespace counts as unset.
VITE_API_KEY=the_same_value_as_SOCTRIAGE_API_KEYS
```

## Database

The backend uses **SQLAlchemy 2.x** with a single `cases` table that stores scalar fields (status, severity, timestamps) as columns and nested enrichment / report / timeline objects as JSON. Both PostgreSQL and SQLite handle this natively.

There is no Alembic migration step. `database.init_db()` calls `Base.metadata.create_all()` on application startup, which is safe to run repeatedly. Schema changes today mean editing [`backend/database.py`](backend/database.py) and dropping the local SQLite file, or running an ad-hoc `ALTER TABLE` against your Postgres. Alembic can be added once the schema starts shipping breaking changes.

## Running Locally

```bash
# Terminal 1: backend (FastAPI on :8080, auto-reload)
cd backend
uvicorn main:app --host 0.0.0.0 --port 8080 --reload

# Terminal 2: frontend (Vite dev server on :5173)
cd frontend
npm run dev
```

The backend's health check lives at <http://localhost:8080/health>. It reports
the commit the process is running, which is `unknown` locally and is not an
error.

## Running Tests and Checks

CI runs five workflows. All of them can be run locally:

```bash
# Backend tests
cd backend
pytest                                      # full suite, 230 tests
pytest --cov=. --cov-report=term-missing    # with coverage, as CI runs it

# Backend quality
ruff check .                                # config in backend/ruff.toml
mypy                                        # config in backend/mypy.ini

# Frontend
cd ../frontend
npm run lint                                # eslint
npm test                                    # vitest, 18 specs
npm run build                               # vite build
```

The backend suite is 230 tests at **99% line coverage**, reported to Codecov on
every push to `main`; the badge in the README links to the live report.

The two remaining workflows need no local equivalent. **Security** runs
pip-audit, npm audit, gitleaks and CodeQL. **Deploy verification** polls the
live backend and frontend after a push until each reports the commit that was
just pushed, which catches a deploy that silently stopped happening.

## How to Extend

The backend is organized so each kind of change has an obvious home:

| You want to add... | Touch... |
|---|---|
| A new HTTP endpoint | A handler in [`backend/routes/triage.py`](backend/routes/triage.py) (or a new file under `routes/` registered in `main.py`) |
| A new enrichment source | [`backend/services/enrichment.py`](backend/services/enrichment.py). See how it calls the ThreatScan API and shapes the result into an `EnrichmentResult` |
| A change to the AI report shape | The Pydantic models in [`backend/models.py`](backend/models.py) and the prompt + parsing in [`backend/services/ai_engine.py`](backend/services/ai_engine.py) |
| Case workflow / status transitions | [`backend/services/case_manager.py`](backend/services/case_manager.py). Opens, updates, and persists cases via SQLAlchemy sessions |
| A new persisted field on a case | A new column on `CaseRow` in [`backend/database.py`](backend/database.py); update the case-manager methods and the response models in `models.py` |
| Authentication on a route | [`backend/auth.py`](backend/auth.py), then call `_require_key(request)` as the first statement of the handler, ahead of the limiter and the case lookup |
| A new abuse control | [`backend/limits.py`](backend/limits.py). Add the check to `Limiter`, wire it through `build_limiter()`, and document the variable in `.env.example` |
| A new audited action | [`backend/audit.py`](backend/audit.py). Note that entries carry no free text and no key material, and adding a field means changing `ENTRY_FIELDS` deliberately |

Every service has a focused test file under [`backend/tests/`](backend/tests/):
`test_enrichment.py`, `test_ai_engine.py`, `test_case_manager.py`,
`test_triage_routes.py`, `test_limits.py`, `test_auth.py`, `test_audit.py`.
When adding a new service or route, add a matching `test_<thing>.py`. The suite
has tight coverage today and the bar is to keep it there.

Shared fixtures live in [`backend/conftest.py`](backend/conftest.py), including
the throwaway SQLite database every test runs against, a `client` fixture that
presents a valid API key, and an `anon_client` fixture that presents none.

## Commit Conventions

This repo uses [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`.

Types in active use:

- `feat`: new feature
- `fix`: bug fix
- `test`: adding or updating tests
- `docs`: documentation only
- `refactor`: non-behavioral code change
- `ci`: CI / build pipeline change
- `chore`: tooling, dependencies, housekeeping

Recent examples from `git log`:

```
feat(frontend): replace the Cases status buttons with a note when unkeyed
feat(audit): record every write as a structured audit log line
feat(auth): require an API key on the three case-mutating PATCH routes
ci: add Dependabot dependency update proposals (Tier 2)
feat(limits): add abuse controls to the four write endpoints
```

## Pull Request Process

1. Fork or branch from `main`.
2. Make focused commits using the convention above.
3. Run the checks under [Running Tests and Checks](#running-tests-and-checks). Add tests for any new behavior.
4. Push and open a pull request against `main`.
5. The **Backend tests**, **Backend quality**, **Frontend** and **Security** workflows must be green before merge. **Deploy verification** runs on pushes to `main` rather than on pull requests.

For larger or design-level changes (new services, schema changes, auth, etc.) please open an issue first to discuss the approach.

## License

By contributing you agree your changes are licensed under the project's [MIT License](LICENSE).

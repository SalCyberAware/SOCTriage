# Contributing to SOCTriage

SOCTriage is an AI-powered SOC alert triage assistant — paste an IOC, get enriched threat intelligence, a Claude-generated incident report with MITRE ATT&CK mapping, and a full response playbook, all backed by persistent case management.

## Prerequisites

- **Python 3.11+** (CI pins 3.11.9 — see [`backend/runtime.txt`](backend/runtime.txt))
- **Node.js 20+** and **npm** (for the frontend)
- **PostgreSQL 16+** *(optional locally)* — the backend falls back to SQLite if `DATABASE_URL` is unset; Railway provides Postgres in production
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
pip install -r requirements-dev.txt    # installs runtime + test deps

# Frontend
cd ../frontend
npm install
```

## Environment Variables

Copy the template and fill in your keys:

```bash
cd backend
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | Claude API key for incident-report generation |
| `THREATSCAN_API_URL` | yes | Base URL of the enrichment service (e.g. `https://threatscan-production.up.railway.app/api`) |
| `FRONTEND_URL` | recommended | CORS allowlist origin; set to `https://your-frontend.vercel.app` in production |
| `ENV` | optional | `development` / `production` |
| `PORT` | optional | Defaults to `8080` |
| `DATABASE_URL` | optional | PostgreSQL URL. If unset, the backend uses a local SQLite file (`backend/soctriage.db`). Railway injects this automatically when a Postgres service is attached. |

For the frontend, create `frontend/.env` if the backend isn't on the default URL:

```dotenv
VITE_API_URL=http://localhost:8080
```

## Database

The backend uses **SQLAlchemy 2.x** with a single `cases` table that stores scalar fields (status, severity, timestamps) as columns and nested enrichment / report / timeline objects as JSON — both PostgreSQL and SQLite handle this natively.

There's no Alembic migration step — `database.init_db()` calls `Base.metadata.create_all()` on application startup, which is safe to run repeatedly. Schema changes today mean editing [`backend/database.py`](backend/database.py) and dropping the local SQLite file (or running an ad-hoc `ALTER TABLE` against your Postgres). Alembic can be added once the schema starts shipping breaking changes.

## Running Locally

```bash
# Terminal 1 — backend (FastAPI on :8080, auto-reload)
cd backend
uvicorn main:app --host 0.0.0.0 --port 8080 --reload

# Terminal 2 — frontend (Vite dev server on :5173)
cd frontend
npm run dev
```

The backend's health check lives at <http://localhost:8080/health>.

## Running Tests

```bash
cd backend
pytest                                              # full suite (71 tests as of 1.0.0)
pytest --cov=. --cov-report=term-missing            # what CI runs
```

CI reports coverage to Codecov on every push to `main`; the badge in the README links to the live report. Coverage at the time of 1.0.0 is **99.4%**.

## How to Extend

The backend is organized so each kind of change has an obvious home:

| You want to add… | Touch… |
|---|---|
| A new HTTP endpoint | A handler in [`backend/routes/triage.py`](backend/routes/triage.py) (or a new file under `routes/` registered in `main.py`) |
| A new enrichment source | [`backend/services/enrichment.py`](backend/services/enrichment.py) — see how it calls the ThreatScan API and shapes the result into an `EnrichmentResult` |
| A change to the AI report shape | The Pydantic models in [`backend/models.py`](backend/models.py) and the prompt + parsing in [`backend/services/ai_engine.py`](backend/services/ai_engine.py) |
| Case workflow / status transitions | [`backend/services/case_manager.py`](backend/services/case_manager.py) — opens, updates, and persists cases via SQLAlchemy sessions |
| A new persisted field on a case | A new column on `CaseRow` in [`backend/database.py`](backend/database.py); update the case-manager methods and the response models in `models.py` |

Every service has a focused test file under [`backend/tests/`](backend/tests/). When adding a new service or route, add a matching `test_<thing>.py` — the suite has tight coverage today (99%+) and the bar is to keep it there.

## Commit Conventions

This repo uses [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`.

Types in active use:

- `feat` — new feature
- `fix` — bug fix
- `test` — adding or updating tests
- `docs` — documentation only
- `refactor` — non-behavioral code change
- `ci` — CI / build pipeline change
- `chore` — tooling, dependencies, housekeeping

Recent examples from `git log`:

```
ci: add coverage tracking via pytest-cov and upload to Codecov
test(backend): cover POST /api/triage end-to-end
test(backend): add tests for AI engine service
ci: add GitHub Actions workflow for backend tests
```

## Pull Request Process

1. Fork or branch from `main`.
2. Make focused commits using the convention above.
3. `cd backend && pytest` — make sure the suite stays green; add tests for any new behavior.
4. Push and open a pull request against `main`.
5. The **Backend tests** workflow must be green before merge.

For larger or design-level changes (new services, schema changes, auth, etc.) please open an issue first to discuss the approach.

## License

By contributing you agree your changes are licensed under the project's [MIT License](LICENSE).

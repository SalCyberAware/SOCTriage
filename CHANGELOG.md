# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Abuse controls on the four write endpoints** (`backend/limits.py`) — a per-IP rate limit (default 10 writes / 5 minutes, shared across `POST /api/triage` and the three `PATCH` routes) returning `429` with a `Retry-After` header; a global daily cap on `POST /api/triage` (default 50 per UTC day) returning `503`; and length caps on every free-text input (`raw_alert` 10,000 chars, `ioc` 256, `analyst_notes` / `note` / `resolution` 2,000) returning `400`. Every check runs before the ThreatScan enrichment and the Anthropic call, so a rejected request spends no quota and opens no case. All six limits are configurable via `SOCTRIAGE_*` environment variables, and a junk or non-positive value falls back to the default rather than disabling the cap. The reads (`GET /api/cases`, `/api/cases/{id}`, `/api/dashboard`) and `/health` are deliberately left open: they cost nothing per call.

### Security

- The daily cap covers `POST /api/triage` alone because it is the only endpoint with money attached — one Anthropic completion plus one ThreatScan scan, which itself fans out to 11 engines behind their own free-tier quotas. Limiter state is in-memory and single-instance: it resets when the process restarts, making the daily cap a soft backstop rather than an accounting guarantee. A shared store such as Redis is the multi-instance upgrade.

## [1.0.0] - 2026-05-27

Initial public release.

### Added

- **AI-powered incident reports** — `POST /api/triage` enriches an IOC, generates a structured incident report via the Anthropic Claude API, and opens a case in one round-trip. The report includes a title, severity, threat-type classification, executive summary, affected assets, MITRE ATT&CK techniques with attack.mitre.org URLs, recommended actions, and a step-by-step containment / investigation / eradication / recovery playbook.
- **IOC enrichment via ThreatScan** — IPs, domains, URLs, and file hashes are submitted to the [ThreatScan](https://github.com/SalCyberAware/ThreatScan) backend, which queries 11 threat intelligence engines (VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, GreyNoise, MalwareBazaar, URLhaus, ThreatFox, Google Safe Browsing, IPInfo, WHOIS / DNS) and returns a weighted verdict and 0–100 threat score.
- **MITRE ATT&CK mapping** — every report includes the relevant ATT&CK techniques with technique ID, name, tactic, and a direct link to attack.mitre.org.
- **Severity scoring** — `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`, derived from the AI report and normalized from common LLM-output variations; an explicit `severity_override` on intake takes precedence when supplied.
- **Case management API** — cases are opened automatically on every triage; `GET /api/cases` lists them, `GET /api/cases/{id}` returns a single case with its full timeline, `PATCH /api/cases/{id}/status` transitions status (`OPEN` → `IN_PROGRESS` → `ESCALATED` → `CLOSED`), `PATCH /api/cases/{id}/note` appends an analyst note, and `PATCH /api/cases/{id}/close` closes a case with a resolution.
- **Persistent storage** — cases are persisted via **SQLAlchemy 2.x** to PostgreSQL in production (Railway's `DATABASE_URL` is auto-detected; the legacy `postgres://` scheme is rewritten to `postgresql://` so SQLAlchemy 2.x accepts it) and to a local SQLite file (`backend/soctriage.db`) when `DATABASE_URL` is unset. Scalar fields are real columns; nested enrichment / report / timeline objects are stored as JSON.
- **Dashboard** — `GET /api/dashboard` returns aggregate stats by case status and severity for the frontend's live dashboard.
- **Health endpoint** — `GET /health` returns service status, name, and version for uptime monitoring.
- **CORS lockdown** — the production allowlist is driven by `FRONTEND_URL`; only that origin is allowed when set, with credentials enabled and the full method/header set permitted.
- **Pydantic v2 models** — strict typing for `AlertIntake`, `EnrichmentResult`, `IncidentReport`, `MITRETechnique`, `Case`, `Severity`, and `CaseStatus`.
- **71-test pytest suite** covering the enrichment service (ThreatScan integration, all error paths via parametrized status codes), the AI engine (JSON parsing, severity normalization, prompt construction), the case manager (open / list / get / update / close / note + persistence round-trips), and the triage routes end-to-end.
- **99.4% line coverage** reported by pytest-cov and uploaded to Codecov on every push.
- **GitHub Actions CI** — the `Backend tests` workflow runs pytest with coverage on Python 3.11.9, uploads `coverage.xml` to Codecov, and gates pull requests on `main`.
- **React + Vite frontend** deployed to **Vercel**; **FastAPI backend** deployed to **Railway** with a Procfile.

### Security

- Anthropic and ThreatScan API keys are server-side only; the frontend never sees them.
- CORS allowlist is strict in production (`FRONTEND_URL` is required to permit anything other than `*`).
- No logging of user input beyond what's persisted as part of a case; no analytics.

[Unreleased]: https://github.com/SalCyberAware/SOCTriage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SalCyberAware/SOCTriage/releases/tag/v1.0.0

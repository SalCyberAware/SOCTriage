# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **API key authentication on the three case-mutating routes** (`backend/auth.py`). `PATCH /api/cases/{id}/status`, `/note` and `/close` now require a key in the `X-API-Key` header, matched against the comma-separated `SOCTRIAGE_API_KEYS`. Several values are accepted so a key can be rotated without a window where none works. `POST /api/triage`, the three reads and `/health` stay open. Keys are compared with `hmac.compare_digest` rather than `==`, and the loop over configured keys does not short-circuit on a match, so neither the value nor which key matched leaks through response timing. The check runs before the case lookup, so an unauthenticated caller gets an identical 401 for a case id that exists and one that does not, and before the rate limiter, so a refused request cannot spend a legitimate client's allowance.

- **Audit logging of every write** (`backend/audit.py`). All four write endpoints, including the unauthenticated `POST /api/triage`, emit one JSON object per line on stdout after the write succeeds: timestamp, endpoint template, case id, the client IP as resolved behind the proxy, and whether the caller presented a valid API key. Entries are written only when something changed, so a 401, a 429, a 404 and every read record nothing. No key material and no free text is ever recorded: not `raw_alert`, analyst notes, note bodies or resolution text. That is structural, since `audit.build_entry` has no parameter such a string could arrive through. Application logs rather than a database table, because the case timeline already persists what changed, and the client IP the trail adds must not go into a table served by an open endpoint.

- **Build identity and post-deploy verification.** `GET /health` reports the commit the backend process is running (from Railway's `RAILWAY_GIT_COMMIT_SHA`, with `GIT_COMMIT_SHA` as a platform-neutral override), and the frontend bakes its commit into `<meta name="build-commit">` in `index.html` at build time via a Vite plugin. A `Deploy verification` workflow then polls both live surfaces after every push to `main` until each reports the commit that was just pushed. This catches the failure mode where CI is green, the repo is clean, the site returns 200, and the deployed build is months old, which is exactly what a September 2026 audit found.

- **Security scanning in CI.** A `Security` workflow runs pip-audit over the backend requirements, npm audit over the frontend production tree, gitleaks over the full git history, and CodeQL. It runs on push and pull request, and also weekly on a schedule, because a CVE disclosed against a dependency that has not changed in months would otherwise never surface.

- **Dependabot** (`.github/dependabot.yml`) proposes dependency updates weekly for pip and npm, and monthly for GitHub Actions.

- **Abuse controls on the four write endpoints** (`backend/limits.py`): a per-IP rate limit (default 10 writes / 5 minutes, shared across `POST /api/triage` and the three `PATCH` routes) returning `429` with a `Retry-After` header; a global daily cap on `POST /api/triage` (default 50 per UTC day) returning `503`; and length caps on every free-text input (`raw_alert` 10,000 chars, `ioc` 256, `analyst_notes` / `note` / `resolution` 2,000) returning `400`. Every check runs before the ThreatScan enrichment and the Anthropic call, so a rejected request spends no quota and opens no case. All six limits are configurable via `SOCTRIAGE_*` environment variables, and a junk or non-positive value falls back to the default rather than disabling the cap. The reads (`GET /api/cases`, `/api/cases/{id}`, `/api/dashboard`) and `/health` are deliberately left open: they cost nothing per call.

- **Lint and type checking in CI.** A `Backend quality` workflow runs **ruff** (`backend/ruff.toml`: line-length 120, target py311, the E/F/I/N/W/UP rule set, matching PromptShield) and **mypy** (`backend/mypy.ini`) over the backend on every push and pull request. This closes the gap the September 2026 fastapi bump exposed: that upgrade had to be validated by hand-diffing the old and new stacks, because nothing in CI would have caught a renamed symbol or a changed signature.

- **Frontend CI.** A `Frontend` workflow runs eslint, the vite build, and vitest. eslint was already wired into `package.json` but nothing ever ran it, so two `react-hooks/set-state-in-effect` errors sat in `src/App.jsx` unnoticed.

- **Frontend test suite.** vitest + React Testing Library (`frontend/src/App.test.jsx`, 18 specs) covering IOC-type derivation, the analyst's explicit type override reaching the request body, the Cases list load path, and the API key gate on the Cases tab. The frontend previously had no tests at all.

### Changed

- **The Cases tab shows a note instead of status buttons when no API key is configured.** The hosted demo ships no key, because a browser bundle cannot hold a secret: whatever `VITE_API_KEY` is set to is inlined at build time and readable in devtools. Rather than offering a status button that could only ever return 401, the expanded case now shows one line saying a key is required, linking to the README's Authentication section. The rest of the tab is untouched: the case list, the AI summary, the MITRE techniques and the timeline all render as before. Setting `VITE_API_KEY` restores the buttons and sends the key in `X-API-Key`; empty or whitespace counts as unset.

- **fastapi 0.115.0 to 0.141.1 and python-dotenv 1.0.1 to 1.2.2**, pulling starlette 0.38.6 to 1.6.0. Validated by hand-diffing the old and new stacks at the time, which is what prompted the `Backend quality` workflow above.

### Fixed

- **`POST /api/triage` returned 500 when `ioc_type` was omitted.** `AlertIntake.ioc_type` is optional, but `enrich_ioc` passed the intake's `None` straight into `EnrichmentResult.ioc_type`, which is a required string. The resulting `ValidationError` was raised again by the `except` branch meant to swallow it, so both the success and the failure path failed. The type is now detected from the indicator in `services/enrichment.py` (`detect_ioc_type`, mirroring `detectType` in the frontend) when the analyst does not supply one. Found by mypy on its first run, not by the test suite; covered now by 13 new tests.
- **The frontend assumed uppercase enum names while the API returns lowercase enum values.** Every status change sent `"IN_PROGRESS"`, was rejected as a 422 and silently discarded, so case status could not be changed from the UI at all; severity and status badges fell back to gray for the same reason. The UI now sends and keys on the enum values, checks `resp.ok` and surfaces a failure in an error banner instead of refreshing with unchanged data, reads the report IOC from `result.enrichment.ioc` (`TriageResponse` has no top-level `ioc`), renders the playbook as one item per step instead of one concatenated blob, and replaces the hardcoded "online" text with a health indicator that polls `GET /health`.
- **`services/ai_engine.py` assumed the first content block from Claude is a text block.** The SDK types it as a union, so a non-text block would have raised an `AttributeError` deep in the JSON parse. It now fails with a clear message naming the block type.
- **Two `react-hooks/set-state-in-effect` errors in `src/App.jsx`**, fixed rather than suppressed. The IOC type is now derived during render with an explicit analyst pick taking precedence, instead of being written by a `useEffect` keyed on `[ioc]`; the Cases list loads through a cancellable promise instead of calling a state-setting function synchronously in an effect body. Neither was a live user-visible bug, since the new vitest specs pass against the old code too, but both were the structure that produced ThreatScan's dropped-file bug, one feature away: an effect keyed on `[ioc]` cannot tell an analyst's keystroke from a programmatic write, so the first example chip or rescan button would have had its type silently reverted.

### Security

- **The write gate fails closed.** With `SOCTRIAGE_API_KEYS` unset, the three PATCH routes return 401 to everyone rather than falling back to accepting unauthenticated writes. An auth check that disappears along with its configuration is not a control, because the case it has to survive is a missing variable: a service moved between projects, a variable dropped in a redeploy, a misspelled name. Fail-open turns each of those into a silently world-writable API that still returns 200 and still looks healthy. The 401 body distinguishes an unconfigured deployment from a wrong key, which is not exploitable and saves a self-hoster from debugging a key that was never going to work.
- The audit trail records a client IP, which is personal data. It goes to application logs, where the platform's retention applies, and deliberately not into the `cases` table, whose timeline is served verbatim by an open endpoint.
- The daily cap covers `POST /api/triage` alone because it is the only endpoint with money attached: one Anthropic completion plus one ThreatScan scan, which itself fans out to 11 engines behind their own free-tier quotas. Limiter state is in-memory and single-instance: it resets when the process restarts, making the daily cap a soft backstop rather than an accounting guarantee. A shared store such as Redis is the multi-instance upgrade.

## [1.0.0] - 2026-05-27

Initial public release.

### Added

- **AI-powered incident reports.** `POST /api/triage` enriches an IOC, generates a structured incident report via the Anthropic Claude API, and opens a case in one round-trip. The report includes a title, severity, threat-type classification, executive summary, affected assets, MITRE ATT&CK techniques with attack.mitre.org URLs, recommended actions, and a step-by-step containment / investigation / eradication / recovery playbook.
- **IOC enrichment via ThreatScan.** IPs, domains, URLs, and file hashes are submitted to the [ThreatScan](https://github.com/SalCyberAware/ThreatScan) backend, which queries 11 threat intelligence engines (VirusTotal, AbuseIPDB, URLScan.io, AlienVault OTX, GreyNoise, MalwareBazaar, URLhaus, ThreatFox, Google Safe Browsing, IPInfo, WHOIS / DNS) and returns a weighted verdict and 0 to 100 threat score.
- **MITRE ATT&CK mapping.** Every report includes the relevant ATT&CK techniques with technique ID, name, tactic, and a direct link to attack.mitre.org.
- **Severity scoring.** `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`, derived from the AI report and normalized from common LLM-output variations; an explicit `severity_override` on intake takes precedence when supplied.
- **Case management API.** Cases are opened automatically on every triage; `GET /api/cases` lists them, `GET /api/cases/{id}` returns a single case with its full timeline, `PATCH /api/cases/{id}/status` transitions status (`OPEN`, `IN_PROGRESS`, `ESCALATED`, `CLOSED`), `PATCH /api/cases/{id}/note` appends an analyst note, and `PATCH /api/cases/{id}/close` closes a case with a resolution.
- **Persistent storage.** Cases are persisted via **SQLAlchemy 2.x** to PostgreSQL in production (Railway's `DATABASE_URL` is auto-detected; the legacy `postgres://` scheme is rewritten to `postgresql://` so SQLAlchemy 2.x accepts it) and to a local SQLite file (`backend/soctriage.db`) when `DATABASE_URL` is unset. Scalar fields are real columns; nested enrichment / report / timeline objects are stored as JSON.
- **Dashboard.** `GET /api/dashboard` returns aggregate stats by case status and severity for the frontend's live dashboard.
- **Health endpoint.** `GET /health` returns service status, name, and version for uptime monitoring.
- **CORS lockdown.** The production allowlist is driven by `FRONTEND_URL`; only that origin is allowed when set, with credentials enabled and the full method/header set permitted.
- **Pydantic v2 models.** Strict typing for `AlertIntake`, `EnrichmentResult`, `IncidentReport`, `MITRETechnique`, `Case`, `Severity`, and `CaseStatus`.
- **71-test pytest suite** covering the enrichment service (ThreatScan integration, all error paths via parametrized status codes), the AI engine (JSON parsing, severity normalization, prompt construction), the case manager (open / list / get / update / close / note + persistence round-trips), and the triage routes end-to-end.
- **99.4% line coverage** reported by pytest-cov and uploaded to Codecov on every push.
- **GitHub Actions CI.** The `Backend tests` workflow runs pytest with coverage on Python 3.11.9, uploads `coverage.xml` to Codecov, and gates pull requests on `main`.
- **React + Vite frontend** deployed to **Vercel**; **FastAPI backend** deployed to **Railway** with a Procfile.

### Security

- Anthropic and ThreatScan API keys are server-side only; the frontend never sees them.
- CORS allowlist is strict in production (`FRONTEND_URL` is required to permit anything other than `*`).
- No logging of user input beyond what is persisted as part of a case; no analytics.

[Unreleased]: https://github.com/SalCyberAware/SOCTriage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SalCyberAware/SOCTriage/releases/tag/v1.0.0

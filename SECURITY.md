# Security Policy

SOCTriage is a portfolio / personal project, not a hardened commercial product. That said, security issues are taken seriously and fixed when reported. Because SOCTriage runs a real database and calls an LLM with user-controlled input, this policy specifically calls out injection and prompt-related issues.

## Supported Versions

Only the `main` branch receives security fixes. There are no maintenance branches for older releases.

| Version | Supported |
|---------|-----------|
| `main`  | ✅        |
| Tagged releases prior to `main` | ❌ |

## Reporting a Vulnerability

Please report security issues privately via **[GitHub Security Advisories](https://github.com/SalCyberAware/SOCTriage/security/advisories/new)** — do not open a public issue, and do not include exploit details in a PR description.

When reporting, please include:

- A clear description of the issue and its impact
- Reproduction steps or a minimal proof of concept
- Affected commit SHA or branch
- Any relevant logs, request/response samples, or screenshots

## Response Timeline

This is a single-maintainer project, so response times are best-effort, not contractual:

- **Initial acknowledgement:** within 5 business days
- **Triage and severity assessment:** within 10 business days of acknowledgement
- **Fix and disclosure:** depends on severity; you'll be kept in the loop

If you don't hear back within 5 business days, please ping the advisory thread.

## In Scope

Issues that meaningfully affect the security of the backend, frontend, or persisted data:

- **Authentication or authorization bypass** on any current or future protected endpoint
- **Remote code execution** in the FastAPI backend
- **SQL injection** — relevant because cases are persisted via SQLAlchemy; raw-SQL bypasses or unsafe `text()` usage are in scope
- **Cross-site scripting (XSS)** in the React frontend, particularly in rendered alert content or AI-generated report fields
- **Cross-site request forgery (CSRF)** against state-changing endpoints (`POST /api/triage`, the `PATCH /api/cases/*` family)
- **Server-side request forgery (SSRF)** — particularly via the enrichment service's outbound calls
- **Information disclosure** of API keys, environment variables, internal paths, or other cases' data through the API
- **Prompt injection that exfiltrates secrets** or causes the AI engine to leak environment data into responses (prompt injection that merely influences report wording is *not* a security issue — see Out of Scope)
- **CORS misconfiguration** that bypasses the production allowlist
- **Insecure deserialization** of JSON payloads stored on `CaseRow`
- **Dependency vulnerabilities** with a working exploit against this repo

## Out of Scope

These are known limitations of a portfolio project running on free hosting tiers:

- **Rate-limit bypass on the public demo** — the demo runs on shared infrastructure with modest limits; bypass techniques are not a security finding
- **API-key DoS** (burning through the Anthropic or ThreatScan quota on the public demo) — expected behavior, not a vulnerability
- **Prompt injection that only changes the wording of an AI-generated report** without exfiltrating data or escalating privileges — interesting, but not a vulnerability against this project
- **Brute force or DoS against the live demo's hosting tier**
- **Missing security headers on third-party assets** outside this project's control
- **Self-XSS** that requires the victim to paste attacker-supplied content into their own dev console
- **Outdated browser compatibility** — only modern evergreen browsers are supported
- **Reports from automated scanners** with no manual validation or proof of exploitability

## Safe Harbor

Good-faith security research that follows this policy will not be pursued legally. Specifically: testing against a local clone of the repo is always fine; testing against the public demo at [soctriage.vercel.app](https://soctriage.vercel.app) is fine if you avoid disrupting other users, don't attempt to access cases that aren't yours, and avoid burning through the demo's Anthropic / ThreatScan quota.

## Disclosure

Once a fix is merged, the advisory will be published with credit to the reporter (unless anonymity is requested).

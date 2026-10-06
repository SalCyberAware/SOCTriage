import os
from contextlib import asynccontextmanager
from typing import TypedDict

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# Imported after load_dotenv() on purpose: database.py resolves DATABASE_URL at
# import time, so the .env file has to be loaded before it is imported.
from database import init_db  # noqa: E402
from routes.triage import router as triage_router  # noqa: E402
from security_headers import SecurityHeadersMiddleware  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Migrate the database to the newest schema, then hand off to the app.
    init_db()
    yield


# The interactive docs (/docs, /redoc) and the schema behind them
# (/openapi.json) are OFF unless this is set to an explicit true value. They
# hand anyone a complete map of every route, parameter and header, which is
# useful on a laptop and nothing but reconnaissance on a public deployment.
# A dedicated flag rather than ENV=development, so that a production service
# carrying a stale ENV value cannot switch them on by accident.
API_DOCS_FLAG = "SOCTRIAGE_ENABLE_API_DOCS"


def api_docs_enabled() -> bool:
    """Whether the docs flag is set to an explicit true value."""
    return os.getenv(API_DOCS_FLAG, "").strip().lower() in ("1", "true", "yes")


class DocsUrls(TypedDict):
    docs_url: str | None
    redoc_url: str | None
    openapi_url: str | None


def api_docs_urls() -> DocsUrls:
    """FastAPI's docs settings: its defaults when enabled, all None when not."""
    if api_docs_enabled():
        return DocsUrls(docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
    return DocsUrls(docs_url=None, redoc_url=None, openapi_url=None)


app = FastAPI(
    title="SOC Triage Assistant API",
    description="AI-powered SOC alert triage: enrichment, MITRE mapping, incident reports, case management",
    version="1.0.0",
    lifespan=lifespan,
    **api_docs_urls(),
)

# CORS is FAIL CLOSED, for the same reason auth.py is: an allowlist that turns
# into "*" when its variable goes missing is not an allowlist. With FRONTEND_URL
# unset, no cross-origin request is allowed; same-origin and non-browser
# clients are unaffected. Methods and headers are exactly what
# frontend/src/App.jsx sends, and nothing in the app uses cookies, so
# credentials stay off.
CORS_ALLOW_METHODS = ["GET", "POST", "PATCH"]
CORS_ALLOW_HEADERS = ["Content-Type", "X-API-Key", "X-Session-Token"]


def cors_allowed_origins() -> list[str]:
    """The cross-origin allowlist: FRONTEND_URL, or nothing when it is unset."""
    origin = os.getenv("FRONTEND_URL", "").strip()
    return [origin] if origin else []


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins(),
    allow_credentials=False,
    allow_methods=CORS_ALLOW_METHODS,
    allow_headers=CORS_ALLOW_HEADERS,
)

# Added after CORS, so it is the outer layer and also stamps the preflight
# answers CORSMiddleware produces on its own. frontend/vercel.json sends the
# same four on the static site.
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(triage_router)


def _build_commit() -> str:
    """The git commit this process is actually running.

    Railway sets ``RAILWAY_GIT_COMMIT_SHA`` on every deployment that originates
    from a GitHub push, and exposes it to the running container as well as the
    build. ``GIT_COMMIT_SHA`` is a platform-neutral override for anywhere that
    is not Railway. Neither is set during local development, which is what
    ``"unknown"`` means; it is not an error condition.

    Read per request rather than captured at import so that tests can vary it.
    The value is fixed for the lifetime of a deployed process either way.
    """
    return (
        os.getenv("RAILWAY_GIT_COMMIT_SHA")
        or os.getenv("GIT_COMMIT_SHA")
        or "unknown"
    )


@app.get("/health")
def health():
    return {
        "status":  "ok",
        "service": "SOC Triage Assistant",
        "version": "1.0.0",
        # Build identity: "1.0.0" is a literal and cannot tell today's build
        # from April's. This can. See PromptShield docs/AUTOMATION_PLAN.md.
        "commit":  _build_commit(),
    }

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# Imported after load_dotenv() on purpose: database.py resolves DATABASE_URL at
# import time, so the .env file has to be loaded before it is imported.
from database import init_db  # noqa: E402
from routes.triage import router as triage_router  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Migrate the database to the newest schema, then hand off to the app.
    init_db()
    yield


app = FastAPI(
    title="SOC Triage Assistant API",
    description="AI-powered SOC alert triage — enrichment, MITRE mapping, incident reports, case management",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS is FAIL CLOSED, for the same reason auth.py is: an allowlist that turns
# into "*" when its variable goes missing is not an allowlist. With FRONTEND_URL
# unset, no cross-origin request is allowed; same-origin and non-browser
# clients are unaffected. Methods and headers are exactly what
# frontend/src/App.jsx sends, and nothing in the app uses cookies, so
# credentials stay off.
CORS_ALLOW_METHODS = ["GET", "POST", "PATCH"]
CORS_ALLOW_HEADERS = ["Content-Type", "X-API-Key"]


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

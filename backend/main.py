from contextlib import asynccontextmanager
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from database import init_db
from routes.triage import router as triage_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create database tables if they do not yet exist, then hand off to the app.
    init_db()
    yield


app = FastAPI(
    title="SOC Triage Assistant API",
    description="AI-powered SOC alert triage — enrichment, MITRE mapping, incident reports, case management",
    version="1.0.0",
    lifespan=lifespan,
)

FRONTEND_URL = os.getenv("FRONTEND_URL", "*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

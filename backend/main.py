from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from routes.triage import router as triage_router

app = FastAPI(
    title="SOC Triage Assistant API",
    description="AI-powered SOC alert triage — enrichment, MITRE mapping, incident reports, case management",
    version="1.0.0"
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

@app.get("/health")
def health():
    return {
        "status":  "ok",
        "service": "SOC Triage Assistant",
        "version": "1.0.0"
    }


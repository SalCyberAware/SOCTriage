from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SOC Triage Assistant API",
    description="AI-powered SOC alert triage — enrichment, MITRE mapping, incident reports",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Will lock to Vercel URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok", "service": "SOC Triage Assistant"}

# SOCTriage

**AI-powered SOC alert triage assistant — free, open-source alternative to enterprise SOAR platforms.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-soctriage.vercel.app-00d4aa?style=flat-square)](https://soctriage.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Railway-6366f1?style=flat-square)](https://soctriage-production.up.railway.app/health)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11-3b82f6?style=flat-square)](https://python.org)

---

## What It Does

SOCTriage automates the first 30 minutes of SOC alert triage. Paste an IP, domain, URL, or file hash — SOCTriage enriches it across **11 threat intelligence engines** simultaneously and generates a full **AI-powered incident report** with MITRE ATT&CK mapping, severity scoring, recommended actions, and a step-by-step response playbook.

Enterprise SOAR platforms (Splunk SOAR, Palo Alto XSOAR) cost **$100,000+ per year**. SOCTriage is free.

<div align="center">

![SOCTriage Incident Report](soctriage-report.png)

![MITRE Techniques and Engine Verdicts](soctriage-techniques.png)

</div>

---

## Live Demo

**Frontend:** https://soctriage.vercel.app  
**Backend Health:** https://soctriage-production.up.railway.app/health

---

## Features

- **IOC Enrichment** — Queries 11 threat intelligence engines via [ThreatScan](https://github.com/SalCyberAware/ThreatScan) and returns aggregated verdicts and threat scores
- **AI Incident Reports** — Claude AI generates executive summaries, threat classifications, affected asset identification, and recommended actions
- **MITRE ATT&CK Mapping** — Every IOC is automatically mapped to relevant ATT&CK techniques and tactics with direct links to attack.mitre.org
- **Severity Scoring** — LOW / MEDIUM / HIGH / CRITICAL based on weighted engine results (0–100 scale)
- **Response Playbook** — Step-by-step containment, investigation, eradication, and recovery guidance tailored to the specific threat
- **Case Management** — Cases are opened automatically with full timeline logging; status can be updated (OPEN → IN_PROGRESS → ESCALATED → CLOSED)
- **Dashboard** — Live stats by case status and severity

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React + Vite → Vercel |
| Backend | Python FastAPI → Railway |
| AI Engine | Anthropic Claude API |
| Enrichment | ThreatScan API (11 engines) |
| Data Models | Pydantic v2 |

---

## Threat Intelligence Engines

SOCTriage enriches IOCs through ThreatScan, which queries:

1. VirusTotal
2. AbuseIPDB
3. URLScan.io
4. AlienVault OTX
5. GreyNoise
6. MalwareBazaar
7. URLhaus (abuse.ch)
8. ThreatFox
9. Google Safe Browsing
10. IPInfo
11. WHOIS / DNS

---

## API Endpoints

```
POST   /api/triage              Submit IOC for enrichment + AI report + case creation
GET    /api/cases               List all cases
GET    /api/cases/{id}          Get single case with full timeline
PATCH  /api/cases/{id}/status   Update case status
PATCH  /api/cases/{id}/note     Add analyst note
PATCH  /api/cases/{id}/close    Close case with resolution
GET    /api/dashboard           Stats by status and severity
GET    /health                  Health check
```

### Example Request

```bash
curl -X POST https://soctriage-production.up.railway.app/api/triage \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": "185.220.101.45",
    "ioc_type": "ip",
    "raw_alert": "CrowdStrike: suspicious outbound connection from WS-042 at 2:00 AM",
    "analyst_notes": "User reported no activity at that time"
  }'
```

### Example Response

```json
{
  "case_id": "4FA22FE3",
  "status": "success",
  "report": {
    "title": "Suspicious Outbound C2 Connection from WS-042 to Malicious IP 185.220.101.45",
    "severity": "high",
    "threat_type": "C2 (Command and Control)",
    "summary": "Workstation WS-042 initiated a suspicious outbound connection...",
    "mitre_techniques": [
      {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/001/"
      }
    ],
    "recommended_actions": [
      "Immediately isolate WS-042 from the network",
      "Block 185.220.101.45 at perimeter firewall",
      "Conduct full forensic image of WS-042"
    ],
    "playbook": [
      "STEP 1 - CONTAINMENT: Isolate WS-042 immediately via NAC or VLAN quarantine...",
      "STEP 2 - IDENTIFICATION: Pull CrowdStrike process tree and network telemetry..."
    ]
  },
  "enrichment": {
    "verdict": "malicious",
    "score": 83
  }
}
```

---

## Self-Hosting

### Prerequisites

- Python 3.11+
- Anthropic API key (console.anthropic.com)
- ThreatScan running locally or use the live instance

### Backend Setup

```bash
git clone https://github.com/SalCyberAware/SOCTriage.git
cd SOCTriage/backend
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your API keys

uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

### Environment Variables

```env
ANTHROPIC_API_KEY=your_anthropic_api_key
THREATSCAN_API_URL=https://threatscan-production.up.railway.app/api
FRONTEND_URL=http://localhost:5173
ENV=development
PORT=8080
```

### Frontend Setup

```bash
cd SOCTriage/frontend
npm install

echo "VITE_API_URL=http://localhost:8080" > .env

npm run dev
```

---

## Project Structure

```
SOCTriage/
├── backend/
│   ├── main.py              # FastAPI app, CORS, route registration
│   ├── models.py            # Pydantic data models
│   ├── requirements.txt
│   ├── Procfile             # Railway start command
│   ├── runtime.txt          # Python 3.11.9
│   ├── routes/
│   │   └── triage.py        # API endpoints
│   └── services/
│       ├── enrichment.py    # ThreatScan integration
│       ├── ai_engine.py     # Claude AI report generation
│       └── case_manager.py  # In-memory case store + timeline
└── frontend/
    └── src/
        └── App.jsx          # React UI (single file)
```

---

## Roadmap

**Phase 2 — Enterprise Foundation**
- [ ] PostgreSQL database (replace in-memory store)
- [ ] Full case management UI with investigation timeline
- [ ] Evidence upload and attachment
- [ ] PDF export of incident reports
- [ ] Dashboard with charts

**Phase 3 — Enterprise Ready**
- [ ] JWT authentication (multi-analyst support)
- [ ] SIEM webhook integration
- [ ] Splunk integration
- [ ] Jira / ServiceNow ticket creation

---

## Author

**Salah-Adin Mozeb**  
CompTIA Security+ | Network+ | A+ | Cisco CCNA  
M.S. Cybersecurity — Georgia Tech (in progress)  
GitHub: [@SalCyberAware](https://github.com/SalCyberAware)

---

## License

MIT — free to use, modify, and distribute.

import { useState, useEffect, useCallback } from "react";

const API = import.meta.env.VITE_API_URL || "https://soctriage-production.up.railway.app";

const SEVERITY_COLOR = {
  LOW: "#22c55e",
  MEDIUM: "#f59e0b",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

const STATUS_COLOR = {
  OPEN: "#60a5fa",
  IN_PROGRESS: "#f59e0b",
  ESCALATED: "#f97316",
  CLOSED: "#6b7280",
};

const IOC_TYPES = ["IP", "URL", "DOMAIN", "HASH"];

function detectType(val) {
  if (!val) return "IP";
  if (/^[a-fA-F0-9]{32,64}$/.test(val.trim())) return "HASH";
  if (/^https?:\/\//i.test(val.trim())) return "URL";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val.trim())) return "IP";
  return "DOMAIN";
}

function Badge({ label, color, size = "sm" }) {
  const pad = size === "lg" ? "6px 14px" : "3px 9px";
  const fs = size === "lg" ? "13px" : "11px";
  return (
    <span style={{
      background: color + "22",
      color,
      border: `1px solid ${color}55`,
      borderRadius: 3,
      padding: pad,
      fontSize: fs,
      fontFamily: "var(--mono)",
      fontWeight: 700,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

function Spinner() {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16, padding: "48px 0" }}>
      <div className="spinner" />
      <span style={{ color: "var(--muted)", fontFamily: "var(--mono)", fontSize: 13 }}>
        Enriching IOC + generating AI report…
      </span>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="stat-card">
      <div style={{ fontSize: 36, fontWeight: 800, color: color || "var(--accent)", fontFamily: "var(--mono)" }}>{value}</div>
      <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.1em", marginTop: 4 }}>{label}</div>
    </div>
  );
}

function MitreTag({ t }) {
  return (
    <div className="mitre-tag">
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--accent)", fontWeight: 700 }}>{t.technique_id}</span>
        <span style={{ fontSize: 12, color: "var(--muted)", background: "var(--surface2)", padding: "1px 7px", borderRadius: 2 }}>{t.tactic}</span>
      </div>
      <div style={{ fontSize: 13, color: "var(--text)", fontWeight: 600, marginBottom: 3 }}>{t.technique_name}</div>
      <div style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.5 }}>{t.description}</div>
      <a href={t.mitre_url} target="_blank" rel="noreferrer"
        style={{ fontSize: 11, color: "var(--accent)", textDecoration: "none", marginTop: 4, display: "inline-block", opacity: 0.7 }}>
        → attack.mitre.org
      </a>
    </div>
  );
}

function ReportView({ result, onBack }) {
  const r = result.report;
  const e = result.enrichment;
  const sevColor = SEVERITY_COLOR[r.severity] || "#6b7280";

  return (
    <div className="report-view fade-in">
      <button className="back-btn" onClick={onBack}>← New Triage</button>

      <div className="report-header">
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.12em", marginBottom: 6 }}>
            Case #{result.case_id}
          </div>
          <h2 style={{ margin: 0, fontSize: 22, color: "var(--text)", fontWeight: 700, lineHeight: 1.3 }}>{r.title}</h2>
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <Badge label={r.severity} color={sevColor} size="lg" />
            <Badge label={r.threat_type} color="var(--accent)" />
            <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--muted)" }}>{result.ioc}</span>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 4 }}>THREAT SCORE</div>
          <div style={{ fontSize: 42, fontWeight: 900, fontFamily: "var(--mono)", color: sevColor, lineHeight: 1 }}>{e.score}</div>
          <div style={{ fontSize: 11, color: "var(--muted)" }}>/ 100</div>
        </div>
      </div>

      <div className="report-section">
        <div className="section-label">Executive Summary</div>
        <p style={{ margin: 0, color: "var(--text-soft)", lineHeight: 1.7, fontSize: 14 }}>{r.summary}</p>
      </div>

      <div className="report-grid-2">
        <div className="report-section">
          <div className="section-label">Recommended Actions</div>
          <ol style={{ margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
            {r.recommended_actions.map((a, i) => (
              <li key={i} style={{ color: "var(--text-soft)", fontSize: 13, lineHeight: 1.5 }}>{a}</li>
            ))}
          </ol>
        </div>
        <div className="report-section">
          <div className="section-label">Affected Assets</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {r.affected_assets.length ? r.affected_assets.map((a, i) => (
              <span key={i} style={{ background: "var(--surface2)", border: "1px solid var(--border)", borderRadius: 3, padding: "3px 10px", fontSize: 12, fontFamily: "var(--mono)", color: "var(--text-soft)" }}>{a}</span>
            )) : <span style={{ color: "var(--muted)", fontSize: 13 }}>None identified</span>}
          </div>
        </div>
      </div>

      {r.mitre_techniques?.length > 0 && (
        <div className="report-section">
          <div className="section-label">MITRE ATT&CK Techniques</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 10 }}>
            {r.mitre_techniques.map((t, i) => <MitreTag key={i} t={t} />)}
          </div>
        </div>
      )}

      {r.playbook && (
        <div className="report-section">
          <div className="section-label">Response Playbook</div>
          <pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-soft)", whiteSpace: "pre-wrap", lineHeight: 1.7, background: "var(--surface2)", padding: 16, borderRadius: 6, border: "1px solid var(--border)" }}>{r.playbook}</pre>
        </div>
      )}

      <div className="report-section">
        <div className="section-label">Engine Verdicts</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {e.engines?.map((eng, i) => {
            const ENGINE_NAMES = {
              virustotal: "VirusTotal",
              abuseipdb: "AbuseIPDB",
              urlscan: "URLScan.io",
              malwarebazaar: "MalwareBazaar",
              otx: "AlienVault OTX",
              greynoise: "GreyNoise",
              ipinfo: "IPInfo",
              urlhaus: "URLhaus",
              safebrowsing: "Google Safe Browsing",
              threatfox: "ThreatFox",
              whois: "WHOIS / DNS",
            };
            const engineName = ENGINE_NAMES[eng.id] || eng.id || eng.engine || eng.name || `Engine ${i + 1}`;
            return (
            <div key={i} style={{ background: "var(--surface2)", border: "1px solid var(--border)", borderRadius: 4, padding: "6px 12px", fontSize: 12 }}>
              <span style={{ color: "var(--muted)", fontFamily: "var(--mono)" }}>{engineName}</span>
              {eng.verdict && <span style={{ marginLeft: 8, color: eng.verdict === "malicious" ? "#ef4444" : eng.verdict === "clean" ? "#22c55e" : "var(--muted)" }}>
                {eng.verdict}
              </span>}
            </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function TriageTab() {
  const [ioc, setIoc] = useState("");
  const [iocType, setIocType] = useState("IP");
  const [rawAlert, setRawAlert] = useState("");
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setIocType(detectType(ioc));
  }, [ioc]);

  async function submit() {
    if (!ioc.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const resp = await fetch(`${API}/api/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ioc: ioc.trim(),
          ioc_type: iocType.toLowerCase(),
          raw_alert: rawAlert || null,
          analyst_notes: notes || null,
        }),
      });
      if (!resp.ok) throw new Error(`Server returned ${resp.status}`);
      const data = await resp.json();
      setResult(data);
    } catch (e) {
      setError(e.message || "Request failed");
    } finally {
      setLoading(false);
    }
  }

  if (result) return <ReportView result={result} onBack={() => setResult(null)} />;

  return (
    <div className="triage-tab fade-in">
      <div className="triage-hero">
        <div className="triage-hero-text">
          <h2>Submit IOC for Triage</h2>
          <p>Paste an IP, URL, domain, or hash. SOCTriage will enrich it across 11 threat intelligence engines and generate an AI-powered incident report with MITRE ATT&CK mapping.</p>
        </div>
      </div>

      <div className="form-card">
        <div className="form-row">
          <div className="form-group" style={{ flex: 3 }}>
            <label>Indicator of Compromise</label>
            <input
              className="input"
              value={ioc}
              onChange={e => setIoc(e.target.value)}
              onKeyDown={e => e.key === "Enter" && submit()}
              placeholder="8.8.8.8 · malware.example.com · https://... · d41d8cd..."
              spellCheck={false}
            />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label>IOC Type</label>
            <select className="input" value={iocType} onChange={e => setIocType(e.target.value)}>
              {IOC_TYPES.map(t => <option key={t}>{t}</option>)}
            </select>
          </div>
        </div>

        <div className="form-group">
          <label>Raw Alert <span style={{ color: "var(--muted)", fontWeight: 400 }}>(optional)</span></label>
          <textarea
            className="input"
            rows={4}
            value={rawAlert}
            onChange={e => setRawAlert(e.target.value)}
            placeholder="Paste the raw SIEM alert, log entry, or email header…"
            spellCheck={false}
            style={{ resize: "vertical" }}
          />
        </div>

        <div className="form-group">
          <label>Analyst Notes <span style={{ color: "var(--muted)", fontWeight: 400 }}>(optional)</span></label>
          <input
            className="input"
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Any context or initial hypothesis…"
          />
        </div>

        {error && (
          <div style={{ background: "#ef444422", border: "1px solid #ef444455", borderRadius: 6, padding: "10px 14px", color: "#ef4444", fontSize: 13, fontFamily: "var(--mono)" }}>
            ✗ {error}
          </div>
        )}

        <button
          className="btn-primary"
          onClick={submit}
          disabled={loading || !ioc.trim()}
        >
          {loading ? "Analyzing…" : "▶ Run Triage"}
        </button>
      </div>

      {loading && <Spinner />}
    </div>
  );
}

function CasesTab() {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/cases`);
      const data = await r.json();
      setCases(Array.isArray(data) ? data.reverse() : []);
    } catch {
      setCases([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function updateStatus(caseId, status) {
    await fetch(`${API}/api/cases/${caseId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    load();
  }

  if (loading) return <div style={{ padding: 48, textAlign: "center", color: "var(--muted)", fontFamily: "var(--mono)" }}>Loading cases…</div>;
  if (!cases.length) return (
    <div style={{ padding: 64, textAlign: "center" }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>📭</div>
      <div style={{ color: "var(--muted)", fontFamily: "var(--mono)" }}>No cases yet. Run a triage to create one.</div>
    </div>
  );

  return (
    <div className="fade-in">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <h2 style={{ margin: 0 }}>Cases <span style={{ color: "var(--muted)", fontWeight: 400, fontSize: 16 }}>({cases.length})</span></h2>
        <button className="btn-ghost" onClick={load}>↻ Refresh</button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {cases.map(c => (
          <div key={c.case_id} className="case-row">
            <div className="case-summary" onClick={() => setExpanded(expanded === c.case_id ? null : c.case_id)}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--accent)", flexShrink: 0 }}>#{c.case_id}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.ioc}</span>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
                <Badge label={c.severity} color={SEVERITY_COLOR[c.severity] || "#6b7280"} />
                <Badge label={c.status} color={STATUS_COLOR[c.status] || "#6b7280"} />
                <span style={{ color: "var(--muted)", fontSize: 18 }}>{expanded === c.case_id ? "▲" : "▼"}</span>
              </div>
            </div>

            {expanded === c.case_id && (
              <div className="case-detail fade-in">
                <div style={{ marginBottom: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {["OPEN", "IN_PROGRESS", "ESCALATED", "CLOSED"].map(s => (
                    <button
                      key={s}
                      className={`status-btn ${c.status === s ? "active" : ""}`}
                      onClick={() => updateStatus(c.case_id, s)}
                      style={{ "--btn-color": STATUS_COLOR[s] }}
                    >
                      {s.replace("_", " ")}
                    </button>
                  ))}
                </div>

                {c.report && (
                  <>
                    <div className="section-label" style={{ marginBottom: 8 }}>Summary</div>
                    <p style={{ margin: "0 0 12px", color: "var(--text-soft)", fontSize: 13, lineHeight: 1.6 }}>{c.report.summary}</p>

                    {c.report.mitre_techniques?.length > 0 && (
                      <>
                        <div className="section-label" style={{ marginBottom: 8 }}>MITRE Techniques</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
                          {c.report.mitre_techniques.map((t, i) => (
                            <a key={i} href={t.mitre_url} target="_blank" rel="noreferrer"
                              style={{ background: "var(--surface2)", border: "1px solid var(--accent)33", borderRadius: 3, padding: "3px 10px", fontSize: 12, fontFamily: "var(--mono)", color: "var(--accent)", textDecoration: "none" }}>
                              {t.technique_id} · {t.technique_name}
                            </a>
                          ))}
                        </div>
                      </>
                    )}
                  </>
                )}

                <div className="section-label" style={{ marginBottom: 8 }}>Timeline</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {c.timeline?.map((ev, i) => (
                    <div key={i} style={{ display: "flex", gap: 12, fontSize: 12 }}>
                      <span style={{ color: "var(--muted)", fontFamily: "var(--mono)", flexShrink: 0 }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      <span style={{ color: "var(--text-soft)" }}>{ev.action}{ev.notes ? ` — ${ev.notes}` : ""}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardTab() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetch(`${API}/api/dashboard`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  if (!stats) return <div style={{ padding: 48, textAlign: "center", color: "var(--muted)", fontFamily: "var(--mono)" }}>Loading…</div>;

  const statusEntries = Object.entries(stats.by_status || {});
  const sevEntries = Object.entries(stats.by_severity || {});

  return (
    <div className="fade-in">
      <h2 style={{ marginTop: 0 }}>Dashboard</h2>
      <div className="stat-grid">
        <StatCard label="Total Cases" value={stats.total} />
        {statusEntries.map(([k, v]) => (
          <StatCard key={k} label={k.replace("_", " ")} value={v} color={STATUS_COLOR[k]} />
        ))}
      </div>

      <h3 style={{ color: "var(--muted)", fontSize: 13, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 12 }}>By Severity</h3>
      <div className="stat-grid">
        {sevEntries.map(([k, v]) => (
          <StatCard key={k} label={k} value={v} color={SEVERITY_COLOR[k]} />
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("triage");

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');

        :root {
          --bg: #080c0d;
          --surface: #0d1416;
          --surface2: #111a1c;
          --border: #1c2a2d;
          --accent: #00d4aa;
          --accent2: #0097ff;
          --text: #e2e8f0;
          --text-soft: #94a3b8;
          --muted: #475569;
          --mono: 'JetBrains Mono', monospace;
          --sans: 'Syne', sans-serif;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
          background: var(--bg);
          color: var(--text);
          font-family: var(--sans);
          min-height: 100vh;
          background-image:
            radial-gradient(ellipse 80% 50% at 50% -10%, #00d4aa0a, transparent),
            repeating-linear-gradient(0deg, transparent, transparent 39px, #1c2a2d18 39px, #1c2a2d18 40px),
            repeating-linear-gradient(90deg, transparent, transparent 39px, #1c2a2d10 39px, #1c2a2d10 40px);
        }

        .app-shell {
          max-width: 900px;
          margin: 0 auto;
          padding: 0 20px 80px;
        }

        header {
          padding: 28px 0 0;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--border);
          margin-bottom: 32px;
        }

        .logo {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .logo-icon {
          width: 34px;
          height: 34px;
          border-radius: 8px;
          background: linear-gradient(135deg, #00d4aa22, #0097ff22);
          border: 1px solid var(--accent);
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 16px;
        }

        .logo-text {
          font-size: 20px;
          font-weight: 800;
          color: var(--text);
          letter-spacing: -0.02em;
        }

        .logo-text span { color: var(--accent); }

        .logo-sub {
          font-family: var(--mono);
          font-size: 10px;
          color: var(--muted);
          letter-spacing: 0.12em;
          text-transform: uppercase;
        }

        nav {
          display: flex;
          gap: 0;
          border-bottom: none;
        }

        .nav-btn {
          background: none;
          border: none;
          cursor: pointer;
          padding: 12px 20px;
          font-family: var(--sans);
          font-size: 13px;
          font-weight: 600;
          color: var(--muted);
          border-bottom: 2px solid transparent;
          transition: color 0.15s, border-color 0.15s;
          letter-spacing: 0.04em;
        }

        .nav-btn:hover { color: var(--text); }
        .nav-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

        .fade-in { animation: fadeIn 0.25s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

        .triage-hero {
          margin-bottom: 28px;
        }

        .triage-hero h2 {
          font-size: 26px;
          font-weight: 800;
          margin-bottom: 8px;
          letter-spacing: -0.02em;
        }

        .triage-hero p {
          color: var(--text-soft);
          font-size: 14px;
          line-height: 1.6;
          max-width: 600px;
          font-family: var(--sans);
          font-weight: 400;
        }

        .form-card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .form-row {
          display: flex;
          gap: 12px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        label {
          font-size: 12px;
          font-weight: 700;
          color: var(--muted);
          text-transform: uppercase;
          letter-spacing: 0.08em;
        }

        .input {
          background: var(--surface2);
          border: 1px solid var(--border);
          border-radius: 6px;
          color: var(--text);
          font-family: var(--mono);
          font-size: 13px;
          padding: 10px 12px;
          outline: none;
          transition: border-color 0.15s;
          width: 100%;
        }

        .input:focus { border-color: var(--accent); }
        .input::placeholder { color: var(--muted); }

        textarea.input { font-family: var(--mono); }

        select.input { cursor: pointer; }

        .btn-primary {
          background: var(--accent);
          color: #000;
          border: none;
          border-radius: 6px;
          padding: 12px 24px;
          font-family: var(--sans);
          font-size: 14px;
          font-weight: 700;
          cursor: pointer;
          letter-spacing: 0.04em;
          transition: opacity 0.15s, transform 0.1s;
          align-self: flex-start;
        }

        .btn-primary:hover:not(:disabled) { opacity: 0.85; transform: translateY(-1px); }
        .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

        .btn-ghost {
          background: none;
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 8px 16px;
          color: var(--text-soft);
          font-family: var(--sans);
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: border-color 0.15s, color 0.15s;
        }

        .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }

        .spinner {
          width: 36px;
          height: 36px;
          border: 3px solid var(--border);
          border-top-color: var(--accent);
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        .report-view { display: flex; flex-direction: column; gap: 20px; }

        .back-btn {
          background: none;
          border: none;
          color: var(--accent);
          font-family: var(--mono);
          font-size: 13px;
          cursor: pointer;
          padding: 0;
          align-self: flex-start;
          transition: opacity 0.15s;
        }
        .back-btn:hover { opacity: 0.7; }

        .report-header {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 24px;
          display: flex;
          gap: 24px;
          align-items: flex-start;
        }

        .report-section {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .report-grid-2 {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }

        .section-label {
          font-size: 11px;
          font-weight: 700;
          color: var(--muted);
          text-transform: uppercase;
          letter-spacing: 0.1em;
        }

        .mitre-tag {
          background: var(--surface2);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 12px;
        }

        .stat-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
          gap: 12px;
          margin-bottom: 28px;
        }

        .stat-card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 20px;
          text-align: center;
        }

        .case-row {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          overflow: hidden;
          transition: border-color 0.15s;
        }

        .case-row:hover { border-color: #1e3a3a; }

        .case-summary {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 14px 16px;
          cursor: pointer;
          user-select: none;
        }

        .case-detail {
          border-top: 1px solid var(--border);
          padding: 16px;
          background: var(--surface2);
        }

        .status-btn {
          background: none;
          border: 1px solid var(--border);
          border-radius: 4px;
          padding: 4px 10px;
          color: var(--muted);
          font-family: var(--mono);
          font-size: 11px;
          cursor: pointer;
          transition: all 0.15s;
          text-transform: uppercase;
          letter-spacing: 0.06em;
        }

        .status-btn:hover { border-color: var(--btn-color); color: var(--btn-color); }
        .status-btn.active { background: var(--btn-color); color: #000; border-color: var(--btn-color); font-weight: 700; }

        .health-dot {
          width: 8px;
          height: 8px;
          background: var(--accent);
          border-radius: 50%;
          display: inline-block;
          margin-right: 6px;
          animation: pulse 2s ease infinite;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }

        @media (max-width: 600px) {
          .form-row { flex-direction: column; }
          .report-grid-2 { grid-template-columns: 1fr; }
          .report-header { flex-direction: column; }
          .nav-btn { padding: 10px 12px; font-size: 12px; }
        }
      `}</style>

      <div className="app-shell">
        <header>
          <div className="logo">
            <div className="logo-icon">🛡</div>
            <div>
              <div className="logo-text">SOC<span>Triage</span></div>
              <div className="logo-sub">AI-Powered Alert Triage</div>
            </div>
          </div>
          <nav>
            {[["triage", "▶ Triage"], ["cases", "Cases"], ["dashboard", "Dashboard"]].map(([id, label]) => (
              <button key={id} className={`nav-btn${tab === id ? " active" : ""}`} onClick={() => setTab(id)}>
                {label}
              </button>
            ))}
          </nav>
        </header>

        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 28, fontSize: 12, color: "var(--muted)", fontFamily: "var(--mono)" }}>
          <span className="health-dot" />
          soctriage-production.up.railway.app · online
        </div>

        {tab === "triage" && <TriageTab />}
        {tab === "cases" && <CasesTab />}
        {tab === "dashboard" && <DashboardTab />}
      </div>
    </>
  );
}

import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { initWebMCP } from "./webmcp_bridge.js";

const CFG = window.CYBERGUARD_CONFIG || {};
// config.js normally sets CFG.apiBase. This fallback only fires if config.js
// failed to load: localhost -> local API; anything else -> injected override or
// same-origin (so a single-host deploy still works).
const _host = (typeof window !== "undefined" && window.location.hostname) || "";
const _isLocal = _host === "localhost" || _host === "127.0.0.1" || _host === "0.0.0.0" || _host === "";
const _fallbackApiBase = _isLocal
  ? "http://localhost:8000"
  : (window.__CYBERGUARD_API_URL__ || window.location.origin);
const API_BASE = (CFG.apiBase || _fallbackApiBase).replace(/\/+$/, "");
const bridge = initWebMCP(API_BASE, { credentials: "include", headers: CFG.apiKey ? { "X-API-Key": String(CFG.apiKey) } : {} });
const PHASES = ["DISCOVER", "INSPECT", "CORRELATE", "ATTRIBUTE", "REPORT"];
const PHASE_TOOLS = { DISCOVER: ["get_security_summary", "get_suspicious_users"], INSPECT: ["investigate_user"], CORRELATE: ["get_user_risk_score"], ATTRIBUTE: ["detect_attack_pattern"], REPORT: ["generate_incident_report"] };
function phaseFor(tool) { return PHASES.find((phase) => PHASE_TOOLS[phase].includes(tool)); }
function pretty(value) { return value === undefined || value === null ? "-" : String(value); }
function redirectToLogin() { window.history.replaceState({}, "", "/"); window.history.pushState({}, "", "/"); window.dispatchEvent(new PopStateEvent("popstate")); }
function goTo(path) { window.history.pushState({}, "", path); window.dispatchEvent(new PopStateEvent("popstate")); }
function inlineMarkdown(text) {
  return String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`")) return <code key={index}>{part.slice(1, -1)}</code>;
    return <React.Fragment key={index}>{part}</React.Fragment>;
  });
}
function markdownToHtml(markdown) {
  const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]);
  const lines = String(markdown || "").split("\n");
  const output = []; let index = 0;
  const inline = (value) => escape(value).replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line) { index += 1; continue; }
    if (line.startsWith("|")) {
      const rows = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) { rows.push(lines[index].trim()); index += 1; }
      const cells = (row) => row.split("|").slice(1, -1).map((cell) => cell.trim());
      const tableRows = rows.filter((row) => !/^\|[\s:|-]+\|$/.test(row));
      const headers = cells(tableRows.shift() || "");
      output.push(`<table><thead><tr>${headers.map((cell) => `<th>${inline(cell)}</th>`).join("")}</tr></thead><tbody>${tableRows.map((row) => `<tr>${cells(row).map((cell) => `<td>${inline(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
      continue;
    }
    if (line.startsWith("# ")) { output.push(`<h1>${inline(line.slice(2))}</h1>`); index += 1; continue; }
    if (line.startsWith("## ")) { output.push(`<h2>${inline(line.slice(3))}</h2>`); index += 1; continue; }
    if (/^\d+\.\s/.test(line) || line.startsWith("- ")) {
      const ordered = /^\d+\.\s/.test(line); const items = [];
      while (index < lines.length && (ordered ? /^\d+\.\s/.test(lines[index].trim()) : lines[index].trim().startsWith("- "))) { items.push(lines[index].trim().replace(ordered ? /^\d+\.\s/ : /^- /, "")); index += 1; }
      output.push(`<${ordered ? "ol" : "ul"}>${items.map((item) => `<li>${inline(item)}</li>`).join("")}</${ordered ? "ol" : "ul"}>`); continue;
    }
    output.push(`<p>${inline(line)}</p>`); index += 1;
  }
  return output.join("\n");
}
function MarkdownReport({ markdown }) {
  const lines = String(markdown || "").split("\n");
  const blocks = []; let index = 0;
  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line) { index += 1; continue; }
    if (line.startsWith("|")) {
      const rows = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) { rows.push(lines[index].trim()); index += 1; }
      const cells = (row) => row.split("|").slice(1, -1).map((cell) => cell.trim());
      const tableRows = rows.filter((row) => !/^\|[\s:|-]+\|$/.test(row));
      const headers = cells(tableRows.shift() || "");
      blocks.push(<table key={`table-${index}`}><thead><tr>{headers.map((header) => <th key={header}>{inlineMarkdown(header)}</th>)}</tr></thead><tbody>{tableRows.map((row, rowIndex) => <tr key={rowIndex}>{cells(row).map((cell, cellIndex) => <td key={cellIndex}>{inlineMarkdown(cell)}</td>)}</tr>)}</tbody></table>);
      continue;
    }
    if (line.startsWith("# ") || line.startsWith("## ")) { blocks.push(line.startsWith("# ") ? <h3 key={index}>{inlineMarkdown(line.slice(2))}</h3> : <h4 key={index}>{inlineMarkdown(line.slice(3))}</h4>); index += 1; continue; }
    if (/^\d+\.\s/.test(line) || line.startsWith("- ")) {
      const ordered = /^\d+\.\s/.test(line); const items = [];
      while (index < lines.length && (ordered ? /^\d+\.\s/.test(lines[index].trim()) : lines[index].trim().startsWith("- "))) { items.push(lines[index].trim().replace(ordered ? /^\d+\.\s/ : /^- /, "")); index += 1; }
      const List = ordered ? "ol" : "ul"; blocks.push(<List key={index}>{items.map((item, itemIndex) => <li key={itemIndex}>{inlineMarkdown(item)}</li>)}</List>); continue;
    }
    blocks.push(<p key={index}>{inlineMarkdown(line)}</p>); index += 1;
  }
  return <div className="markdown-report">{blocks}</div>;
}

function AdminLogin({ onAuthenticated, demoLogin }) {
  const [username, setUsername] = useState(demoLogin ? "admin" : ""); const [password, setPassword] = useState(demoLogin ? "demo1234" : ""); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  async function submit(event) {
    event.preventDefault(); if (!username.trim() || !password) { setError("Enter your administrator credentials."); return; }
    setLoading(true); setError("");
    try { const response = await fetch(`${API_BASE}/api/auth/login`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: username.trim(), password }) }); if (!response.ok) { setError(response.status === 401 ? "Invalid administrator credentials." : response.status === 503 ? "Administrator access is not configured on the server." : "Authentication service unavailable."); return; } window.history.pushState({}, "", "/dashboard"); onAuthenticated(); }
    catch { setError("Unable to reach the authentication service."); } finally { setLoading(false); }
  }
  return <main className="auth-page"><section className="login-card"><button className="back-link" onClick={() => goTo("/")}>← BACK TO CYBERGUARD</button><a className="brand login-brand" href="/" aria-label="CyberGuard home"><span className="brand-mark">C</span><span>CYBERGUARD</span><small>SECURITY INTELLIGENCE</small></a><div className="eyebrow">RESTRICTED OPERATOR ACCESS</div><h1>Admin Login</h1><p>Sign in to access the CyberGuard security investigation console.</p>{demoLogin && <div className="demo-notice" role="note">DEMO MODE · credentials prefilled (admin / demo1234) — just click LOGIN</div>}<form onSubmit={submit} noValidate><label htmlFor="login-username">USERNAME OR EMAIL</label><input id="login-username" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /><label htmlFor="login-password">PASSWORD</label><input id="login-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />{error && <div className="login-error" role="alert">{error}</div>}<button className="primary-action login-action" type="submit" disabled={loading}>{loading ? "AUTHENTICATING..." : "LOGIN TO CYBERGUARD  →"}</button></form><span className="login-footnote">SESSION PROTECTED · HTTP-ONLY COOKIE</span></section></main>;
}

function Landing() {
  return <main className="landing-page">
    <header className="landing-nav"><a className="brand" href="/" aria-label="CyberGuard home"><span className="brand-mark">C</span><span>CYBERGUARD SOC</span><small>SECURITY INTELLIGENCE</small></a><nav><a href="#capabilities">Capabilities</a><a href="#how-it-works">How It Works</a></nav><button className="outline-action nav-login" onClick={() => goTo("/login")}>ADMIN LOGIN →</button></header>
    <section className="landing-hero"><div className="eyebrow">AGENT-NATIVE CYBERSECURITY INVESTIGATION PLATFORM</div><h1>Turn security events<br /><em>into evidence.</em></h1><p>CyberGuard combines AI-powered analysis, machine learning, cybersecurity intelligence, and WebMCP to help security teams investigate suspicious activity with confidence.</p><div className="landing-actions"><button className="primary-action" onClick={() => goTo("/login")}>ADMIN LOGIN <span>→</span></button><a className="text-button landing-explore" href="#capabilities">EXPLORE CAPABILITIES ↓</a></div><div className="hero-signal"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><i>LIVE INVESTIGATION SIGNAL</i></div></section>
    <section className="landing-section" id="capabilities"><div className="landing-section-head"><div className="eyebrow">CAPABILITIES / 01</div><h2>Security intelligence<br /><em>built for investigation.</em></h2></div><div className="capability-grid"><Capability number="01" title="AI + WebMCP" text="AI agents interact with structured cybersecurity tools and perform multi-step investigations." /><Capability number="02" title="Machine Learning" text="Detect unusual behavior and classify suspicious activity using explainable ML signals." /><Capability number="03" title="Cybersecurity Intelligence" text="Identify brute force, credential stuffing, account takeover, and impossible-travel patterns." /><Capability number="04" title="Investigation Dashboard" text="Bring together events, users, risk scores, evidence, and incident reports in one console." /></div></section>
    <section className="landing-section workflow-section" id="how-it-works"><div className="landing-section-head"><div className="eyebrow">HOW IT WORKS / 02</div><h2>From signal<br /><em>to certainty.</em></h2></div><div className="workflow-list">{["Security Activity", "AI Agent + WebMCP", "Security APIs", "ML + Cybersecurity Analysis", "Risk & Threat Detection", "Evidence-backed Investigation", "Incident Report"].map((step, index) => <div className="workflow-step" key={step}><span>{String(index + 1).padStart(2, "0")}</span><strong>{step}</strong>{index < 6 && <i>↓</i>}</div>)}</div></section>
    <section className="landing-section example-section"><div className="example-copy"><div className="eyebrow">EXAMPLE INVESTIGATION / 03</div><h2>Ask a question.<br /><em>Follow the evidence.</em></h2><p>“Find the most suspicious user today and investigate them.”</p><div className="example-result"><span>RESULT</span><strong>Possible Account Takeover</strong><b>HIGH SEVERITY</b></div></div><div className="example-trace">{["get_suspicious_users()", "investigate_user()", "get_user_risk_score()", "detect_attack_pattern()", "generate_incident_report()"].map((call, index) => <div key={call}><span>{String(index + 1).padStart(2, "0")}</span><code>{call}</code></div>)}<div className="example-evidence"><span>EVIDENCE</span><b>47 failed logins</b><b>8 IP addresses</b><b>New device</b><b>Anomaly score: 0.93</b></div></div></section>
    <section className="landing-cta"><div><div className="eyebrow">SECURITY OPERATIONS CONSOLE</div><h2>Ready when the signal<br /><em>needs an answer.</em></h2></div><button className="primary-action" onClick={() => goTo("/login")}>ACCESS ADMIN CONSOLE →</button></section>
    <footer className="landing-footer"><span>© CYBERGUARD SOC</span><span>ANALYTICAL ONLY · HUMAN-AUTHORIZED RESPONSE</span></footer>
  </main>;
}
function Capability({ number, title, text }) { return <article className="capability-card"><span>{number}</span><div className="capability-icon">+</div><h3>{title}</h3><p>{text}</p></article>; }

function Dashboard({ onLogout, onSessionExpired }) {
  const [summary, setSummary] = useState({}); const [users, setUsers] = useState([]); const [target, setTarget] = useState("");
  const [result, setResult] = useState(null); const [running, setRunning] = useState(false); const [banner, setBanner] = useState(""); const [toast, setToast] = useState("");
  const [securityCenter, setSecurityCenter] = useState({ summary: {}, events: [], incidents: [] }); const [selectedIncident, setSelectedIncident] = useState(null); const [securityBusy, setSecurityBusy] = useState(false);
  const native = bridge.mode === "webmcp";
  async function loadData() { try { const [nextSummary, nextUsers] = await Promise.all([bridge.client.getSecuritySummary(), bridge.client.getSuspiciousUsers(5)]); setSummary(nextSummary || {}); setUsers(nextUsers || []); } catch (error) { if (error.status === 401) { redirectToLogin(); onSessionExpired(); return; } setBanner(`Security data unavailable at ${API_BASE}: ${error.message}`); } }
  async function loadSecurityCenter() { try { const [centerSummary, events, incidents] = await Promise.all([fetch(`${API_BASE}/admin/security/summary`, { credentials: "include" }).then((response) => response.json()), fetch(`${API_BASE}/admin/security/events`, { credentials: "include" }).then((response) => response.json()), fetch(`${API_BASE}/admin/incidents`, { credentials: "include" }).then((response) => response.json())]); setSecurityCenter({ summary: centerSummary || {}, events: events.events || [], incidents: incidents.incidents || [] }); } catch (error) { if (error.status === 401) onSessionExpired(); } }
  useEffect(() => { loadData(); }, []);
  useEffect(() => { loadSecurityCenter(); const interval = window.setInterval(loadSecurityCenter, 5000); return () => window.clearInterval(interval); }, []);
  async function simulateSuspiciousLogin() { setSecurityBusy(true); try { await fetch(`${API_BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: "USR-1042", ip_address: "203.0.113.7", country: "India", device_type: "Desktop", login_successful: true, failed_logins: 47, successful_logins: 1, unique_ips: ["203.0.113.7", "198.51.100.8"], anomaly_score: 0.93, device_changed: true, location_changed: true, login_hour: 2 }) }); await loadSecurityCenter(); setToast("High-risk demo login detected"); } finally { setSecurityBusy(false); } }
  async function denySelectedIncident() { if (!selectedIncident) return; setSecurityBusy(true); try { const response = await fetch(`${API_BASE}/admin/access-control/deny?user_id=${encodeURIComponent(selectedIncident.user_id)}`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: selectedIncident.attack_type }) }); if (!response.ok) throw new Error("Containment action was not authorized"); await loadSecurityCenter(); setSelectedIncident(null); setToast("Demo containment recorded"); } catch (error) { setBanner(error.message); } finally { setSecurityBusy(false); } }
  async function investigate(userId = null) { if (running) return; setRunning(true); setBanner(""); setResult(null); try { const next = await bridge.runInvestigation(userId || null); if (next.status && next.status !== "COMPLETE") setBanner(`${next.status}: ${next.message || "Investigation did not complete."}`); else setResult(next); } catch (error) { if (error.status === 401) { redirectToLogin(); onSessionExpired(); return; } setBanner(`Investigation failed: ${error.message}`); } finally { setRunning(false); } }
  function downloadReport() {
    if (!result?.markdown_report) return;
    const reportHtml = `<!doctype html><html><head><meta charset="utf-8"><title>CyberGuard Incident Report</title><style>body{margin:40px;background:#0b0b0b;color:#d6d5d1;font:14px system-ui,sans-serif;line-height:1.7}main{max-width:1000px;margin:auto;background:#121212;border:1px solid #30302e;border-radius:14px;padding:36px}h1{font-size:25px;color:#fff}h2{font-size:14px;color:#b5f36b;text-transform:uppercase;letter-spacing:.12em;margin-top:28px}table{width:100%;border-collapse:collapse;margin:18px 0;font:12px ui-monospace,monospace}th,td{text-align:left;padding:10px;border:1px solid #30302e}th{color:#b5f36b;background:#1a1a1a}td{color:#bdbbb5}code{color:#b5f36b;background:#1d1d1d;padding:2px 5px}li{margin:6px 0}strong{color:#fff}</style></head><body><main>${markdownToHtml(result.markdown_report)}</main></body></html>`;
    const reportBlob = new Blob([reportHtml], { type: "text/html;charset=utf-8" });
    const reportUrl = URL.createObjectURL(reportBlob);
    const link = document.createElement("a");
    link.href = reportUrl;
    link.download = `cyberguard-incident-${result.target_user_id || "report"}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(reportUrl);
    setToast("Incident report downloaded");
    window.setTimeout(() => setToast(""), 2200);
  }
  const assessment = result?.assessment || {}; const telemetry = result?.telemetry || {}; const trace = result?.audit_trace || []; const seen = new Set(trace.map((step) => phaseFor(step.tool)).filter(Boolean)); const severity = assessment.severity || "AWAITING";
  return <div className="app-shell">
    <header className="topbar"><a className="brand" href="#overview" aria-label="CyberGuard overview"><span className="brand-mark">C</span><span>CYBERGUARD</span><small>SECURITY INTELLIGENCE</small></a><div className="system-status"><span className={`status-chip ${native ? "native" : "fallback"}`} id="modePill"><i id="modeDot" /><b id="modeText">{native ? "NATIVE WebMCP" : "REST FALLBACK"}</b></span><span className="api-state"><i /> API {summary.status ? "ONLINE" : "READY"}</span><button className="logout-button" onClick={onLogout}>LOG OUT</button></div></header>
    {banner && <div className="banner" id="banner" role="alert">{banner}</div>}
    <main>
      <section className="overview-strip" id="overview" aria-label="Security overview"><div className="section-label">SECURITY OVERVIEW <span>LIVE TELEMETRY</span></div><div className="metric-row"><Metric label="Monitored" value={summary.monitored_users} id="mMonitored" /><Metric label="Flagged" value={summary.flagged_suspicious_users} id="mFlagged" accent="warning" /><Metric label="Risk status" value={summary.status || "READY"} id="mStatus" /><Metric label="Active incidents" value={securityCenter.summary.active_incidents} accent="critical" /></div></section>
      <section className="security-center"><div className="section-heading"><div><div className="eyebrow">ADMIN SECURITY CENTER / LIVE</div><h2>What needs attention?</h2><div className="demo-notice">DEMO ENVIRONMENT · NO REAL ACCOUNT OR INFRASTRUCTURE IS MODIFIED</div></div><button className="outline-action" disabled={securityBusy} onClick={simulateSuspiciousLogin}>SIMULATE HIGH-RISK LOGIN</button></div><div className="center-metrics"><Metric label="Total logins" value={securityCenter.summary.total_logins} /><Metric label="Safe" value={securityCenter.summary.safe_logins} /><Metric label="Suspicious" value={securityCenter.summary.suspicious_logins} accent="warning" /><Metric label="High risk" value={securityCenter.summary.high_risk_events} accent="critical" /><Metric label="Active incidents" value={securityCenter.summary.active_incidents} /><Metric label="Demo contained" value={securityCenter.summary.contained} /></div><div className="center-grid"><div className="event-list"><div className="subhead">LIVE SECURITY EVENTS</div>{securityCenter.events.length ? securityCenter.events.slice(0, 6).map((event, index) => <button className="security-event" key={`${event.session_id || event.event_id}-${index}`} onClick={() => event.incident_id && setSelectedIncident(securityCenter.incidents.find((incident) => incident.incident_id === event.incident_id) || null)}><span>{pretty(event.user_id)}</span><span>{pretty(event.attack_type)}</span><strong>{pretty(event.risk_score)}</strong><b className={String(event.status).toLowerCase()}>{pretty(event.status)}</b></button>) : <p className="empty-state">No login events recorded.</p>}</div><div className="incident-list"><div className="subhead">INCIDENT QUEUE</div>{securityCenter.incidents.length ? securityCenter.incidents.slice(0, 5).map((incident) => <button className="incident-row" key={incident.incident_id} onClick={() => setSelectedIncident(incident)}><span><b>{incident.incident_id}</b><small>{incident.user_id} · {incident.attack_type}</small></span><strong>{incident.risk_score}</strong><em>{incident.status}</em></button>) : <p className="empty-state">No incidents created yet.</p>}</div></div></section>
      {selectedIncident && <div className="containment-modal" role="dialog" aria-modal="true"><div className="modal-card"><div className="eyebrow">AUTHORIZED SECURITY ACTION</div><h2>Confirm demo containment</h2><p>Access for <strong>{selectedIncident.user_id}</strong> will be denied at the application layer only.</p><div className="modal-detail"><span>RISK <b>{selectedIncident.risk_score} / 100</b></span><span>THREAT <b>{selectedIncident.attack_type}</b></span><span>MODE <b>DEMO</b></span></div><div className="modal-actions"><button className="outline-action" onClick={() => setSelectedIncident(null)}>CANCEL</button><button className="danger-action" disabled={securityBusy || selectedIncident.status !== "ACTIVE"} onClick={denySelectedIncident}>{selectedIncident.status === "ACTIVE" ? "DENY ACCESS — DEMO" : "ALREADY CONTAINED"}</button></div></div></div>}
      <section className="workspace" id="workspace"><div className="section-heading"><div><div className="eyebrow">OPERATOR CONSOLE / 01</div><h2>Investigation workspace</h2></div><div className="workspace-actions"><button className="primary-action compact-action" id="btnAuto" disabled={running} onClick={() => investigate()}>⟶ {running ? "RUNNING" : "RUN INVESTIGATION"}</button><span id="runSource">{result ? (result._source === "server_agent" ? "SERVER AGENT LOOP" : "CLIENT FALLBACK CHAIN") : "AWAITING COMMAND"}</span></div></div><div className="workspace-grid">
        <aside className="panel users-panel" id="users"><PanelTitle index="01" title="Suspicious users" action={<button className="text-button" id="btnRefresh" disabled={running} onClick={loadData}>REFRESH ↻</button>} /><div className="target-form"><label htmlFor="inpTarget">TARGET USER ID</label><div><input id="inpTarget" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => event.key === "Enter" && investigate(target.trim() || null)} placeholder="USR-402" /><button id="btnTarget" disabled={running} onClick={() => investigate(target.trim() || null)}>GO</button></div></div><div className="user-list" id="suspList">{users.length ? users.map((user) => <button className="user-row" key={user.user_id} disabled={running} onClick={() => investigate(user.user_id)}><span className="user-id">{pretty(user.user_id)}</span><span className="user-threat">{pretty(user.threat_type || "SUSPICIOUS")}</span><span className="user-score">{Number(user.anomaly_score ?? 0).toFixed(2)}</span><span className="user-status">● FLAGGED</span></button>) : <span className="empty-state">No suspicious users returned.</span>}</div></aside>
        <section className="panel trace-panel"><PanelTitle index="02" title="Investigation trace" action={<span className="trace-source">{running ? "PROCESSING" : `${trace.length} EVENTS`}</span>} /><div className="stepper" id="stepper">{PHASES.map((phase) => <div className={`step ${seen.has(phase) ? "done" : ""} ${running && !seen.has(phase) ? "pending" : ""}`} key={phase}><span className="step-dot" /><b>{phase}</b><small>{seen.has(phase) ? "COMPLETE" : "WAITING"}</small></div>)}</div><div className="terminal" id="terminal">{trace.length ? trace.map((step, index) => <div className="trace-event" key={`${step.tool}-${index}`}><div><span className="event-phase">[{step.step || phaseFor(step.tool)}]</span><strong>{step.tool}()</strong><time>{pretty(step.ts).replace("T", " ").replace(/\.\d+Z?$/, "")}</time></div><details><summary>INPUT / OUTPUT</summary><pre>{JSON.stringify({ input: step.input, output: step.output }, null, 2)}</pre></details></div>) : <div className="terminal-idle">// idle — launch an investigation to begin the trace</div>}{result && <div className="trace-complete">// investigation complete — {pretty(result.target_user_id)}</div>}</div></section>
        <section className="panel findings-panel" id="threat"><PanelTitle index="03" title="Threat analysis" action={<span className={`severity-dot ${severity.toLowerCase()}`} />} /><div className={`threat-card ${severity.toLowerCase()}`} id="threatBadge"><span className="eyebrow">THREAT ATTRIBUTION</span><strong>{pretty(assessment.threat_classification || "No assessment yet")}</strong><div><span className="severity-label">{severity}</span><span>{pretty(assessment.confidence_pct)}% CONFIDENCE</span></div></div><div className="finding-grid" id="metrics"><Finding label="Risk score" value={assessment.risk_score} /><Finding label="Anomaly score" value={telemetry.anomaly_score} /><Finding label="MITRE technique" value={assessment.mitre_technique_id} /><Finding label="Failed logins" value={telemetry.failed_logins} /><Finding label="Unique IPs" value={telemetry.unique_ip_count ?? telemetry.unique_ips?.length} /><Finding label="Successful" value={telemetry.successful_logins} /></div><div className="factors"><span className="eyebrow">RISK FACTORS</span>{(telemetry.risk_factors || assessment.risk_factors || []).length ? (telemetry.risk_factors || assessment.risk_factors).map((factor, index) => <span key={index}>+ {pretty(factor)}</span>) : <span className="muted">Available after investigation.</span>}</div></section>
      </div></section>
      <section className="report-section"><div className="section-heading"><div><div className="eyebrow">CASE FILE / 02</div><h2>Incident report</h2></div><button className="outline-action" id="btnCopy" disabled={!result?.markdown_report} onClick={downloadReport}>DOWNLOAD REPORT ↓</button></div><article className="report-card" id="report">{result?.markdown_report ? <MarkdownReport markdown={result.markdown_report} /> : <div className="report-empty">No generated report yet. Run an investigation to compile evidence and recommendations.</div>}</article></section>
    </main>{toast && <div className="toast" id="toast">{toast}</div>}
  </div>;
}
function Metric({ label, value, id, accent = "" }) { return <div className={`metric ${accent}`}><span>{label}</span><strong id={id}>{pretty(value)}</strong></div>; }
function Finding({ label, value }) { return <div className="finding"><span>{label}</span><strong>{pretty(value)}</strong></div>; }
function PanelTitle({ index, title, action }) { return <div className="panel-title"><span className="panel-index">{index}</span><h3>{title}</h3>{action}</div>; }
function App() {
  const [authenticated, setAuthenticated] = useState(null);
  const [demoLogin, setDemoLogin] = useState(false);
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => { const onPopState = () => setPath(window.location.pathname); window.addEventListener("popstate", onPopState); fetch(`${API_BASE}/api/auth/me`, { credentials: "include" }).then((response) => response.ok ? response.json() : { authenticated: false }).then((data) => { const isAuthenticated = Boolean(data.authenticated); setDemoLogin(Boolean(data.demo_login)); if (isAuthenticated && path !== "/dashboard") { window.history.replaceState({}, "", "/dashboard"); setPath("/dashboard"); } if (!isAuthenticated && path === "/dashboard") { window.history.replaceState({}, "", "/"); setPath("/"); } setAuthenticated(isAuthenticated); }).catch(() => { if (path === "/dashboard") { window.history.replaceState({}, "", "/"); setPath("/"); } setAuthenticated(false); }); return () => window.removeEventListener("popstate", onPopState); }, []);
  function logout() { fetch(`${API_BASE}/api/auth/logout`, { method: "POST", credentials: "include" }).finally(() => { redirectToLogin(); setAuthenticated(false); }); }
  if (authenticated === null) return <main className="auth-loading">CHECKING SESSION...</main>;
  if (!authenticated && path === "/login") return <AdminLogin demoLogin={demoLogin} onAuthenticated={() => { setAuthenticated(true); setPath("/dashboard"); }} />;
  if (!authenticated) return <Landing />;
  return <Dashboard onLogout={logout} onSessionExpired={() => setAuthenticated(false)} />;
}
const reactRoot = window.__CYBERGUARD_ROOT__ || createRoot(document.getElementById("root"));
window.__CYBERGUARD_ROOT__ = reactRoot;
reactRoot.render(<App />);

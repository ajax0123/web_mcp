/* app.js — CyberGuard dashboard logic, externalised from index.html so the page
   CSP can be `script-src 'self'` (no inline, no eval, no CDN) — PP-M7.
   The API target and the per-operator credential come from ./config.js
   (window.CYBERGUARD_CONFIG); nothing is baked into a downloadable asset — PP-H3. */
import { initWebMCP } from "./webmcp_bridge.js";

const CFG = (typeof window !== "undefined" && window.CYBERGUARD_CONFIG) || {};
const API_BASE = (CFG.apiBase || "http://localhost:8000").replace(/\/+$/, "");
const AUTH_HEADERS = CFG.apiKey ? { "X-API-Key": String(CFG.apiKey) } : {};
const bridge = initWebMCP(API_BASE, { headers: AUTH_HEADERS });

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------- header ---------------- */
(function setModePill() {
  const native = bridge.mode === "webmcp";
  $("modeText").textContent = native ? "NATIVE WebMCP" : "REST FALLBACK";
  $("modePill").className =
    "ml-1 flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold " +
    (native ? "bg-emerald-600 text-white" : "bg-amber-600 text-white");
  $("modeDot").className = "w-2 h-2 rounded-full " + (native ? "bg-emerald-200" : "bg-amber-200");
})();

function banner(msg) {
  const b = $("banner");
  b.classList.remove("hidden");
  b.firstElementChild.textContent = msg;
}
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 1800);
}

async function loadSummary() {
  try {
    const s = await bridge.client.getSecuritySummary();
    $("mMonitored").textContent = s.monitored_users ?? "—";
    $("mFlagged").textContent = s.flagged_suspicious_users ?? "—";
    $("mStatus").textContent = s.status ?? "—";
    $("modeDot").classList.add("running-dot");
    setTimeout(() => $("modeDot").classList.remove("running-dot"), 1200);
  } catch (e) {
    banner(`Security summary unavailable — is the API on ${API_BASE}? (${e.message})`);
  }
}

async function loadSuspicious() {
  const ul = $("suspList");
  ul.replaceChildren(el("li", "text-xs text-slate-600", "loading…"));
  try {
    const list = await bridge.client.getSuspiciousUsers(5); // helper unwraps -> array
    if (!list.length) {
      ul.replaceChildren(el("li", "text-xs text-slate-600", "none flagged"));
      return;
    }
    ul.replaceChildren();
    for (const u of list) {
      const li = document.createElement("li");
      li.className =
        "group cursor-pointer rounded-lg border border-slate-800 bg-slate-800/40 hover:border-cyan-700 " +
        "hover:bg-slate-800 px-3 py-2 transition";
      const score = Number(u.anomaly_score ?? 0);
      const sev = score >= 0.8 ? "text-red-400" : score >= 0.5 ? "text-amber-400" : "text-slate-400";

      // Build with DOM APIs + textContent only — every field below is
      // server/telemetry data and must never reach the parser as markup (H-9).
      const row1 = document.createElement("div");
      row1.className = "flex items-center justify-between";
      const uid = document.createElement("span");
      uid.className = "font-mono text-sm text-slate-100";
      uid.textContent = u.user_id ?? "?";
      const sc = document.createElement("span");
      sc.className = "text-xs font-bold " + sev;
      sc.textContent = score.toFixed(2);
      row1.append(uid, sc);

      const row2 = document.createElement("div");
      row2.className = "flex items-center justify-between mt-0.5";
      const name = document.createElement("span");
      name.className = "text-[11px] text-slate-500 truncate";
      // masked by the backend (username_masked); fall back to legacy `username`
      name.textContent = u.username_masked ?? u.username ?? "";
      const fails = document.createElement("span");
      fails.className = "text-[11px] text-slate-500";
      fails.textContent = `${u.failed_logins ?? "?"} fails`;
      row2.append(name, fails);

      li.append(row1, row2);
      li.addEventListener("click", () => runFlow(u.user_id));
      ul.appendChild(li);
    }
  } catch (e) {
    const li = document.createElement("li");
    li.className = "text-xs text-red-400";
    li.textContent = "error: " + (e && e.message ? e.message : String(e));
    ul.replaceChildren(li);
  }
}

/* ---------------- stepper ---------------- */
const PHASES = [
  { key: "DISCOVER", tools: ["get_security_summary", "get_suspicious_users"] },
  { key: "INSPECT", tools: ["investigate_user"] },
  { key: "CORRELATE", tools: ["get_user_risk_score"] },
  { key: "ATTRIBUTE", tools: ["detect_attack_pattern"] },
  { key: "REPORT", tools: ["generate_incident_report"] },
];
const phaseOf = (tool) => PHASES.find((p) => p.tools.includes(tool))?.key;

function buildStepper() {
  const stepper = $("stepper");
  stepper.replaceChildren();
  for (const p of PHASES) {
    const cell = el("div", "rounded-lg border border-slate-800 bg-slate-800/40 py-2 px-1");
    cell.dataset.phase = p.key;
    const head = el("div", "flex items-center justify-center gap-1");
    const dot = el("span", "w-2 h-2 rounded-full bg-slate-600");
    dot.dataset.dot = "";
    head.append(dot, el("span", "text-[10px] font-bold tracking-wide text-slate-400", p.key));
    const note = el("div", "text-[9px] text-slate-600 mt-0.5", "idle");
    note.dataset.note = "";
    cell.append(head, note);
    stepper.appendChild(cell);
  }
}
function setPhase(key, state, note) {
  const cell = document.querySelector(`#stepper [data-phase="${key}"]`);
  if (!cell) return;
  const dot = cell.querySelector("[data-dot]");
  const noteEl = cell.querySelector("[data-note]");
  const map = {
    idle: ["bg-slate-600", "border-slate-800", "idle", "text-slate-600"],
    running: ["bg-cyan-400 running-dot", "border-cyan-700", "running…", "text-cyan-400"],
    done: ["bg-emerald-400", "border-emerald-800", "done", "text-emerald-400"],
    skipped: ["bg-slate-700", "border-slate-800", "skipped", "text-slate-600"],
  };
  const [dotCls, borderCls, txt, noteCls] = map[state] || map.idle;
  dot.className = "w-2 h-2 rounded-full " + dotCls;
  cell.className = "rounded-lg border bg-slate-800/40 py-2 px-1 " + borderCls;
  noteEl.textContent = note || txt;
  noteEl.className = "text-[9px] mt-0.5 " + noteCls;
}

/* ==========================================================================
 * SAFE DOM RENDERING (L-6)
 * Every value below comes from the backend (`audit_trace`, `assessment`,
 * `telemetry`, `markdown_report`) and is therefore untrusted. Nothing here
 * assigns a string to `innerHTML`; all text goes through `textContent` /
 * `createTextNode`, so a hostile report string cannot become markup.
 * ======================================================================== */

/** el("div", "cls", "text") -> HTMLElement. `text` is set via textContent. */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

/* ---------------- terminal ---------------- */
function jsonDetails(label, obj) {
  const d = el("details", "flex-1 min-w-0 bg-slate-900 rounded border border-slate-800");
  d.append(
    el(
      "summary",
      "cursor-pointer select-none px-2 py-1 text-[10px] uppercase tracking-wide text-slate-500 hover:text-slate-300",
      label
    ),
    el(
      "pre",
      "px-2 pb-2 text-[11px] text-emerald-300 overflow-x-auto max-h-56",
      JSON.stringify(obj, null, 2)
    )
  );
  return d;
}
function appendTerminal(step) {
  const ts = String(step.ts || "").replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", "");
  const row = el("div", "border-b border-slate-800/70 py-2");
  const head = el("div", "flex items-center gap-2");
  head.append(
    el("span", "text-cyan-500", `[${step.step}]`),
    el("span", "text-slate-100 font-semibold", `${step.tool}()`),
    el("span", "ml-auto text-slate-600", ts)
  );
  const io = el("div", "mt-1 flex gap-2");
  io.append(jsonDetails("input", step.input), jsonDetails("output", step.output));
  row.append(head, io);
  const term = $("terminal");
  term.appendChild(row);
  term.scrollTop = term.scrollHeight;
}

/* ---------------- markdown -> DOM ----------------
 * Subset: `# `/`## ` headings, `---` rule, `|`-tables, `1. ` ordered lists,
 * `- ` unordered lists, paragraphs. Inline: **bold**, `code`, and a
 * whole-line _emphasis_. Built entirely from DOM nodes. */
function mdInlineInto(parent, text) {
  const s = String(text);
  const re = /\*\*([^*]+)\*\*|`([^`]+)`/g;
  let last = 0;
  let m;
  while ((m = re.exec(s))) {
    if (m.index > last) parent.appendChild(document.createTextNode(s.slice(last, m.index)));
    if (m[1] !== undefined) parent.appendChild(el("strong", null, m[1]));
    else parent.appendChild(el("code", "px-1 rounded bg-slate-800 text-cyan-300", m[2]));
    last = m.index + m[0].length;
  }
  if (last < s.length) parent.appendChild(document.createTextNode(s.slice(last)));
}
function mdList(tag, cls, items) {
  const list = el(tag, cls);
  for (const it of items) {
    const li = el("li");
    mdInlineInto(li, it);
    list.appendChild(li);
  }
  return list;
}
function mdTable(tbl) {
  const rows = tbl.filter((r) => !/^\|[\s:|-]+\|$/.test(r));
  const cells = (r) => r.split("|").slice(1, -1).map((c) => c.trim());
  const wrap = el("div", "overflow-x-auto my-2");
  const table = el("table", "w-full text-[11px] border-collapse");
  const thead = el("thead");
  const htr = el("tr");
  for (const h of cells(rows[0] || "")) {
    const th = el("th", "border border-slate-800 px-2 py-1 text-left bg-slate-900 text-slate-300");
    mdInlineInto(th, h);
    htr.appendChild(th);
  }
  thead.appendChild(htr);
  const tbody = el("tbody");
  for (const r of rows.slice(1)) {
    const tr = el("tr");
    for (const c of cells(r)) {
      const td = el("td", "border border-slate-800 px-2 py-1 text-slate-400");
      mdInlineInto(td, c);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.append(thead, tbody);
  wrap.appendChild(table);
  return wrap;
}
function renderMarkdownInto(root, md) {
  root.replaceChildren();
  const lines = String(md || "").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (line.startsWith("# ")) {
      const h = el("h1", "text-base font-bold text-slate-100 mb-2");
      mdInlineInto(h, line.slice(2)); root.appendChild(h); i++; continue;
    }
    if (line.startsWith("## ")) {
      const h = el("h2", "text-xs font-semibold uppercase tracking-wide text-cyan-400 mt-4 mb-1");
      mdInlineInto(h, line.slice(3)); root.appendChild(h); i++; continue;
    }
    if (/^-{3,}$/.test(line.trim())) { root.appendChild(el("hr", "my-3 border-slate-800")); i++; continue; }
    if (line.startsWith("|")) {
      const tbl = [];
      while (i < lines.length && lines[i].startsWith("|")) { tbl.push(lines[i]); i++; }
      root.appendChild(mdTable(tbl));
      continue;
    }
    if (/^\d+\.\s/.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) { items.push(lines[i].replace(/^\d+\.\s/, "")); i++; }
      root.appendChild(mdList("ol", "list-decimal list-inside space-y-1 my-2 text-[11px] text-slate-400", items));
      continue;
    }
    if (line.startsWith("- ")) {
      const items = [];
      while (i < lines.length && lines[i].startsWith("- ")) { items.push(lines[i].slice(2)); i++; }
      root.appendChild(mdList("ul", "list-disc list-inside space-y-1 my-2 text-[11px] text-slate-400", items));
      continue;
    }
    const p = el("p", "text-[11px] text-slate-400 my-1");
    const em = line.match(/^_(.+)_$/);
    if (em) p.appendChild(el("em", "text-slate-500", em[1]));
    else mdInlineInto(p, line);
    root.appendChild(p);
    i++;
  }
}

/* ---------------- findings ---------------- */
const SEV_CLASS = { CRITICAL: "bg-red-600", HIGH: "bg-orange-500", MEDIUM: "bg-amber-500", LOW: "bg-slate-500" };
function tile(label, value) {
  const t = el("div", "rounded-lg border border-slate-800 bg-slate-950 px-2 py-2");
  t.append(
    el("div", "text-[10px] uppercase tracking-wide text-slate-500", label),
    el("div", "text-sm font-bold text-slate-100 mt-0.5 truncate", value)
  );
  return t;
}
function renderFindings(r) {
  const a = r.assessment || {};
  const t = r.telemetry || {};
  // sevCls comes from a fixed whitelist; a hostile `severity` only misses the
  // map and falls back to a constant class — it is never interpolated as markup.
  const sevCls = SEV_CLASS[a.severity] || "bg-slate-600";

  const badge = $("threatBadge");
  badge.replaceChildren(
    el("div", "text-xs uppercase tracking-widest text-slate-500", "Threat Attribution"),
    el("div", "mt-1 text-lg font-bold text-slate-100", a.threat_classification ?? "—")
  );
  const meta = el("div", "mt-2 flex items-center gap-2 flex-wrap");
  meta.append(
    el("span", "px-2 py-0.5 rounded text-xs font-bold text-white " + sevCls, a.severity ?? "—"),
    el("span", "text-sm text-slate-300", (a.confidence_pct ?? "—") + "% confidence"),
    el("span", "ml-auto text-xs font-mono text-slate-500", a.mitre_technique_id ?? "")
  );
  badge.appendChild(meta);

  $("metrics").replaceChildren(
    tile("Failed Logins", t.failed_logins ?? "—"),
    tile("Successful", t.successful_logins ?? "—"),
    tile("Unique IPs", t.unique_ip_count ?? (t.unique_ips || []).length),
    tile("Anomaly Score", t.anomaly_score ?? "—"),
    tile("MITRE ID", a.mitre_technique_id ?? "—"),
    tile("Risk Score", a.risk_score ?? "—")
  );
}
function renderReport(md) {
  const box = $("report");
  if (md) renderMarkdownInto(box, md);
  else box.replaceChildren(el("p", "text-slate-600 text-sm", "No report."));
  const btn = $("btnCopy");
  btn.disabled = !md;
  btn.onclick = async () => {
    try { await navigator.clipboard.writeText(md); toast("Report copied to clipboard"); }
    catch { toast("Clipboard blocked by browser"); }
  };
}

/* ---------------- run ---------------- */
let running = false;
function setBusy(b) {
  running = b;
  for (const id of ["btnAuto", "btnTarget", "btnRefresh"]) $(id).disabled = b;
  document.querySelectorAll("#suspList li").forEach((li) => (li.style.pointerEvents = b ? "none" : ""));
}
/** Append one line of server/status text to the terminal (L-6: textContent). */
function termLine(cls, text) {
  const t = $("terminal");
  t.appendChild(el("div", cls, text));
  t.scrollTop = t.scrollHeight;
}

async function runFlow(userId) {
  if (running) return;
  setBusy(true);
  $("banner").classList.add("hidden");
  buildStepper();
  $("terminal").replaceChildren(
    el("div", "text-cyan-500", "// investigating " + (userId || "worst offender (auto-triage)") + " …")
  );
  $("runSource").textContent = "";
  const t0 = performance.now();

  let result;
  try {
    result = await bridge.runInvestigation(userId || null);
  } catch (e) {
    termLine("text-red-400 mt-2", "[ERROR] " + (e && e.message ? e.message : String(e)));
    banner(`Investigation failed: ${e.message}`);
    setBusy(false);
    return;
  }

  if (result.status && result.status !== "COMPLETE") {
    termLine("text-amber-400 mt-2", "[" + result.status + "] " + (result.message || ""));
    if (result._server_error) termLine("text-slate-600", "server: " + result._server_error);
    if (result.correlation_id) termLine("text-slate-600", "correlation_id: " + result.correlation_id);
    setBusy(false);
    return;
  }

  await animateTrace(result);
  renderFindings(result);
  renderReport(result.markdown_report);

  const ms = Math.round(performance.now() - t0);
  const src = result._source === "server_agent" ? "server agent loop" : "client fallback chain";
  $("runSource").textContent = `${src} · ${ms}ms`;
  if (result._server_error) banner(`Server agent unreachable (${result._server_error}); ran client-side fallback.`);
  setBusy(false);
}

async function animateTrace(result) {
  const trace = result.audit_trace || [];
  const seen = new Set(trace.map((s) => phaseOf(s.tool)).filter(Boolean));
  for (const p of PHASES) {
    if (seen.has(p.key)) continue;
    const note = p.key === "DISCOVER" && result.auto_selected === false ? "target supplied" : undefined;
    setPhase(p.key, "skipped", note);
  }
  for (const step of trace) {
    const ph = phaseOf(step.tool);
    if (ph) setPhase(ph, "running");
    appendTerminal(step);
    await sleep(430);
    const phase = PHASES.find((p) => p.key === ph);
    if (phase && phase.tools[phase.tools.length - 1] === step.tool) setPhase(ph, "done");
  }
  for (const key of seen) setPhase(key, "done");
  termLine("text-emerald-400 mt-2", "// investigation complete — " + (result.target_user_id || ""));
}

/* ---------------- wire up ---------------- */
$("btnAuto").addEventListener("click", () => runFlow(null));
$("btnTarget").addEventListener("click", () => runFlow($("inpTarget").value.trim() || null));
$("inpTarget").addEventListener("keydown", (e) => { if (e.key === "Enter") runFlow($("inpTarget").value.trim() || null); });
$("btnRefresh").addEventListener("click", loadSuspicious);

buildStepper();
loadSummary();
loadSuspicious();

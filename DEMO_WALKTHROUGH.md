# CyberGuard SOC — Demo Walkthrough

**Autonomous Tier-2 SOC investigation, driven from the browser via WebMCP.**

Manual log triage is slow and disjointed. This project turns a website's telemetry
and a set of data-science anomaly models into **callable agent tools**, then lets an
agent run the entire investigation lifecycle — DISCOVER → INSPECT → CORRELATE →
ATTRIBUTE → REPORT — from a single click, ending in an executive incident report.

Built across four phases:

| Phase | Deliverable | Key files |
| :--- | :--- | :--- |
| 1 | MCP stdio server + FastAPI ML backend | `cyberguard_mcp_server.py`, `cyberguard_api/main.py`, `cyberguard_api/models/*` |
| 2 | WebMCP in-browser bridge + REST facade + test harness | `frontend/webmcp_bridge.js`, `cyberguard_api/routes_webmcp.py`, `frontend/test_webmcp.html` |
| 3 | Autonomous agent investigation loop | `cyberguard_api/services/agent_controller.py`, `POST /api/v1/agent/investigate` |
| 4 | Interactive investigation dashboard | `frontend/index.html`, `runInvestigation()` in the bridge |

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  BROWSER   http://localhost:5173                                                 │
│                                                                                 │
│   frontend/index.html — Investigation Dashboard  (Tailwind CDN, zero build)      │
│     Header: mode pill + security metrics                                         │
│     Left:  Auto-Triage · Target lookup · clickable suspicious-user list          │
│     Mid:   live stepper  DISCOVER→INSPECT→CORRELATE→ATTRIBUTE→REPORT             │
│            + expandable JSON viewers (tool input / output)                        │
│     Right: threat badge · telemetry tiles · rendered Markdown report + Copy      │
│                              │                                                   │
│                              ▼                                                   │
│   frontend/webmcp_bridge.js — WebMCP In-Browser Bridge                           │
│     • initWebMCP(apiBase)                                                        │
│     • navigator.modelContext.registerTool(...)   ← NATIVE WebMCP  (if present)   │
│     • CyberGuardFallbackClient                   ← REST FALLBACK  (always works) │
│     • runInvestigation(userId?)   ── high-level orchestration helper             │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               │   HTTP / JSON      CORS allow: :3000, :5173
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  FASTAPI BACKEND   http://localhost:8000        cyberguard_api/                   │
│                                                                                 │
│   routes_webmcp.py — WebMCP REST facade   /api/v1/*                              │
│     GET  /security/summary            GET  /users/suspicious?limit=              │
│     GET  /users/{id}/investigate      GET  /users/{id}/risk-score               │
│     POST /analyze/attack-pattern      POST /reports/incident                     │
│     POST /agent/investigate ─────────────────┐   GET /webmcp/manifest            │
│                                              ▼                                   │
│   services/agent_controller.py — run_autonomous_investigation(user_id?)         │
│     a. TRIAGE       get_security_summary + get_suspicious_users(3) → max anomaly │
│     b. DEEP-DIVE    investigate_user → get_user_risk_score                       │
│     c. ATTRIBUTION  detect_attack_pattern                                        │
│     d. REGISTRATION generate_incident_report                                     │
│        → consolidated JSON  { assessment, telemetry, audit_trace, markdown }     │
│                    │                                    │                        │
│          ┌─────────┘                                    └──────────┐             │
│          ▼                                                         ▼             │
│   TELEMETRY STORE                                     ML INFERENCE  models/*.pkl │
│   MOCK_TELEMETRY — services/telemetry.py (10 users)   • cyberguard_rf_final.pkl  │
│     USR-205 0.96 BF · USR-402 0.93 ATO · USR-319 0.88   login attack RF          │
│     CS · USR-512 0.74 · USR-108 0.68 flagged (≥0.60)    32 feat → 1037, thr 0.55 │
│     + USR-620/733/814/905/101  medium → normal        • isolation_forest_model   │
│                                                        behavioral anomaly, 13ft │
│   (investigate_user / get_user_risk_score /          • network_attack_model +   │
│    heuristic detect_attack_pattern read here)          bot_specialist_model     │
│                                                        CICIDS flow RF, 65ft/15c │
│                                                      (services/network_detector)│
└─────────────────────────────────────────────────────────────────────────────────┘

  Parallel surface — cyberguard_mcp_server.py (FastMCP, stdio, see .mcp.json)
    exposes the SAME six tools to desktop MCP hosts (e.g. Claude Desktop).
```

**How the ML models are reached.** The autonomous agent only has a `user_id`, so
`detect_attack_pattern` runs a **grounded heuristic over the telemetry store**
(`_heuristic_pattern`). Supplying a feature vector to
`POST /api/v1/analyze/attack-pattern` invokes the real models:
`login_event` (32 features) → `cyberguard_rf_final.pkl`; `network_flow`
(65 features) → `network_attack_model.pkl` + `bot_specialist_model.pkl`.
The isolation-forest anomaly score is served through the legacy
`POST /get_user_risk_score` route in `main.py`.

---

## 2. Quick-Start (2 terminals)

Prereqs: **Python 3.12** (3.14 has no `scikit-learn==1.6.1` wheels), a modern browser.

### Terminal 1 — FastAPI backend on port 8000

```bash
cd web_mcp

# first run only
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r cyberguard_api/requirements.txt

# run (from the repo root — the app is the package cyberguard_api.main)
uvicorn cyberguard_api.main:app --host 0.0.0.0 --port 8000 --reload
```

Wait for `CyberGuard models loaded successfully`. Sanity check:

```bash
curl -s localhost:8000/health
# {"status":"ok","models_loaded":{"random_forest":true,"preprocessor":true,"isolation_forest":true,"scaler":true}}
```

### Terminal 2 — static frontend on port 5173

```bash
cd web_mcp/frontend
python3 -m http.server 5173
```

Open **http://localhost:5173/index.html**.

> Port **5173** is not arbitrary — it is in the backend CORS allowlist
> (`DEFAULT_DEV_ORIGINS` in `routes_webmcp.py`, alongside `:3000`). Serving the
> page from any other origin needs `register_webmcp_routes(app, extra_origins=[...])`.

Bridge contract sandbox: **http://localhost:5173/test_webmcp.html**.

---

## 3. The demo click-path

1. **Open the dashboard.** Header pill reads `REST FALLBACK` in a normal browser
   (there is no `navigator.modelContext`); it reads `NATIVE WebMCP` only inside a
   WebMCP-enabled agent runtime. Security metrics load: Monitored **10**, Flagged
   **5**, Status `ELEVATED_RISK`. Left panel lists the top 5 by anomaly score —
   USR-205 (0.96), USR-402 (0.93), USR-319 (0.88), USR-512 (0.74), USR-108 (0.68).

2. **Click "Auto-Triage & Investigate Worst Offender."** One call to
   `bridge.runInvestigation(null)` → `POST /api/v1/agent/investigate`. Triage
   ranks the pool and auto-selects **USR-205** (highest anomaly score, 0.96).

3. **Watch the stepper.** DISCOVER → INSPECT → CORRELATE → ATTRIBUTE → REPORT
   light up as the audit trace replays. Each step has `input` / `output` JSON you
   can expand in the terminal pane.

4. **Read the auto-triage findings (right panel).**
   - Threat badge: **Brute Force** · **CRITICAL** · **88% confidence**
   - Tiles: Failed Logins **38** · Successful **0** · Unique IPs **1** ·
     Anomaly Score **0.96** · MITRE **T1110.001** · Risk Score **96**
   - Incident report `INC-2026-<hex>`, rendered from Markdown.

5. **Flagship Account Takeover showcase.** Type `USR-402` → *Investigate* (or click
   the row). DISCOVER shows *skipped — target supplied*; steps 3–6 run.
   - Threat badge: **Account Takeover (ATO)** · **CRITICAL** · **93% confidence**
   - Tiles: Failed Logins **47** · Successful **1** · Unique IPs **3** ·
     Anomaly Score **0.93** · MITRE **T1078.004** · Risk Score **93**

6. **Click "Copy Report."** The full executive incident report is on the clipboard,
   ready to paste into a ticket.

7. **Other targeted runs.** Any of the 10 seeded IDs works — e.g. `USR-319`
   (Credential Stuffing, `T1110.004`), `USR-108` (Suspicious Authentication),
   `USR-905` (Normal baseline). The trace runs steps 3–6 only.

If the backend agent endpoint is unreachable, `runInvestigation()` transparently
falls back to **client-side sequential tool chaining** (same six tools, same
response shape); the footer then reads `client fallback chain` and a banner notes it.

---

## 4. 90-Second Live Hackathon Pitch

> **[0:00–0:15] — The Hook**
> "A SOC analyst opens their shift to forty thousand login events across five
> consoles. Traditional dashboards show what *happened* — charts, counts,
> timelines — but not which account to open first or what the story is. Triage is
> manual, slow, and disjointed."

> **[0:15–0:35] — The Innovation**
> "We used **WebMCP** to turn the website's own telemetry and our data-science
> anomaly models into **callable agent tools**, right in the browser.
> `navigator.modelContext.registerTool` exposes `get_suspicious_users`,
> `investigate_user`, `get_user_risk_score`, `detect_attack_pattern`,
> `generate_incident_report`. Any WebMCP-aware agent — or our built-in fallback
> client — can now drive a full investigation. No per-client backend glue."
> *(point at the header mode pill)*

> **[0:35–1:10] — The Demonstration**
> *(click "Auto-Triage & Investigate Worst Offender")*
> "One click. The agent triages a 10-user pool, picks the worst offender —
> **USR-205**, anomaly **0.96** — and runs the lifecycle autonomously —"
> *(point at the stepper animating)*
> "**DISCOVER** the suspicious set, **INSPECT** the top user's telemetry,
> **CORRELATE** the ML risk score, **ATTRIBUTE** the attack pattern, **REPORT** —
> thirty-eight failed logins, no success, single source IP: **Brute Force**,
> **CRITICAL**, MITRE **T1110.001**."
> *(type `USR-402`, click Investigate — the flagship case)*
> "Or point it at a specific account. USR-402: **Account Takeover**, **93%
> confidence**, MITRE **T1078.004** — forty-seven failed logins then one success,
> geo-velocity flag set, three source IPs, four new devices. Every step is in the
> audit trace with its tool inputs and outputs."
> *(click "Copy Report")*
> "And the analyst walks away with a formatted executive incident report in the
> clipboard."

> **[1:10–1:30] — The Safety Boundary**
> "Hard guardrail: this agent is **analytical only**. It never terminates a
> session, revokes a token, or edits a firewall rule. Every remediation is a
> *recommendation* tagged for human authorization — *'Recommend SOC Admin trigger
> 2FA reset.'* The human stays in the loop on every destructive action."

---

## 5. Investigation lifecycle → tools → endpoints

| Stepper phase | Tool(s) | REST endpoint | Reads |
| :--- | :--- | :--- | :--- |
| **DISCOVER** | `get_security_summary`, `get_suspicious_users` | `GET /api/v1/security/summary`, `GET /api/v1/users/suspicious?limit=3` | telemetry store |
| **INSPECT** | `investigate_user` | `GET /api/v1/users/{id}/investigate` | telemetry store |
| **CORRELATE** | `get_user_risk_score` | `GET /api/v1/users/{id}/risk-score` | telemetry store (anomaly→0-100) |
| **ATTRIBUTE** | `detect_attack_pattern` | `POST /api/v1/analyze/attack-pattern` | heuristic; RF/bot-specialist when `login_event`/`network_flow` supplied |
| **REPORT** | `generate_incident_report` | `POST /api/v1/reports/incident` | — (formats + registers `INC-YYYY-NNNN`) |

Orchestrator: `POST /api/v1/agent/investigate` `{ "user_id": "USR-402" }` (body
optional). Response keys: `status`, `target_user_id`, `auto_selected`,
`selection_reason`, `assessment` `{threat_classification, severity, confidence,
confidence_pct, mitre_technique_id, attack_detected, risk_score}`, `triage`,
`telemetry`, `risk_score`, `attack_attribution`, `incident`,
`recommended_actions`, `markdown_report`, `audit_trace[]`
`{step, tool, input, output, ts}`.

---

## 6. Safety & scope guardrails

- **Analytical & recommendation only.** No tool terminates accounts, revokes
  tokens, modifies `iptables`, or calls any mutating security control.
- Remediation is emitted as **human-authorized recommendations**
  (`recommended_actions[]`), e.g. *"Recommend SOC Admin invalidate active
  sessions"*, *"Recommend SOC Admin trigger MFA / 2FA credential reset"*.
- The incident report footer states the run was *"analytical only, no remediation
  executed."*
- Every claim in a report is anchored to a tool output captured in `audit_trace`
  — no free-form invention of IPs, users, or metrics.
- `generate_incident_report` only **records** an incident id + the recommendation
  list; it does not dispatch anything.

---

## 7. Team Handoff Matrix

Person 1 (integration): WebMCP bridge, agent controller, REST facade, dashboard —
this repo. The three roles below plug into fixed contracts.

### Person 2 — Data Science

| | |
| :--- | :--- |
| **Owns** | `cyberguard_api/models/*.pkl` + `*_metadata.json`, `cyberguard_api/services/network_detector.py`, the (external) training pipeline |
| **Inputs** | labeled login events (32 engineered features), behavioral aggregates (13 features), CICIDS network flows (65 features) |
| **Outputs** | `cyberguard_rf_final.pkl` + `cyberguard_preprocessor_final.pkl` (login-attack probability, decision threshold `0.55`); `isolation_forest_model.pkl` + `feature_scaler.pkl` (behavioral anomaly score); `network_attack_model.pkl` + `bot_specialist_model.pkl` + `network_imputer.pkl` + `network_label_encoder.pkl` (15-class attack type) |
| **Contract** | pickles **must load under `scikit-learn==1.6.1`**; estimators expose `feature_names_in_`; exact feature order recorded in the metadata JSON; RF exposes `predict_proba`, isolation forest exposes `decision_function` + `predict`; imputer is a fitted `SimpleImputer` with `feature_names_in_` (65) |
| **Next** | replace the `_heuristic_pattern` telemetry heuristic with a real per-user feature-vector call into `cyberguard_rf_final.pkl`; ship a documented feature-builder that maps a `user_id` → 32-feature login vector |

### Person 3 — Cybersecurity rules

| | |
| :--- | :--- |
| **Owns** | classification thresholds in `_heuristic_pattern()` and `_name_login_pattern()` (`routes_webmcp.py`), `NETWORK_MITRE` map, severity policy `_severity_from()` and recommendation builders `_recommendations()` (`agent_controller.py`) / `clientRecommendations()` (`webmcp_bridge.js`) |
| **Inputs** | telemetry counters (`failed_logins`, `successful_logins`, `unique_ips`, `geo_velocity_violation`, `device_changes`, `anomaly_score`) and ML outputs (probability, class, confidence) |
| **Outputs** | `classified_pattern` ∈ {Normal, Brute Force, Credential Stuffing, Account Takeover (ATO), …}; `mitre_technique_id` (valid ATT&CK id, e.g. `T1078.004`); `severity` ∈ {LOW, MEDIUM, HIGH, CRITICAL}; non-destructive `recommendations[]` |
| **Contract** | recommendation strings stay **analytical** — no auto-remediation verbs; severity enum is fixed (validated by `IncidentRequest`); `classified_pattern` strings drive the recommendation switch — **keep `agent_controller.py` and `webmcp_bridge.js` in sync**; MITRE ids must resolve on attack.mitre.org |
| **Next** | promote heuristics to a declarative rules table / decision file; add coverage for password spraying, session hijacking, MFA-fatigue; wire the RF probability into pattern selection once Person 2's feature-builder lands |

### Person 4 — DevOps / Deployment

| | |
| :--- | :--- |
| **Owns** | `.venv`, `cyberguard_api/requirements.txt`, CORS config (`configure_cors` / `DEFAULT_DEV_ORIGINS`), `.gitignore`, static hosting for `frontend/`, `.mcp.json` |
| **Inputs** | this repo; Python 3.12 runtime; model pickles (~170 MB total — candidate for Git LFS or object storage, not plain git) |
| **Outputs** | reproducible 2-process run today (uvicorn `:8000` + static `:5173`); for prod: reverse proxy, real `allow_origins`, model volume mount, liveness probe on `GET /health` |
| **Contract** | run `uvicorn cyberguard_api.main:app` **from the repo root** (package import — not from inside `cyberguard_api/`); `frontend/index.html` hardcodes `const API_BASE = "http://localhost:8000"` and the bridge's `DEFAULT_ROUTES` are all `/api/v1/...` — both must point at the deployed API origin; the deployed frontend origin **must** be added to the CORS allowlist; models mounted at `cyberguard_api/models/` |
| **Next** | multi-stage `Dockerfile` (cache the model layer); env-driven `API_BASE` + `cors_origins`; CI smoke test: `POST /api/v1/agent/investigate` asserts `status == "COMPLETE"` |

---

## 8. Verification checklist

```bash
# backend up, all four models loaded
curl -s localhost:8000/health | grep -q '"random_forest":true' && echo OK

# 10-user pool surfaced by the summary
curl -s localhost:8000/api/v1/security/summary
# -> {"monitored_users":10,"flagged_suspicious_users":5,"high_severity_alerts":3,"status":"ELEVATED_RISK"}

# full autonomous pipeline, no human input — auto-triage picks the worst offender
curl -s -X POST localhost:8000/api/v1/agent/investigate \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); \
    assert d["status"]=="COMPLETE" and d["target_user_id"]=="USR-205"; \
    print(d["assessment"]["threat_classification"], d["assessment"]["severity"], \
          str(d["assessment"]["confidence_pct"])+"%")'
# -> Brute Force CRITICAL 88%

# flagship Account Takeover showcase — explicit target
curl -s -X POST localhost:8000/api/v1/agent/investigate -d '{"user_id":"USR-402"}' \
  -H 'content-type: application/json' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); \
    print(d["assessment"]["threat_classification"], d["assessment"]["severity"], \
          str(d["assessment"]["confidence_pct"])+"%")'
# -> Account Takeover (ATO) CRITICAL 93%

# tool -> route map
curl -s localhost:8000/api/v1/webmcp/manifest | python3 -m json.tool

# frontend served + bridge resolves
curl -s -o /dev/null -w '%{http_code}\n' localhost:5173/index.html          # 200
curl -s -o /dev/null -w '%{http_code}\n' localhost:5173/webmcp_bridge.js    # 200
```

Then: open `index.html`, click **Auto-Triage & Investigate Worst Offender**,
confirm the stepper completes and the report renders.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| `ModuleNotFoundError: No module named 'cyberguard_api'` | run `uvicorn` from `web_mcp/` (repo root), not from inside `cyberguard_api/` |
| `module 'sklearn...' has no attribute '_RemainderColsList'` | wrong scikit-learn; the pickles need **1.6.1** (`pip install -r cyberguard_api/requirements.txt` in the 3.12 venv) |
| Browser console: CORS error | serve the frontend from `http://localhost:5173` (or `:3000`), or add the origin via `register_webmcp_routes(app, extra_origins=[...])` |
| Header pill stuck on `REST FALLBACK` | expected in a normal browser — there is no `navigator.modelContext`; native mode appears only inside a WebMCP agent runtime |
| Dashboard footer says `client fallback chain` + banner | the `/api/v1/agent/investigate` endpoint errored; the bridge chained the six tools client-side instead — check the backend logs |
| `login model inference unavailable` (503 on `/api/v1/analyze/attack-pattern` with `login_event`) | preprocessor pickle failed to load — same scikit-learn version issue |

# CyberGuard SOC — WebMCP Autonomous Investigation

Turn a website's security telemetry and its data-science anomaly models into
**callable agent tools** via [WebMCP](https://github.com/webmachinelearning/webmcp),
then let an agent run a full Tier-2 SOC investigation —
**DISCOVER → INSPECT → CORRELATE → ATTRIBUTE → REPORT** — from a single click,
ending in an executive incident report.

> **Stack:** FastAPI · scikit-learn 1.6.1 · WebMCP (`navigator.modelContext`) ·
> vanilla-JS + Tailwind CDN dashboard · FastMCP stdio server.

For the architecture diagram, the 90-second pitch script, and the team handoff
matrix, see **[`DEMO_WALKTHROUGH.md`](DEMO_WALKTHROUGH.md)**.

---

## What it does

- **6 SOC tools** — `get_security_summary`, `get_suspicious_users`,
  `investigate_user`, `get_user_risk_score`, `detect_attack_pattern`,
  `generate_incident_report` — exposed three ways:
  - **Native WebMCP** in the browser (`navigator.modelContext.registerTool`)
  - **REST** under `/api/v1/*` (fallback client, always works)
  - **MCP stdio** for desktop hosts (`cyberguard_mcp_server.py`, see `.mcp.json`)
- **Autonomous agent loop** (`POST /api/v1/agent/investigate`) that triages,
  deep-dives, attributes an attack pattern (with MITRE ATT&CK id), and registers
  an incident — returning a consolidated JSON + Markdown report + full audit trace.
- **Interactive dashboard** (`frontend/index.html`) with a live stepper,
  expandable tool-I/O JSON viewers, threat badge, telemetry tiles, and a
  copy-ready incident report.
- **ML models**: login-attack Random Forest (32→1037 features, ROC-AUC 0.88),
  behavioral isolation forest (13 features), 15-class CICIDS network-flow RF with
  a bot-specialist validator.

**Safety:** analytical and recommendation only. No tool terminates accounts,
revokes tokens, or edits firewall rules — every remediation is a human-authorized
recommendation.

---

## Quick start (2 terminals)

Requires **CPython 3.11 or 3.12** (pinned in `.python-version` / `pyproject.toml`;
3.13+ has no `scikit-learn==1.6.1` wheels). One-shot setup:

```bash
cd web_mcp
scripts/bootstrap.sh          # builds a clean .venv, installs pins, verifies import
```

```bash
# -- Terminal 1 -- FastAPI backend on :8000 -----------------------
cd web_mcp
source .venv/bin/activate
uvicorn cyberguard_api.main:app --host 0.0.0.0 --port 8000 --reload   # dev
#   production-style:  scripts/run.sh   (workers + --proxy-headers, no --reload)
#   the app is the package `cyberguard_api.main`; run from the repo root

# -- Terminal 2 -- static frontend on :5173 ----------------------
cd web_mcp/frontend
python3 serve.py 5173          # static server WITH security headers + CSP (PP-M7)
#   open http://localhost:5173/index.html
```

Port **5173** is required — it is in the backend CORS allowlist
(`DEFAULT_DEV_ORIGINS`, alongside `:3000`). Then click
**"Auto-Triage & Investigate Worst Offender"**.

The dashboard is zero-CDN: Tailwind is precompiled into `frontend/app.css`, the
logic is `frontend/app.js`, and the **API target + operator key** come from
`frontend/config.js` (edit it, or template it from the deploy — no secret is
baked into `index.html`). When the API runs with `API_KEYS` set, put a
per-operator key in `config.js` as `apiKey`.

`APP_ENV` defaults to `dev`, where `API_KEYS` may be empty and `/api/v1/*` is
open (logged warning). Set `APP_ENV=production` and you must also set `API_KEYS`
and `CORS_ORIGINS` or the process refuses to start. See `.env.example`.

Quick check:

```bash
curl -s localhost:8000/health          # {"status":"ok"} — process liveness only
curl -s localhost:8000/readyz          # 200 once every ML model is loaded + verified, else 503
curl -s -X POST localhost:8000/api/v1/agent/investigate | python3 -m json.tool   # dev: no key needed
# with auth enabled:  curl -H "X-API-Key: $KEY" ...
```

---

## Repository structure

```
web_mcp/
├── cyberguard_mcp_server.py        FastMCP stdio server — 6 tools (desktop MCP hosts)
├── .mcp.json                       stdio server registration
├── cyberguard_api/                 FastAPI application (run as a package from repo root)
│   ├── main.py                     app + startup model load + legacy ML scoring routes
│   ├── routes_webmcp.py            WebMCP REST facade /api/v1/*, CORS, telemetry store,
│   │                               ML attack-pattern inference
│   ├── services/
│   │   ├── network_detector.py     network RF + bot-specialist pipeline
│   │   └── agent_controller.py     run_autonomous_investigation() — the agent loop
│   ├── models/                     *.pkl model artifacts + *_metadata.json
│   └── requirements.txt            pinned deps (scikit-learn==1.6.1)
└── frontend/                       static, zero-build
    ├── webmcp_bridge.js            WebMCP bridge + CyberGuardFallbackClient + runInvestigation()
    ├── index.html                  Phase 4 investigation dashboard (Tailwind CDN)
    └── test_webmcp.html            bridge contract / integration sandbox
```

---

## API reference

### WebMCP REST facade — `/api/v1/*` (`routes_webmcp.py`)

| Method | Path | Tool | Notes |
| :--- | :--- | :--- | :--- |
| GET | `/api/v1/security/summary` | `get_security_summary` | counts + status |
| GET | `/api/v1/users/suspicious?limit=` | `get_suspicious_users` | `{ result: [...] }`, ranked by anomaly |
| GET | `/api/v1/users/{user_id}/investigate` | `investigate_user` | 404 if unknown |
| GET | `/api/v1/users/{user_id}/risk-score` | `get_user_risk_score` | 0–100 + factors |
| POST | `/api/v1/analyze/attack-pattern` | `detect_attack_pattern` | `{user_id, login_event?, network_flow?}` — feature vector selects RF vs heuristic |
| POST | `/api/v1/reports/incident` | `generate_incident_report` | `{user_id, threat_type, severity, recommendations[]}` |
| POST | `/api/v1/agent/investigate` | — | `{user_id?}` — autonomous loop, full assessment |
| GET | `/api/v1/webmcp/manifest` | — | tool → route map |

### Legacy ML scoring routes (`main.py`)

| Method | Path | Model |
| :--- | :--- | :--- |
| GET | `/` | service info |
| GET | `/health` | process liveness — `{"status":"ok"}` |
| GET | `/readyz` | readiness — 200 once all ML models load + verify, else 503 |
| POST | `/analyze_ip` | `cyberguard_rf_final.pkl` (List[LoginEvent], 32 features) — **API key required** |
| POST | `/get_user_risk_score` | `isolation_forest_model.pkl` (List[UserBehaviorInput], 13 features) — **API key required** |
| POST | `/detect_attack_pattern` | `network_attack_model.pkl` + `bot_specialist_model.pkl` (65 features) — **API key required** |

All `/api/v1/*` routes and the three ML POST routes require `X-API-Key` /
`Authorization: Bearer` (bypassed only when `APP_ENV=dev` and `API_KEYS` is
unset). Every response carries `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy`, a `Content-Security-Policy`, and (in production) HSTS. Bodies
over `MAX_BODY_BYTES` (default 1 MB) get a `413` at the ASGI edge. Per-client
rate limiting via `slowapi` (`RATE_LIMIT`, default `60/minute`).

---

## Using the bridge

```js
import { initWebMCP } from "./webmcp_bridge.js";

const bridge = initWebMCP("http://localhost:8000");
// bridge.mode            -> "webmcp" | "fallback"
// bridge.client          -> CyberGuardFallbackClient (always available)
// bridge.registeredTools -> tools registered with native WebMCP

// individual tools
const suspects = await bridge.client.getSuspiciousUsers(1); // array (envelope unwrapped)
const risk     = await bridge.client.getUserRiskScore(suspects[0].user_id);

// full autonomous investigation (server agent, or client-side fallback chain)
const result = await bridge.runInvestigation();      // or runInvestigation("USR-402")
result.assessment;       // { threat_classification, severity, confidence_pct, mitre_technique_id }
result.telemetry;        // { failed_logins, successful_logins, unique_ips, anomaly_score, ... }
result.audit_trace;      // [ { step, tool, input, output, ts } ]
result.markdown_report;  // string, ready to render
result._source;          // "server_agent" | "client_fallback"
```

Exports: `initWebMCP` (default + named), `CyberGuardFallbackClient`,
`isWebMCPSupported`, `WEBMCP_TOOL_DEFS`, `TOOL_NAMES`, `DEFAULT_ROUTES`,
`validateArgs`, `getToolDef`. A `window.CyberGuardWebMCP` handle is attached for
console debugging. Load as `<script type="module">` — ES modules need an HTTP
origin (not `file://`).

---

## Phases

| Phase | Scope |
| :--- | :--- |
| 1 | MCP stdio server + FastAPI ML backend + DS models |
| 2 | WebMCP in-browser bridge, `/api/v1/*` REST facade, `test_webmcp.html` |
| 3 | Autonomous agent loop — `agent_controller.py`, `POST /api/v1/agent/investigate` |
| 4 | Interactive dashboard — `index.html`, `runInvestigation()` orchestration helper |

---

## Verification

```bash
# 1. a clean checkout installs + imports with zero errors (C-1)
scripts/fresh_clone_check.sh

# 2. models loaded + verified (M-9)
curl -sf localhost:8000/readyz | grep -q '"status": "ready"' && echo "models OK"

# 3. security response headers (H-4)
curl -sI localhost:8000/health | grep -Ei 'x-frame-options|x-content-type-options|content-security-policy'

# 4. oversized payload is refused at the edge (M-11)
head -c 2000000 /dev/zero | tr '\0' 'a' \
  | curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8000/detect_attack_pattern \
      -H 'content-type: application/json' --data-binary @-      # -> 413

# 5. end-to-end agent run (dev; add -H "X-API-Key: $KEY" once auth is enabled)
curl -s -X POST localhost:8000/api/v1/agent/investigate \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); \
    assert d["status"]=="COMPLETE"; print(d["target_user_id"], d["assessment"])'
# auto-triage picks the worst offender in the 10-user pool:
# -> USR-205  Brute Force / CRITICAL / 88%  (anomaly 0.96)
# target USR-402 explicitly ({"user_id":"USR-402"}) for the Account Takeover showcase

# 6. gateway unit tests
.venv/bin/pytest tests/test_gateway.py
```

See **[`DEMO_WALKTHROUGH.md` §8](DEMO_WALKTHROUGH.md)** for the full checklist and
**§9** for troubleshooting (`ModuleNotFoundError`, `_RemainderColsList`, CORS).

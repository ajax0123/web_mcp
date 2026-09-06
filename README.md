# CyberGuard — Agent-Native Autonomous SOC Platform

![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![WebMCP](https://img.shields.io/badge/WebMCP-Standard-6E44FF)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.6.1-F7931E?logo=scikitlearn&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-Deployed-000000?logo=vercel&logoColor=white)
![Render](https://img.shields.io/badge/Render-Deployed-46E3B7?logo=render&logoColor=white)

CyberGuard turns a website's authentication telemetry and its machine-learning
anomaly models into **callable agent tools** through the
[WebMCP](https://github.com/webmachinelearning/webmcp) standard, then lets an
agent run a complete Tier‑2 SOC investigation — from triage to a signed-off
executive incident report — with a single click.

### Live deployment

| Surface | URL |
| :--- | :--- |
| **Frontend dashboard** (Vercel) | https://cyberguard-frontend-iota.vercel.app |
| **Backend API** (Render) | https://cyberguard-backend-bw5v.onrender.com |
| **Swagger / OpenAPI** | https://cyberguard-backend-bw5v.onrender.com/docs |

> The Render service runs on the free tier (`APP_ENV=staging`). ML `.pkl`
> artifacts load lazily on first inference request; the autonomous agent path is
> pure telemetry math and stays warm. First request after idle may cold-start.

---

## 1. Executive Architecture Overview

Traditional SOC dashboards are **passive** — they render charts, counts, and
timelines but leave a human to decide which account to open first and what the
story is. CyberGuard is **active**: the same telemetry and ML models are exposed
as WebMCP tools that a browser-side agent invokes directly, so the workspace
*investigates* rather than merely *displays*.

The platform bridges **client-side WebMCP agent tools** with **server-side ML
inference**. A browser (or any WebMCP-aware agent runtime) registers six
investigation tools via `navigator.modelContext`; each tool call is a thin
transport shim to the FastAPI gateway, which owns PII redaction, deterministic
scoring, and the RandomForest / IsolationForest pipelines. An autonomous
controller chains those same tools into a five-stage investigation and emits a
grounded, audit-traced incident report.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  BROWSER CLIENT / AGENT                                                        │
│  navigator.modelContext  ──(native WebMCP)──┐                                  │
│  REST / JSON-RPC fallback ──────────────────┤   frontend/webmcp_bridge.js      │
│  (standard + headless browsers)             │   6 tools · runInvestigation()   │
└─────────────────────────────────────────────┼────────────────────────────────-─┘
                                              │  HTTPS / JSON   (CORS-pinned)
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  FASTAPI GATEWAY & PII REDACTION LAYER                                         │
│  https://cyberguard-backend-bw5v.onrender.com                                  │
│  API-key / Bearer auth · strict CORS · security headers · body-size cap ·      │
│  per-client rate limiting · SHA-256 model-integrity gate                       │
│  project_user() — the ONLY user shape returned; username + IPs always masked   │
└─────────────────────────────────────────────┬────────────────────────────────-─┘
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  AUTONOMOUS AGENT CONTROLLER      services/agent_controller.py                 │
│  5-stage stepper:                                                              │
│    DISCOVER ─▶ INSPECT ─▶ CORRELATE ─▶ ATTRIBUTE ─▶ REPORT                     │
│  every tool call appended to audit_trace[] (fully replayable)                  │
└──────────────────────┬─────────────────────────────────┬──────────────────────-┘
                       ▼                                 ▼
┌────────────────────────────────────┐  ┌──────────────────────────────────────-─┐
│  DUAL ML INFERENCE ENGINE          │  │  TELEMETRY STORE                       │
│  IsolationForest — behavioural      │  │  Active 10-user mock store            │
│    anomaly detection (13 features)  │  │  ATO · Brute Force · Credential        │
│  RandomForest — attack classifiers  │  │  Stuffing · normal enterprise         │
│    login RF (32→1037 feat)          │  │  baselines                            │
│    network RF + Bot specialist      │  │  services/telemetry.py                │
│    (65 feat · 15 CICIDS classes)    │  │  TELEMETRY_BACKEND = mock (default)   │
└────────────────────────────────────┘  └──────────────────────────────────────-─┘

  Parallel surface — cyberguard_mcp_server.py (FastMCP, stdio, see .mcp.json)
  exposes the SAME six tools to desktop MCP hosts (e.g. Claude Desktop).
```

---

## 2. WebMCP Integration & Standardized Tool Contracts

`frontend/webmcp_bridge.js` is a **dual-mode** bridge:

| Mode | Trigger | Behaviour |
| :--- | :--- | :--- |
| **Native WebMCP** | `navigator.modelContext.registerTool` is present | Registers every tool directly on the browser's model-context surface, so an in-page agent calls them as first-class tools. |
| **Resilient fallback** | standard browsers, headless runtimes, no `navigator.modelContext` | `CyberGuardFallbackClient` speaks plain **REST** (or JSON-RPC 2.0) to the backend. Same tool schemas, same response shapes — always available. |

The bridge validates every argument against the tool's JSON Schema before it
`fetch`es; no business logic lives client-side. `runInvestigation(userId?)` calls
the server agent loop first and transparently falls back to client-side tool
chaining that produces an identical response envelope if the agent endpoint is
unreachable.

### The six core WebMCP tools

| Tool | Purpose | REST route |
| :--- | :--- | :--- |
| `get_security_summary` | Global security posture — monitored/flagged counts, active critical-alert counters, `ELEVATED_RISK` / `NOMINAL` status band. | `GET /api/v1/security/summary` |
| `get_suspicious_users` | Ranked anomalous candidates, top *N* sorted by anomaly score (default 5, max 100). | `GET /api/v1/users/suspicious?limit=` |
| `investigate_user` | Deep-dive into a user's authentication events with deterministic PII masking (`404` for an unknown id). | `GET /api/v1/users/{user_id}/investigate` |
| `get_user_risk_score` | Deterministic 0–100 risk index with verified contributing factors — every factor cites an observed telemetry field. | `GET /api/v1/users/{user_id}/risk-score` |
| `detect_attack_pattern` | Pattern classification mapped to MITRE ATT&CK techniques (grounded heuristic on a bare `user_id`; real RF inference when a `login_event` / `network_flow` feature vector is supplied). | `POST /api/v1/analyze/attack-pattern` |
| `generate_incident_report` | Creates a structured forensic incident record (`INC-2026-<hex>`) plus the non-destructive remediation action list. | `POST /api/v1/reports/incident` |

**Orchestrator:** `POST /api/v1/agent/investigate` `{ "user_id": "USR-402" }`
(body optional — omit to auto-triage). **Tool→route map:** `GET /api/v1/webmcp/manifest`.

The bridge also registers three supplementary read tools backed by the security
decision engine — `get_active_incidents` (`GET /api/v1/incidents`),
`get_incident_details` (`GET /api/v1/incidents/{incident_id}`), and
`get_access_control_status` (`GET /api/v1/users/{user_id}/access-control`).

---

## 3. Telemetry Baseline & Mock Store (10 Profiles)

The active telemetry surface is the in-memory `MockTelemetryStore` in
`cyberguard_api/services/telemetry.py`, bound by `TELEMETRY_BACKEND=mock`
(default; a production process fail-closes unless `TELEMETRY_BACKEND=external`
+ `TELEMETRY_API_URL` are set). It seeds **10 monitored enterprise users**:

| User | Anomaly | Profile | MITRE |
| :--- | :---: | :--- | :--- |
| `USR-205` | **0.96** | High-Volume Brute Force | `T1110.001` |
| `USR-402` | **0.93** | Account Takeover / ATO | `T1078.004` |
| `USR-319` | **0.88** | Distributed Credential Stuffing | `T1110.004` |
| `USR-512` | 0.74 | Session & Device Anomaly | `T1078` |
| `USR-108` | 0.68 | Elevated Authentication Failures | `T1078` |
| `USR-620` | 0.58 | Medium suspicious — low-volume distributed probing | — |
| `USR-733` | 0.44 | Low suspicious — single geo-jump, no heavy brute force | — |
| `USR-814` | 0.12 | Normal enterprise baseline | — |
| `USR-905` | 0.08 | Normal enterprise baseline | — |
| `USR-101` | 0.19 | Normal enterprise baseline | — |

**Resulting baseline metrics** (`GET /api/v1/security/summary`):

```json
{ "monitored_users": 10, "flagged_suspicious_users": 5,
  "high_severity_alerts": 3, "status": "ELEVATED_RISK" }
```

- **10** monitored
- **5** flagged — anomaly score ≥ `0.60` (`USR-205`, `USR-402`, `USR-319`, `USR-512`, `USR-108`)
- **3** critical alerts — anomaly score ≥ `0.85` (`USR-205`, `USR-402`, `USR-319`)
- status **`ELEVATED_RISK`**

Auto-triage picks the highest-anomaly user, **`USR-205`** — 38 failed logins, 0
successful, 1 source IP → **Brute Force / CRITICAL / 88 % confidence /
`T1110.001`**. Target `USR-402` explicitly for the flagship **Account Takeover**
showcase — 47 failed then 1 successful, geo-velocity flag set, 3 source IPs,
4 device changes → **ATO / CRITICAL / 93 % / `T1078.004`**.

---

## 4. Machine Learning & Behavioral Detection Core

Three scikit-learn `1.6.1` pipelines under `cyberguard_api/models/`, each loaded
only after its SHA-256 digest matches `models/manifest.json`
(`services/model_loader.py`).

### IsolationForest — behavioural anomaly detection

`isolation_forest_model.pkl` + `feature_scaler.pkl`. Evaluates **13 continuous
behavioural metrics** per user (login volumes, failure rate, unique IPs /
countries / devices / ASNs, hour-diff spread, device-change count, account span,
logins-per-day) and scores each by average tree **path length** — points that
isolate in few splits are anomalous:

$$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$

where $h(x)$ is the path length for sample $x$, $\mathbb{E}(h(x))$ its average
across the forest, and $c(n)$ the expected path length for $n$ samples. The API
returns `anomaly_score` (higher = more anomalous) and `is_anomaly`. Served via
`POST /get_user_risk_score`; the deterministic 0–100 projection used by the
WebMCP `get_user_risk_score` tool is `round(anomaly_score * 100)`.

### RandomForest — threat classifiers

| Artifact(s) | Task | Shape |
| :--- | :--- | :--- |
| `cyberguard_rf_final.pkl` + `cyberguard_preprocessor_final.pkl` | Supervised **login-attack** classification | 32 engineered features → 1037 encoded · 300 trees, depth 18 · test ROC-AUC ≈ 0.88 · operating threshold `0.70` (`LOGIN_THRESHOLD`, raised from the 0.55 dev point to cut false positives) |
| `network_attack_model.pkl` + `bot_specialist_model.pkl` (+ `network_imputer.pkl`, `network_label_encoder.pkl`) | **Network-flow / bot** detection | 65 CICIDS2017 features · 15 classes (BENIGN, Bot, DDoS, DoS ×4, FTP/SSH-Patator, Heartbleed, Infiltration, PortScan, Web Attack ×3) · 100 trees, depth 20 · a Bot-specialist validator (threshold `0.90`) overrides a "Bot" verdict to the best non-Bot class when its score is low |

Every prediction returns the raw probability **and** the applied threshold so a
consumer can set its own alert boundary. Direct routes: `POST /analyze_ip`
(login list) and `POST /detect_attack_pattern` (network flow); both are also
reachable through `POST /api/v1/analyze/attack-pattern`, where the presence of a
`login_event` or `network_flow` vector selects the inference path — with neither,
the endpoint falls back to the grounded telemetry heuristic
(`inference_mode: "heuristic_fallback"`).

### Lazy-loading optimization (cloud free-tier)

`cyberguard_rf_final.pkl` (~51 MB) and `network_attack_model.pkl` (~57 MB)
unpickle into hundreds of MB of RandomForest — enough to OOM-kill a 512 MB
worker at boot. Defaults keep the process alive:

- `CYBERGUARD_EAGER_MODEL_LOAD=0` — models load on the **first inference request**
  that needs them, not in the lifespan. The telemetry store, `/health`,
  `/readyz` reporting, and the pure-math agent path all stay up.
- `CYBERGUARD_VERIFY_MODELS_ON_IMPORT=0` — no boot-time full-manifest hash pass;
  `load_verified()` still SHA-256-checks each `.pkl` on the lazy load.
- `WEB_CONCURRENCY=1` — a single worker, no per-worker model duplication.

Set `CYBERGUARD_EAGER_MODEL_LOAD=1` on an instance with ≥ ~1 GB RAM to restore
boot-time warmup. For production, point `CYBERGUARD_MODEL_MANIFEST` at a
read-only copy of `manifest.json` outside the writable model directory (and
optionally an Ed25519 detached signature) so a compromised model volume cannot
rewrite its own digests.

### Autonomous attribution

Inside the agent loop only a `user_id` is known, so `detect_attack_pattern` runs
the **deterministic grounded classifier** (`telemetry.classify_pattern`,
`inference_mode: "heuristic"`) over the telemetry counters and maps the verdict
to a MITRE ATT&CK id (`T1078.004` ATO, `T1110.001` Brute Force, `T1110.004`
Credential Stuffing, `T1078` suspicious authentication). Every input counter is
echoed back under `evidence`.

---

## 5. Local Development & Quickstart

Requires **CPython 3.12** (`>=3.11,<3.13`; 3.13+ has no `scikit-learn==1.6.1`
wheels). The git repository root **is** the project root — run `uvicorn` as a
package from there.

```bash
# Clone & enter repo
git clone <repo-url> && cd web_mcp

# Backend setup
python3 -m venv venv && source venv/bin/activate
pip install -r cyberguard_api/requirements.txt      # or: scripts/bootstrap.sh
uvicorn cyberguard_api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend setup (dev server with hot reload)
cd frontend && npm install && npm run dev
```

Zero-build alternative for the frontend — serves the committed
`frontend/dist/` bundle with real security headers, no npm required:

```bash
cd frontend && python3 serve.py 5173      # open http://localhost:5173/
```

Port **5173** (and `:3000`) is in the backend dev CORS allowlist
(`DEFAULT_DEV_ORIGINS`). Then click **RUN INVESTIGATION** on the dashboard.

### Key environment configuration

| Variable | Role |
| :--- | :--- |
| `APP_ENV` | `dev` \| `staging` \| `production`. `production` is fail-closed — the process refuses to start unless `API_KEYS` and `CORS_ORIGINS` are set, disables `/docs`, and turns on HSTS. The Render deploy uses `staging`. |
| `CORS_ORIGINS` | Comma-delimited or JSON list of browser origins allowed to call `/api/v1/*`. Must list the exact deployed frontend origin (`https://cyberguard-frontend-iota.vercel.app`). Unset in dev → localhost origins. |
| `CYBERGUARD_CONNECT_SRC` | CSP `connect-src` for `frontend/serve.py`; must include the API origin. |
| `API_KEYS` | Comma-separated accepted keys (`X-API-Key` / `Authorization: Bearer`). Empty + non-production → `/api/v1/*` open with a one-time warning. |
| `TELEMETRY_BACKEND` | `mock` (default) or `external` (+ `TELEMETRY_API_URL`). |
| `LOGIN_THRESHOLD` | Login-RF operating threshold (default `0.70`). |

See `.env.example` for the full set. Quick checks:

```bash
curl -s localhost:8000/health          # {"status":"ok"} — process liveness
curl -s localhost:8000/readyz          # 200 once every ML model + the store verify, else 503
curl -s -X POST localhost:8000/api/v1/agent/investigate | python3 -m json.tool

# Live (staging — no key needed): auto-triage the worst offender
curl -s -X POST https://cyberguard-backend-bw5v.onrender.com/api/v1/agent/investigate \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); \
    print(d["target_user_id"], d["assessment"]["threat_classification"], d["assessment"]["severity"])'
# -> USR-205 Brute Force CRITICAL
```

---

## 6. Safety, PII Redaction & Operational Boundaries

**Universal PII masking at the projection layer.** `project_user()` is the *only*
user shape that may appear in any API response, on any transport (REST, MCP
stdio, agent loop) — there is no unmasked path and the legacy
`?scope=full` / `X-Scope-Token` bypass has been removed. Usernames mask to
`a***n@enterprise.internal`; source IPs mask to `198.x.x.x` and are truncated to
a 3-entry sample plus a count.

**Read / Analyze / Recommend only — zero autonomous destructive actions.** No
tool terminates a session, revokes a token, edits a firewall rule / `iptables`,
kills a process, or drops a network interface. `generate_incident_report` only
*records* an incident id and the recommendation list; remediation is emitted as
human-authorized text (*"Recommend SOC Admin trigger MFA / 2FA credential
reset"*), and every report footer states the run was analytical only.

**Grounded telemetry mandate.** Every line in a report is anchored to a tool
output captured in `audit_trace[]`. `contributing_factors()` emits a factor only
when the telemetry field backing it is actually set — no invented timing
windows, no intent claims, no free-form IPs or users. This eliminates LLM
hallucination by construction: the narrative is a function of observed counters.

**Gateway hardening.** `/api/v1/*` and the three direct ML routes require a valid
`X-API-Key` / Bearer token (bypassed only in non-production with `API_KEYS`
unset). Strict CORS allowlist (never `*` with credentials). Every response
carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy`, a `Content-Security-Policy`, `Cross-Origin-Opener-Policy`, and
HSTS in production. Request bodies over `MAX_BODY_BYTES` (default 1 MB) get a
`413` at the ASGI edge. Per-client rate limiting via `slowapi` (600/min dev,
60/min production). The frontend CSP pins `connect-src` to the single Render API
origin. A layered defense tree under `cyberguard_api/security/` (identity / ODAC,
runtime RASP + containment, perimeter WAF + API-schema validation,
infrastructure, SIEM) plus an auth-defense middleware (rate-limit, bot
detection, credential intel, MFA step-up, telemetry) wraps the ML API.

---

## 7. Repository Map

```
web_mcp/
├── cyberguard_api/
│   ├── main.py                 FastAPI app · lifespan · direct ML scoring routes · /health /readyz
│   ├── routes_webmcp.py        WebMCP REST facade /api/v1/* · CORS · attack-pattern inference
│   ├── gateway.py              settings · API-key auth · security-headers + body-size ASGI middleware
│   ├── observability.py        structured logging · request-id · /metrics
│   ├── security/               layered defense tree + auth-defense middleware (locked perimeter)
│   ├── services/
│   │   ├── telemetry.py        10-user mock store · PII projection · deterministic scoring / classifier
│   │   ├── agent_controller.py run_autonomous_investigation() — the 5-stage loop
│   │   ├── model_loader.py     SHA-256-verified joblib loading · manifest tooling
│   │   └── network_detector.py network RF + Bot-specialist pipeline
│   └── models/                 *.pkl artifacts · *_metadata.json · manifest.json
├── cyberguard_mcp_server.py    FastMCP stdio server — same six tools for desktop MCP hosts
├── frontend/
│   ├── webmcp_bridge.js        WebMCP bridge + CyberGuardFallbackClient + runInvestigation()
│   ├── app.jsx / app.css       React investigation dashboard (zero-CDN, precompiled CSS)
│   ├── serve.py                static server with security headers (serves committed dist/)
│   ├── vercel.json             Vercel build + headers + SPA rewrites (CSP pins the API origin)
│   └── dist/                   committed production bundle
├── render.yaml · Procfile · Dockerfile      deployment blueprints
└── DEMO_WALKTHROUGH.md         architecture diagram · 90-second pitch · demo click-path
```

For the full demo click-path, the 90-second pitch script, and the verification
checklist, see **[`DEMO_WALKTHROUGH.md`](DEMO_WALKTHROUGH.md)**.

# CyberGuard SOC — WebMCP Autonomous Investigation

An autonomous SOC investigation platform that turns security telemetry and ML anomaly detection into **callable agent tools** using [WebMCP](https://github.com/webmachinelearning/webmcp).

The system investigates suspicious activity through:

**DISCOVER → INSPECT → CORRELATE → ATTRIBUTE → REPORT**

and produces an executive-ready incident report.

> **Stack:** FastAPI · scikit-learn · WebMCP · JavaScript · Tailwind CSS · FastMCP

For the architecture diagram and demo walkthrough, see **[`DEMO_WALKTHROUGH.md`](DEMO_WALKTHROUGH.md)**.

---

## What It Does

### 🔍 Autonomous SOC Investigation

* Automatically identifies suspicious users.
* Investigates user activity and risk factors.
* Detects attack patterns using ML models.
* Maps detected threats to MITRE ATT&CK techniques.
* Generates a consolidated incident report.
* Maintains a complete investigation audit trace.

### 🧩 WebMCP Integration

Six security tools are exposed through:

* **Native WebMCP** — `navigator.modelContext`
* **REST API** — `/api/v1/*`
* **MCP stdio** — for desktop MCP hosts

Available tools:

```text
get_security_summary
get_suspicious_users
investigate_user
get_user_risk_score
detect_attack_pattern
generate_incident_report
```

### 🤖 ML Detection

CyberGuard combines multiple ML models for:

* Login attack detection
* Behavioral anomaly detection
* Network attack classification
* Bot attack validation

---

## Architecture

```text
Browser Dashboard
       │
       ▼
   WebMCP Bridge
       │
       ├──────────────► REST API
       │
       ▼
 Autonomous Agent
       │
       ├── Security Summary
       ├── Suspicious Users
       ├── User Investigation
       ├── Risk Scoring
       ├── Attack Detection
       └── Incident Report
              │
              ▼
        Executive Report
```

---

## Quick Start

### Requirements

* Python 3.12
* scikit-learn 1.6.1

### 1. Start the backend

```bash
cd web_mcp

python3.12 -m venv .venv
source .venv/bin/activate

pip install -r cyberguard_api/requirements.txt

uvicorn cyberguard_api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Start the frontend

Open a second terminal:

```bash
cd web_mcp/frontend
python3 -m http.server 5173
```

Open:

```text
http://localhost:5173
```

Then click:

**Auto-Triage & Investigate Worst Offender**

### 3. Verify the backend

```bash
curl http://localhost:8000/health
```

---

## Repository Structure

```text
web_mcp/
├── cyberguard_mcp_server.py
├── .mcp.json
│
├── cyberguard_api/
│   ├── main.py
│   ├── routes_webmcp.py
│   ├── services/
│   │   ├── network_detector.py
│   │   └── agent_controller.py
│   ├── models/
│   └── requirements.txt
│
└── frontend/
    ├── index.html
    ├── webmcp_bridge.js
    └── test_webmcp.html
```

---

## API

| Method | Endpoint                              | Purpose                      |
| ------ | ------------------------------------- | ---------------------------- |
| GET    | `/api/v1/security/summary`            | Security overview            |
| GET    | `/api/v1/users/suspicious`            | Find suspicious users        |
| GET    | `/api/v1/users/{user_id}/investigate` | Investigate a user           |
| GET    | `/api/v1/users/{user_id}/risk-score`  | Calculate user risk          |
| POST   | `/api/v1/analyze/attack-pattern`      | Detect attack pattern        |
| POST   | `/api/v1/reports/incident`            | Generate incident report     |
| POST   | `/api/v1/agent/investigate`           | Run autonomous investigation |
| GET    | `/api/v1/webmcp/manifest`             | WebMCP tool manifest         |

---

## Autonomous Investigation

The main investigation endpoint:

```http
POST /api/v1/agent/investigate
```

returns:

```text
Threat Classification
Severity
Confidence
MITRE ATT&CK Technique
Telemetry Summary
Audit Trace
Markdown Incident Report
```

Example flow:

```text
Suspicious User
      ↓
Risk Assessment
      ↓
Behavior Investigation
      ↓
Attack Pattern Detection
      ↓
MITRE Attribution
      ↓
Incident Report
```

---

## Safety

CyberGuard is **analytical and recommendation-only**.

It does not:

* Terminate accounts
* Revoke authentication tokens
* Modify firewall rules
* Execute remediation automatically

All remediation actions remain **human-authorized**.

---

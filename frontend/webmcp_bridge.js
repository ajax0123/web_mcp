/**
 * webmcp_bridge.js
 * ----------------------------------------------------------------------------
 * CyberGuard SOC — Phase 2: WebMCP in-browser bridge.
 *
 * Registers the CyberGuard investigation tools with the browser's native
 * WebMCP surface (`navigator.modelContext.registerTool`) when available, so an
 * in-page AI agent can call them directly. When WebMCP is NOT present, the same
 * tools stay reachable through `CyberGuardFallbackClient`, which speaks plain
 * REST or JSON-RPC 2.0 to the backend.
 *
 * Every tool `execute` is a thin transport shim: validate args against the
 * tool's JSON Schema, then `fetch` the backend. No business logic lives here.
 *
 * ---------------------------------------------------------------------------
 * Backend contract (default) — matches cyberguard_api/routes_webmcp.py
 * ---------------------------------------------------------------------------
 *   GET  {base}/api/v1/security/summary
 *   GET  {base}/api/v1/users/suspicious?limit=5
 *   GET  {base}/api/v1/users/{user_id}/investigate
 *   GET  {base}/api/v1/users/{user_id}/risk-score
 *   POST {base}/api/v1/analyze/attack-pattern   { "user_id": "USR-402" }
 *   POST {base}/api/v1/reports/incident         { "user_id", "threat_type",
 *                                                 "severity", "recommendations" }
 *
 * `{token}` / `:token` segments in a route path are filled from the call args;
 * the consumed keys are then dropped from the query string / JSON body.
 *
 * Override any of this via `initWebMCP(base, { routes, mode, rpcPath, ... })`
 * to match whatever Phase-2 backend is actually deployed.
 *
 * ---------------------------------------------------------------------------
 * Usage
 * ---------------------------------------------------------------------------
 *   import { initWebMCP } from "./webmcp_bridge.js";
 *
 *   const bridge = initWebMCP("https://api.cyberguard.local");
 *   console.log(bridge.mode);            // "webmcp" | "fallback"
 *
 *   // Works in both modes — fallback client is always available:
 *   const summary = await bridge.client.getSecuritySummary();
 *   const worst   = await bridge.client.getSuspiciousUsers(1);
 *
 *   // JSON-RPC backend instead of REST:
 *   initWebMCP("https://api.cyberguard.local", { mode: "jsonrpc", rpcPath: "/rpc" });
 *
 * Load as an ES module (`<script type="module">`). A `window.CyberGuardWebMCP`
 * handle is also attached for console debugging.
 *
 * SAFETY: these tools are analytical only. `generate_incident_report` records
 * recommendations; it does not execute remediation.
 * ----------------------------------------------------------------------------
 */

"use strict";

/* ==========================================================================
 * 1. Tool definitions — pure data (name, description, JSON Schema, HTTP hint)
 * ========================================================================== */

/** @typedef {{name:string, description:string, inputSchema:object, sideEffect?:boolean}} ToolDef */

const USER_ID_SCHEMA = {
  type: "string",
  minLength: 2,
  maxLength: 64,
  pattern: "^[A-Za-z0-9._:-]+$",
  description: 'Target user identifier, e.g. "USR-402".',
};

/** @type {ToolDef[]} */
export const WEBMCP_TOOL_DEFS = [
  {
    name: "get_security_summary",
    description:
      "Returns high-level summary counts of anomalies, active alerts, and flagged entities.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: "get_suspicious_users",
    description:
      "Returns users ranked by anomaly detection score from the DS engine. " +
      "Optional `limit` caps the result count (default 5).",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 5,
          description: "Maximum number of ranked users to return.",
        },
      },
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: "investigate_user",
    description:
      "Retrieves detailed authentication telemetry, failed attempts, and originating IPs for a specific user.",
    inputSchema: {
      type: "object",
      properties: { user_id: { ...USER_ID_SCHEMA } },
      required: ["user_id"],
      additionalProperties: false,
    },
  },
  {
    name: "get_user_risk_score",
    description:
      "Calculates the normalized 0-100 risk score and top contributing risk factors for a user.",
    inputSchema: {
      type: "object",
      properties: { user_id: { ...USER_ID_SCHEMA } },
      required: ["user_id"],
      additionalProperties: false,
    },
  },
  {
    name: "detect_attack_pattern",
    description:
      "Runs the user's behavioral signals through the attack classification model " +
      "(returns classified pattern, confidence, and MITRE technique id).",
    inputSchema: {
      type: "object",
      properties: { user_id: { ...USER_ID_SCHEMA } },
      required: ["user_id"],
      additionalProperties: false,
    },
  },
  {
    name: "generate_incident_report",
    description:
      "Generates an official SOC incident id and records containment recommendations. " +
      "Analytical only — does not execute remediation.",
    sideEffect: true,
    inputSchema: {
      type: "object",
      properties: {
        user_id: { ...USER_ID_SCHEMA },
        threat_type: {
          type: "string",
          // Superset of every label the backend classifiers can emit
          // (_heuristic_pattern / _name_login_pattern in routes_webmcp.py).
          enum: [
            "Normal",
            "Brute Force",
            "Credential Stuffing",
            "Account Takeover",
            "Account Takeover (ATO)",
            "Password Spraying",
            "Session Hijacking",
            "Anomalous Authentication",
            "Suspicious Authentication Activity",
          ],
          description: "Threat classification for the incident.",
        },
        severity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Assessed severity level.",
        },
        recommendations: {
          type: "array",
          minItems: 1,
          maxItems: 25,
          items: { type: "string", minLength: 3, maxLength: 500 },
          description: "Non-destructive, human-authorized containment / hardening steps.",
        },
      },
      required: ["user_id", "threat_type", "severity", "recommendations"],
      additionalProperties: false,
    },
  },
  {
    name: "get_active_incidents",
    description: "Returns incidents created by CyberGuard login security analysis.",
    inputSchema: { type: "object", properties: {}, required: [], additionalProperties: false },
  },
  {
    name: "get_incident_details",
    description: "Returns evidence and containment state for an incident.",
    inputSchema: { type: "object", properties: { incident_id: { type: "string", minLength: 2, maxLength: 128 } }, required: ["incident_id"], additionalProperties: false },
  },
  {
    name: "get_access_control_status",
    description: "Returns the application-level access state for a user.",
    inputSchema: { type: "object", properties: { user_id: { ...USER_ID_SCHEMA } }, required: ["user_id"], additionalProperties: false },
  },
];

/** @type {string[]} */
export const TOOL_NAMES = WEBMCP_TOOL_DEFS.map((d) => d.name);

/**
 * Default REST routing: tool name -> { method, path, query?, sideEffect? }.
 * `path` may contain {user_id} / :user_id tokens, filled from the call args.
 * Matches cyberguard_api/routes_webmcp.py (mounted under /api/v1).
 */
export const DEFAULT_ROUTES = {
  get_security_summary: { method: "GET", path: "/api/v1/security/summary" },
  get_suspicious_users: { method: "GET", path: "/api/v1/users/suspicious", query: true },
  investigate_user: { method: "GET", path: "/api/v1/users/{user_id}/investigate" },
  get_user_risk_score: { method: "GET", path: "/api/v1/users/{user_id}/risk-score" },
  detect_attack_pattern: { method: "POST", path: "/api/v1/analyze/attack-pattern" },
  generate_incident_report: {
    method: "POST",
    path: "/api/v1/reports/incident",
    sideEffect: true,
  },
  get_active_incidents: { method: "GET", path: "/api/v1/incidents" },
  get_incident_details: { method: "GET", path: "/api/v1/incidents/{incident_id}" },
  get_access_control_status: { method: "GET", path: "/api/v1/users/{user_id}/access-control" },
};

/** @param {string} name */
export function getToolDef(name) {
  return WEBMCP_TOOL_DEFS.find((d) => d.name === name) || null;
}

/* ==========================================================================
 * 2. Feature detection
 * ========================================================================== */

/** True when the browser exposes the native WebMCP tool-registration surface. */
export function isWebMCPSupported() {
  return (
    typeof navigator !== "undefined" &&
    !!navigator.modelContext &&
    typeof navigator.modelContext.registerTool === "function"
  );
}

/* ==========================================================================
 * 3. Minimal JSON Schema validator (subset: type/required/enum/bounds/pattern)
 * ========================================================================== */

/**
 * Validate + lightly coerce `input` against `schema`.
 * @returns {{ok:boolean, value:any, errors:string[]}}
 */
export function validateArgs(schema, input) {
  const errors = [];
  const value = coerce(schema, input === undefined ? {} : input, "$", errors);
  return { ok: errors.length === 0, value, errors };
}

function coerce(schema, val, path, errors) {
  if (!schema || typeof schema !== "object") return val;

  switch (schema.type) {
    case "object": {
      const src = val && typeof val === "object" && !Array.isArray(val) ? val : {};
      const props = schema.properties || {};
      const out = {};
      if (schema.additionalProperties === false) {
        for (const k of Object.keys(src)) {
          if (!(k in props)) errors.push(`${path}: unexpected property "${k}"`);
        }
      }
      for (const [k, sub] of Object.entries(props)) {
        if (k in src && src[k] !== undefined) {
          out[k] = coerce(sub, src[k], `${path}.${k}`, errors);
        } else if (sub && "default" in sub) {
          out[k] = sub.default;
        }
      }
      for (const req of schema.required || []) {
        if (!(req in out)) errors.push(`${path}: missing required property "${req}"`);
      }
      return out;
    }

    case "array": {
      if (!Array.isArray(val)) {
        errors.push(`${path}: expected array`);
        return val;
      }
      if (schema.minItems != null && val.length < schema.minItems) {
        errors.push(`${path}: expected >= ${schema.minItems} items`);
      }
      if (schema.maxItems != null && val.length > schema.maxItems) {
        errors.push(`${path}: expected <= ${schema.maxItems} items`);
      }
      return schema.items
        ? val.map((v, i) => coerce(schema.items, v, `${path}[${i}]`, errors))
        : val;
    }

    case "string": {
      if (typeof val !== "string") {
        errors.push(`${path}: expected string`);
        return val;
      }
      if (schema.enum && !schema.enum.includes(val)) {
        errors.push(`${path}: must be one of ${JSON.stringify(schema.enum)}`);
      }
      if (schema.minLength != null && val.length < schema.minLength) {
        errors.push(`${path}: shorter than minLength ${schema.minLength}`);
      }
      if (schema.maxLength != null && val.length > schema.maxLength) {
        errors.push(`${path}: longer than maxLength ${schema.maxLength}`);
      }
      if (schema.pattern && !new RegExp(schema.pattern).test(val)) {
        errors.push(`${path}: does not match pattern ${schema.pattern}`);
      }
      return val;
    }

    case "integer":
    case "number": {
      let n = val;
      if (typeof n === "string" && n.trim() !== "" && !Number.isNaN(Number(n))) {
        n = Number(n);
      }
      if (typeof n !== "number" || Number.isNaN(n)) {
        errors.push(`${path}: expected ${schema.type}`);
        return val;
      }
      if (schema.type === "integer" && !Number.isInteger(n)) {
        errors.push(`${path}: expected integer`);
      }
      if (schema.minimum != null && n < schema.minimum) {
        errors.push(`${path}: below minimum ${schema.minimum}`);
      }
      if (schema.maximum != null && n > schema.maximum) {
        errors.push(`${path}: above maximum ${schema.maximum}`);
      }
      return n;
    }

    case "boolean": {
      if (typeof val !== "boolean") errors.push(`${path}: expected boolean`);
      return val;
    }

    default:
      return val;
  }
}

/* ==========================================================================
 * 4. Transport — REST + JSON-RPC over fetch, with timeout + retry
 * ========================================================================== */

class CyberGuardTransport {
  /**
   * @param {string} apiBaseUrl
   * @param {object} [opts]
   * @param {"rest"|"jsonrpc"} [opts.mode="rest"]
   * @param {string} [opts.rpcPath=""]        Path appended to base for JSON-RPC POSTs.
   * @param {object} [opts.routes]            Per-tool REST route overrides (merged over DEFAULT_ROUTES).
   * @param {Record<string,string>} [opts.headers]
   * @param {RequestCredentials} [opts.credentials="same-origin"]
   * @param {number} [opts.timeoutMs=15000]
   * @param {number} [opts.retries=2]         Retries for read tools (5xx/429/network). Side-effect tools never retry.
   * @param {typeof fetch} [opts.fetchImpl]
   */
  constructor(apiBaseUrl, opts = {}) {
    if (!apiBaseUrl || typeof apiBaseUrl !== "string") {
      throw new TypeError("CyberGuardTransport: apiBaseUrl (string) is required");
    }
    this.baseUrl = apiBaseUrl.replace(/\/+$/, "");
    this.mode = opts.mode === "jsonrpc" ? "jsonrpc" : "rest";
    this.rpcPath = opts.rpcPath || "";
    this.routes = { ...DEFAULT_ROUTES, ...(opts.routes || {}) };
    this.headers = { ...(opts.headers || {}) };
    this.credentials = opts.credentials || "same-origin";
    this.timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 15000;
    this.retries = Number.isFinite(opts.retries) ? opts.retries : 2;

    this.fetchImpl =
      opts.fetchImpl ||
      (typeof fetch === "function" ? fetch.bind(globalThis) : null);
    if (!this.fetchImpl) {
      throw new Error(
        "CyberGuardTransport: no fetch implementation available (pass opts.fetchImpl)"
      );
    }
  }

  /**
   * Invoke a tool by name against the backend. Returns parsed JSON payload.
   * @param {string} toolName
   * @param {object} args
   */
  async call(toolName, args) {
    return this.mode === "jsonrpc"
      ? this._jsonrpc(toolName, args)
      : this._rest(toolName, args);
  }

  /**
   * Raw request against an arbitrary backend path (not a registered tool).
   * Used by high-level orchestration helpers such as `runInvestigation`.
   * @param {string} path            absolute path, e.g. "/api/v1/agent/investigate"
   * @param {{method?:string, body?:any, retries?:number}} [opts]
   * @returns {Promise<any>} parsed JSON payload
   */
  async request(path, opts = {}) {
    const method = (opts.method || "GET").toUpperCase();
    const url = this.baseUrl + path;
    /** @type {RequestInit} */
    const init = {
      method,
      headers: { Accept: "application/json", ...this.headers },
      credentials: this.credentials,
    };
    if (opts.body !== undefined && method !== "GET" && method !== "HEAD") {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    return this._send(url, init, opts.retries ?? this.retries);
  }

  async _rest(toolName, args) {
    const route = this.routes[toolName] || { method: "POST", path: `/${toolName}` };
    const method = (route.method || "POST").toUpperCase();
    const { path, rest } = fillPathParams(route.path || `/${toolName}`, args);
    let url = this.baseUrl + path;

    /** @type {RequestInit} */
    const init = {
      method,
      headers: { Accept: "application/json", ...this.headers },
      credentials: this.credentials,
    };

    if (method === "GET" || method === "HEAD") {
      const qs = toQuery(rest);
      if (qs) url += (url.includes("?") ? "&" : "?") + qs;
    } else {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(rest);
    }

    const retries = route.sideEffect ? 0 : this.retries;
    return this._send(url, init, retries);
  }

  async _jsonrpc(toolName, args) {
    const url = this.baseUrl + (this.rpcPath || "");
    const body = {
      jsonrpc: "2.0",
      id: randomId(),
      method: toolName,
      params: args || {},
    };
    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...this.headers,
      },
      credentials: this.credentials,
      body: JSON.stringify(body),
    };

    const sideEffect = !!(this.routes[toolName] && this.routes[toolName].sideEffect);
    const data = await this._send(url, init, sideEffect ? 0 : this.retries);

    if (data && typeof data === "object" && data.error) {
      const err = new Error(data.error.message || "JSON-RPC error");
      err.name = "JsonRpcError";
      err.code = data.error.code;
      err.data = data.error.data;
      throw err;
    }
    return data && typeof data === "object" && "result" in data ? data.result : data;
  }

  async _send(url, init, retries) {
    let attempt = 0;
    let lastErr;

    while (attempt <= retries) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(url, { ...init, signal: ac.signal });
        clearTimeout(timer);

        const text = await res.text();
        let data;
        try {
          data = text ? JSON.parse(text) : null;
        } catch {
          data = text; // non-JSON body — surface as-is
        }

        if (!res.ok) {
          const err = new Error(
            `HTTP ${res.status} ${res.statusText || ""} from ${url}`.trim()
          );
          err.name = "HttpError";
          err.status = res.status;
          err.body = data;
          if ((res.status >= 500 || res.status === 429) && attempt < retries) {
            lastErr = err;
            await backoff(attempt++);
            continue;
          }
          throw err;
        }
        return data;
      } catch (err) {
        clearTimeout(timer);
        lastErr = err;
        const retriable =
          err.name === "AbortError" ||
          err.name === "TypeError" || // fetch network failure
          /network|failed|timeout/i.test(String(err && err.message));
        if (retriable && attempt < retries) {
          await backoff(attempt++);
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  }
}

/* ==========================================================================
 * 5. Fallback client — same tools, plain REST/JSON-RPC, no WebMCP needed
 * ========================================================================== */

export class CyberGuardFallbackClient {
  /**
   * @param {string} apiBaseUrl
   * @param {object} [opts] — see CyberGuardTransport; plus opts._transport to reuse one.
   */
  constructor(apiBaseUrl, opts = {}) {
    this.transport =
      opts._transport instanceof CyberGuardTransport
        ? opts._transport
        : new CyberGuardTransport(apiBaseUrl, opts);
    this.baseUrl = this.transport.baseUrl;
  }

  /** Tool catalog (name, description, inputSchema). */
  listTools() {
    return WEBMCP_TOOL_DEFS.map((d) => ({
      name: d.name,
      description: d.description,
      inputSchema: d.inputSchema,
    }));
  }

  /**
   * Generic invoke: validates `args` against the tool schema, then calls backend.
   * @param {string} name
   * @param {object} [args]
   */
  async callTool(name, args = {}) {
    const def = getToolDef(name);
    if (!def) throw new Error(`Unknown tool: ${name}`);
    const { ok, value, errors } = validateArgs(def.inputSchema, args);
    if (!ok) {
      const err = new Error(`Invalid args for ${name}: ${errors.join("; ")}`);
      err.name = "InvalidInput";
      err.errors = errors;
      throw err;
    }
    return this.transport.call(name, value);
  }

  /* ---- typed convenience wrappers ---- */

  getSecuritySummary() {
    return this.callTool("get_security_summary", {});
  }

  /**
   * @param {number} [limit=5]
   * @returns {Promise<object[]>} ranked users — the backend `{ result: [...] }`
   *   envelope is unwrapped so callers can index the array directly.
   */
  async getSuspiciousUsers(limit = 5) {
    const res = await this.callTool("get_suspicious_users", { limit });
    return Array.isArray(res) ? res : (res && (res.result || res.users)) || [];
  }

  /** @param {string} userId */
  investigateUser(userId) {
    return this.callTool("investigate_user", { user_id: userId });
  }

  /** @param {string} userId */
  getUserRiskScore(userId) {
    return this.callTool("get_user_risk_score", { user_id: userId });
  }

  /** @param {string} userId */
  detectAttackPattern(userId) {
    return this.callTool("detect_attack_pattern", { user_id: userId });
  }

  /**
   * @param {{user_id:string, threat_type:string, severity:string, recommendations:string[]}} report
   */
  generateIncidentReport(report) {
    const { user_id, threat_type, severity, recommendations } = report || {};
    return this.callTool("generate_incident_report", {
      user_id,
      threat_type,
      severity,
      recommendations,
    });
  }

  getActiveIncidents() { return this.callTool("get_active_incidents", {}); }
  getIncidentDetails(incidentId) { return this.callTool("get_incident_details", { incident_id: incidentId }); }
  getAccessControlStatus(userId) { return this.callTool("get_access_control_status", { user_id: userId }); }

  /* ---- high-level orchestration ---- */

  /**
   * Run the full autonomous investigation lifecycle.
   *
   * Primary path: POST /api/v1/agent/investigate (server-side agent loop).
   * If that endpoint is unreachable / errors, transparently falls back to
   * client-side sequential tool chaining that produces the SAME response shape.
   *
   * @param {string|null} [userId]  target user; null → auto-triage worst offender
   * @returns {Promise<object>} consolidated assessment. Always exposes:
   *   `assessment` {threat_classification, severity, confidence, confidence_pct, mitre_technique_id},
   *   `telemetry` {failed_logins, successful_logins, unique_ips, anomaly_score, ...},
   *   `audit_trace` [{step, tool, input, output, ts}],
   *   `markdown_report` (string, ready to render).
   *   `_source` is "server_agent" or "client_fallback".
   */
  async runInvestigation(userId = null) {
    const body = userId ? { user_id: userId } : {};
    try {
      const res = await this.transport.request("/api/v1/agent/investigate", {
        method: "POST",
        body,
        retries: 0,
      });
      if (!res || typeof res !== "object") throw new Error("empty agent response");
      return { _source: "server_agent", ...res };
    } catch (serverErr) {
      const serverMsg = String((serverErr && serverErr.message) || serverErr);
      try {
        const out = await this._runInvestigationClientSide(userId);
        out._source = "client_fallback";
        out._server_error = serverMsg;
        return out;
      } catch (fallbackErr) {
        // Total outage: agent endpoint AND the tool endpoints are unreachable.
        // Return a structured error so the UI can render it — never throw.
        return {
          status: "ERROR",
          target_user_id: userId,
          message: "Agent endpoint and client-side fallback both failed.",
          _source: "client_fallback",
          _server_error: serverMsg,
          _fallback_error: String((fallbackErr && fallbackErr.message) || fallbackErr),
          audit_trace: [],
          generated_at: new Date().toISOString(),
        };
      }
    }
  }

  /** Client-side reproduction of the server agent loop (fallback). */
  async _runInvestigationClientSide(userId = null) {
    const trace = [];
    const rec = (step, tool, input, output) =>
      trace.push({ step, tool, input, output, ts: new Date().toISOString() });

    let securitySummary = null;
    let candidates = null;
    const autoSelected = !userId;

    if (!userId) {
      securitySummary = await this.getSecuritySummary();
      rec(1, "get_security_summary", {}, securitySummary);
      candidates = await this.getSuspiciousUsers(3);
      rec(2, "get_suspicious_users", { limit: 3 }, candidates);
      if (!candidates.length) {
        return {
          status: "NO_TARGETS",
          message: "Triage returned no suspicious users.",
          triage: { security_summary: securitySummary, candidates: [] },
          audit_trace: trace,
          generated_at: new Date().toISOString(),
        };
      }
      const top = candidates.reduce((a, b) =>
        (b.anomaly_score ?? 0) > (a.anomaly_score ?? 0) ? b : a
      );
      userId = top.user_id;
    }

    const telemetry = await this.investigateUser(userId);
    rec(3, "investigate_user", { user_id: userId }, telemetry);
    const risk = await this.getUserRiskScore(userId);
    rec(4, "get_user_risk_score", { user_id: userId }, risk);
    const attack = await this.detectAttackPattern(userId);
    rec(5, "detect_attack_pattern", { user_id: userId }, attack);

    const threatType = attack.classified_pattern;
    const severity = deriveSeverity(risk, attack);
    const recommendations = clientRecommendations(attack, risk, telemetry);
    const incident = await this.generateIncidentReport({
      user_id: userId,
      threat_type: threatType,
      severity,
      recommendations,
    });
    rec(
      6,
      "generate_incident_report",
      { user_id: userId, threat_type: threatType, severity, recommendations },
      incident
    );

    const confidence = Number(attack.confidence ?? 0);
    return {
      status: "COMPLETE",
      target_user_id: userId,
      auto_selected: autoSelected,
      generated_at: new Date().toISOString(),
      assessment: {
        threat_classification: threatType,
        severity,
        confidence,
        confidence_pct: Math.round(confidence * 100),
        mitre_technique_id: attack.mitre_technique_id ?? null,
        attack_detected: attack.attack_detected ?? null,
        risk_score: risk.risk_score ?? null,
      },
      triage: { security_summary: securitySummary, candidates },
      telemetry,
      risk_score: risk,
      attack_attribution: attack,
      incident,
      recommended_actions: recommendations,
      markdown_report: renderIncidentMarkdown(userId, telemetry, risk, attack, incident),
      audit_trace: trace,
    };
  }
}

/* --- fallback-path helpers (JS port of services/agent_controller.py) --- */

const _SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function deriveSeverity(risk, attack) {
  let level = String((risk && risk.risk_level) || "MEDIUM").toUpperCase();
  if (!_SEVERITY_ORDER.includes(level)) level = "MEDIUM";
  if (
    attack &&
    attack.attack_detected &&
    _SEVERITY_ORDER.indexOf(level) < _SEVERITY_ORDER.indexOf("HIGH")
  ) {
    level = "HIGH";
  }
  return level;
}

function clientRecommendations(attack, risk, telemetry) {
  const pattern = String((attack && attack.classified_pattern) || "");
  const recs = [];
  if (pattern.includes("Account Takeover")) {
    recs.push(
      "Recommend SOC Admin invalidate all active sessions for the account and force step-up re-authentication",
      "Recommend SOC Admin trigger MFA / 2FA credential reset",
      "Quarantine and forensically image the new device fingerprints before trust is re-granted",
      "Hunt the successful session for mailbox rules, OAuth/app-consent grants, and lateral movement"
    );
  } else if (pattern.includes("Brute Force")) {
    recs.push(
      "Apply source-IP rate limiting / temporary block on the authentication endpoint",
      "Recommend SOC Admin review account lockout thresholds for the targeted account"
    );
  } else if (pattern.includes("Credential Stuffing")) {
    recs.push(
      "Enable breached-password / credential-stuffing detection on the login flow",
      "Rate-limit authentication per source IP CIDR and require CAPTCHA on anomaly"
    );
  } else {
    recs.push(
      "Maintain enhanced monitoring; escalate if the anomaly score rises or a successful login follows"
    );
  }
  if (telemetry && telemetry.geo_velocity_violation) {
    recs.push(
      "Enforce conditional access blocking unapproved ASNs and impossible-travel geo pairs"
    );
  }
  if (risk && (risk.risk_score ?? 0) >= 80) {
    recs.unshift("Page the on-call SOC lead — risk score is CRITICAL");
  }
  return recs;
}

/** GR-1: origin description must agree with the IP count — never "Single origin" when >1 IP. */
function originNote(nIps, geo) {
  if (Number(nIps) > 1) {
    const note = `Multiple origins on record (${nIps} unique IPs)`;
    return geo ? `${note}; geo_velocity_violation flag set` : note;
  }
  return geo ? "geo_velocity_violation flag set" : "Single origin on record";
}

function renderIncidentMarkdown(userId, telemetry, risk, attack, incident) {
  const t = telemetry || {};
  const anomaly = t.anomaly_score ?? 0;
  // Backend telemetry is masked: `unique_ips_masked` sample + `unique_ip_count`.
  const ips = t.unique_ips_masked || t.unique_ips || [];
  const ipCount = t.unique_ip_count ?? ips.length;
  const factors = (risk && risk.top_contributing_factors) || [];
  const conf = Math.round(Number(attack.confidence ?? 0) * 100);
  const lines = [
    `# INCIDENT REPORT: ${incident.incident_id} / ${userId}`,
    "",
    "## 1. Executive Summary",
    `- Threat Classification: ${attack.classified_pattern}`,
    `- Severity Level: ${incident.severity}`,
    `- Confidence Score: ${conf}%`,
    `- MITRE ATT&CK: ${attack.mitre_technique_id || "n/a"}`,
    `- Investigation Verdict: ${attack.signature_details || ""}`,
    "",
    "## 2. Telemetry & Machine Learning Evidence",
    "| Indicator | Observed Value | Risk Assessment |",
    "| :--- | :--- | :--- |",
    `| Anomaly Score | ${anomaly} | ${anomaly >= 0.8 ? "High" : anomaly >= 0.5 ? "Elevated" : "Low"} deviation |`,
    `| Risk Score (0-100) | ${risk.risk_score} (${risk.risk_level}) | ${factors[0] || "n/a"} |`,
    `| Failed vs Successful Logins | ${t.failed_logins} / ${t.successful_logins} | ${
      (t.successful_logins ?? 0) >= 1 && (t.failed_logins ?? 0) >= 10
        ? "Failed + successful events both present"
        : "Failures only"
    } |`,
    `| Unique Source IPs | ${ipCount} — ${ips.join(", ") || "n/a"} | ${originNote(
      ipCount,
      Boolean(t.geo_velocity_violation)
    )} |`,
    `| Device Changes | ${t.device_changes} | ${
      (t.device_changes ?? 0) > 0 ? "New unrecognised fingerprint" : "Stable"
    } |`,
    "",
    "## 3. Threat Narrative & Attack Vector",
    `Classifier attribution: ${attack.classified_pattern} (MITRE ${
      attack.mitre_technique_id || "n/a"
    }, ${conf}% confidence). ${attack.signature_details || ""}`,
    "",
    "## 4. Recommended Mitigations (Non-Destructive)",
    ...(incident.recommended_actions || []).map((r, i) => `${i + 1}. ${r}`),
    "",
    `_Incident ${incident.incident_id} status: ${incident.status}. Generated by client-side fallback chaining — analytical only, no remediation executed._`,
  ];
  return lines.join("\n");
}

/* ==========================================================================
 * 6. Bootstrap — initWebMCP(apiBaseUrl, opts)
 * ========================================================================== */

/**
 * Wire the CyberGuard tools into the current page.
 *
 * - If native WebMCP is present, registers all tools via
 *   `navigator.modelContext.registerTool`; each `execute` validates against the
 *   tool schema and proxies to the backend.
 * - A `CyberGuardFallbackClient` is ALWAYS returned on `.client`, so callers get
 *   an identical surface whether or not WebMCP is enabled.
 *
 * @param {string} apiBaseUrl              Backend API base URL.
 * @param {object} [opts]
 * @param {boolean} [opts.autoRegister=true]  Register with WebMCP when supported.
 * @param {"rest"|"jsonrpc"} [opts.mode="rest"]
 * @param {string}  [opts.rpcPath=""]
 * @param {object}  [opts.routes]
 * @param {Record<string,string>} [opts.headers]
 * @param {RequestCredentials} [opts.credentials="same-origin"]
 * @param {number}  [opts.timeoutMs=15000]
 * @param {number}  [opts.retries=2]
 * @param {typeof fetch} [opts.fetchImpl]
 * @returns {{
 *   supported: boolean,
 *   mode: "webmcp"|"fallback",
 *   registeredTools: string[],
 *   client: CyberGuardFallbackClient,
 *   transport: CyberGuardTransport,
 *   callTool: (name:string, args?:object) => Promise<any>,
 *   unregisterAll: () => void
 * }}
 */
export function initWebMCP(apiBaseUrl, opts = {}) {
  const transport = new CyberGuardTransport(apiBaseUrl, opts);
  const client = new CyberGuardFallbackClient(apiBaseUrl, {
    ...opts,
    _transport: transport,
  });

  const supported = isWebMCPSupported();
  const autoRegister = opts.autoRegister !== false;
  /** @type {{name:string, handle:any}[]} */
  const registrations = [];

  if (supported && autoRegister) {
    for (const def of WEBMCP_TOOL_DEFS) {
      const tool = {
        name: def.name,
        description: def.description,
        inputSchema: def.inputSchema,
        async execute(input) {
          // WebMCP hands the params object directly; tolerate an { arguments } wrapper.
          const rawArgs =
            input && typeof input === "object" && input.arguments &&
            typeof input.arguments === "object"
              ? input.arguments
              : input || {};
          try {
            const { ok, value, errors } = validateArgs(def.inputSchema, rawArgs);
            if (!ok) {
              return toToolResult(
                { error: "InvalidInput", tool: def.name, details: errors },
                true
              );
            }
            const data = await transport.call(def.name, value);
            return toToolResult(data, false);
          } catch (err) {
            return toToolResult(
              {
                error: (err && err.name) || "BridgeError",
                tool: def.name,
                message: String((err && err.message) || err),
                status: err && err.status,
                body: err && err.body,
              },
              true
            );
          }
        },
      };

      let handle;
      try {
        // registerTool returns an unregister handle in the current proposal;
        // some builds return void and expose unregisterTool(name) instead.
        handle = navigator.modelContext.registerTool(tool);
        registrations.push({ name: def.name, handle });
      } catch (err) {
        // Non-fatal: keep going, fallback client still covers this tool.
        console.warn(`[webmcp_bridge] registerTool("${def.name}") failed:`, err);
      }
    }
  }

  function unregisterAll() {
    for (const reg of registrations.splice(0)) {
      try {
        if (reg.handle && typeof reg.handle.unregister === "function") {
          reg.handle.unregister();
        } else if (
          navigator.modelContext &&
          typeof navigator.modelContext.unregisterTool === "function"
        ) {
          navigator.modelContext.unregisterTool(reg.name);
        }
      } catch (err) {
        console.warn(`[webmcp_bridge] unregister("${reg.name}") failed:`, err);
      }
    }
  }

  return {
    supported,
    mode: supported && autoRegister && registrations.length ? "webmcp" : "fallback",
    registeredTools: registrations.map((r) => r.name),
    client,
    transport,
    callTool: (name, args) => client.callTool(name, args),
    runInvestigation: (userId = null) => client.runInvestigation(userId),
    unregisterAll,
  };
}

/* ==========================================================================
 * 7. Helpers
 * ========================================================================== */

/** Wrap a payload in the MCP tool-result shape. */
function toToolResult(payload, isError = false) {
  const text =
    typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  const result = {
    content: [{ type: "text", text }],
    isError: !!isError,
  };
  if (payload && typeof payload === "object") result.structuredContent = payload;
  return result;
}

/**
 * Substitute {param} / :param tokens in a route path from `args`.
 * @returns {{path:string, rest:object}} filled path + the args not consumed by tokens.
 */
function fillPathParams(path, args) {
  const src = args && typeof args === "object" ? args : {};
  const consumed = new Set();
  const filled = String(path).replace(
    /[:{]([A-Za-z_][A-Za-z0-9_]*)\}?/g,
    (_m, key) => {
      if (src[key] === undefined || src[key] === null) {
        const err = new Error(`missing path parameter "${key}"`);
        err.name = "InvalidInput";
        throw err;
      }
      consumed.add(key);
      return encodeURIComponent(src[key]);
    }
  );
  const rest = {};
  for (const [k, v] of Object.entries(src)) {
    if (!consumed.has(k)) rest[k] = v;
  }
  return { path: filled, rest };
}

/** Flatten a flat object to a query string; arrays repeat the key. */
function toQuery(obj) {
  if (!obj || typeof obj !== "object") return "";
  const parts = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      for (const item of v) parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(item)}`);
    } else {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
  }
  return parts.join("&");
}

function randomId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `rpc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Exponential backoff with jitter: ~250ms, 500ms, 1s, ... capped at 5s. */
function backoff(attempt) {
  const delay = Math.min(5000, 250 * 2 ** attempt) + Math.floor(Math.random() * 100);
  return new Promise((resolve) => setTimeout(resolve, delay));
}

/* ==========================================================================
 * 8. Debug handle for non-bundler / console use
 * ========================================================================== */

if (typeof window !== "undefined") {
  window.CyberGuardWebMCP = {
    initWebMCP,
    isWebMCPSupported,
    CyberGuardFallbackClient,
    WEBMCP_TOOL_DEFS,
    TOOL_NAMES,
    DEFAULT_ROUTES,
    validateArgs,
    getToolDef,
  };
}

export default initWebMCP;

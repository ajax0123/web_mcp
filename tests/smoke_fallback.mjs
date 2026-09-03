/**
 * Smoke test — client-side fallback in frontend/webmcp_bridge.js.
 *
 * Case 3: if POST /api/v1/agent/investigate is delayed or unresponsive, the
 * bridge must fall back to sequential client-side tool chaining CLEANLY — no
 * throw, same response shape, all UI keys present.
 *
 * Scenarios (only the /agent/investigate call is sabotaged; the six tool
 * endpoints still hit the real backend):
 *   hang    fetch never resolves  -> AbortController timeout -> fallback
 *   reject  fetch throws (ECONNREFUSED-style)              -> fallback
 *   503     fetch returns 503                              -> fallback
 *
 * Usage:  node tests/smoke_fallback.mjs [API_BASE]
 */

import { initWebMCP } from "../frontend/webmcp_bridge.js";

const API = (process.argv[2] || "http://localhost:8000").replace(/\/+$/, "");
const REAL_FETCH = globalThis.fetch;

let pass = 0;
let fail = 0;
function check(cond, label) {
  console.log(`    ${cond ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m"} ${label}`);
  cond ? pass++ : fail++;
}

/** fetchImpl that breaks ONLY the agent endpoint, per `mode`. */
function sabotage(mode) {
  return async (url, init) => {
    if (String(url).includes("/api/v1/agent/investigate")) {
      if (mode === "hang") {
        // Unresponsive endpoint: settle ONLY when the caller's AbortController
        // fires (exactly how a real hung fetch behaves under a timeout).
        return new Promise((_resolve, reject) => {
          const sig = init && init.signal;
          if (sig) {
            const onAbort = () =>
              reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
            sig.aborted ? onAbort() : sig.addEventListener("abort", onAbort, { once: true });
          }
        });
      }
      if (mode === "reject") throw new TypeError("fetch failed"); // conn refused style
      if (mode === "503")
        return new Response('{"detail":"service unavailable"}', {
          status: 503,
          statusText: "Service Unavailable",
          headers: { "content-type": "application/json" },
        });
    }
    return REAL_FETCH(url, init); // real backend for the tool endpoints
  };
}

/** Reject if `p` has not settled within `ms` — turns a real hang into a visible failure. */
function withHardTimeout(p, ms, label) {
  return Promise.race([
    p,
    new Promise((_r, reject) =>
      setTimeout(() => reject(new Error(`HARD TIMEOUT after ${ms}ms — ${label}`)), ms).unref?.()
    ),
  ]);
}

async function runScenario(mode) {
  console.log(`\n[3.${mode}] agent endpoint "${mode}" — expect clean client fallback`);
  const t0 = Date.now();
  const bridge = initWebMCP(API, {
    fetchImpl: sabotage(mode),
    timeoutMs: mode === "hang" ? 1200 : 8000,
  });

  let r, threw = null;
  try {
    r = await withHardTimeout(bridge.runInvestigation(null), 12000, `[${mode}] runInvestigation`);
  } catch (e) {
    threw = e;
  }
  const ms = Date.now() - t0;

  check(threw === null, `runInvestigation() did not throw  (UI-safe)${threw ? " — " + threw.message : ""}`);
  if (!r) return;
  check(r.status === "COMPLETE", `status == COMPLETE via fallback  (got ${r.status})`);
  check(r._source === "client_fallback", `_source == client_fallback  (got ${r._source})`);
  check(typeof r._server_error === "string" && r._server_error.length > 0, `_server_error captured  ("${r._server_error}")`);
  check(!!r.assessment && !!r.assessment.threat_classification, "assessment.threat_classification present");
  check(!!r.telemetry && "failed_logins" in r.telemetry && "anomaly_score" in r.telemetry, "telemetry keys present");
  check(Array.isArray(r.audit_trace) && r.audit_trace.length === 6, `audit_trace has all 6 steps  (got ${r.audit_trace?.length})`);
  check(r.audit_trace.every((s) => typeof s.ts === "string"), "every audit step carries a timestamp");
  check(typeof r.markdown_report === "string" && r.markdown_report.startsWith("# INCIDENT REPORT"), "markdown_report ready for UI");
  if (mode === "hang") {
    check(ms < 5000, `aborted + fell back promptly  (${ms}ms < 5000 — timeout honored, no UI hang)`);
  }
}

async function runTargeted() {
  console.log(`\n[3.targeted] fallback with explicit user_id — triage still skipped`);
  const bridge = initWebMCP(API, { fetchImpl: sabotage("reject") });
  let r, threw = null;
  try {
    r = await withHardTimeout(bridge.runInvestigation("USR-108"), 12000, "targeted runInvestigation");
  } catch (e) {
    threw = e;
  }
  check(threw === null, "runInvestigation('USR-108') did not throw");
  if (!r) return;
  check(r._source === "client_fallback", "_source == client_fallback");
  check(r.target_user_id === "USR-108", "target_user_id == USR-108");
  check(r.auto_selected === false, "auto_selected == false");
  const tools = r.audit_trace.map((s) => s.tool);
  check(!tools.includes("get_security_summary") && !tools.includes("get_suspicious_users"), "triage tools skipped in fallback path");
  check(r.audit_trace.length === 4, `audit_trace has 4 steps (deep-dive → report)  (got ${r.audit_trace.length})`);
}

async function main() {
  // Watchdog: keeps the event loop alive AND guarantees a non-zero exit if the
  // suite ever hangs (rather than Node silently exiting 0 on an empty loop).
  const watchdog = setTimeout(() => {
    console.error("\n\x1b[31mFATAL: smoke_fallback watchdog fired — suite hung\x1b[0m");
    process.exit(3);
  }, 60000);

  // sanity: backend reachable for the tool endpoints
  try {
    const h = await REAL_FETCH(`${API}/health`);
    if (!h.ok) throw new Error(`health ${h.status}`);
  } catch (e) {
    console.error(`FATAL: backend not reachable at ${API} (${e.message})`);
    process.exit(2);
  }

  for (const mode of ["hang", "reject", "503"]) await runScenario(mode);
  await runTargeted();

  clearTimeout(watchdog);
  const line = `\n  smoke_fallback: ${pass} passed, ${fail} failed`;
  console.log(fail === 0 ? `\x1b[32m${line}\x1b[0m` : `\x1b[31m${line}\x1b[0m`);
  process.exit(fail ? 1 : 0);
}

main();

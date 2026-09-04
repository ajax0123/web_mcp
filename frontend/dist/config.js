/* config.js — runtime configuration for the CyberGuard dashboard (PP-H3).
 *
 * Loaded before the app bundle; the ONLY place the API target + operator
 * credential live. Served verbatim from frontend/public/config.js -> dist/config.js
 * (never bundled). Edit it, overwrite it at deploy time (envsubst / a build step),
 * or set `window.__CYBERGUARD_API_URL__` from an inline <script> before this file.
 *
 * Do NOT commit a real key here.
 */
(function () {
  var host = (typeof window !== "undefined" && window.location && window.location.hostname) || "";
  var isLocal =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "" ||
    host.endsWith(".local");

  // The live Render backend. This literal MUST match the vercel.json CSP
  // `connect-src` host and the live Render service URL. Render appends a random
  // suffix (…-bw5v) that changes if the service is recreated — repoint both
  // places together, or move to a stable custom domain.
  var PROD_API_BASE = "https://cyberguard-backend-bw5v.onrender.com";

  // Vercel (or any static host) may inject the API origin either as an inline
  // window.__CYBERGUARD_API_URL__ <script> before this file, or as a window.__ENV__
  // map produced from project Environment Variables. The dashboard works whether
  // those are populated or not — an empty/absent value falls through to the
  // localhost dev target or PROD_API_BASE.
  var ENV = (typeof window !== "undefined" && window.__ENV__) || {};

  // Precedence: explicit inline override -> injected env -> localhost in dev -> prod default.
  var API_BASE =
    (typeof window !== "undefined" && window.__CYBERGUARD_API_URL__) ||
    ENV.CYBERGUARD_API_URL ||
    (isLocal ? "http://localhost:8000" : PROD_API_BASE);

  window.CYBERGUARD_CONFIG = {
    // Base URL of the CyberGuard API. Must also be allowed by the page CSP `connect-src`.
    apiBase: API_BASE,

    // Sent as `X-API-Key` on every /api/v1 request. Empty in dev / staging
    // (the gateway is a warn-once no-op when API_KEYS is unset and APP_ENV != production).
    apiKey: "",
  };
})();

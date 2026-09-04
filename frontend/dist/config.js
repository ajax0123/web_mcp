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

  // Precedence: explicit override  ->  localhost in dev  ->  deployed API default.
  // Change the production URL to your Render/Railway host, or inject
  // window.__CYBERGUARD_API_URL__ before this script.
  var API_BASE =
    (typeof window !== "undefined" && window.__CYBERGUARD_API_URL__) ||
    (isLocal ? "http://localhost:8000" : "https://cyberguard-api.onrender.com");

  window.CYBERGUARD_CONFIG = {
    // Base URL of the CyberGuard API. Must also be allowed by the page CSP `connect-src`.
    apiBase: API_BASE,

    // Sent as `X-API-Key` on every /api/v1 request. Empty in dev / staging
    // (the gateway is a warn-once no-op when API_KEYS is unset and APP_ENV != production).
    apiKey: "",
  };
})();

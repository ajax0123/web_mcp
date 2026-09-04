/* config.js — runtime configuration for the CyberGuard dashboard (PP-H3).
 *
 * This file is loaded before app.js and is the ONLY place the API target and
 * the operator credential live. It is intended to be:
 *   - edited per environment, or
 *   - overwritten by the deploy (envsubst / a ConfigMap / an entrypoint script).
 *
 * Do NOT commit a real key here. In production, serve a per-operator, short-lived
 * token minted for the signed-in user (e.g. from an auth proxy) rather than a
 * shared static API key.
 */
window.CYBERGUARD_CONFIG = {
  // Base URL of the CyberGuard API. Must also appear in the page/response CSP
  // `connect-src`. Default: local dev.
  apiBase: "http://localhost:8000",

  // Sent as `X-API-Key` on every /api/v1 request. Empty in dev (the API's
  // gateway is a warn-once no-op when APP_ENV=dev and API_KEYS is unset).
  apiKey: "",
};

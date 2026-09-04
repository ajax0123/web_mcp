# CyberGuard dashboard — static frontend

Zero-CDN, zero-runtime-compile (audit PP-M7 / A-L4).

| file | role |
| :--- | :--- |
| `index.html` | markup shell — links `app.css`, loads `config.js`, then the flat React entry `app.jsx` |
| `app.css` | **precompiled** utility stylesheet — a hand-authored Tailwind subset covering exactly the classes `index.html` / `app.js` use. No external stylesheet, no JIT compiler, so the CSP needs no external host and no `'unsafe-eval'`. |
| `app.jsx` | flat React dashboard logic using the existing WebMCP bridge |
| `config.js` | **runtime config** — `apiBase` + per-operator `apiKey` (sent as `X-API-Key`). Edit it, or template it from the deploy. No secret is baked into `index.html`. |
| `webmcp_bridge.js` | WebMCP bridge + REST fallback client |
| `serve.py` | dev static server that sets the security response headers (CSP / X-Frame-Options / nosniff / …) |

## Run (dev)

```bash
cd web_mcp/frontend
python3 serve.py 5173
# open http://localhost:5173/index.html
```

## Regenerating `app.css` with real Tailwind

The hand-authored subset is verified for **class coverage** (every referenced
utility has a rule) but not pixel-rendered in CI. For a production build, replace
it with a real Tailwind pass and keep the same filename:

```bash
npx tailwindcss -i tailwind.src.css -o app.css --content './index.html' './app.jsx' --minify
```

A Playwright screenshot check of `index.html` against the mock API is the
recommended regression guard (tracked as A-L4).

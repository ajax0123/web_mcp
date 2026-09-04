#!/usr/bin/env python3
"""
serve.py — static file server for the CyberGuard dashboard with real HTTP
security response headers (PP-M7).

    python3 serve.py [port]        # default 5173, binds 127.0.0.1

FE-1: this serves the COMMITTED production bundle in ./dist/ (built from app.jsx
with `npm run build`). No Vite dev server, no `npm install`, no network — a plain
`python3 serve.py 5173` gives judges a working dashboard. If ./dist/ is absent it
falls back to serving this directory (only useful with `npm run dev` running).

For production, serve ./dist/ from nginx / a CDN with an equivalent header set
(and HTTPS + HSTS). This dev server exists so the dashboard isn't shipped
header-less by `python -m http.server`.

The CSP here is the AUTHORITATIVE one; the <meta> tag in index.html is a
backstop. `connect-src` must include your API origin — override with
    CYBERGUARD_CONNECT_SRC="https://api.example.com"
"""
from __future__ import annotations

import os
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_CONNECT = os.getenv("CYBERGUARD_CONNECT_SRC", "http://localhost:8000")

CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    f"connect-src 'self' {_CONNECT}; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    # Enable when served over TLS:
    # "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}

# FE-1: `nosniff` means the browser refuses a `<script type="module">` whose
# Content-Type is not a JS MIME. Python's mimetypes DB is inconsistent across
# platforms (it has returned application/octet-stream / text/plain for .js /
# .mjs), so pin the ones the bundle actually uses.
_EXPLICIT_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".jsx": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ico": "image/x-icon",
    ".html": "text/html; charset=utf-8",
}


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, **_EXPLICIT_TYPES}

    def do_GET(self) -> None:
        # SPA client-side routes -> the app shell.
        if self.path.split("?", 1)[0] in {"/", "/dashboard", "/login"}:
            self.path = "/index.html"
        super().do_GET()

    def guess_type(self, path):  # noqa: D401 - belt-and-suspenders over extensions_map
        ext = Path(str(path)).suffix.lower()
        if ext in _EXPLICIT_TYPES:
            return _EXPLICIT_TYPES[ext]
        return super().guess_type(path)

    def end_headers(self) -> None:
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def _serve_root() -> str:
    here = Path(__file__).resolve().parent
    dist = here / "dist"
    if (dist / "index.html").is_file():
        return str(dist)
    sys.stderr.write(
        "WARNING: frontend/dist/ not found — serving source dir. Run `npm run build` "
        "(or `npm run dev`) for a working dashboard.\n"
    )
    return str(here)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5173
    directory = _serve_root()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, directory=directory))
    print(f"CyberGuard dashboard: http://127.0.0.1:{port}/")
    print(f"  serving {directory}")
    print(f"  CSP connect-src: 'self' {_CONNECT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()

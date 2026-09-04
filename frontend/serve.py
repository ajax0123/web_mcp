#!/usr/bin/env python3
"""
serve.py — static file server for the CyberGuard dashboard with real HTTP
security response headers (PP-M7).

    python3 serve.py [port]        # default 5173, binds 127.0.0.1

For production, serve the same directory from nginx / a CDN with an equivalent
header set (and HTTPS + HSTS). This dev server exists so the dashboard isn't
shipped header-less by `python -m http.server`.

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


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] in {"/", "/dashboard"}:
            self.path = "/index.html"
        super().do_GET()

    def end_headers(self) -> None:  # noqa: D401
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5173
    directory = str(Path(__file__).resolve().parent)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, directory=directory))
    print(f"CyberGuard dashboard: http://127.0.0.1:{port}/index.html")
    print(f"  serving {directory}")
    print(f"  CSP connect-src: 'self' {_CONNECT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()

# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
"""Temporary AIS landing page; no identity endpoints or user data."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATIC = Path(__file__).resolve().parent / "static"
PAGE = b"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aiaiaiai AIS</title><link rel="stylesheet" href="/static/auth.css">
</head><body><main class="ecosystem-auth-panel" aria-labelledby="title">
<p class="auth-product-name">aiaiaiai AIS</p><h1 id="title">Identity, in progress.</h1>
<p>Sign-in and registration are not available yet.</p>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            body, kind, status = b"ok\n", "text/plain; charset=utf-8", 200
        elif path == "/":
            body, kind, status = PAGE, "text/html; charset=utf-8", 200
        elif path == "/static/auth.css":
            body, kind, status = (STATIC / "auth.css").read_bytes(), "text/css; charset=utf-8", 200
        else:
            body, kind, status = b"Not found\n", "text/plain; charset=utf-8", 404
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 1927), Handler).serve_forever()

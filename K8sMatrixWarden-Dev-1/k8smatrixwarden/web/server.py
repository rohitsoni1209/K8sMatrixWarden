"""
Thin stdlib `http.server` shell over WebApp (web/app.py).

`serve()` builds the platform once, wraps a WebApp, and dispatches every request to
`WebApp.route(...)`. No third-party web framework — the same zero-dependency stance the rest
of the tool takes, so `k8smatrixwarden web` runs on a bare Python install.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from ..bootstrap import build_platform
from .app import WebApp

_MAX_BODY = 2 * 1024 * 1024  # 2 MiB cap on POST bodies


def make_handler(app: WebApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "k8smatrixwarden-web"
        protocol_version = "HTTP/1.1"

        def _dispatch(self, method: str) -> None:
            path, _, query = self.path.partition("?")
            length = min(int(self.headers.get("Content-Length", 0) or 0), _MAX_BODY)
            body = self.rfile.read(length) if length else b""
            resp = app.route(method, path, query, body)
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(resp.body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_HEAD(self):
            self._dispatch("GET")

        def log_message(self, fmt, *args):  # keep the console quiet unless it's an error
            if not str(args[1] if len(args) > 1 else "").startswith("2"):
                super().log_message(fmt, *args)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080,
          reports_dir: str = "k8smatrixwarden-reports",
          config_path: Optional[str] = None, allow_scan: bool = True,
          open_browser: bool = False) -> None:
    platform = build_platform(config_path)
    app = WebApp(platform, reports_dir=reports_dir, allow_scan=allow_scan)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    url = f"http://{host}:{port}/"
    print(f"🛡️  K8sMatrixWarden dashboard → {url}")
    print(f"    reports dir: {reports_dir}   ·   scanning: "
          f"{'enabled' if allow_scan else 'disabled'}   ·   Ctrl-C to stop")
    if open_browser:
        threading.Timer(0.5, lambda: _open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 dashboard stopped")
    finally:
        httpd.server_close()


def _open(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass

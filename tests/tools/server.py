"""Synthetic HTTP target; no host port, credentials or external links."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNT = 0
LOCK = threading.Lock()
MARKER = "vardrsec-tool-fixture"


class Target(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        global COUNT
        with LOCK:
            COUNT += 1
            limit = COUNT > 60
        status = 503 if limit else 200 if self.path in ("/", "/probe") else 404
        body = (
            f'<html><title>{MARKER}</title><a href="/probe">probe</a></html>'.encode()
            if self.path == "/"
            else MARKER.encode()
        )
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Target).serve_forever()

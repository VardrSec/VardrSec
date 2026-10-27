"""Disposable authorization target. No published ports or non-fixture data."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOKENS = {who: os.environ[f"FIXTURE_{who.upper()}_TOKEN"] for who in ("owner", "peer")}
REQUESTS = []
LOCK = threading.Lock()
BODY_CANARY = "disposable-private-response-canary"
COOKIE_CANARY = "disposable-response-cookie-canary"


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            return self.reply(200, {"ready": True})
        if path == "/observations":
            with LOCK:
                return self.reply(200, {"requests": list(REQUESTS)})
        who = next(
            (
                name
                for name, token in TOKENS.items()
                if self.headers.get("Authorization") == "Bearer " + token
            ),
            "anonymous",
        )
        with LOCK:
            REQUESTS.append({"identity": who, "path": self.path})
            over_budget = len(REQUESTS) > 30
        if over_budget:
            return self.reply(503, {"error": "fixture_request_ceiling"})
        if path == "/session":
            return self.reply(200 if who != "anonymous" else 401, {"user": {"id": who}})
        if path == "/unavailable/records/42":
            return self.reply(503, {"error": "fixture_unavailable"})
        if path == "/fixed/records/42" and who != "owner":
            return self.reply(
                401 if who == "anonymous" else 403, {"error": "forbidden"}
            )
        if path in {"/fixed/records/42", "/vulnerable/records/42"}:
            return self.reply(200, {"owner": "owner", "api_key": BODY_CANARY})
        self.reply(404, {"error": "unknown_fixture_route"})

    def reply(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Set-Cookie", f"session={COOKIE_CANARY}; HttpOnly")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Target).serve_forever()

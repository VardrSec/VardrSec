"""Disposable authorization target. No published ports or non-fixture data."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOKENS = {
    who: os.environ[f"FIXTURE_{who.upper()}_TOKEN"]
    for who in ("owner", "peer", "reader")
}
REQUESTS = []
LOCK = threading.Lock()
STATE = {"fixed": False, "value": "initial"}
BODY_CANARY = "disposable-private-response-canary"
COOKIE_CANARY = "disposable-response-cookie-canary"


class Target(BaseHTTPRequestHandler):
    def identity(self):
        return next(
            (
                name
                for name, token in TOKENS.items()
                if self.headers.get("Authorization") == "Bearer " + token
            ),
            "anonymous",
        )

    def record(self, who, changed=None):
        REQUESTS.append(
            {
                "identity": who,
                "path": self.path,
                "method": self.command,
                **({"changed": changed} if changed is not None else {}),
            }
        )
        return len(REQUESTS) > 60

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            return self.reply(200, {"ready": True})
        if path == "/observations":
            with LOCK:
                return self.reply(200, {"requests": list(REQUESTS)})
        who = self.identity()
        with LOCK:
            over_budget = self.record(who)
        if over_budget:
            return self.reply(503, {"error": "fixture_request_ceiling"})
        if path == "/session":
            return self.reply(200 if who != "anonymous" else 401, {"user": {"id": who}})
        if path == "/verification/state":
            with LOCK:
                return (
                    self.reply(200, {"value": STATE["value"]})
                    if who == "reader"
                    else self.reply(403, {"error": "wrong_reader"})
                )
        if path == "/unavailable/records/42":
            return self.reply(503, {"error": "fixture_unavailable"})
        if path == "/fixed/records/42" and who != "owner":
            return self.reply(
                401 if who == "anonymous" else 403, {"error": "forbidden"}
            )
        if path in {"/fixed/records/42", "/vulnerable/records/42"}:
            return self.reply(200, {"owner": "owner", "api_key": BODY_CANARY})
        self.reply(404, {"error": "unknown_fixture_route"})

    def do_POST(self):
        # Only the orchestrator's explicit repair step may toggle this fixture.
        if self.path != "/control/fix" or self.client_address[0] != "127.0.0.1":
            return self.reply(403, {"error": "fixture_control_only"})
        with LOCK:
            STATE["fixed"] = True
        self.reply(200, {"fixed": True})

    def do_PUT(self):
        who = self.identity()
        try:
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}"
            )
        except (ValueError, TypeError):
            return self.reply(400, {"error": "invalid_fixture_body"})
        with LOCK:
            before = STATE["value"]
            if len(REQUESTS) >= 60:
                status = 503
            elif self.path == "/verification/reset" and who == "owner":
                STATE["value"], status = "initial", 204
            elif (
                self.path == "/verification/write"
                and who in ("owner", "peer")
                and body == {"value": "fixture-write-marker"}
            ):
                if who == "owner" or not STATE["fixed"]:
                    STATE["value"] = body["value"]
                status = (
                    204  # Identical masked status; only readback proves the effect.
                )
            else:
                status = 403
            self.record(who, STATE["value"] != before)
        self.reply(
            status, None if status == 204 else {"error": "fixture_write_rejected"}
        )

    def reply(self, status, body):
        payload = b"" if status == 204 else json.dumps(body).encode()
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

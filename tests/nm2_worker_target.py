"""Thin controlled-HTTP wrapper around the existing disposable Gate target.

No process-tree exercises. The optional delay applies only to an existing GET
resource response, after the existing target has recorded the request.
"""

import os
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, "/fixture/gate")
from target import Target, ThreadingHTTPServer  # noqa: E402


def response_delay(value):
    if value not in {"0", "15"}:
        raise ValueError("fixture_delay_must_be_0_or_15_seconds")
    return int(value)


class ControlledTarget(Target):
    delay = response_delay(os.environ.get("NM2_FIXTURE_DELAY_SECONDS", "0"))

    def record(self, who, changed=None):
        over_budget = super().record(who, changed)
        # The parent records no headers or credential values.
        from target import REQUESTS

        REQUESTS[-1]["received_monotonic_ns"] = time.monotonic_ns()
        return over_budget

    def reply(self, status, body):
        if self.command == "GET" and urlsplit(self.path).path == "/fixed/records/42":
            time.sleep(self.delay)
        try:
            return super().reply(status, body)
        except (BrokenPipeError, ConnectionResetError):
            # An ordinary request may outlive the caller's controlled lease.
            return None


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), ControlledTarget).serve_forever()

"""Thin controlled-HTTP wrapper around the existing disposable Gate target.

No process-tree exercises. The optional delay applies only to an existing GET
resource response, after the existing target has recorded the request.
"""

import os
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, "/fixture/gate")
from target import REQUESTS, Target, ThreadingHTTPServer  # noqa: E402


def response_delay(value):
    if value not in {"0", "15"}:
        raise ValueError("fixture_delay_must_be_0_or_15_seconds")
    return int(value)


def request_ceiling(value):
    if type(value) is not str or value not in {"60", "175"}:
        raise ValueError("fixture_request_ceiling_must_be_60_or_175")
    return int(value)


class ControlledTarget(Target):
    delay = response_delay(os.environ.get("NM2_FIXTURE_DELAY_SECONDS", "0"))
    ceiling = request_ceiling(os.environ.get("NM2_FIXTURE_REQUEST_CEILING", "60"))
    utc_timing = os.environ.get("NM2_FIXTURE_UTC_TIMING") == "1"

    def record(self, who, changed=None):
        super().record(who, changed)
        # The parent records no headers or credential values.
        REQUESTS[-1]["received_monotonic_ns"] = time.monotonic_ns()
        if self.utc_timing:
            REQUESTS[-1]["received_utc_ns"] = time.time_ns()
        return len(REQUESTS) > self.ceiling

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

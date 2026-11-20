"""Verify the bounded idle reader's isolated success and redacted failure."""
import unittest

from nm2_projection_test_process import check_projection


def check_idle(public, raw):
    assert public["schema"] == "vardr.nm2-worker-idle-public/1"
    assert public["status"] == "selected_idle_control_slice_passed"
    measured = public["measurements"]
    assert measured["issued_attempts"] == 1
    assert measured["target_request_count"] == 5
    assert measured["native_exit_code"] == 124
    assert measured["operator_stop_requested"] is False
    assert measured["limits"] == {"max_attempts": None, "idle_timeout_seconds": 60}


def check_idle_refusal(public, raw):
    assert public == {"stage": "idle_control_observation", "reason": "idle_native_exit_not_observed"}


class IdleHostedEntrypoint(unittest.TestCase):
    def test_idle_success_loads_real_independent_reader_outside_checkout(self):
        from test_nm2_worker_idle_limit import vector

        raw, selection, *_ = vector()
        check_projection(self, raw, selection, "public_projection", check_idle, bounded_error=True)

    def test_idle_failure_remains_fixed_and_redacted_outside_checkout(self):
        from test_nm2_worker_idle_limit import vector

        raw, selection, *_ = vector()
        raw.update(status="held", stage="idle_control_observation", reason="idle_native_exit_not_observed",
                   error="private-canary")
        check_projection(self, raw, selection, "failure_projection", check_idle_refusal, bounded_error=True)

"""Verify the bounded count reader's isolated success and redacted failure."""
import unittest

from nm2_projection_test_process import check_projection


def check_count(public, raw):
    assert public["schema"] == "vardr.nm2-worker-count-public/1"
    assert public["status"] == "selected_count_control_slice_passed"
    assert public["measurements"]["issued_attempts"] == 1
    assert "idle_seconds" not in public["measurements"]


def check_count_refusal(public, raw):
    assert public == {"stage": "count_control_eligibility", "reason": "count_second_job_not_eligible"}


class CountHostedEntrypoint(unittest.TestCase):
    def test_count_success_loads_real_independent_reader_outside_checkout(self):
        from test_nm2_worker_count_projection import vector

        raw, selection = vector()
        check_projection(self, raw, selection, "public_projection", check_count)

    def test_count_failure_remains_fixed_and_redacted_outside_checkout(self):
        from test_nm2_worker_count_projection import vector

        raw, selection = vector()
        raw.update(status="held", stage="count_control_eligibility", reason="count_second_job_not_eligible",
                   stderr="private-canary", error="private-canary")
        check_projection(self, raw, selection, "failure_projection", check_count_refusal)

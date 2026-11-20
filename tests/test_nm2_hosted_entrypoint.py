"""Exercise real hosted availability projections outside the checkout."""
import unittest

from nm2_projection_test_process import check_projection


def check_registration_diagnostic(public, raw):
    assert public["command_failure"] == raw["command_failure"]
    assert public["stage"] == "operator_worker_enable"


def check_availability(public, raw):
    assert public["schema"] == "vardr.nm2-worker-persistent-public/1"
    assert public["status"] == "selected_availability_slice_passed"
    assert public["measurements"]["last_sequence"] == "35"


class HostedEntrypointTests(unittest.TestCase):
    def test_isolated_failure_sidecar_keeps_registration_diagnostic(self):
        from test_nm2_worker_persistent_projection import vector

        raw, selection = vector()
        raw.update(status="held", stage="operator_worker_enable", reason="fixture_command_failed",
                   command_failure={"failure_phase": "enable_registration", "failure_code": "host_refused",
                                    "registration_failure": {"checkpoint": "request", "request_stage": "status",
                                                             "http_status": 409}})
        check_projection(self, raw, selection, "failure_projection", check_registration_diagnostic)

    def test_isolated_success_uses_the_real_persistent_projector(self):
        from test_nm2_worker_persistent_projection import vector

        raw, selection = vector()
        check_projection(self, raw, selection, "public_projection", check_availability)


if __name__ == "__main__":
    unittest.main()

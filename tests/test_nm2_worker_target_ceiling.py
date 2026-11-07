"""Pure owned-target request boundaries; no server, HTTP or Docker."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import nm2_worker_acceptance as acceptance


def load_target(ceiling=None):
    source = Path(acceptance.__file__).with_name("nm2_worker_target.py")
    spec = importlib.util.spec_from_file_location("controlled_ceiling_test", source)
    module = importlib.util.module_from_spec(spec)
    environment = {
        f"FIXTURE_{name}_TOKEN": "private-token-canary-" + name
        for name in ("OWNER", "PEER", "READER")
    }
    if ceiling is not None:
        environment["NM2_FIXTURE_REQUEST_CEILING"] = ceiling
    with (
        patch.dict(os.environ, environment, clear=True),
        patch.dict(sys.modules),
        patch("sys.path", [str(source.parent / "gate"), *sys.path]),
        patch(
            "http.server.ThreadingHTTPServer",
            side_effect=AssertionError("no server binding"),
        ),
    ):
        sys.modules.pop("target", None)
        spec.loader.exec_module(module)
    return module


class ControlledRequestCeiling(unittest.TestCase):
    def check_boundary(self, configured, expected):
        module = load_target(configured)
        instance = object.__new__(module.ControlledTarget)
        instance.command, instance.path = "GET", "/fixed/records/42"
        records = module.REQUESTS
        self.assertEqual(instance.ceiling, expected)
        for count in range(1, expected + 1):
            self.assertIs(instance.record("owner"), False, count)
        self.assertEqual(len(records), expected)
        self.assertIs(instance.record("owner"), True)
        self.assertEqual(len(records), expected + 1)
        self.assertEqual(
            set(records[-1]), {"identity", "path", "method", "received_monotonic_ns"}
        )
        self.assertIs(type(records[-1]["received_monotonic_ns"]), int)
        self.assertNotIn("private-token-canary", json.dumps(records))

    def test_default_budget_still_allows60_and_refuses61(self):
        self.check_boundary(None, 60)

    def test_explicit_persistent_budget_allows175_and_refuses176(self):
        self.check_boundary("175", 175)

    def test_unknown_configuration_refuses_before_server_or_recording(self):
        module = load_target()
        for value in (
            None,
            60,
            175,
            True,
            "0",
            "61",
            "176",
            "060",
            " 175",
            "175 ",
            "1e2",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.request_ceiling(value)
        with self.assertRaisesRegex(
            ValueError, "fixture_request_ceiling_must_be_60_or_175"
        ):
            load_target("176")

    def test_only_selected_persistent_scenario_sets175(self):
        for scenario in acceptance.SCENARIOS:
            value = acceptance.target_environment(scenario)
            if scenario == "persistent-availability":
                self.assertEqual(value, {"NM2_FIXTURE_REQUEST_CEILING": "175"})
            else:
                self.assertNotIn("NM2_FIXTURE_REQUEST_CEILING", value)
                self.assertEqual(
                    value,
                    {}
                    if scenario in {
                        "healthy", "persistent-count-limit", "persistent-idle-limit",
                        "persistent-empty-stop", "strict-authority-drift",
                        "strict-review-authority",
                    }
                    else {"NM2_FIXTURE_DELAY_SECONDS": "15"},
                )
        with self.assertRaises(acceptance.AcceptanceRefused):
            acceptance.target_environment("unknown")


if __name__ == "__main__":
    unittest.main()

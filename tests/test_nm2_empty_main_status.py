"""Actual official main return routing; no real fixture, manifest or commands."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import Mock, patch

import nm2_worker_acceptance as fixture


class EmptyMainStatus(unittest.TestCase):
    def invoke(self, status, *, scenario="persistent-empty-stop", run_error=None):
        selected = {"project": "synthetic-main-status"}
        owner = Mock(receipt={"status": status})
        owner.run.side_effect = run_error
        argv = ["--cohort", "unused-model-cohort.json", "--execute"]
        if scenario != "healthy":
            argv += ["--scenario", scenario, "--database-revision", "0041persistentruntime"]
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(fixture, "manifest", return_value=selected) as manifest, \
            patch.object(fixture, "Fixture", return_value=owner) as factory, \
            patch.object(fixture, "command", side_effect=AssertionError("real_command_forbidden")) as command, \
            redirect_stdout(output), redirect_stderr(errors):
            code = fixture.main(argv)
        manifest.assert_called_once()
        factory.assert_called_once_with(selected, scenario=scenario,
            database_revision="0040runtimesequence" if scenario == "healthy" else "0041persistentruntime")
        owner.run.assert_called_once_with()
        command.assert_not_called()
        return code, output.getvalue(), errors.getvalue()

    def test_actual_main_returns_zero_for_new_empty_and_all_prior_success_statuses(self):
        cases = (
            ("selected_empty_stop_slice_passed", "persistent-empty-stop"),
            ("initial_stages_passed", "healthy"),
            ("selected_failure_slice_passed", "local-emergency-stop"),
            ("selected_availability_slice_passed", "persistent-availability"),
            ("selected_count_control_slice_passed", "persistent-count-limit"),
            ("selected_idle_control_slice_passed", "persistent-idle-limit"),
        )
        for status, scenario in cases:
            with self.subTest(status=status):
                code, output, errors = self.invoke(status, scenario=scenario)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(output), {"status": status})
                self.assertEqual(errors, "")

    def test_actual_main_keeps_held_unknown_and_raised_fixture_nonzero(self):
        for status in ("held", "not_run", "unknown", "selected_empty_stop_slice_passed "):
            with self.subTest(status=status):
                code, output, errors = self.invoke(status)
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(output), {"status": status})
                self.assertEqual(errors, "")
        code, output, errors = self.invoke("selected_empty_stop_slice_passed",
            run_error=RuntimeError("synthetic-private-canary"))
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertIn("fixture held", errors)
        self.assertNotIn("synthetic-private-canary", errors)

    def test_empty_execution_still_requires_exact_reviewed_revision_before_fixture(self):
        with patch.object(fixture, "manifest") as manifest, patch.object(fixture, "Fixture") as factory:
            with self.assertRaisesRegex(fixture.AcceptanceRefused, "persistent_database_revision_required"):
                fixture.main(["--cohort", "unused-model-cohort.json", "--execute",
                    "--scenario", "persistent-empty-stop"])
        manifest.assert_not_called()
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""No Docker execution: retention contract and ownership refusals."""

import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import acceptance_retention as retention


class RetentionTests(unittest.TestCase):
    def test_disabled_default_is_exact_passthrough(self):
        call = Mock(return_value="result")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(retention.compose_fixture_run(
                call, "run", "--rm", "runner", project="fixture", purpose="probe",
                timeout=9), "result")
        call.assert_called_once_with("run", "--rm", "runner", timeout=9)

    def test_opt_in_refuses_non_github_environment(self):
        with patch.dict(os.environ, {"VARDRSEC_CI_RETAIN": "1"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "GitHub-hosted"):
                retention.enabled()

    def test_invalid_flag_refused(self):
        with patch.dict(os.environ, {"VARDRSEC_CI_RETAIN": "yes"}, clear=True):
            with self.assertRaises(RuntimeError):
                retention.enabled()

    def test_valid_environment_and_wrong_workspace(self):
        values = {"VARDRSEC_CI_RETAIN": "1", "GITHUB_ACTIONS": "true",
                  "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                  "GITHUB_WORKSPACE": str(retention.ROOT), "GITHUB_RUN_ID": "1",
                  "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "acceptance"}
        with patch.dict(os.environ, values, clear=True), patch.object(
            Path, "read_text", return_value="ID=ubuntu\n"):
            self.assertTrue(retention.enabled())
            with patch.dict(os.environ, {"GITHUB_WORKSPACE": "/unrelated"}):
                with self.assertRaisesRegex(RuntimeError, "checkout"):
                    retention.enabled()

    def test_existing_fixture_refused(self):
        with patch.object(retention, "enabled", return_value=True), patch.object(
            retention, "docker", return_value=Mock(stdout="existing-id")) as docker:
            with self.assertRaisesRegex(RuntimeError, "existing"):
                retention.run_flags("fixture")
        self.assertEqual(docker.call_count, 1)

    def test_owned_copy_marker_and_mismatch(self):
        values = {"VARDRSEC_CI_RETAIN": "1", "GITHUB_ACTIONS": "true",
                  "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
                  "GITHUB_WORKSPACE": "/checkout", "RUNNER_TEMP": "/fixture-temp",
                  "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "acceptance"}
        marker = '{"GITHUB_RUN_ID":"1","GITHUB_RUN_ATTEMPT":"2","GITHUB_JOB":"acceptance"}'
        with patch.dict(os.environ, values, clear=True), patch.object(
            retention, "ROOT", Path("/fixture-temp/community-run")), patch.object(
            Path, "is_symlink", return_value=False), patch.object(
            Path, "is_file", return_value=True), patch.object(
            Path, "read_text", side_effect=["ID=ubuntu\n", marker, "ID=ubuntu\n", '{}']):
            self.assertTrue(retention.enabled())
            with self.assertRaisesRegex(RuntimeError, "another CI run"):
                retention.enabled()

    def test_existing_volume_refused_before_any_mutation(self):
        with patch.object(retention, "scope", return_value="owner"), patch.object(
            retention, "docker", side_effect=[Mock(stdout=""), Mock(stdout="existing-volume")]) as docker:
            with self.assertRaisesRegex(RuntimeError, "existing"):
                retention.require_new_project("fixture")
        self.assertEqual(docker.call_count, 2)

    def test_retained_run_stops_on_timeout_without_remove(self):
        call = Mock(side_effect=subprocess.TimeoutExpired("fixture", 1))
        with patch.object(retention, "enabled", return_value=True), patch.object(
            retention, "fixture_name", return_value="unique"), patch.object(
            retention, "run_flags", return_value=["--name", "unique"]), patch.object(
            retention, "stop_container") as stop:
            with self.assertRaises(subprocess.TimeoutExpired):
                retention.compose_fixture_run(call, "run", "--rm", "runner",
                    project="fixture", purpose="probe")
        call.assert_called_once_with("run", "--name", "unique", "runner")
        stop.assert_called_once_with("unique")

    def test_unowned_container_never_stopped(self):
        with patch.object(retention, "enabled", return_value=True), patch.object(
            retention, "scope", return_value="owner"), patch.object(retention, "docker",
            side_effect=[Mock(stdout="immutable-id"), Mock(stdout='{}')]) as docker:
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                retention.stop_container("fixture")
        self.assertFalse(any(c.args[0] in ("stop", "kill", "rm") for c in docker.call_args_list))

    def test_stop_failure_still_forces_running_owned_container(self):
        with patch.object(retention, "enabled", return_value=True), patch.object(
            retention, "scope", return_value="owner"), patch.object(retention, "docker",
            side_effect=[Mock(stdout="immutable-id"),
                         Mock(stdout='{"org.vardrsec.acceptance.run":"owner"}'),
                         subprocess.CalledProcessError(1, "stop"),
                         Mock(stdout="true"), Mock()]) as docker:
            retention.stop_container("fixture")
        self.assertEqual(docker.call_args.args, ("kill", "immutable-id"))
        self.assertFalse(any(c.args[0] == "rm" for c in docker.call_args_list))

    def test_existing_work_refused_without_modification(self):
        with patch.object(retention, "enabled", return_value=True), patch.object(
            Path, "exists", return_value=True), patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(RuntimeError, "existing"):
                retention.fresh_work(retention.ROOT / "artifacts" / "already-present")
        mkdir.assert_not_called()

    def test_project_ownership_verified_before_any_stop(self):
        directory = retention.ROOT / "artifacts" / "fixture"
        wrong = '{"com.docker.compose.project":"fixture", "com.docker.compose.project.working_dir":"/unrelated"}'
        with patch.object(retention, "scope", return_value="owner"), patch.object(
            retention, "docker", side_effect=[Mock(stdout="immutable-id"), Mock(stdout=wrong)]) as docker:
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                retention.stop_project(directory, "fixture")
        self.assertFalse(any(c.args[0] == "stop" for c in docker.call_args_list))


if __name__ == "__main__":
    unittest.main()

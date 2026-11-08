"""Inert call-shape and closed-receipt checks; never run a Docker fault."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import nm2_worker_hosted as hosted
import nm2_worker_launch_acceptance as local
from nm2_worker_launch_acceptance import (
    AcceptanceRefused, LaunchFixture, PID1_LOSS_SCENARIO, PID1_LOSS_SCOPE,
    PID1_LOSS_SOURCES, canonical, digest,
)
from test_nm2_worker_stopped_predecessor_hosted import evidence


def fixture():
    value = object.__new__(LaunchFixture)
    value.pid1_loss = True
    value.receipt = {"scenario": PID1_LOSS_SCENARIO}
    value.docker_executable = Mock()
    value.docker_executable.__str__ = Mock(return_value="/qualified/docker")
    value.docker_executable.read_bytes.return_value = b"qualified fixture"
    value.docker_sha256 = digest(b"qualified fixture")
    value.docker_config = Path("/qualified/docker-config")
    value.m = {"docker_context": "default"}
    value.environment = {"PATH": "qualified"}
    identity = SimpleNamespace(container_id="6" * 64, image_id="sha256:" + "5" * 64,
                               project="vardrsec-nm2-synthetic")
    observer = Mock()
    observer.capture_running.return_value = identity
    return value, observer, identity


def pid1_evidence():
    raw, selection, inventories = evidence()
    raw["scenario"], raw["acceptance_scope"] = PID1_LOSS_SCENARIO, PID1_LOSS_SCOPE
    for name, commit in PID1_LOSS_SOURCES.items():
        selection["sources"][name]["commit"] = commit
    raw["sources"] = deepcopy(selection["sources"])
    first = raw["launch_pair"][0]
    raw["pid1_loss"] = {
        "signal": "KILL", "kill_calls": 1, "container_id": first["container_id"],
        "exit_code": 137, "new_work_disabled_before_report": False,
        "new_work_disabled_after_report": True,
        "original_artifact_files": [
            {"name": "vardrgate_result.json", "size": 900, "sha256": "a" * 64},
        ],
    }
    inventories[1]["containers"][first["container_id"]]["state"]["exit_code"] = 137
    raw["after_sha256"] = digest(canonical(inventories[1]))
    return raw, selection, inventories


class PID1LossProposalTests(unittest.TestCase):
    def test_old_new_fixture_defaults_pid1_mode_off(self):
        self.assertFalse(object.__new__(LaunchFixture).pid1_loss)

    def test_only_one_exact_pinned_host_kill_after_fresh_identity(self):
        value, observer, identity = fixture()
        with patch("nm2_worker_launch_acceptance.command") as command:
            value.kill_active_pid1(observer, identity)
            with self.assertRaises(AcceptanceRefused):
                value.kill_active_pid1(observer, identity)
        observer.capture_running.assert_called_once_with(
            container_id=identity.container_id, image_id=identity.image_id, project=identity.project,
        )
        command.assert_called_once_with(
            ["/qualified/docker", "--config", str(value.docker_config), "--context", "default",
             "kill", "--signal", "KILL", identity.container_id],
            env=value.environment, timeout=10,
        )
        self.assertEqual(value.receipt["pid1_loss"]["kill_calls"], 1)

    def test_changed_identity_or_executable_refuses_before_dispatch(self):
        for changed in ("identity", "executable"):
            value, observer, identity = fixture()
            if changed == "identity":
                observer.capture_running.return_value = None
            else:
                value.docker_sha256 = "0" * 64
            with self.subTest(changed=changed), patch("nm2_worker_launch_acceptance.command") as command:
                with self.assertRaises(AcceptanceRefused):
                    value.kill_active_pid1(observer, identity)
                command.assert_not_called()

    def test_ambiguous_kill_failure_is_not_retried(self):
        value, observer, identity = fixture()
        with patch("nm2_worker_launch_acceptance.command", side_effect=AcceptanceRefused("held")) as command:
            with self.assertRaises(AcceptanceRefused):
                value.kill_active_pid1(observer, identity)
            with self.assertRaises(AcceptanceRefused):
                value.kill_active_pid1(observer, identity)
        command.assert_called_once()

    def test_manual_route_is_explicit_and_keeps_partial_scope(self):
        self.assertEqual(hosted.execution_options({
            "NM2_SCENARIO": PID1_LOSS_SCENARIO, "NM2_DATABASE_REVISION": "0041persistentruntime",
            **{"NM2_" + name.upper() + "_SHA": commit for name, commit in PID1_LOSS_SOURCES.items()},
        }), (PID1_LOSS_SCENARIO, "0041persistentruntime"))
        workflow = (hosted.SOURCE / ".github/workflows/compose.yml").read_text(encoding="utf-8")
        options = next(line for line in workflow.splitlines() if line.strip().startswith("options: [healthy,"))
        self.assertEqual(options.count(PID1_LOSS_SCENARIO), 1)
        self.assertIn("default: healthy", workflow)
        raw, selection, inventories = pid1_evidence()
        projected = hosted.public_projection(raw, selection, inventories=inventories)
        self.assertEqual(projected["nm2_exit_status"], "incomplete")
        self.assertEqual(projected["pid1_loss"]["original_artifact_status"], "producer_verified_unchanged")
        self.assertNotIn(raw["launch_pair"][0]["container_id"].encode(), canonical(projected))

    def test_shared_reply_loss_routes_keep_conditional_kwargs_and_pid1_separate(self):
        operations = {"claim", "consume", "runtime-bind", "result", "finish"}
        self.assertEqual(set(hosted.REPLY_LOSS_OPERATIONS.values()), operations)
        self.assertNotIn(PID1_LOSS_SCENARIO, hosted.REPLY_LOSS_OPERATIONS)
        routes = [(operation, "--" + operation + "-reply-loss") for operation in sorted(operations)]
        routes.append(("pid1", "--pid1-loss"))
        fixed = ["--cohort", "unused", "--compose-executable", "unused",
                 "--compose-sha256", "0" * 64, "--docker-config", "unused"]
        for operation, flag in routes:
            status = ("selected_terminal_reply_loss_slice_passed" if operation in {"result", "finish"}
                      else "selected_launch_slice_passed" if operation == "pid1"
                      else "selected_" + operation.replace("-", "_") + "_reply_loss_slice_passed")
            with self.subTest(operation=operation), patch.object(local, "LaunchFixture") as factory, \
                    patch.object(local, "manifest", return_value={}):
                factory.return_value.receipt = {"status": status}
                self.assertEqual(local.main([*fixed, flag, "--execute"]), 0)
                factory.assert_called_once()
                factory.return_value.run.assert_called_once_with()
                kwargs = factory.call_args.kwargs
                if operation == "pid1":
                    self.assertIs(kwargs["pid1_loss"], True)
                    self.assertNotIn("reply_loss_operation", kwargs)
                    self.assertNotIn("claim_reply_loss", kwargs)
                elif operation == "claim":
                    self.assertIs(kwargs["claim_reply_loss"], True)
                    self.assertNotIn("reply_loss_operation", kwargs)
                    self.assertNotIn("pid1_loss", kwargs)
                else:
                    self.assertEqual(kwargs["reply_loss_operation"], operation)
                    self.assertNotIn("claim_reply_loss", kwargs)
                    self.assertNotIn("pid1_loss", kwargs)
        with patch.object(local, "LaunchFixture") as factory:
            self.assertEqual(local.main([*fixed, "--pid1-loss"]), 2)
            factory.assert_not_called()
        valid = {"NM2_SCENARIO": PID1_LOSS_SCENARIO, "NM2_DATABASE_REVISION": "0041persistentruntime",
                 **{"NM2_" + name.upper() + "_SHA": commit for name, commit in PID1_LOSS_SOURCES.items()}}
        with self.assertRaises(hosted.HostedRefused):
            hosted.execution_options({**valid, "NM2_RUNNER_SHA": "0" * 40})

    def test_fault_binding_exit_disable_and_artifact_shapes_fail_closed(self):
        for key, bad in (
            ("kill_calls", True), ("kill_calls", 2), ("signal", "TERM"),
            ("container_id", "7" * 64), ("exit_code", 125),
            ("new_work_disabled_before_report", True), ("new_work_disabled_after_report", False),
            ("original_artifact_files", [{"name": "vardrgate_stopped_result.json", "size": 9,
                                          "sha256": "a" * 64}]),
        ):
            raw, selection, inventories = pid1_evidence()
            raw["pid1_loss"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(hosted.HostedRefused):
                hosted.public_projection(raw, selection, inventories=inventories)
        raw, selection, inventories = pid1_evidence()
        inventories[1]["containers"][raw["launch_pair"][0]["container_id"]]["state"]["exit_code"] = 125
        raw["after_sha256"] = digest(canonical(inventories[1]))
        with self.assertRaises(hosted.HostedRefused):
            hosted.public_projection(raw, selection, inventories=inventories)

    def test_desktop_reader_keeps_exact_context_and_linux_container_scope(self):
        raw, selection, inventories = pid1_evidence()
        raw["platform"] = "win32"
        selection["docker_context"] = "desktop-linux"
        result = hosted.pid1_loss_desktop_projection(raw, selection, inventories=inventories)
        self.assertEqual((result["platform"], result["container_platform"]), ("win32", "linux"))
        self.assertEqual(result["pid1_loss"]["exit_code"], 137)
        raw["pid1_loss"]["original_artifact_files"] = []
        result = hosted.pid1_loss_desktop_projection(raw, selection, inventories=inventories)
        self.assertEqual(result["pid1_loss"]["original_artifact_status"], "not_observed")
        selection["docker_context"] = "default"
        with self.assertRaises(hosted.HostedRefused):
            hosted.pid1_loss_desktop_projection(raw, selection, inventories=inventories)


if __name__ == "__main__":
    unittest.main()

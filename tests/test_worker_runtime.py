"""Refusal tests for the trusted-host observer; no container or tool execution."""

import copy
from dataclasses import FrozenInstanceError, replace
import json
import subprocess
import unittest
from unittest.mock import patch

import worker_runtime as runtime


class WorkerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identity = runtime.RuntimeIdentity(
            "daemon-id",
            "a" * 64,
            "sha256:" + "b" * 64,
            "owned-fixture",
            "2026-11-05T20:00:00.123456789Z",
            "c" * 64,
        )
        self.info = {
            "id": self.identity.container_id,
            "image": self.identity.image_id,
            "user": "0:0",
            "labels": {
                "com.docker.compose.project": "owned-fixture",
                "com.docker.compose.service": "managed-worker",
                "com.docker.compose.oneoff": "False",
                "io.vardrsec.managed-worker": "1",
            },
            "mounts": [],
            "state": {
                "Status": "exited",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "ExitCode": 137,
                "StartedAt": self.identity.started_at,
                "FinishedAt": "2026-11-05T20:00:30.123456789Z",
            },
            "host": {
                "pid": "",
                "privileged": False,
                "init": False,
                "auto_remove": False,
                "restart": "no",
                "cap_add": ["SETUID", "SETGID", "SETPCAP"],
                "cap_drop": ["ALL"],
                "security": ["no-new-privileges:true"],
            },
        }
        self.calls = []
        self.inspect_count = 0
        self.endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
        self.daemon = "daemon-id"
        self.wait = "137"
        self.change_final = False

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        args = argv[3:]
        if args[:2] == ["context", "inspect"]:
            value = json.dumps(self.endpoint)
        elif args[0] == "info":
            value = json.dumps(self.daemon)
        elif args[:2] == ["container", "wait"]:
            value = self.wait
        elif args[:2] == ["container", "inspect"]:
            self.inspect_count += 1
            info = copy.deepcopy(self.info)
            if self.change_final and self.inspect_count == 3:
                info["state"]["StartedAt"] = "2026-11-05T20:01:00Z"
            value = json.dumps(info)
        else:
            self.fail("unexpected CLI operation")
        return subprocess.CompletedProcess(argv, 0, value, "")

    def observe(self):
        with patch.object(runtime.subprocess, "run", self.command):
            return runtime.LocalDocker("desktop-linux").observe_exit(self.identity)

    def test_exact_retained_exit_is_observed_without_mutating_daemon(self):
        proof = self.observe()
        self.assertEqual(proof.identity, self.identity)
        self.assertEqual(proof.exit_code, 137)
        self.assertEqual(self.inspect_count, 3)
        self.assertTrue(all(0 < kw["timeout"] <= 15 for _, kw in self.calls))
        self.assertTrue(
            all(
                argv[:3] == ["docker", "--context", "desktop-linux"]
                for argv, _ in self.calls
            )
        )
        self.assertFalse(
            any("Config.Env" in arg for argv, _ in self.calls for arg in argv)
        )
        with self.assertRaises(FrozenInstanceError):
            proof.exit_code = 0

    def test_arbitrary_inspection_document_cannot_construct_proof(self):
        with self.assertRaises(runtime.RuntimeRefused):
            runtime.ObservedExit(self.identity, self.info["state"]["FinishedAt"], 137)
        with self.assertRaises(runtime.RuntimeRefused):
            runtime.LocalDocker("desktop-linux").observe_exit(dict(self.info))

    def test_remote_daemon_or_changed_selected_engine_is_refused(self):
        for endpoint, daemon in [
            ("tcp://localhost:2375", "daemon-id"),
            ("ssh://host", "daemon-id"),
            (self.endpoint, "other-daemon"),
        ]:
            with self.subTest(endpoint=endpoint):
                self.endpoint, self.daemon = endpoint, daemon
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_wrong_incarnation_image_owner_or_pid_boundary_remains_held(self):
        alterations = [
            ("image", "sha256:" + "d" * 64),
            ("id", "d" * 64),
            ("user", "10001:10001"),
            ("state.StartedAt", "2026-11-05T19:59:59Z"),
            ("host.pid", "host"),
            ("host.privileged", True),
            ("host.init", True),
            ("host.auto_remove", True),
            ("host.restart", "unless-stopped"),
            ("host.cap_add", ["SETUID", "SETGID", "SETPCAP", "KILL"]),
            ("host.cap_drop", []),
            ("host.security", []),
            ("labels.com.docker.compose.project", "somebody-else"),
        ]
        original = copy.deepcopy(self.info)
        for key, value in alterations:
            with self.subTest(key=key):
                self.info = copy.deepcopy(original)
                section, _, field = key.partition(".")
                if field:
                    self.info[section][field] = value
                else:
                    self.info[key] = value
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_ambiguous_or_inconsistent_daemon_state_is_never_exit_proof(self):
        original = copy.deepcopy(self.info["state"])
        changes = [
            ("Status", "created"),
            ("Status", "dead"),
            ("Running", True),
            ("Paused", True),
            ("Restarting", True),
            ("Dead", True),
            ("ExitCode", 1),
            ("ExitCode", True),
            ("FinishedAt", "0001-01-01T00:00:00Z"),
            ("FinishedAt", "2026-99-99T20:00:30Z"),
            ("FinishedAt", "2026-11-05T20:00:00.123456788Z"),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.info["state"] = {**original, key: value}
                with self.assertRaises(runtime.RuntimeRefused):
                    self.observe()

    def test_restart_on_final_inspection_refuses_before_intent(self):
        self.change_final = True
        with self.assertRaises(runtime.RuntimeRefused):
            self.observe()

    def test_timeout_missing_container_and_malformed_reply_do_not_create_proof(self):
        for error in [
            subprocess.TimeoutExpired(["docker"], 15),
            OSError("private failure"),
        ]:
            with self.subTest(kind=type(error).__name__):
                with patch.object(runtime.subprocess, "run", side_effect=error):
                    with self.assertRaisesRegex(
                        runtime.RuntimeRefused, "^worker_runtime_refused$"
                    ):
                        runtime.LocalDocker("desktop-linux").observe_exit(self.identity)
        for value in ["", "[]", "null", "not-json", "x" * (1024 * 1024 + 1)]:
            with self.subTest(length=len(value)):
                with patch.object(
                    runtime.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, value, ""),
                ):
                    with self.assertRaises(runtime.RuntimeRefused):
                        runtime.LocalDocker("desktop-linux").observe_exit(self.identity)

    def test_identity_rejects_short_ids_invalid_timestamps_and_nonces(self):
        for change in [
            {"container_id": "a" * 12},
            {"started_at": "2026-13-01T00:00:00Z"},
            {"owner_nonce": "true"},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(runtime.RuntimeRefused):
                    replace(self.identity, **change)


if __name__ == "__main__":
    unittest.main()

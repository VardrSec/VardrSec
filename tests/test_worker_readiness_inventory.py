import copy
import json
import subprocess
import unittest
from unittest.mock import patch

import test_worker_volumes as cases
import worker_runtime as runtime
import worker_volumes as volumes


class ReadinessInventoryTests(unittest.TestCase):
    def setUp(self):
        self.f = cases.ManagedVolumeTests()
        self.f.setUp()
        self.observer = self.f.observer()
        self.state = self.f.volume_resource_row("runner-state")
        self.ready = self.f.volume_resource_row("worker-ready")
        self.names = [self.ready["name"], self.state["name"]]
        self.rows = {row["name"]: row for row in (self.state, self.ready)}
        self.endpoint = "unix:///owned/docker.sock"
        self.round = 0
        self.calls = []
        self.drift = None

    def command(self, argv, **options):
        self.assertEqual(argv[:3], ["docker", "--context", "fixture-local"])
        self.assertGreater(options["timeout"], 0)
        args = argv[3:]
        self.calls.append(args)
        if args == [
            "context",
            "inspect",
            "fixture-local",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ]:
            value = self.endpoint
        elif args == ["info", "--format", "{{json .ID}}"]:
            value = (
                "foreign-daemon"
                if self.drift == "daemon" and self.round == 2
                else self.f.identity.daemon_id
            )
        elif args == ["info", "--format", volumes.DAEMON_FORMAT]:
            value = {"root": self.f.root, "os": "linux"}
        elif args == [
            "volume",
            "ls",
            "--filter",
            "label=com.docker.compose.project=fixture",
            "--format",
            "{{json .Name}}",
        ]:
            self.round += 1
            names = self.names
            if self.round == 2 and self.drift == "removed":
                names = [self.state["name"]]
            if self.round == 2:
                names = list(reversed(names))
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(map(json.dumps, names)), ""
            )
        elif (
            args[:4]
            == ["volume", "inspect", "--format", volumes.VOLUME_RESOURCE_FORMAT]
            and len(args) == 5
        ):
            value = copy.deepcopy(self.rows[args[4]])
            if (
                self.round == 2
                and self.drift == "replaced"
                and args[4] == self.ready["name"]
            ):
                value["created_at"] = "2026-11-06T01:00:01Z"
        else:
            self.fail("unexpected command")
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    def observe(self):
        self.round = 0
        self.calls = []
        with patch.object(runtime.subprocess, "run", side_effect=self.command):
            try:
                return volumes.capture_readiness_inventory(self.observer, "fixture")
            finally:
                self.assertIsNone(self.observer._deadline)
                self.assertFalse(self.observer._observation_lock.locked())

    def test_retains_unattached_readiness_with_no_compose_configuration_hash(self):
        value = self.observe()
        self.assertEqual(value["context"], "fixture-local")
        self.assertEqual(value["daemon_id"], self.f.identity.daemon_id)
        self.assertEqual(value["local_endpoint"], self.endpoint)
        self.assertEqual(value["daemon_root"], self.f.root)
        [ready] = value["readiness"]
        self.assertEqual(ready["name"], self.ready["name"])
        self.assertIsNone(ready["config_hash"])
        self.assertEqual(ready["intent_id"], self.ready["intent_id"][0])
        self.assertEqual(self.round, 2)
        self.observer._bound.assert_not_called()

    def test_empty_readiness_set_is_descriptive_even_with_existing_state_volume(self):
        self.names = [self.state["name"]]
        self.assertEqual(self.observe()["readiness"], [])
        self.assertEqual(self.round, 2)

    def test_role_or_marker_mismatch_cannot_hide_candidate(self):
        original = dict(self.ready)
        for changed in (
            {"ready": [None]},
            {"volume": "other-volume"},
            {"volume": "other-volume", "ready": [None]},
            {"project": "foreign-project"},
        ):
            self.rows[self.ready["name"]] = {**original, **changed}
            with (
                self.subTest(changed=changed),
                self.assertRaises(runtime.RuntimeRefused),
            ):
                self.observe()

    def test_duplicate_or_malformed_names_refuse_before_any_volume_inspection(self):
        for names in ([self.ready["name"]] * 2, ["--alternate"], [None], ["a"] * 257):
            self.names = names
            with self.assertRaises(runtime.RuntimeRefused):
                self.observe()
            self.assertFalse(
                any(call[:2] == ["volume", "inspect"] for call in self.calls)
            )

    def test_changed_list_volume_or_daemon_refuses_without_retry(self):
        for drift in ("removed", "replaced", "daemon"):
            self.drift = drift
            with self.subTest(drift=drift), self.assertRaises(runtime.RuntimeRefused):
                self.observe()
            self.assertEqual(self.round, 2)

"""Inactive worker packaging candidate; no Docker, credentials or tool execution."""

import json
from pathlib import Path
import unittest


class WorkerComposeTests(unittest.TestCase):
    def test_worker_is_a_separate_explicit_profile_with_no_restart_or_exec_health(self):
        root = Path(__file__).resolve().parents[1]
        overlay = json.loads((root / "compose.worker.json").read_text())
        self.assertEqual(set(overlay["services"]), {"managed-worker"})
        worker = overlay["services"]["managed-worker"]
        self.assertEqual(worker["profiles"], ["managed-worker"])
        self.assertEqual(worker["restart"], "no")
        self.assertEqual(worker["pull_policy"], "never")
        self.assertEqual(worker["entrypoint"], ["/usr/local/bin/vardr-worker-owner"])
        self.assertEqual(worker["command"], [])
        self.assertIs(worker["init"], False)
        self.assertEqual(worker["healthcheck"], {"disable": True})
        self.assertNotIn("managed-worker", (root / "compose.yaml").read_text())

    def test_only_approved_bootstrap_caps_and_bounded_writable_data_are_declared(self):
        root = Path(__file__).resolve().parents[1]
        worker = json.loads((root / "compose.worker.json").read_text())["services"][
            "managed-worker"
        ]
        self.assertEqual(worker["user"], "0:0")
        self.assertIs(worker["read_only"], True)
        self.assertEqual(worker["ipc"], "private")
        self.assertEqual(worker["cap_drop"], ["ALL"])
        self.assertEqual(set(worker["cap_add"]), {"SETUID", "SETGID", "SETPCAP"})
        self.assertEqual(worker["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(
            (worker["pids_limit"], worker["mem_limit"], worker["cpus"]),
            (64, "512m", 1.0),
        )
        mounts = {entry["target"]: entry for entry in worker["volumes"]}
        self.assertEqual(
            set(mounts),
            {"/home/runner/.vardrmap", "/trust", "/run/vardr-worker-admission"},
        )
        self.assertTrue(
            mounts["/trust"]["read_only"]
            and mounts["/run/vardr-worker-admission"]["read_only"]
        )
        self.assertEqual(len(worker["tmpfs"]), 2)
        self.assertNotIn("docker.sock", json.dumps(worker))
        self.assertNotIn("ports", worker)
        self.assertNotIn("privileged", worker)
        self.assertNotIn("depends_on", worker)


if __name__ == "__main__":
    unittest.main()

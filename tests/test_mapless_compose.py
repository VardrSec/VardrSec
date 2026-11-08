"""Static packaging contract only; no Docker, installed state or tool execution."""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MaplessComposeTests(unittest.TestCase):
    def setUp(self):
        self.model = json.loads((ROOT / "compose.mapless.json").read_text())
        self.runner = self.model["services"]["runner"]

    def test_only_explicit_runner_no_map_database_credentials_or_trust(self):
        self.assertEqual(set(self.model["services"]), {"runner"})
        self.assertEqual(self.runner["profiles"], ["tools"])
        self.assertEqual(self.runner["command"], ["--help"])
        self.assertNotIn("environment", self.runner)
        self.assertNotIn("env_file", self.runner)
        self.assertNotIn("depends_on", self.runner)
        self.assertNotIn("restart", self.runner)
        self.assertNotIn("REQUESTS_CA_BUNDLE", json.dumps(self.model))
        self.assertNotIn("POSTGRES", json.dumps(self.model))
        self.assertNotIn("VARDRMAP", json.dumps(self.model))

    def test_reuses_existing_toolkit_contexts_without_new_source_pins(self):
        self.assertEqual(self.runner["image"], "vardrrunner:development")
        self.assertEqual(
            self.runner["build"],
            {
                "context": "${RUNNER_SOURCE:-./.sources/runner}",
                "target": "toolkit",
                "additional_contexts": {"gate": "${GATE_SOURCE:-./.sources/gate}"},
            },
        )

    def test_state_uses_existing_project_and_volume_layout_without_host_mounts(self):
        self.assertEqual(self.model["name"], "vardrsec")
        self.assertEqual(self.model["volumes"], {"runner-state": {}})
        self.assertEqual(
            self.runner["volumes"], ["runner-state:/home/runner/.vardrmap"]
        )
        self.assertEqual(self.model["networks"], {"runner": {}})
        self.assertNotIn("container_name", self.runner)

    def test_preserves_existing_container_security_and_no_daemon_access(self):
        self.assertEqual(self.runner["cap_drop"], ["ALL"])
        self.assertEqual(self.runner["security_opt"], ["no-new-privileges:true"])
        for name in (
            "privileged",
            "cap_add",
            "ports",
            "devices",
            "pid",
            "network_mode",
            "entrypoint",
        ):
            self.assertNotIn(name, self.runner)
        self.assertNotIn("docker.sock", json.dumps(self.model))


if __name__ == "__main__":
    unittest.main()

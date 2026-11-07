import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import worker_compose_inventory as inventory

MODEL = Path(__file__).resolve().parents[1] / "compose.worker.json"
CID = "1" * 64
OTHER = "2" * 64
ENDPOINT = "unix:///var/run/docker.sock"


class ComposeInventoryTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.installation = root / "installation"
        self.config = root / "config"
        self.installation.mkdir()
        self.config.mkdir()
        self.model = self.installation / "compose.worker.json"
        self.model.write_bytes(MODEL.read_bytes())
        self.override = root / "worker-override.json"
        self.empty = root / "empty.env"
        self.empty.write_bytes(b"")
        self.public = root / "planned-public"
        self.docker = root / "docker.exe"
        self.compose = root / "docker-compose.exe"
        self.docker.write_bytes(b"docker-test-pin")
        self.compose.write_bytes(b"compose-test-pin")
        self.override_model = {
            "networks": {"runner": {"external": True, "name": "owned_runner"}},
            "volumes": {"runner-state": {"external": True, "name": "owned_state"}},
        }
        self.write_override(self.override_model)
        self.client = inventory.LocalClient(
            self.docker,
            hashlib.sha256(self.docker.read_bytes()).hexdigest(),
            self.compose,
            hashlib.sha256(self.compose.read_bytes()).hexdigest(),
            self.config,
            "local",
            ENDPOINT,
        )
        self.project = inventory.WorkerProject(
            "owned",
            self.installation,
            self.override,
            self.empty,
            "sha256:" + "3" * 64,
            self.public,
            "ready_one",
            "owned_state",
            "owned_runner",
        )

    def write_override(self, model):
        self.override.write_text(json.dumps(model), encoding="utf-8")

    @staticmethod
    def result(output, code=0):
        return subprocess.CompletedProcess([], code, output, b"")

    def replies(self, listing=b"", *, version=b"v5.6.1\n", endpoint=ENDPOINT):
        return [
            self.result(json.dumps(ENDPOINT).encode()),
            self.result(version),
            self.result(listing),
            self.result(json.dumps(endpoint).encode()),
        ]

    def test_exact_binary_model_and_environment_are_selected(self):
        ambient = {
            "VARDRMAP_API_KEY": "operator-secret",
            "DOCKER_HOST": "tcp://elsewhere:2375",
            "COMPOSE_FILE": "unreviewed.yaml",
            "DOCKER_CLI_PLUGIN_USE_DIAL_STDIO": "1",
            "HTTP_PROXY": "http://elsewhere",
            "PATH": "unreviewed",
        }
        replies = self.replies(f"{OTHER}\r\n{CID}\r\n".encode())
        with (
            patch.dict(os.environ, ambient),
            patch.object(inventory.subprocess, "run", side_effect=replies) as run,
        ):
            report = inventory.capture_visible_workers(self.client, self.project)
        self.assertEqual(
            report,
            {
                "context": "local",
                "local_endpoint": ENDPOINT,
                "project": "owned",
                "compose_worker_ids": [CID, OTHER],
            },
        )
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            commands[0],
            [
                str(self.docker),
                "--config",
                str(self.config),
                "--context",
                "local",
                "context",
                "inspect",
                "local",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
        )
        self.assertEqual(
            commands[1], [str(self.compose), "--context", "local", "version", "--short"]
        )
        self.assertEqual(
            commands[2],
            [
                str(self.compose),
                "--context",
                "local",
                "--project-name",
                "owned",
                "--project-directory",
                str(self.installation),
                "--env-file",
                str(self.empty),
                "-f",
                str(self.model),
                "-f",
                str(self.override),
                "--profile",
                "managed-worker",
                "ps",
                "--all",
                "--no-trunc",
                "--quiet",
                "managed-worker",
            ],
        )
        self.assertEqual(commands[3], commands[0])
        for index, call in enumerate(run.call_args_list):
            self.assertEqual(call.kwargs["input"], b"")
            self.assertLessEqual(call.kwargs["timeout"], 12)
            environment = call.kwargs["env"]
            self.assertEqual(environment["DOCKER_CONFIG"], str(self.config))
            self.assertFalse(
                (ambient.keys() - {"VARDRMAP_API_KEY"}) & environment.keys()
            )
            if index == 2:
                self.assertEqual(
                    environment["VARDRMAP_API_KEY"], "synthetic_read_only_compose_ps"
                )
                self.assertEqual(
                    environment["VARDRSEC_WORKER_CREDENTIAL_FILE"], str(self.empty)
                )
            else:
                self.assertNotIn("VARDRMAP_API_KEY", environment)
        self.assertFalse(self.public.exists())

    def test_empty_output_is_only_an_empty_compose_view(self):
        with patch.object(inventory.subprocess, "run", side_effect=self.replies()):
            value = inventory.capture_visible_workers(self.client, self.project)
        self.assertEqual(value["compose_worker_ids"], [])
        self.assertNotIn("clear", value)

    def test_wrong_pins_remote_pipe_or_nonempty_dotenv_refuse_before_process(self):
        for client in (
            replace(self.client, docker_sha256="a" * 64),
            replace(self.client, compose_sha256="b" * 64),
            replace(self.client, endpoint="npipe:////remote/pipe/docker"),
        ):
            with (
                self.subTest(client=client),
                patch.object(inventory.subprocess, "run") as run,
            ):
                with self.assertRaises(inventory.ComposeInventoryRefused):
                    inventory.capture_visible_workers(client, self.project)
                run.assert_not_called()
        self.empty.write_bytes(b"UNREVIEWED=1\n")
        with patch.object(inventory.subprocess, "run") as run:
            with self.assertRaises(inventory.ComposeInventoryRefused):
                inventory.capture_visible_workers(self.client, self.project)
            run.assert_not_called()

    def test_changed_model_or_nonclosed_override_refuses_before_process(self):
        for extra in (
            {"services": {}},
            {"networks": {"runner": {"external": 1, "name": "owned_runner"}}},
            {"networks": {"runner": {"external": True, "name": "wrong_network"}}},
        ):
            self.write_override({**self.override_model, **extra})
            with (
                self.subTest(extra=extra),
                patch.object(inventory.subprocess, "run") as run,
            ):
                with self.assertRaises(inventory.ComposeInventoryRefused):
                    inventory.capture_visible_workers(self.client, self.project)
                run.assert_not_called()
        self.write_override(self.override_model)
        self.model.write_bytes(self.model.read_bytes() + b"\n")
        with patch.object(inventory.subprocess, "run") as run:
            with self.assertRaises(inventory.ComposeInventoryRefused):
                inventory.capture_visible_workers(self.client, self.project)
            run.assert_not_called()

    def test_unknown_version_or_failed_command_never_returns_an_empty_inventory(self):
        for version in (self.result(b"v5.6.2\n"), self.result(b"", 1)):
            replies = self.replies()
            replies[1] = version
            with patch.object(inventory.subprocess, "run", side_effect=replies) as run:
                with self.assertRaises(inventory.ComposeInventoryRefused):
                    inventory.capture_visible_workers(self.client, self.project)
                self.assertEqual(run.call_count, 2)

    def test_short_duplicate_or_diagnostic_output_is_held(self):
        for bad in (
            b"abc\n",
            f"{CID}\n{CID}\n".encode(),
            f"{CID}\n\n".encode(),
            f"{CID}\v{OTHER}".encode(),
            b"\xff",
            b"x" * 65537,
        ):
            with (
                self.subTest(size=len(bad)),
                patch.object(
                    inventory.subprocess, "run", side_effect=self.replies(bad)
                ),
            ):
                with self.assertRaises(inventory.ComposeInventoryRefused):
                    inventory.capture_visible_workers(self.client, self.project)

    def test_context_or_executable_drift_after_listing_refuses(self):
        with patch.object(
            inventory.subprocess,
            "run",
            side_effect=self.replies(
                f"{CID}\n".encode(), endpoint="unix:///elsewhere.sock"
            ),
        ):
            with self.assertRaises(inventory.ComposeInventoryRefused):
                inventory.capture_visible_workers(self.client, self.project)
        replies = iter(self.replies(f"{CID}\n".encode()))

        def replace_executable(argv, **_):
            if "ps" in argv:
                self.compose.write_bytes(b"changed")
            return next(replies)

        with patch.object(inventory.subprocess, "run", side_effect=replace_executable):
            with self.assertRaises(inventory.ComposeInventoryRefused):
                inventory.capture_visible_workers(self.client, self.project)

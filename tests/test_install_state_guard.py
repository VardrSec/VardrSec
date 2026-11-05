"""Read-only inventory guard: no Docker calls or installed-state mutations."""

import argparse
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec


class InstallStateGuardTests(unittest.TestCase):
    def setUp(self):
        # These existing tests isolate inventory handling; resolver cases live separately.
        resolver = patch.object(vardrsec, "installation_volume_names", side_effect=lambda: {
            f"{vardrsec.os.environ.get('COMPOSE_PROJECT_NAME') or 'vardrsec'}_database",
            f"{vardrsec.os.environ.get('COMPOSE_PROJECT_NAME') or 'vardrsec'}_runner-state",
        })
        resolver.start()
        self.addCleanup(resolver.stop)

    def test_expected_database_or_runner_state_refuses_fresh_install(self):
        for names, expected in (
            ("", False),
            ("vardrsec_database\n", True),
            ("vardrsec_runner-state\n", True),
            ("other_runner-state\n", False),
            ("vardrsec_runner-state-copy\n", False),
        ):
            with (
                self.subTest(names=names),
                patch.dict(vardrsec.os.environ, {"COMPOSE_PROJECT_NAME": "vardrsec"}),
                patch.object(
                    vardrsec.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=names),
                ) as command,
            ):
                self.assertEqual(vardrsec.has_installation_data(), expected)
                self.assertEqual(
                    command.call_args.args[0],
                    ["docker", "volume", "ls", "--format", "{{.Name}}"],
                )
                self.assertEqual(command.call_args.kwargs["timeout"], 30)

    def test_explicit_project_identity_is_matched_exactly(self):
        for names, expected in (
            ("vardrsec_runner-state\n", False),
            ("research_runner-state\n", True),
            ("research_database\n", True),
        ):
            with (
                self.subTest(names=names),
                patch.dict(vardrsec.os.environ, {"COMPOSE_PROJECT_NAME": "research"}),
                patch.object(
                    vardrsec.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=names),
                ),
            ):
                self.assertEqual(vardrsec.has_installation_data(), expected)

    def test_unavailable_inventory_never_means_empty(self):
        failures = [
            subprocess.CompletedProcess(
                [], 1, stdout="", stderr="synthetic private daemon error"
            ),
            OSError("synthetic private path"),
            subprocess.TimeoutExpired("docker", 30),
        ]
        for failure in failures:
            effect = failure if isinstance(failure, Exception) else None
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(
                    vardrsec.subprocess, "run", side_effect=effect, return_value=failure
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "^Cannot inspect installation volumes; installation refused$",
                ):
                    vardrsec.has_installation_data()

    def test_runner_state_or_unknown_inventory_prevents_all_install_steps(self):
        for inventory in (
            subprocess.CompletedProcess([], 0, stdout="vardrsec_runner-state\n"),
            subprocess.CompletedProcess([], 1, stdout=""),
        ):
            with (
                self.subTest(inventory=inventory.returncode),
                patch.dict(vardrsec.os.environ, {"COMPOSE_PROJECT_NAME": "vardrsec"}),
                patch.object(vardrsec.subprocess, "run", return_value=inventory),
                patch.object(vardrsec, "configure") as configure,
                patch.object(vardrsec, "sources") as sources,
                patch.object(vardrsec, "compose") as compose,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises((SystemExit, ValueError)):
                    vardrsec.dispatch(
                        argparse.Namespace(action="install"), argparse.ArgumentParser()
                    )
                configure.assert_not_called()
                sources.assert_not_called()
                compose.assert_not_called()

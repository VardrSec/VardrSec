"""Standard fresh-install sequencing with synthetic state and mocked Compose."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import vardrsec
from test_install_project_resolution import model

STANDARD = (vardrsec.ROOT / "compose.yaml").read_bytes().replace(b"\r\n", b"\n")


class FreshInstallPreflightTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / "compose.yaml").write_bytes(STANDARD)
        for context in (patch.object(vardrsec, "ROOT", self.root),
                        patch.dict(vardrsec.os.environ, {}, clear=True)):
            context.start(); self.addCleanup(context.stop)

    def install(self, inventory="", fail_config=False, race=False):
        observed = []
        steps = []
        original = vardrsec.dispatch
        standard_check = vardrsec.require_standard_fresh_layout
        checks = 0
        def layout_check():
            nonlocal checks
            standard_check()
            checks += 1
            if race == "late" and checks == 2:
                (self.root / ".env").write_text("retained concurrent synthetic config")
        def dispatch(args, parser):
            if args.action in ("install", "configure"):
                return original(args, parser)
            steps.append(args.action)
        def command(args, **kwargs):
            self.assertFalse((self.root / ".env").exists())
            self.assertFalse((self.root / "trust").exists())
            if "config" in args:
                observed.append(dict(kwargs["env"]))
                if fail_config:
                    return subprocess.CompletedProcess([], 1, stdout="synthetic-secret", stderr="synthetic-secret")
                return subprocess.CompletedProcess([], 0, stdout=json.dumps(model(self.root, "vardrsec")))
            self.assertEqual(args, ["docker", "volume", "ls", "--format", "{{.Name}}"])
            if race is True:
                (self.root / ".env").write_text("retained concurrent synthetic config")
            return subprocess.CompletedProcess([], 0, stdout=inventory)
        with patch.object(vardrsec, "require_standard_fresh_layout", side_effect=layout_check), \
             patch.object(vardrsec, "dispatch", side_effect=dispatch), \
             patch.object(vardrsec.subprocess, "run", side_effect=command), \
             patch.object(vardrsec.secrets, "token_hex", side_effect=[str(i) * 64 for i in range(1, 5)]) as random, \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            failure = None
            try:
                vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
            except (ValueError, SystemExit, FileExistsError) as exc:
                failure = exc
        return observed, steps, out.getvalue() + err.getvalue(), failure, random.call_count

    def test_one_command_generates_once_checks_before_write_and_persists_same_values(self):
        observed, steps, output, error, calls = self.install()
        self.assertIsNone(error)
        self.assertEqual(calls, 4)
        written = dict(line.split("=", 1) for line in (self.root / ".env").read_text().splitlines())
        self.assertEqual(written, observed[0])
        self.assertEqual(steps, ["sources", "build", "database-role", "start", "export-ca"])
        self.assertTrue((self.root / "trust").is_dir())
        for key, value in written.items():
            if key != "HTTPS_PORT": self.assertNotIn(value, output)

    def test_process_precedence_retained_without_changing_generated_file(self):
        with patch.dict(vardrsec.os.environ, {"HTTPS_PORT": "9443", "POSTGRES_PASSWORD": "synthetic-shell-value"}):
            observed, _, output, error, calls = self.install()
        self.assertIsNone(error)
        self.assertEqual(calls, 4)
        self.assertEqual(observed[0]["HTTPS_PORT"], "9443")
        self.assertEqual(observed[0]["POSTGRES_PASSWORD"], "synthetic-shell-value")
        written = (self.root / ".env").read_text()
        self.assertIn("HTTPS_PORT=8443", written)
        self.assertNotIn("synthetic-shell-value", written + output)

    def test_existing_state_or_unresolved_config_never_creates_configuration(self):
        for inventory, fail in (
            ("vardrsec_database\n", False), ("vardrsec_runner-state\n", False),
            ("vardrsec_proxy-data\n", False), ("vardrsec_proxy-config\n", False), ("", True),
        ):
            with self.subTest(inventory=inventory, failure=fail):
                _, steps, output, error, _ = self.install(inventory=inventory, fail_config=fail)
                self.assertIsNotNone(error)
                self.assertEqual(steps, [])
                self.assertFalse((self.root / ".env").exists())
                self.assertFalse((self.root / "trust").exists())
                self.assertNotIn("synthetic-secret", output + str(error))

    def test_custom_or_alternate_selection_refuses_before_generation_or_commands(self):
        for key in ("COMPOSE_ENV_FILES", "COMPOSE_DISABLE_ENV_FILE", "COMPOSE_FILE", "COMPOSE_PROFILES"):
            with self.subTest(key=key), patch.dict(vardrsec.os.environ, {key: "synthetic"}), \
                 patch.object(vardrsec.subprocess, "run") as run, patch.object(vardrsec, "configuration_values") as generate:
                with self.assertRaisesRegex(ValueError, "standard .env selection"):
                    vardrsec.dispatch(argparse.Namespace(action="install"), argparse.ArgumentParser())
                run.assert_not_called(); generate.assert_not_called()
        for filename in ("compose.yaml", ".active-images.json"):
            path = self.root / filename
            path.write_text("synthetic custom layout")
            with patch.object(vardrsec.subprocess, "run") as run:
                with self.assertRaises(ValueError): vardrsec.require_standard_fresh_layout()
                run.assert_not_called()
            if filename == "compose.yaml": path.write_bytes(STANDARD)

    def test_observed_concurrent_config_is_preserved_and_stops_lifecycle(self):
        _, steps, _, error, _ = self.install(race=True)
        self.assertIsNotNone(error)
        self.assertEqual(steps, [])
        self.assertEqual((self.root / ".env").read_text(), "retained concurrent synthetic config")
        self.assertFalse((self.root / "trust").exists())

    def test_late_config_appearance_cannot_reclassify_fresh_attempt_as_resume(self):
        _, steps, _, error, _ = self.install(race="late")
        self.assertIsNotNone(error)
        self.assertEqual(steps, [])
        self.assertEqual((self.root / ".env").read_text(), "retained concurrent synthetic config")
        self.assertFalse((self.root / "trust").exists())

    def test_standard_crlf_checkout_is_supported(self):
        (self.root / "compose.yaml").write_bytes(STANDARD.replace(b"\n", b"\r\n"))
        vardrsec.require_standard_fresh_layout()

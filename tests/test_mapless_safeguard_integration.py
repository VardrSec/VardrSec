"""Cohort interactions with mocked commands; no Docker or installation."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec


class MaplessSafeguardIntegrationTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp(prefix="vardr-safeguard-integration-"))
        model = json.loads((vardrsec.ROOT / "compose.mapless.json").read_text())
        (root / "compose.mapless.json").write_text(json.dumps(model))
        (root / "compose.yaml").write_text("synthetic Full model: preserve")
        (root / ".active-images.json").write_text('{"services":{}}')
        (root / ".env").write_text("synthetic config: preserve")
        return root, model

    def test_dormant_models_volume_identity_triggers_install_guard_before_sources(self):
        root, model = self.fixture()
        volume = model["name"] + "_" + next(iter(model["volumes"]))
        before = {p.name: p.read_bytes() for p in root.iterdir()}
        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "installation_volume_names", return_value={volume}),
            patch.dict(vardrsec.os.environ, {"COMPOSE_PROJECT_NAME": model["name"]}),
            patch.object(
                vardrsec.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, stdout=volume + "\n"),
            ) as inventory,
            patch.object(
                vardrsec, "run", side_effect=AssertionError("No Git or Docker")
            ),
            patch.object(vardrsec, "configure") as configure,
            patch.object(vardrsec, "sources") as sources,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                vardrsec.dispatch(
                    argparse.Namespace(action="install"), argparse.ArgumentParser()
                )
            inventory.assert_called_once()
            configure.assert_not_called()
            sources.assert_not_called()
        self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_sources_cli_with_dormant_model_binds_only_model_build_inputs(self):
        root, model = self.fixture()
        pins = {
            name: {"repository": repo, "commit": value * 40}
            for name, repo, value in [
                ("runner", "VardrSec/VardrRunner", "b"),
                ("gate", "VardrSec/VardrGate", "c"),
            ]
        }
        (root / "versions.json").write_text(json.dumps({"components": pins}))
        before = {p.name: p.read_bytes() for p in root.iterdir()}
        commands = []

        def git(*args, **kwargs):
            self.assertEqual(args[0], "git")
            commands.append(args)
            source, operation = Path(args[2]), args[3]
            self.assertIn(source.name, pins)
            if operation == "init":
                (source / ".git").mkdir()
            reply = ""
            if operation == "rev-parse" and "--show-toplevel" in args:
                reply = f"{source.resolve()}\n{(source / '.git').resolve()}\n.git\n"
            return subprocess.CompletedProcess(args, 0, stdout=reply)

        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(sys, "argv", ["vardrsec.py", "sources", "--mapless"]),
            patch("updater.operation_guard", return_value=contextlib.nullcontext()),
            patch.object(vardrsec, "run", side_effect=git),
            patch.object(
                vardrsec.subprocess,
                "run",
                side_effect=AssertionError("No real commands"),
            ),
        ):
            vardrsec.main()
        self.assertEqual(
            {Path(c[2]).name for c in commands if c[3] == "fetch"}, set(pins)
        )
        build = model["services"]["runner"]["build"]
        for context in (build["context"], build["additional_contexts"]["gate"]):
            self.assertTrue(
                (root / context.split(":-", 1)[1].removesuffix("}")).is_dir()
            )
        self.assertEqual(before, {name: (root / name).read_bytes() for name in before})
        self.assertFalse((root / ".sources" / "map").exists())

    def test_dormant_model_does_not_change_full_compose_or_active_image_selection(self):
        root, _ = self.fixture()
        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "run") as command,
        ):
            vardrsec.compose("config")
        command.assert_called_once_with(
            "docker",
            "compose",
            "-f",
            str(root / "compose.yaml"),
            "-f",
            str(root / ".active-images.json"),
            "config",
        )

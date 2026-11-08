"""Mapless source selection only; no Git/network, installer or execution trial."""

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


class MaplessSourcesTests(unittest.TestCase):
    def root(self):
        # Retain new synthetic fixtures; never target an installed environment.
        root = Path(tempfile.mkdtemp(prefix="vardr-mapless-sources-"))
        pins = {
            name: {"repository": "VardrSec/" + repo, "commit": revision * 40}
            for name, repo, revision in (
                ("runner", "VardrRunner", "b"),
                ("gate", "VardrGate", "c"),
            )
        }
        (root / "versions.json").write_text(json.dumps({"components": pins}))
        return root, pins

    def test_selects_only_runner_gate_without_map_manifest_or_environment(self):
        root, pins = self.root()
        (root / ".sources").mkdir()
        sentinel = root / ".sources" / "map"
        sentinel.write_bytes(b"synthetic existing Map cache: preserve")
        (root / ".env").write_bytes(b"synthetic existing config: preserve")
        commands = []

        def command(*args, **kwargs):
            commands.append(args)
            path, action = Path(args[2]), args[3]
            if action == "init":
                (path / ".git").mkdir()
            if action == "rev-parse" and "--show-toplevel" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=str(path.resolve())
                    + "\n"
                    + str((path / ".git").resolve())
                    + "\n.git\n",
                )
            return subprocess.CompletedProcess(args, 0, stdout="")

        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "run", side_effect=command),
        ):
            vardrsec.sources(mapless=True)
        fetches = [args for args in commands if args[3] == "fetch"]
        self.assertEqual([Path(args[2]).name for args in fetches], ["runner", "gate"])
        for args in fetches:
            name = Path(args[2]).name
            self.assertEqual(
                args[-2:],
                (
                    "https://github.com/" + pins[name]["repository"] + ".git",
                    pins[name]["commit"],
                ),
            )
        self.assertEqual(
            sentinel.read_bytes(), b"synthetic existing Map cache: preserve"
        )
        self.assertEqual(
            (root / ".env").read_bytes(), b"synthetic existing config: preserve"
        )

    def test_default_source_selection_still_requires_map(self):
        root, _ = self.root()
        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "run") as command,
        ):
            with self.assertRaises(KeyError):
                vardrsec.sources()
        command.assert_not_called()
        self.assertFalse((root / ".sources").exists())

    def test_existing_changed_runner_is_preserved_and_not_reset(self):
        root, _ = self.root()
        source = root / ".sources" / "runner"
        (source / ".git").mkdir(parents=True)
        (source / "retained.txt").write_bytes(b"synthetic operator change")
        replies = [
            subprocess.CompletedProcess(
                [],
                0,
                stdout=str(source.resolve())
                + "\n"
                + str((source / ".git").resolve())
                + "\n.git\n",
            ),
            subprocess.CompletedProcess([], 0, stdout="a" * 40),
            subprocess.CompletedProcess([], 0, stdout=" M retained.txt"),
        ]
        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "run", side_effect=replies) as command,
        ):
            with self.assertRaisesRegex(ValueError, "preserve it"):
                vardrsec.sources(mapless=True)
        self.assertEqual(command.call_count, 3)
        self.assertEqual(
            (source / "retained.txt").read_bytes(), b"synthetic operator change"
        )
        self.assertFalse((root / ".sources" / "gate").exists())

    def test_bad_selected_repository_is_not_fetched(self):
        root, pins = self.root()
        pins["runner"]["repository"] = "other/repo"
        (root / "versions.json").write_text(json.dumps({"components": pins}))
        with (
            patch.object(vardrsec, "ROOT", root),
            patch.object(vardrsec, "run") as command,
        ):
            with self.assertRaisesRegex(ValueError, "Unexpected component"):
                vardrsec.sources(mapless=True)
        command.assert_not_called()

    def test_dispatch_selects_explicit_mode_and_preserves_internal_default(self):
        for args, selected in (
            (argparse.Namespace(action="sources", mapless=True), True),
            (argparse.Namespace(action="sources"), False),
        ):
            with (
                self.subTest(selected=selected),
                patch.object(vardrsec, "sources") as sources,
            ):
                vardrsec.dispatch(args, None)
                sources.assert_called_once_with(mapless=selected)

    def test_cli_accepts_mapless_install_and_sources_but_requires_install_for_lifecycle(
        self,
    ):
        for action in ("sources", "install", "build", "start", "restore", "update"):
            with (
                self.subTest(action=action),
                patch.object(sys, "argv", ["vardrsec.py", action, "--mapless"]),
                patch(
                    "updater.operation_guard", return_value=contextlib.nullcontext()
                ) as guard,
                patch.object(vardrsec, "dispatch") as dispatch,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                if action in ("sources", "install"):
                    vardrsec.main()
                    self.assertTrue(dispatch.call_args.args[0].mapless)
                else:
                    with self.assertRaises(SystemExit) as exit:
                        vardrsec.main()
                    self.assertEqual(exit.exception.code, 2)
                    guard.assert_not_called()
                    dispatch.assert_not_called()

    def test_runner_owns_arguments_after_separator(self):
        with (
            patch.object(
                sys, "argv", ["vardrsec.py", "runner", "--", "example", "--mapless"]
            ),
            patch("updater.operation_guard", return_value=contextlib.nullcontext()),
            patch.object(vardrsec, "dispatch") as dispatch,
        ):
            vardrsec.main()
        args = dispatch.call_args.args[0]
        self.assertFalse(args.mapless)
        self.assertIn("--mapless", args.runner_args)

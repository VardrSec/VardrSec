import contextlib
import argparse
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


class LifecycleTests(unittest.TestCase):
    def test_configuration_never_overwrites_keys_or_prints_them(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vardrsec, "ROOT", Path(directory)),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                vardrsec.configure()
            original = (Path(directory) / ".env").read_bytes()
            values = dict(line.split("=", 1) for line in original.decode().splitlines())
            keys = [
                values[name]
                for name in ("POSTGRES_PASSWORD", "BACKEND_JWT_SECRET", "AUTH_SECRET")
            ]
            self.assertEqual(len(set(keys)), 3)
            for key in keys:
                self.assertEqual(len(key), 64)
                self.assertNotIn(key, output.getvalue())
            with self.assertRaises(FileExistsError):
                vardrsec.configure()
            self.assertEqual((Path(directory) / ".env").read_bytes(), original)

    def test_source_manifest_cannot_redirect_to_another_repository(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vardrsec, "ROOT", Path(directory)),
            patch.object(vardrsec, "run") as run,
        ):
            manifest = {
                "components": {"map": {"repository": "other/repo", "commit": "a" * 40}}
            }
            (Path(directory) / "versions.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Unexpected component"):
                vardrsec.sources()
            run.assert_not_called()

    def test_source_preparation_preserves_a_changed_checkout(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vardrsec, "ROOT", Path(directory)),
            patch.object(vardrsec, "run") as run,
        ):
            manifest = {
                "components": {
                    "map": {"repository": "VardrSec/VardrMap", "commit": "a" * 40}
                }
            }
            (Path(directory) / "versions.json").write_text(json.dumps(manifest))
            (Path(directory) / ".sources" / "map").mkdir(parents=True)
            (Path(directory) / ".sources" / "map" / ".git").mkdir()
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="a" * 40),
                subprocess.CompletedProcess([], 0, stdout=" M work.py"),
            ]
            with self.assertRaisesRegex(ValueError, "preserve it"):
                vardrsec.sources()
            self.assertEqual(run.call_count, 2)

    def test_missing_git_fails_before_creating_an_incomplete_source_directory(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vardrsec, "ROOT", Path(directory)),
            patch.object(vardrsec.shutil, "which", return_value=None),
        ):
            with self.assertRaisesRegex(ValueError, "Required command 'git'"):
                vardrsec.sources()
            self.assertFalse((Path(directory) / ".sources").exists())

    def test_interrupted_initial_fetch_can_resume_without_resetting_user_work(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vardrsec, "ROOT", Path(directory)),
        ):
            root = Path(directory)
            entries = {
                name: {"repository": "VardrSec/" + repo, "commit": letter * 40}
                for name, repo, letter in (
                    ("map", "VardrMap", "a"),
                    ("runner", "VardrRunner", "b"),
                    ("gate", "VardrGate", "c"),
                )
            }
            (root / "versions.json").write_text(
                json.dumps({"components": entries}), encoding="utf-8"
            )
            failed, checked_out = False, []

            def command(*args, **kwargs):
                nonlocal failed
                path, action = Path(args[2]), args[3]
                if action == "init":
                    (path / ".git").mkdir()
                if action == "fetch" and not failed:
                    failed = True
                    raise subprocess.CalledProcessError(128, args)
                if action == "rev-parse":
                    return subprocess.CompletedProcess(args, 128, stdout="")
                if action == "checkout":
                    checked_out.append(path.name)
                return subprocess.CompletedProcess(args, 0, stdout="")

            with patch.object(vardrsec, "run", side_effect=command):
                with self.assertRaises(subprocess.CalledProcessError):
                    vardrsec.sources()
                self.assertTrue((root / ".sources/map/.git").is_dir())
                vardrsec.sources()
            self.assertEqual(checked_out, ["map", "runner", "gate"])

    def test_windows_container_mode_fails_before_build(self):
        args = argparse.Namespace(action="build")
        with (
            patch.object(vardrsec.shutil, "which", return_value="docker"),
            patch.object(
                vardrsec,
                "run",
                side_effect=[
                    subprocess.CompletedProcess([], 0, stdout="5.6.1"),
                    subprocess.CompletedProcess([], 0, stdout="windows"),
                ],
            ),
            patch.object(vardrsec, "compose") as compose,
        ):
            with self.assertRaisesRegex(ValueError, "Linux containers"):
                vardrsec.dispatch(args, None)
            compose.assert_not_called()

    def test_generated_bootstrap_is_explicit_and_default_remains_interactive(self):
        for generated in (False, True):
            with (
                self.subTest(generated=generated),
                patch.object(vardrsec, "compose") as compose,
            ):
                vardrsec.dispatch(
                    argparse.Namespace(
                        action="bootstrap",
                        username="operator",
                        generate_password=generated,
                    ),
                    None,
                )
                command = compose.call_args.args
                self.assertEqual("-T" in command, generated)
                self.assertEqual("--generate-password" in command, generated)
                self.assertNotIn("--password", command)

    def test_install_chains_the_existing_steps_in_order(self):
        calls = []
        real = vardrsec.dispatch

        def routed(args, parser):
            if args.action == "install":
                return real(args, parser)
            calls.append(args.action)

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(vardrsec, "ROOT", Path(directory)),
                patch.object(vardrsec, "dispatch", side_effect=routed),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                vardrsec.dispatch(argparse.Namespace(action="install"), None)
        self.assertEqual(list(vardrsec.INSTALL_STEPS), calls)
        self.assertIn("update-ca-certificates", out.getvalue())
        self.assertIn("No scans were started", out.getvalue())

    def test_install_refuses_to_run_over_an_existing_installation(self):
        class Parser:
            def error(self, message):
                raise SystemExit(message)

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".env").write_text("POSTGRES_PASSWORD=keep")
            with (
                patch.object(vardrsec, "ROOT", Path(directory)),
                patch.object(vardrsec, "configure") as configure,
            ):
                with self.assertRaises(SystemExit):
                    vardrsec.dispatch(argparse.Namespace(action="install"), Parser())
                configure.assert_not_called()
            self.assertEqual("POSTGRES_PASSWORD=keep", (Path(directory) / ".env").read_text())


if __name__ == "__main__":
    unittest.main()

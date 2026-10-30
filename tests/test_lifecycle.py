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

    def _install(self, env_present, started, fail_at=None):
        calls = []
        real = vardrsec.dispatch

        def routed(args, parser):
            if args.action == "install":
                return real(args, parser)
            calls.append(args.action)
            if args.action == fail_at:
                raise RuntimeError("network dropped")

        class Parser:
            def error(self, message):
                raise SystemExit(message)

        with tempfile.TemporaryDirectory() as directory:
            if env_present:
                (Path(directory) / ".env").write_text("POSTGRES_PASSWORD=keep")
            with (
                patch.object(vardrsec, "ROOT", Path(directory)),
                patch.object(vardrsec, "dispatch", side_effect=routed),
                patch.object(vardrsec, "has_installation_data", return_value=started),
                contextlib.redirect_stdout(io.StringIO()) as out,
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                try:
                    vardrsec.dispatch(argparse.Namespace(action="install"), Parser())
                    error = None
                except BaseException as exc:  # noqa: BLE001 - the test inspects it
                    error = exc
            kept = (
                (Path(directory) / ".env").read_text()
                if (Path(directory) / ".env").exists()
                else None
            )
        return calls, out.getvalue(), err.getvalue(), error, kept

    def test_install_chains_the_existing_steps_in_order(self):
        calls, out, _, error, _ = self._install(env_present=False, started=False)
        self.assertIsNone(error)
        self.assertEqual(list(vardrsec.INSTALL_STEPS), calls)
        self.assertIn("update-ca-certificates", out)
        self.assertIn("No scans were started", out)

    def test_install_resumes_without_regenerating_secrets(self):
        calls, out, _, error, kept = self._install(env_present=True, started=False)
        self.assertIsNone(error)
        self.assertNotIn("configure", calls)
        self.assertEqual(["sources", "build", "start", "export-ca"], calls)
        self.assertIn("Resuming", out)
        self.assertEqual("POSTGRES_PASSWORD=keep", kept)

    def test_install_refuses_once_the_platform_has_been_started(self):
        calls, _, _, error, kept = self._install(env_present=True, started=True)
        self.assertIsInstance(error, SystemExit)
        self.assertEqual([], calls)
        self.assertEqual("POSTGRES_PASSWORD=keep", kept)

    def test_a_failed_step_explains_how_to_resume_and_keeps_credentials(self):
        calls, _, err, error, kept = self._install(env_present=True, started=False, fail_at="build")
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(["sources", "build"], calls)
        self.assertIn("run `python3 vardrsec.py install` again", err)
        self.assertIn("Nothing was deleted", err)
        self.assertEqual("POSTGRES_PASSWORD=keep", kept)


    def test_runner_runs_the_installed_image_set_with_named_variables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".active-images.json").write_text("{}")
            with (
                patch.object(vardrsec, "ROOT", root),
                patch.object(vardrsec, "run") as run,
            ):
                vardrsec.dispatch(
                    argparse.Namespace(
                        action="runner",
                        runner_args=["--env", "OWNER_TOKEN", "--env=PEER_TOKEN", "--", "jobs", "run"],
                    ),
                    None,
                )
        command = list(run.call_args.args)
        # The active image file is what a plain `docker compose run` would miss.
        self.assertEqual(
            [
                "docker", "compose",
                "-f", str(root / "compose.yaml"),
                "-f", str(root / ".active-images.json"),
                "run", "--rm", "--no-deps",
                "-e", "OWNER_TOKEN", "-e", "PEER_TOKEN",
                "runner", "jobs", "run",
            ],
            command,
        )

    def test_runner_arguments_after_the_separator_are_passed_unchanged(self):
        flags, command = vardrsec.runner_invocation(
            ["credentials", "approve", "--env", "OWNER_TOKEN", "--destination", "x"]
        )
        self.assertEqual([], flags)
        self.assertEqual(
            ["credentials", "approve", "--env", "OWNER_TOKEN", "--destination", "x"], command
        )

    def test_runner_variable_names_are_checked(self):
        for arguments in (["--env"], ["--env", "A=B"], ["--env=1BAD"], ["--env", "$(id)"]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                vardrsec.runner_invocation(arguments)

    def _main(self, *argv):
        captured = {}

        def dispatched(args, parser):
            captured["args"] = args

        with (
            patch.object(sys, "argv", ["vardrsec.py", *argv]),
            patch.object(vardrsec, "dispatch", side_effect=dispatched),
            patch("updater.operation_guard", return_value=contextlib.nullcontext()),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            try:
                vardrsec.main()
            except SystemExit as exc:
                return None, exc.code, err.getvalue()
        return captured.get("args"), None, err.getvalue()

    def test_runner_requires_the_separator_so_its_options_stay_its_own(self):
        args, code, err = self._main("runner", "jobs", "run")
        self.assertEqual(2, code)
        self.assertIn("runner -- jobs run", err)
        args, code, _ = self._main("runner", "--", "test-cases", "save", "--destination", "x")
        self.assertIsNone(code)
        self.assertEqual(["test-cases", "save", "--destination", "x"], args.runner_args)
        self.assertIsNone(args.destination)

    def test_other_actions_still_reject_unknown_arguments(self):
        _, code, err = self._main("start", "--bogus")
        self.assertEqual(2, code)
        self.assertIn("unrecognized arguments: --bogus", err)


if __name__ == "__main__":
    unittest.main()

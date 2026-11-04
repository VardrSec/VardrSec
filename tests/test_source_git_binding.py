"""Git binding refusal: local synthetic repositories only, never network fetch."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec


class SourceGitBindingTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp(prefix="vardr-git-binding-"))
        checkout, outside, template = (
            root / "checkout",
            root / "outside",
            root / "template",
        )
        for path in (checkout, outside, template):
            path.mkdir()
        (outside / "retained.txt").write_bytes(
            b"synthetic ignored outside data: preserve"
        )
        pins = {
            name: {"repository": "VardrSec/" + repo, "commit": revision * 40}
            for name, repo, revision in (
                ("map", "VardrMap", "a"),
                ("runner", "VardrRunner", "b"),
                ("gate", "VardrGate", "c"),
            )
        }
        (checkout / "versions.json").write_text(json.dumps({"components": pins}))
        return checkout, outside, template

    def local_repository(self, source, template):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git required for actual local binding fixture")
        source.mkdir(parents=True)
        subprocess.run(
            [
                git,
                "-C",
                str(source),
                "--git-dir=" + str(source / ".git"),
                "--work-tree=" + str(source),
                "init",
                "--template=" + str(template),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return git

    def test_actual_core_worktree_redirect_refuses_before_mutation_in_both_modes(self):
        for mapless in (False, True):
            with self.subTest(mapless=mapless):
                checkout, outside, template = self.fixture()
                source = checkout / ".sources" / "gate"
                git = self.local_repository(source, template)
                subprocess.run(
                    [
                        git,
                        "-C",
                        str(source),
                        "config",
                        "--local",
                        "core.worktree",
                        str(outside),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                (source / ".git" / "info").mkdir(exist_ok=True)
                (source / ".git" / "info" / "exclude").write_text("retained.txt\n")
                original_config = (source / ".git" / "config").read_bytes()
                original = vardrsec.run
                commands = []

                def read_only(*args, **kwargs):
                    commands.append(args)
                    if args[3] != "rev-parse":
                        raise AssertionError(
                            "Only read-only Git binding query is allowed"
                        )
                    return original(*args, **kwargs)

                with (
                    patch.object(vardrsec, "ROOT", checkout),
                    patch.object(vardrsec, "run", side_effect=read_only),
                ):
                    with self.assertRaisesRegex(
                        ValueError, "binding differs from the managed cache"
                    ):
                        vardrsec.sources(mapless=mapless)
                self.assertEqual(len(commands), 1)
                self.assertIn("--show-toplevel", commands[0])
                self.assertEqual(
                    (source / ".git" / "config").read_bytes(), original_config
                )
                self.assertEqual(
                    (outside / "retained.txt").read_bytes(),
                    b"synthetic ignored outside data: preserve",
                )
                self.assertEqual(list(outside.iterdir()), [outside / "retained.txt"])
                self.assertFalse((checkout / ".sources" / "map").exists())
                self.assertFalse((checkout / ".sources" / "runner").exists())

    def test_actual_nominal_unborn_repository_binding_is_supported(self):
        checkout, _, template = self.fixture()
        source = checkout / ".sources" / "runner"
        self.local_repository(source, template)
        vardrsec._require_source_git_binding(source)

    def test_actual_common_metadata_redirect_is_refused_with_nominal_first_two_roots(
        self,
    ):
        checkout, outside, template = self.fixture()
        source, common = checkout / ".sources" / "gate", outside / "common"
        git = self.local_repository(source, template)
        self.local_repository(common, template)
        (source / ".git" / "commondir").write_text((common / ".git").as_posix() + "\n")
        result = subprocess.run(
            [
                git,
                "-C",
                str(source),
                "rev-parse",
                "--show-toplevel",
                "--absolute-git-dir",
                "--git-common-dir",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        roots = result.stdout.splitlines()
        self.assertEqual(
            [Path(value) for value in roots[:2]], [source, source / ".git"]
        )
        self.assertEqual(Path(roots[2]), common / ".git")
        before = {
            str(p.relative_to(common)): p.read_bytes()
            for p in common.rglob("*")
            if p.is_file()
        }
        original = vardrsec.run

        def read_only(*args, **kwargs):
            if args[3] != "rev-parse":
                raise AssertionError(
                    "Mutation/network forbidden even if binding refusal regresses"
                )
            return original(*args, **kwargs)

        for mapless in (False, True):
            with (
                self.subTest(mapless=mapless),
                patch.object(vardrsec, "ROOT", checkout),
                patch.object(vardrsec, "run", side_effect=read_only),
            ):
                with self.assertRaisesRegex(
                    ValueError, "binding differs from the managed cache"
                ):
                    vardrsec.sources(mapless=mapless)
        self.assertEqual(
            before,
            {
                str(p.relative_to(common)): p.read_bytes()
                for p in common.rglob("*")
                if p.is_file()
            },
        )
        self.assertEqual(
            (outside / "retained.txt").read_bytes(),
            b"synthetic ignored outside data: preserve",
        )

    def test_external_metadata_relative_malformed_or_unknown_binding_refuses(self):
        checkout, outside, _ = self.fixture()
        source = checkout / ".sources" / "runner"
        outputs = [
            str(outside) + "\n" + str(source / ".git") + "\n.git",
            str(source) + "\n" + str(outside) + "\n.git",
            str(source) + "\n" + str(source / ".git") + "\n" + str(outside),
            "relative\nmetadata\n.git",
            str(source),
            "",
        ]
        for stdout in outputs:
            with (
                self.subTest(stdout=stdout),
                patch.object(
                    vardrsec,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=stdout),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "binding differs"):
                    vardrsec._require_source_git_binding(source)
        for reply in (
            subprocess.CompletedProcess([], 128, stdout=""),
            subprocess.TimeoutExpired("git", 15),
        ):
            with (
                self.subTest(reply=type(reply).__name__),
                patch.object(
                    vardrsec,
                    "run",
                    return_value=reply,
                    side_effect=reply if isinstance(reply, Exception) else None,
                ),
            ):
                with self.assertRaises(ValueError):
                    vardrsec._require_source_git_binding(source)

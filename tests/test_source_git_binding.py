"""Git binding refusal: local synthetic repositories only, never network fetch."""

import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec
import source_notices


class SourceGitBindingTests(unittest.TestCase):
    def test_notices_use_pinned_blobs_and_preserve_existing_output(self):
        with tempfile.TemporaryDirectory(prefix="vardr-notices-") as directory:
            root = Path(directory).resolve()
            template = root / "template"
            template.mkdir()
            pins, repos = {}, {}
            for name, repository in source_notices.REPOSITORIES.items():
                repo = root / name
                git = self.local_repository(repo, template)
                (repo / "LICENSE").write_bytes((name + " committed license\n").encode())
                subprocess.run(
                    [git, "-C", str(repo), "add", "LICENSE"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        git,
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Fixture",
                        "-c",
                        "user.email=fixture@example.invalid",
                        "commit",
                        "-m",
                        "fixture",
                    ],
                    check=True,
                    capture_output=True,
                )
                commit = source_notices.revision(repo, "HEAD^{commit}")
                pins[name] = {"repository": repository, "commit": commit}
                repos[name] = repo
                (repo / "LICENSE").write_bytes(b"uncommitted replacement")
                (repo / ".env").write_bytes(b"PRIVATE_CANARY")
            checkout = root / "distribution"
            self.local_repository(checkout, template)
            (checkout / "LICENSE").write_bytes(b"distribution committed license\n")
            (checkout / "versions.json").write_text(
                json.dumps({"components": pins}), encoding="utf-8"
            )
            subprocess.run(
                [git, "-C", str(checkout), "add", "LICENSE", "versions.json"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    git,
                    "-C",
                    str(checkout),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                check=True,
                capture_output=True,
            )
            destination = root / "notices"
            digest = source_notices.assemble(checkout, destination, repos)
            manifest_bytes = (destination / "manifest.json").read_bytes()
            self.assertEqual(digest, hashlib.sha256(manifest_bytes).hexdigest())
            manifest = json.loads(manifest_bytes)
            for name in repos:
                expected = (name + " committed license\n").encode()
                self.assertEqual(
                    (destination / name / "LICENSE").read_bytes(), expected
                )
                entry = manifest["components"][name]
                self.assertEqual(entry["commit"], pins[name]["commit"])
                self.assertEqual(
                    entry["files"][0]["sha256"], hashlib.sha256(expected).hexdigest()
                )
            self.assertNotIn(
                b"PRIVATE_CANARY",
                b"".join(
                    path.read_bytes()
                    for path in destination.rglob("*")
                    if path.is_file()
                ),
            )
            archive_destination = root / "with-sources"
            source_notices.assemble(
                checkout, archive_destination, repos, include_sources=True
            )
            archive_manifest = json.loads(
                (archive_destination / "manifest.json").read_bytes()
            )
            for name, component in archive_manifest["components"].items():
                archive = archive_destination / component["source_archive"]["path"]
                self.assertEqual(
                    component["source_archive"]["sha256"],
                    hashlib.sha256(archive.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    component["source_archive"]["bytes"], archive.stat().st_size
                )
                self.assertEqual(
                    component["tree"], manifest["components"][name]["tree"]
                )
                with tarfile.open(archive, "r:") as source:
                    self.assertNotIn(name + "/.env", source.getnames())
                    self.assertEqual(
                        source.extractfile(name + "/LICENSE").read(),
                        (archive_destination / name / "LICENSE").read_bytes(),
                    )
            self.assertTrue(
                all(
                    "source_archive" not in component
                    for component in manifest["components"].values()
                )
            )
            with self.assertRaisesRegex(ValueError, "new destination"):
                source_notices.assemble(checkout, destination, repos)
            self.assertEqual(
                (destination / "manifest.json").read_bytes(), manifest_bytes
            )
            with patch.object(
                source_notices, "git", side_effect=ValueError("missing local object")
            ):
                with self.assertRaises(ValueError):
                    source_notices.assemble(checkout, root / "missing", repos)
            self.assertFalse((root / "missing").exists())

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
        # Git expands Windows TEMP's 8.3 alias. Compare the same canonical paths
        # used by the boundary; the external common directory must still refuse.
        self.assertEqual(
            [Path(value).resolve() for value in roots[:2]],
            [source.resolve(), (source / ".git").resolve()],
        )
        self.assertEqual(Path(roots[2]).resolve(), (common / ".git").resolve())
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

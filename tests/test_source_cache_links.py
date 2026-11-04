"""Observed source-cache links refuse before Git; no concurrent-race proof."""

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vardrsec


class SourceCacheLinksTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp(prefix="vardr-source-link-after-"))
        checkout, outside = root / "checkout", root / "outside"
        checkout.mkdir()
        outside.mkdir()
        (outside / "retained.txt").write_bytes(b"synthetic outside data: preserve")
        pins = {
            name: {"repository": "VardrSec/" + repo, "commit": revision * 40}
            for name, repo, revision in (
                ("map", "VardrMap", "a"),
                ("runner", "VardrRunner", "b"),
                ("gate", "VardrGate", "c"),
            )
        }
        (checkout / "versions.json").write_text(json.dumps({"components": pins}))
        return checkout, outside

    def link(self, path, target):
        try:
            path.symlink_to(target, target_is_directory=True)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                self.skipTest(
                    "native symlink fixture unavailable: WinError1314, not passed"
                )
            raise

    def test_real_cache_component_and_metadata_links_are_preserved_and_refused(self):
        for mode in (False, True):
            for location in ("cache", "component", "metadata", "dangling_cache"):
                with self.subTest(mapless=mode, location=location):
                    checkout, outside = self.fixture()
                    cache = checkout / ".sources"
                    if location in ("cache", "dangling_cache"):
                        self.link(
                            cache,
                            outside if location == "cache" else outside / "missing",
                        )
                    else:
                        cache.mkdir()
                        if location == "component":
                            self.link(cache / "gate", outside)
                        else:
                            (cache / "gate").mkdir()
                            self.link(cache / "gate" / ".git", outside)
                    with (
                        patch.object(vardrsec, "ROOT", checkout),
                        patch.object(vardrsec, "run") as command,
                    ):
                        with self.assertRaisesRegex(
                            ValueError, "Linked source cache refused"
                        ):
                            vardrsec.sources(mapless=mode)
                        command.assert_not_called()
                    self.assertEqual(
                        list(outside.iterdir()), [outside / "retained.txt"]
                    )
                    self.assertEqual(
                        (outside / "retained.txt").read_bytes(),
                        b"synthetic outside data: preserve",
                    )
                    self.assertFalse((cache / "runner").is_dir())

    def test_gitdir_file_is_not_followed(self):
        for mode in (False, True):
            with self.subTest(mapless=mode):
                checkout, outside = self.fixture()
                metadata = checkout / ".sources" / "gate" / ".git"
                metadata.parent.mkdir(parents=True)
                original = "gitdir: " + str(outside)
                metadata.write_text(original)
                with (
                    patch.object(vardrsec, "ROOT", checkout),
                    patch.object(vardrsec, "run") as command,
                ):
                    with self.assertRaisesRegex(
                        ValueError, "External Git metadata refused"
                    ):
                        vardrsec.sources(mapless=mode)
                    command.assert_not_called()
                self.assertEqual(metadata.read_text(), original)
                self.assertEqual(list(outside.iterdir()), [outside / "retained.txt"])

    def test_synthetic_windows_reparse_attribute_is_refused_before_git(self):
        checkout, _ = self.fixture()
        selected = checkout / ".sources" / "runner"
        selected.mkdir(parents=True)
        original = Path.lstat

        def observed(path, *args, **kwargs):
            if path == selected:
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400
                )
            return original(path, *args, **kwargs)

        with (
            patch.object(vardrsec, "ROOT", checkout),
            patch.object(Path, "lstat", observed),
            patch.object(vardrsec, "run") as command,
        ):
            with self.assertRaisesRegex(ValueError, "Linked source cache refused"):
                vardrsec.sources(mapless=True)
            command.assert_not_called()

    def test_unknown_cache_observation_does_not_reach_git(self):
        checkout, _ = self.fixture()
        original = Path.lstat

        def unavailable(path, *args, **kwargs):
            if path == checkout / ".sources":
                raise PermissionError("synthetic cache unavailable")
            return original(path, *args, **kwargs)

        with (
            patch.object(vardrsec, "ROOT", checkout),
            patch.object(Path, "lstat", unavailable),
            patch.object(vardrsec, "run") as command,
        ):
            with self.assertRaises(PermissionError):
                vardrsec.sources(mapless=True)
            command.assert_not_called()

"""Offline refusal and exact-source preparation checks; no Docker execution."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import community_ci as ci


class CommunityPreparationTests(unittest.TestCase):
    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "retained").write_text("keep")
            with self.assertRaises(ValueError):
                ci.new_copy(root, "current")
            self.assertEqual((root / "retained").read_text(), "keep")

    def test_only_tracked_sources_copied_and_pins_do_not_mutate_original(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "source", Path(folder) / "target"
            source.mkdir()
            original = {"components": {k: {"commit": v} for k, v in ci.PINS["baseline"].items()}}
            (source / "versions.json").write_text(json.dumps(original))
            (source / ".env").write_text("private synthetic data")
            with patch.object(ci, "SOURCE", source), patch.object(
                ci.subprocess, "check_output", return_value=b"versions.json\0"
            ):
                ci.new_copy(target, "current")
            self.assertFalse((target / ".env").exists())
            self.assertEqual(json.loads((source / "versions.json").read_text()), original)
            result = json.loads((target / "versions.json").read_text())
            self.assertEqual({k: v["commit"] for k, v in result["components"].items()}, ci.PINS["current"])

    def test_capacity_shortfall_refuses_without_cleanup(self):
        with patch.object(ci.shutil, "disk_usage") as usage:
            usage.return_value.free = 1
            with self.assertRaises(ValueError):
                ci.disk_guard(Path("/tmp"), 2)

    def test_dirty_or_wrong_acquired_sources_refuse(self):
        for outputs in (("wrong", ""), (ci.PINS["current"]["map"], " M tracked")):
            with self.subTest(outputs=outputs), patch.object(
                ci.subprocess, "check_output", side_effect=outputs
            ):
                with self.assertRaises(ValueError):
                    ci.source_receipt(Path("/does-not-execute"), "current")

    def test_wrong_working_directory_container_is_never_stopped(self):
        calls = []

        def output(args, **kwargs):
            if args[1] == "ps":
                return "foreign-container\n"
            return json.dumps([{"Config": {"Labels": {
                "com.docker.compose.project.working_dir": "/foreign/installation"
            }}}])

        with patch.object(ci.subprocess, "check_output", side_effect=output), patch.object(
            ci.subprocess, "run", side_effect=lambda *args, **kwargs: calls.append(args)
        ):
            self.assertEqual(ci.stop_owned(Path("/owned/installation")), 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

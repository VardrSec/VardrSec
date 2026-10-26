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
            run.side_effect = [
                subprocess.CompletedProcess([], 0, stdout="a" * 40),
                subprocess.CompletedProcess([], 0, stdout=" M work.py"),
            ]
            with self.assertRaisesRegex(ValueError, "preserve it"):
                vardrsec.sources()
            self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()

import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery


class RecoveryTests(unittest.TestCase):
    def test_configuration_mismatch_refuses_backup_before_stopping_services(self):
        live = {
            "name": "fixture",
            "services": {
                s: {"environment": {k: "persisted-secret" for k in names}}
                for s, names in recovery.PERSISTED_ENV.items()
            },
        }
        file_config = json.loads(json.dumps(live))
        file_config["services"]["db"]["environment"]["POSTGRES_PASSWORD"] = (
            "different-secret"
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(recovery, "compose") as compose,
            patch.object(
                recovery,
                "container",
                return_value={
                    "Config": {"Env": ["POSTGRES_PASSWORD=persisted-secret"]}
                },
            ),
        ):
            compose.side_effect = [
                subprocess.CompletedProcess([], 0, stdout=json.dumps(live)),
                subprocess.CompletedProcess([], 0, stdout=json.dumps(file_config)),
            ]
            with self.assertRaisesRegex(ValueError, "Persist the matching") as error:
                recovery.backup(Path(directory), Path(directory) / "backup")
            self.assertNotIn("persisted-secret", str(error.exception))
            self.assertNotIn("different-secret", str(error.exception))
            self.assertEqual(compose.call_count, 2)
            self.assertFalse((Path(directory) / "backup").exists())

    def snapshot(self, root):
        for name in recovery.FILES + ("database.dump", "images.tar.gz"):
            (root / name).write_bytes(b"disposable fixture")
        for name in recovery.VOLUMES:
            with tarfile.open(root / f"{name}.tar.gz", "w:gz") as archive:
                info = tarfile.TarInfo("safe-file")
                info.size = 4
                archive.addfile(info, io.BytesIO(b"test"))
        metadata = {
            "schema_version": 1,
            "images": {s: "sha256:" + "a" * 64 for s in recovery.SERVICES},
            "volumes": {v: "fixture" for v in recovery.VOLUMES},
            "files": {p.name: recovery.digest(p) for p in root.iterdir()},
        }
        (root / "snapshot.json").write_text(json.dumps(metadata))

    def test_corrupt_backup_is_rejected_before_docker_or_destination_changes(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(recovery, "command") as command,
        ):
            root = Path(directory)
            source = root / "backup"
            source.mkdir()
            self.snapshot(source)
            (source / ".env").write_bytes(b"changed after snapshot")
            with self.assertRaisesRegex(ValueError, "integrity"):
                recovery.restore(
                    root, source, root / "restored", "vardrsec-restore-test"
                )
            self.assertFalse((root / "restored").exists())
            command.assert_not_called()

    def test_existing_restore_resources_are_preserved(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(
                recovery,
                "command",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout="existing-resource"
                ),
            ) as command,
        ):
            root = Path(directory)
            source = root / "backup"
            source.mkdir()
            self.snapshot(source)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                recovery.restore(
                    root, source, root / "restored", "vardrsec-restore-test"
                )
            self.assertFalse((root / "restored").exists())
            self.assertEqual(command.call_count, 1)

    def test_state_archives_reject_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, kind in (
                ("../outside", tarfile.REGTYPE),
                ("/absolute", tarfile.REGTYPE),
                ("link", tarfile.SYMTYPE),
                ("hardlink", tarfile.LNKTYPE),
            ):
                path = Path(directory) / "state.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    info.linkname = "../../outside"
                    archive.addfile(info)
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(ValueError, "unsafe path"),
                ):
                    recovery.safe_archive(path)


if __name__ == "__main__":
    unittest.main()

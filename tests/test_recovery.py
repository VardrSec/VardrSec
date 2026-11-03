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
    def test_service_lookup_ignores_retained_oneoffs(self):
        canonical = {"Id": "service", "Config": {"Labels": {
            "com.docker.compose.oneoff": "False", "com.docker.compose.service": "runner",
            "com.docker.compose.project": "owned"}}, "Mounts": ["unchanged"]}
        oneoff = {"Config": {"Labels": {"com.docker.compose.oneoff": "True",
            "com.docker.compose.service": "runner", "com.docker.compose.project": "owned"}}}
        with patch.object(recovery, "compose", return_value=subprocess.CompletedProcess(
            [], 0, stdout="oneoff1 service oneoff2\n")), patch.object(
                recovery, "inspect", side_effect=[oneoff, canonical, oneoff]):
            self.assertIs(recovery.container(Path("/synthetic"), "runner", "owned"), canonical)

    def test_service_lookup_refuses_zero_or_multiple_canonical_services(self):
        actual = {"Config": {"Labels": {"com.docker.compose.oneoff": "False",
            "com.docker.compose.service": "runner", "com.docker.compose.project": "owned"}}}
        oneoff = {"Config": {"Labels": {"com.docker.compose.oneoff": "True",
            "com.docker.compose.service": "runner", "com.docker.compose.project": "owned"}}}
        for infos in ([], [oneoff], [oneoff, oneoff], [actual, actual],
                      [oneoff, actual, actual]):
            with self.subTest(count=len(infos)), patch.object(
                recovery, "compose", return_value=subprocess.CompletedProcess(
                    [], 0, stdout=" ".join(str(i) for i in range(len(infos))))
            ), patch.object(recovery, "inspect", side_effect=infos):
                with self.assertRaisesRegex(ValueError, "^Expected exactly one runner container$"):
                    recovery.container(Path("/synthetic"), "runner", "owned")

    def test_service_lookup_refuses_unknown_oneoff_metadata(self):
        for labels in (None, {}, {"com.docker.compose.oneoff": "unknown"},
                       {"com.docker.compose.oneoff": False}):
            with self.subTest(labels=labels), patch.object(
                recovery, "compose", return_value=subprocess.CompletedProcess([], 0, stdout="candidate")
            ), patch.object(recovery, "inspect", return_value={"Config": {"Labels": labels}}):
                with self.assertRaisesRegex(ValueError, "^Expected exactly one runner container$"):
                    recovery.container(Path("/synthetic"), "runner", "owned")

    def test_service_lookup_refuses_unclassified_or_foreign_candidates(self):
        labels = {"com.docker.compose.oneoff": "False", "com.docker.compose.service": "runner",
                  "com.docker.compose.project": "owned"}
        canonical = {"Config": {"Labels": labels}}
        for key, value in (("com.docker.compose.oneoff", "unknown"),
                           ("com.docker.compose.service", "api"),
                           ("com.docker.compose.project", "other")):
            other = {"Config": {"Labels": {**labels, key: value}}}
            with self.subTest(key=key), patch.object(recovery, "compose",
                return_value=subprocess.CompletedProcess([], 0, stdout="canonical other")), patch.object(
                    recovery, "inspect", side_effect=[canonical, other]):
                with self.assertRaisesRegex(ValueError, "^Expected exactly one runner container$"):
                    recovery.container(Path("/synthetic"), "runner", "owned")

    def test_new_backup_emits_version_four_with_verified_role_module(self):
        class ImageSave:
            def __init__(self, *args, **kwargs):
                self.stdout = io.BytesIO(b"synthetic image archive")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def wait(self):
                return 0

        configuration = {
            "name": "synthetic",
            "services": {
                s: {"environment": {k: "synthetic" for k in names}}
                for s, names in recovery.PERSISTED_ENV.items()
            },
        }

        def container(root, service):
            return {
                "Image": "sha256:" + "a" * 64,
                "Config": {"Env": [f"{key}=synthetic" for key in recovery.PERSISTED_ENV.get(service, ())]},
                "Mounts": [{"Type": "volume", "Name": name, "Destination": mount}
                           for name, (_, mount) in recovery.VOLUMES.items()],
            }

        def archive(image, volume, action, stream):
            self.assertEqual(action, "backup")
            with tarfile.open(fileobj=stream, mode="w:gz") as output:
                info = tarfile.TarInfo("retained-evidence")
                info.size = 4
                output.addfile(info, io.BytesIO(b"test"))

        with (tempfile.TemporaryDirectory() as directory,
              patch.object(recovery, "compose", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(configuration))),
              patch.object(recovery, "container", side_effect=container),
              patch.object(recovery, "command", return_value=subprocess.CompletedProcess([], 0, stdout="")),
              patch.object(recovery, "volume_stream", side_effect=archive),
              patch.object(recovery, "volume_fingerprint", return_value="synthetic"),
              patch.object(recovery, "database_fingerprint", return_value={"_sequences": "synthetic"}),
              patch.object(recovery.subprocess, "Popen", ImageSave)):
            root = Path(directory)
            for name in recovery.FILES:
                (root / name).write_bytes(b"synthetic source " + name.encode())
            destination = root / "snapshot"
            recovery.backup(root, destination)
            metadata = recovery.validate(destination)
            self.assertEqual(metadata["schema_version"], 4)
            self.assertEqual(metadata["files"]["database_roles.py"], recovery.digest(root / "database_roles.py"))
            self.assertEqual((destination / "database_roles.py").read_bytes(), (root / "database_roles.py").read_bytes())

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

    def snapshot(self, root, version=4):
        scripts = {1: recovery.LEGACY_FILES, 2: recovery.UPDATE_FILES,
                   3: recovery.ENCRYPTED_FILES, 4: recovery.FILES}[version]
        for name in scripts + ("database.dump", "images.tar.gz"):
            (root / name).write_bytes(b"disposable fixture")
        for name in recovery.VOLUMES:
            with tarfile.open(root / f"{name}.tar.gz", "w:gz") as archive:
                info = tarfile.TarInfo("safe-file")
                info.size = 4
                archive.addfile(info, io.BytesIO(b"test"))
        metadata = {
            "schema_version": version,
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

    def test_historical_and_current_snapshot_formats_remain_supported(self):
        for version in (1, 2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.snapshot(root, version)
                self.assertEqual(recovery.validate(root)["schema_version"], version)

    def test_version_four_requires_hashed_role_module_before_any_restore_action(self):
        for mutation in ("missing", "corrupt", "symlink", "old-version-with-new-manifest"):
            with (self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory,
                  patch.object(recovery, "command") as command):
                root = Path(directory)
                source = root / "backup"
                source.mkdir()
                self.snapshot(source)
                module = source / "database_roles.py"
                if mutation == "missing":
                    metadata = json.loads((source / "snapshot.json").read_text())
                    metadata["files"].pop("database_roles.py")
                    (source / "snapshot.json").write_text(json.dumps(metadata))
                elif mutation == "corrupt":
                    module.write_bytes(b"changed after snapshot")
                elif mutation == "symlink":
                    module.unlink()
                    module.symlink_to(source / "recovery.py")
                else:
                    metadata = json.loads((source / "snapshot.json").read_text())
                    metadata["schema_version"] = 3
                    (source / "snapshot.json").write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    recovery.restore(root, source, root / "restored", "vardrsec-restore-test")
                self.assertFalse((root / "restored").exists())
                command.assert_not_called()

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

import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

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
        for active in ("runner", "managed-worker"):
            with (
                self.subTest(active=active),
                tempfile.TemporaryDirectory() as directory,
                patch.object(recovery, "compose", return_value=subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(live))) as compose,
                patch.object(recovery, "container", side_effect=lambda _root, service: {
                    "Config": {"Env": [f"{name}=persisted-secret"
                                      for name in recovery.PERSISTED_ENV[service]]}}),
                patch.object(recovery, "command", side_effect=lambda *args, **_kwargs:
                    subprocess.CompletedProcess([], 0, stdout="active" if
                        f"label=com.docker.compose.service={active}" in args else "")) as command,
                patch.object(recovery, "database_fingerprint") as fingerprint,
                patch.object(recovery, "volume_stream") as archive,
            ):
                with self.assertRaisesRegex(ValueError, "before backup"):
                    recovery.backup(Path(directory), Path(directory) / "backup")
                self.assertEqual(compose.call_count, 2)
                self.assertEqual(command.call_count, 1 if active == "runner" else 2)
                fingerprint.assert_not_called()
                archive.assert_not_called()
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
            "schema_version": 4,
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

    def test_version_one_snapshot_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.snapshot(root)
            metadata = json.loads((root / "snapshot.json").read_text())
            metadata["schema_version"] = 1
            metadata["files"].pop("updater.py")
            metadata["files"].pop("backup_crypto.py")
            metadata["files"].pop("database_roles.py")
            (root / "snapshot.json").write_text(json.dumps(metadata))
            self.assertEqual(recovery.validate(root)["schema_version"], 1)

    def test_version_two_snapshot_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.snapshot(root)
            metadata = json.loads((root / "snapshot.json").read_text())
            metadata["schema_version"] = 2
            metadata["files"].pop("backup_crypto.py")
            metadata["files"].pop("database_roles.py")
            (root / "snapshot.json").write_text(json.dumps(metadata))
            self.assertEqual(recovery.validate(root)["schema_version"], 2)

    def test_version_three_snapshot_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.snapshot(root)
            metadata = json.loads((root / "snapshot.json").read_text())
            metadata["schema_version"] = 3
            metadata["files"].pop("database_roles.py")
            (root / "snapshot.json").write_text(json.dumps(metadata))
            self.assertEqual(recovery.validate(root)["schema_version"], 3)

    def test_current_snapshot_requires_integrity_checked_role_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.snapshot(root)
            (root / "database_roles.py").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "integrity"):
                recovery.validate(root)
            metadata = json.loads((root / "snapshot.json").read_text())
            metadata["files"].pop("database_roles.py")
            (root / "snapshot.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                recovery.validate(root)

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

    def test_mapless_backup_restore_uses_only_runner_state_and_stays_stopped(self):
        import installation_mode
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            repository = Path(recovery.__file__).parent
            for name in recovery.MAPLESS_FILES:
                if name != installation_mode.MARKER:
                    (source / name).write_bytes((repository / name).read_bytes())
            installation_mode.write_mode(source, "mapless")
            configuration = {"name": "synthetic", "services": {"runner": {}}}
            process = MagicMock()
            process.__enter__.return_value = process
            process.stdout, process.stdin = io.BytesIO(b"saved-image"), io.BytesIO()
            process.wait.return_value = 0

            def stream(_image, _volume, action, output):
                if action == "backup":
                    with tarfile.open(fileobj=output, mode="w:gz") as archive:
                        item = tarfile.TarInfo("records-and-private-config")
                        item.size = 4
                        archive.addfile(item, io.BytesIO(b"kept"))

            bundle, restored = root / "bundle", root / "restored"
            with patch.object(recovery, "compose", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(configuration))) as compose, \
                 patch.object(recovery, "command", return_value=subprocess.CompletedProcess([], 0, stdout="")), \
                 patch.object(recovery, "container", return_value={"Image": "sha256:" + "a" * 64}), \
                 patch.object(recovery, "volume_name", return_value="state"), \
                 patch.object(recovery, "volume_stream", side_effect=stream) as volumes, \
                 patch.object(recovery, "volume_fingerprint", return_value="same-state"), \
                 patch.object(recovery, "database_fingerprint") as database, \
                 patch.object(recovery.subprocess, "Popen", return_value=process):
                recovery.backup(source, bundle)
                metadata = recovery.validate(bundle)
                self.assertEqual((metadata["schema_version"], metadata["mode"]), (6, "mapless"))
                self.assertEqual(set(metadata["images"]), {"runner"})
                recovery.restore(source, bundle, restored, "vardrsec-restore-mapless")
                database.assert_not_called()
                self.assertEqual([call.args[2] for call in volumes.call_args_list], ["backup", "restore"])
                self.assertTrue(all(not {"db", "api", "web", "proxy", "up", "run"}.intersection(call.args[1:]) for call in compose.call_args_list))
            self.assertFalse(any((bundle / name).exists() for name in (".env", "database.dump", "Caddyfile")))
            self.assertEqual(installation_mode.read_mode(restored), "mapless")
            active = json.loads((restored / ".active-images.mapless.json").read_text())
            self.assertEqual(active["name"], "vardrsec-restore-mapless")
            self.assertTrue(json.loads((restored / "restore-receipt.json").read_text())["runner_state_verified"])

    def test_mapless_snapshot_refuses_a_rehashed_full_marker_before_restore(self):
        import installation_mode
        with tempfile.TemporaryDirectory() as directory, patch.object(recovery, "command") as command:
            root = Path(directory)
            source = root / "bundle"
            source.mkdir()
            for name in recovery.MAPLESS_FILES:
                if name != installation_mode.MARKER:
                    (source / name).write_bytes(b"fixture")
            installation_mode.write_mode(source, "full")
            with tarfile.open(source / "runner-state.tar.gz", "w:gz"):
                pass
            (source / "images.tar.gz").write_bytes(b"fixture")
            metadata = {"schema_version": 6, "mode": "mapless", "images": {"runner": "sha256:" + "a" * 64},
                        "volumes": {"runner-state": "fixture"}, "files": {p.name: recovery.digest(p) for p in source.iterdir()}}
            (source / "snapshot.json").write_text(json.dumps(metadata))
            with self.assertRaisesRegex(ValueError, "marker"):
                recovery.restore(root, source, root / "restored", "vardrsec-restore-mapless")
            command.assert_not_called()
            self.assertFalse((root / "restored").exists())


if __name__ == "__main__":
    unittest.main()

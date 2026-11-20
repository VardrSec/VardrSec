from pathlib import Path
import io
import json
import shutil
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_crypto
import recovery
import test_recovery as fixtures
import vardrsec


def run_cli(root, *args):
    with patch.object(vardrsec, "ROOT", root), patch.object(sys, "argv", ["vardrsec.py", *args]):
        vardrsec.main()


class RecipientOptionTests(unittest.TestCase):
    def test_only_omitting_recipient_selects_plaintext(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(recovery, "backup") as backup:
            root = Path(folder)
            destination = root / "snapshot"
            args = ("backup", "--destination", str(destination))
            for recipient in ("", "invalid"):
                with self.subTest(recipient=recipient), self.assertRaisesRegex(ValueError, "X25519"):
                    run_cli(root, *args, "--recipient", recipient)
            backup.assert_not_called()
            self.assertFalse(destination.exists())
            run_cli(root, *args)
            backup.assert_called_once_with(root, destination)

    def test_recipient_rejected_on_unrelated_commands(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(vardrsec, "dispatch") as dispatch:
            for action, recipient in (("update", "age-recipient"), ("unseal-backup", "")):
                with self.subTest(action=action), patch.object(sys, "stderr", new_callable=io.StringIO) as stderr:
                    with self.assertRaises(SystemExit) as error:
                        run_cli(Path(folder), action, "--recipient", recipient)
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn("--recipient is only valid", stderr.getvalue())
            dispatch.assert_not_called()


@unittest.skipUnless(
    shutil.which("age") and shutil.which("age-keygen"), "official age tools required"
)
class EncryptionTests(unittest.TestCase):
    def test_direct_encrypted_backup_removes_plaintext_staging(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            identity, recipient = self.keys(root, "identity.txt")

            def snapshot(_root, destination):
                destination.mkdir()
                fixtures.RecoveryTests().snapshot(destination)

            with patch.object(recovery, "backup", side_effect=snapshot):
                run_cli(root, "backup", "--destination", str(root / "backup.age"), "--recipient", recipient)
            self.assertEqual(list(root.glob(".vardrsec-backup-*")), [])
            backup_crypto.unseal(root / "backup.age", root / "recovered", identity)
            recovery.validate(root / "recovered")

    def keys(self, root, name):
        key = root / name
        subprocess.run(
            ["age-keygen", "--output", str(key)], capture_output=True, check=True
        )
        recipient = subprocess.check_output(
            ["age-keygen", "-y", str(key)], text=True
        ).strip()
        return key, recipient

    def test_round_trip_and_existing_target_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.mkdir()
            fixtures.RecoveryTests().snapshot(source)
            # Cover a current Full bundle, including optional portable launchers.
            metadata = json.loads((source / "snapshot.json").read_text())
            for name in recovery.FULL_FILES + recovery.LAUNCHER_FILES:
                if not (source / name).exists():
                    (source / name).write_bytes((Path(recovery.__file__).parent / name).read_bytes())
                metadata["files"][name] = recovery.digest(source / name)
            metadata.update(schema_version=5, mode="full")
            (source / "snapshot.json").write_text(json.dumps(metadata))
            identity, recipient = self.keys(root, "private-identity.txt")
            encrypted = root / "snapshot.age"
            run_cli(root, "seal-backup", "--backup", str(source), "--destination", str(encrypted), "--recipient", recipient)
            self.assertTrue(encrypted.read_bytes().startswith(b"age-encryption.org/v1"))
            with self.assertRaises(FileExistsError):
                backup_crypto.seal(source, encrypted, recipient)
            destination = root / "recovered"
            backup_crypto.unseal(encrypted, destination, identity)
            metadata = recovery.validate(destination)
            for name in metadata["files"]:
                self.assertEqual(
                    recovery.digest(source / name), recovery.digest(destination / name)
                )
            with self.assertRaisesRegex(ValueError, "must not exist"):
                backup_crypto.unseal(encrypted, destination, identity)

    def test_wrong_identity_corruption_and_truncation_publish_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.mkdir()
            fixtures.RecoveryTests().snapshot(source)
            identity, recipient = self.keys(root, "identity.txt")
            wrong, _ = self.keys(root, "wrong.txt")
            encrypted = root / "snapshot.age"
            backup_crypto.seal(source, encrypted, recipient)
            original = encrypted.read_bytes()
            corrupt = bytearray(original)
            corrupt[len(corrupt) // 2] ^= 1
            for name, key, data in (
                ("wrong", wrong, original),
                ("corrupt", identity, bytes(corrupt)),
                ("truncated", identity, original[:-32]),
            ):
                path = root / (name + ".age")
                path.write_bytes(data)
                destination = root / name
                with self.subTest(name=name), self.assertRaises(ValueError):
                    backup_crypto.unseal(path, destination, key)
                self.assertFalse(destination.exists())
                self.assertEqual(list(root.glob(".vardrsec-unseal-*")), [])

    def test_large_payload_streams_with_exact_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.mkdir()
            fixtures.RecoveryTests().snapshot(source)
            with (source / "images.tar.gz").open("wb") as output:
                for _ in range(32):
                    output.write(os.urandom(1024 * 1024))
            metadata = json.loads((source / "snapshot.json").read_text())
            metadata["files"]["images.tar.gz"] = recovery.digest(
                source / "images.tar.gz"
            )
            (source / "snapshot.json").write_text(json.dumps(metadata))
            identity, recipient = self.keys(root, "identity.txt")
            backup_crypto.seal(source, root / "large.age", recipient)
            backup_crypto.unseal(root / "large.age", root / "recovered", identity)
            self.assertEqual(
                recovery.digest(root / "recovered/images.tar.gz"),
                metadata["files"]["images.tar.gz"],
            )


if __name__ == "__main__":
    unittest.main()

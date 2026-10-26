from pathlib import Path
import json
import shutil
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_crypto
import recovery
import test_recovery as fixtures


@unittest.skipUnless(
    shutil.which("age") and shutil.which("age-keygen"), "official age tools required"
)
class EncryptionTests(unittest.TestCase):
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
            identity, recipient = self.keys(root, "private-identity.txt")
            encrypted = root / "snapshot.age"
            backup_crypto.seal(source, encrypted, recipient)
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

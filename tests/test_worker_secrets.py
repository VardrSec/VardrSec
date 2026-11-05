"""Native host-only custody of disposable STOP capabilities."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

import worker_secrets as custody


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("VARDRSEC_NATIVE_WORKER_SECRETS") == "1",
    "opt-in VARDRSEC_NATIVE_WORKER_SECRETS=1 requires native Windows Credential Manager",
)
class WindowsSecretTests(unittest.TestCase):
    def test_native_roundtrip_refuses_overwrite_and_retires_only_own_unique_entry(self):
        runtime_id = str(uuid.uuid4())
        store = custody.WindowsSecrets()
        self.assertIsNone(store.read(runtime_id))
        try:
            store.create(runtime_id, "ab" * 32)
            self.assertTrue(store.read(runtime_id) == "ab" * 32)
            with self.assertRaises(custody.SecretRefused):
                store.create(runtime_id, "cd" * 32)
            self.assertTrue(store.read(runtime_id) == "ab" * 32)
        finally:
            store.delete(runtime_id)
        self.assertIsNone(store.read(runtime_id))
        store.delete(runtime_id)

    def test_invalid_identifier_or_secret_never_creates_a_credential(self):
        store = custody.WindowsSecrets()
        with self.assertRaises(custody.SecretRefused):
            store.create("../other", "ab" * 32)
        runtime_id = str(uuid.uuid4())
        with self.assertRaises(custody.SecretRefused):
            store.create(runtime_id, "too-short")
        self.assertIsNone(store.read(runtime_id))


@unittest.skipUnless(
    sys.platform.startswith("linux"),
    "requires native Linux descriptor-relative filesystem",
)
class PosixSecretTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "private"
        self.directory.mkdir(mode=0o700)
        self.store = custody.PosixSecrets(self.directory)
        self.runtime_id = str(uuid.uuid4())
        self.file = self.directory / (self.runtime_id + ".stop")

    def tearDown(self):
        self.temporary.cleanup()

    def test_native_roundtrip_is_exclusive_and_owner_only(self):
        self.assertIsNone(self.store.read(self.runtime_id))
        self.store.create(self.runtime_id, "ab" * 32)
        self.assertTrue(self.store.read(self.runtime_id) == "ab" * 32)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(custody.SecretRefused):
            self.store.create(self.runtime_id, "cd" * 32)
        self.assertTrue(self.store.read(self.runtime_id) == "ab" * 32)
        self.store.delete(self.runtime_id)
        self.assertIsNone(self.store.read(self.runtime_id))

    def test_broad_permissions_and_linked_files_refuse_without_repair(self):
        self.store.create(self.runtime_id, "ab" * 32)
        self.file.chmod(0o644)
        with self.assertRaises(custody.SecretRefused):
            self.store.read(self.runtime_id)
        self.file.chmod(0o600)
        os.link(self.file, self.directory / "other")
        with self.assertRaises(custody.SecretRefused):
            self.store.read(self.runtime_id)

    def test_symlink_and_shared_directory_refuse(self):
        self.directory.chmod(0o755)
        with self.assertRaises(custody.SecretRefused):
            self.store.create(self.runtime_id, "ab" * 32)
        self.directory.chmod(0o700)
        self.file.symlink_to(self.directory / "missing")
        with self.assertRaises(custody.SecretRefused):
            self.store.read(self.runtime_id)
        with self.assertRaises(custody.SecretRefused):
            self.store.create(self.runtime_id, "ab" * 32)

    def test_oversized_or_malformed_file_is_not_a_capability(self):
        self.file.write_bytes(b"a" * 65)
        self.file.chmod(0o600)
        with self.assertRaises(custody.SecretRefused):
            self.store.read(self.runtime_id)


if __name__ == "__main__":
    unittest.main()

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import import_database


class DatabaseExportImport(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.artifact = self.root / "database.tar.age"
        self.artifact.write_bytes(b"test ciphertext")
        self.key = self.root / "identity.txt"
        self.key.write_bytes(b"AGE-SECRET-KEY-1" + b"A" * 58 + b"\n")
        self.receipt = self.root / "from-ci.json"
        self.cache_key = "qualified-db-v1-" + "a" * 64

    def load(self, digest=None):
        sha = digest or hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        import_database.import_database(self.artifact, self.key, sha, self.cache_key, self.receipt)

    def test_wrong_digest_or_plugin_identity_never_reaches_age_or_docker(self):
        with patch.object(import_database, "age", return_value="age"), patch("subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "Ciphertext SHA-256"):
                self.load("0" * 64)
            self.key.write_bytes(b"AGE-PLUGIN-TEST-1EXAMPLE\n")
            with self.assertRaisesRegex(ValueError, "X25519 identity"):
                self.load()
            run.assert_not_called()
        self.assertEqual(set(self.root.iterdir()), {self.artifact, self.key})

    def test_decryption_failure_allows_a_corrected_retry_and_preserves_existing_receipts(self):
        def succeed(command, **kwargs):
            if command[0] == "age":
                self.assertEqual(kwargs["stdin"].read(), self.artifact.read_bytes())
                kwargs["stdout"].write(b"private authenticated tar")
            else:
                self.assertEqual(command[:3], ["bash", "scripts/ci/database_bundle.sh", "import-verified"])
                self.assertEqual(Path(command[3]).read_bytes(), b"private authenticated tar")
                self.assertEqual(Path(command[4]), self.receipt)
                self.assertEqual(kwargs["env"]["CACHE_KEY"], self.cache_key)
                self.receipt.write_text("verified")

        with patch.object(import_database, "age", return_value="age"), patch("subprocess.run") as run:
            run.side_effect = subprocess.CalledProcessError(1, ["age"])
            with self.assertRaises(subprocess.CalledProcessError):
                self.load()
            self.assertEqual(set(self.root.iterdir()), {self.artifact, self.key})
            self.assertEqual(run.call_count, 1)
            run.side_effect = succeed
            self.load()
            self.assertEqual(self.receipt.read_text(), "verified")
            with self.assertRaisesRegex(ValueError, "new receipt path"):
                self.load()
            self.assertEqual(run.call_count, 3)

    @unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "requires official age tools")
    def test_real_recipient_decryption_delivers_original_bytes(self):
        self.key.unlink()
        subprocess.run(["age-keygen", "-o", str(self.key)], check=True, capture_output=True)
        public = subprocess.check_output(["age-keygen", "-y", str(self.key)], text=True).strip()
        plain = b"bundle for one recipient"
        self.artifact.write_bytes(subprocess.check_output(["age", "-r", public], input=plain))
        run = subprocess.run

        def dispatch(command, **kwargs):
            if command[0] == "bash":
                self.assertEqual(Path(command[3]).read_bytes(), plain)
                self.assertEqual(kwargs["env"]["CACHE_KEY"], self.cache_key)
            else:
                return run(command, **kwargs)

        with patch("subprocess.run", side_effect=dispatch) as commands:
            self.load()
        self.assertEqual(commands.call_args.args[0][0], "bash")

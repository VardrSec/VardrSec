"""Offline failure-boundary checks; no crypto tooling, Docker or secrets required."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import nm3_full_preservation as lane


class EncryptedTests(unittest.TestCase):
    def scenario(self, accepts_bad=False, publishes_bad=False):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder); backup = private / 'backup'; backup.mkdir()
            def keygen(args, **kwargs):
                Path(args[-1]).write_text('synthetic-placeholder')
                return SimpleNamespace(returncode=0)
            def seal(source, destination, recipient, **kwargs):
                destination.write_bytes(b'synthetic-ciphertext' * 10)
                destination.chmod(0o600)
            def unseal(package, destination, key):
                if destination.name.startswith('rejected-'):
                    if publishes_bad: destination.mkdir()
                    if accepts_bad: return
                    raise ValueError('synthetic rejection')
                destination.mkdir()
            with patch.object(lane.subprocess, 'run', side_effect=keygen), \
                 patch.object(lane.ci, 'capture', return_value='synthetic-recipient'), \
                 patch.object(lane.backup_crypto, 'seal', side_effect=seal), \
                 patch.object(lane.backup_crypto, 'unseal', side_effect=unseal) as decrypt, \
                 patch.object(lane.recovery, 'validate', return_value={'schema_version': 4}):
                if accepts_bad or publishes_bad:
                    with self.assertRaises(ValueError): lane.encrypted_roundtrip(backup, private)
                    self.assertFalse((private / 'unsealed').exists())
                else:
                    self.assertEqual(lane.encrypted_roundtrip(backup, private), private / 'unsealed')
                    self.assertEqual(decrypt.call_count, 4)
                    self.assertEqual((private / 'truncated.age').stat().st_size,
                                     (private / 'snapshot.age').stat().st_size - 32)
                    self.assertNotEqual((private / 'tampered.age').read_bytes(),
                                        (private / 'snapshot.age').read_bytes())
                    self.assertEqual((private / 'identity.txt').stat().st_mode & 0o777, 0o600)
    def test_success_requires_all_rejections_and_authenticated_bundle(self):
        self.scenario()
    def test_bad_package_accepted_cannot_pass(self):
        self.scenario(accepts_bad=True)
    def test_rejection_with_published_destination_cannot_pass(self):
        self.scenario(publishes_bad=True)

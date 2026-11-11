"""Intentional candidate changes retain an exact, non-tautological baseline guard."""
from pathlib import Path
import tempfile
import unittest

from nm1_source_receipt import verify_distribution_manifest, REVIEWED_DISTRIBUTION_MANIFEST_SHA256

ROOT = Path(__file__).resolve().parents[1]

class SourceReceiptTests(unittest.TestCase):
    def test_current_reviewed_manifest(self):
        self.assertEqual(verify_distribution_manifest(ROOT), REVIEWED_DISTRIBUTION_MANIFEST_SHA256)

    def test_arbitrary_manifest_edit_refused(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            (root / 'versions.json').write_bytes((ROOT / 'versions.json').read_bytes() + b' ')
            with self.assertRaisesRegex(AssertionError, 'reviewed candidate baseline'):
                verify_distribution_manifest(root)

    def test_git_line_ending_normalization(self):
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            (root / 'versions.json').write_bytes((ROOT / 'versions.json').read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
            self.assertEqual(verify_distribution_manifest(root), REVIEWED_DISTRIBUTION_MANIFEST_SHA256)

if __name__ == '__main__':
    unittest.main()

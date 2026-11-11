import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

class Integrity(unittest.TestCase):
    def test_rejects_wrong_archive_before_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root/'wrong.zip'
            archive.write_bytes(b'not the reviewed VM artifact')
            with self.assertRaisesRegex(AssertionError, 'checksum mismatch'):
                prepare.prepare(archive, root, root/'output')
            self.assertFalse((root/'output').exists())

    def test_pin(self):
        self.assertEqual(len(prepare.ARCHIVE_SHA256), 64)
        self.assertEqual(prepare.MERGE, '5a0281ff0e3b6e97432a7c779211ff14c0110c94')

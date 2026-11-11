import hashlib
import pathlib
import tempfile
import unittest
from verify_sources import verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.data = b'exact source bytes\n'
        (self.root / 'source').write_bytes(self.data)
        self.row = {'file': 'source', 'bytes': len(self.data),
                    'sha256': hashlib.sha256(self.data).hexdigest()}

    def test_exact_bytes(self):
        verify(self.root, {'files': [self.row]}, False, None)

    def test_corrupt_bytes_rejected(self):
        (self.root / 'source').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            verify(self.root, {'files': [self.row]}, False, None)

    def test_wrong_git_blob_rejected(self):
        self.row['git_blob'] = '0' * 40
        with self.assertRaises(ValueError):
            verify(self.root, {'files': [self.row]}, False, None)

    def test_keyring_required(self):
        with self.assertRaises(ValueError):
            verify(self.root, {'files': [self.row]}, True, None)

    def test_source_checksum_must_be_in_recipe(self):
        self.row.update(source='example', sha512=hashlib.sha512(self.data).hexdigest())
        recipe = self.root / 'alpine-recipes/example/APKBUILD'
        recipe.parent.mkdir(parents=True)
        recipe.write_text('sha512sums=""\n')
        with self.assertRaises(ValueError):
            verify(self.root, {'files': [self.row]}, False, None)


if __name__ == '__main__':
    unittest.main()

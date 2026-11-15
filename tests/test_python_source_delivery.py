import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from python_source_delivery import collect, inventory, legal_files, write_bundle


def source(name='pkg-1/LICENSE', data=b'MIT text'):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.sbom = json.dumps({'components': [{'purl': 'pkg:pypi/pkg@1', 'version': '1'}]}).encode()
        self.data = source()
        self.metadata = {'info': {'name': 'pkg', 'version': '1'}, 'urls': [
            {'packagetype': 'sdist', 'filename': 'pkg-1.tar.gz',
             'url': 'https://files.pythonhosted.org/pkg-1.tar.gz',
             'digests': {'sha256': hashlib.sha256(self.data).hexdigest()}}]}

    def fetch(self, url):
        return json.dumps(self.metadata).encode() if url.endswith('/json') else self.data

    def test_exact_source_and_notice_retained(self):
        manifest, files = collect(self.sbom, self.fetch)
        self.assertTrue(manifest['complete_sdist_coverage'])
        self.assertFalse(manifest['release_clearance'])
        self.assertEqual(files['pkg/1/source/pkg-1.tar.gz'], self.data)
        self.assertEqual(files['pkg/1/notices/pkg-1/LICENSE'], b'MIT text')

    def test_registry_hash_mismatch_fails_closed(self):
        self.metadata['urls'][0]['digests']['sha256'] = '0' * 64
        manifest, files = collect(self.sbom, self.fetch)
        self.assertFalse(manifest['complete_sdist_coverage'])
        self.assertEqual(manifest['packages'][0]['status'], 'collection_failed')
        self.assertNotIn('pkg/1/source/pkg-1.tar.gz', files)

    def test_missing_source_is_not_approved(self):
        self.metadata['urls'] = []
        manifest, _ = collect(self.sbom, self.fetch)
        self.assertFalse(manifest['complete_sdist_coverage'])
        self.assertEqual(manifest['packages'][0]['status'], 'missing_sdist')

    def test_metadata_identity_must_match(self):
        self.metadata['info']['version'] = '2'
        manifest, _ = collect(self.sbom, self.fetch)
        self.assertEqual(manifest['packages'][0]['status'], 'collection_failed')

    def test_archive_traversal_rejected(self):
        with self.assertRaises(ValueError):
            legal_files(source('../LICENSE'), 'pkg.tar.gz')

    def test_no_license_is_not_legal_clearance(self):
        self.data = source('pkg-1/readme.txt')
        self.metadata['urls'][0]['digests']['sha256'] = hashlib.sha256(self.data).hexdigest()
        manifest, _ = collect(self.sbom, self.fetch)
        self.assertTrue(manifest['complete_sdist_coverage'])
        self.assertEqual(manifest['packages'][0]['notice_review'], 'no_conventional_legal_filename_found')

    def test_stable_bundle_and_no_overwrite(self):
        _, files = collect(self.sbom, self.fetch)
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / 'a.tar', Path(directory) / 'b.tar'
            write_bundle(files, a)
            write_bundle(dict(reversed(list(files.items()))), b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with self.assertRaises(FileExistsError):
                write_bundle(files, a)

    def test_dedup_and_version_validation(self):
        d = json.loads(self.sbom)
        d['components'] *= 2
        self.assertEqual(inventory(d), [('pkg', '1')])
        d['components'][0]['version'] = '2'
        with self.assertRaises(ValueError):
            inventory(d)

if __name__ == '__main__':
    unittest.main()

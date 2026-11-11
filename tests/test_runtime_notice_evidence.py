import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import runtime_notice_evidence as evidence

IMAGE = 'sha256:' + 'a' * 64
REV = 'b' * 40
NATIVE = 'usr/local/lib/python3.12/site-packages/psycopg_binary.libs/libpq-test.so.5.18'
SHARP = 'app/node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.8.18.7'


def export(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                entry.type, entry.linkname = data
                archive.addfile(entry)
            else:
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
    stream.seek(0)
    return stream


def collect(entries):
    return evidence.collect(export(entries), IMAGE, 'api', REV)


class RuntimeNoticeTests(unittest.TestCase):
    def test_allowlist_retains_legal_text_only_and_hashes_native(self):
        m, files = collect([
            ('app/node_modules/example/LICENSE.md', b'MIT'),
            ('usr/share/doc/libfoo/copyright', b'copyright'),
            (NATIVE, b'native-code'), (SHARP, b'vips-code'),
            ('root/.ssh/LICENSE', b'private'), ('app/.env', b'private'),
            ('app/node_modules/example/package.json', b'private'),
            ('usr/local/lib/python3.12/site-packages/foo-1.dist-info/METADATA', b'private')])
        self.assertEqual(m['notice_count'], 2)
        self.assertEqual(m['native_file_count'], 2)
        self.assertEqual(len(files), 3)
        self.assertFalse(m['release_clearance'])
        self.assertFalse(m['coverage_complete'])
        self.assertEqual(m['native_files'][1]['sha256'], hashlib.sha256(b'native-code').hexdigest())
        self.assertNotIn(b'native-code', files.values())
        self.assertNotIn(b'private', files.values())

    def test_modified_native_package_payloads_are_hashed_not_retained(self):
        names = ['usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14',
                 'usr/lib/x86_64-linux-gnu/libpcap.so.1.10.7']
        m, files = collect([(name, b'payload') for name in names] +
                           [('usr/lib/other.so.1.2', b'not-selected')])
        self.assertEqual(m['native_file_count'], 2)
        self.assertEqual({entry['path'] for entry in m['native_files']}, set(names))
        self.assertNotIn(b'payload', files.values())
        self.assertNotIn(b'not-selected', files.values())

    def test_site_packages_legal_text_and_root_app_license(self):
        m, _ = collect([('usr/local/lib/python3.12/site-packages/foo-1.dist-info/licenses/LICENSE', b'text'),
                        ('app/LICENSE', b'AGPL')])
        self.assertEqual(m['notice_count'], 2)

    def test_untrusted_links_are_not_followed_or_targets_recorded(self):
        m, files = collect([('usr/share/doc/foo/copyright', (tarfile.SYMTYPE, '/private/file')),
                            (NATIVE, (tarfile.LNKTYPE, 'secret'))])
        self.assertEqual(len(m['unresolved_selected_entries']), 2)
        self.assertEqual(len(files), 1)
        self.assertNotIn('secret', json.dumps(m))
        self.assertNotIn('/private/file', json.dumps(m))

    def test_unsafe_paths_rejected_even_if_unselected(self):
        for path in ('../secret', '/etc/passwd', 'app/../secret', 'app\\secret'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                collect([(path, b'')])

    def test_duplicates_after_normalization_rejected(self):
        with self.assertRaises(ValueError):
            collect([('./app/LICENSE', b'a'), ('app/LICENSE', b'b')])

    def test_individual_and_total_limits(self):
        with patch.object(evidence, 'MAX_NOTICE', 1), self.assertRaises(ValueError):
            collect([('app/LICENSE', b'12')])
        with patch.object(evidence, 'MAX_NOTICES_TOTAL', 2), self.assertRaises(ValueError):
            collect([('app/LICENSE', b'12'), ('app/NOTICE', b'3')])
        with patch.object(evidence, 'MAX_NATIVE', 1), self.assertRaises(ValueError):
            collect([(NATIVE, b'12')])
        with patch.object(evidence, 'MAX_SELECTED', 1), self.assertRaises(ValueError):
            collect([('app/LICENSE', b'1'), ('app/NOTICE', b'2')])

    def test_compressed_notice_is_opaque_not_inspected(self):
        m, files = collect([('usr/share/doc/foo/copyright.gz', b'not decompressed')])
        self.assertEqual(m['notices'][0]['representation'], 'opaque_archive')
        self.assertFalse(m['notices'][0]['content_reviewed'])
        self.assertEqual(files['notices/usr/share/doc/foo/copyright.gz'], b'not decompressed')

    def test_context_rejected(self):
        for args in [('tag:latest', 'api', REV), (IMAGE, 'private', REV), (IMAGE, 'api', 'main')]:
            with self.assertRaises(ValueError):
                evidence.collect(export([]), *args)

    def test_native_selector_is_narrow(self):
        for name in ('root/psycopg_binary.libs/libpq.so.5', 'app/node_modules/other/binary.so',
                     'usr/local/lib/python3.12/site-packages/psycopg_binary.libs/secret.txt'):
            self.assertIsNone(evidence.selection(name))

    def test_reproducible_serialization_no_overwrite(self):
        _, files1 = collect([('app/LICENSE', b'a'), ('app/NOTICE', b'b')])
        _, files2 = collect([('app/NOTICE', b'b'), ('app/LICENSE', b'a')])
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / 'a', Path(directory) / 'b'
            evidence.write_bundle(files1, a)
            evidence.write_bundle(files2, b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with self.assertRaises(FileExistsError):
                evidence.write_bundle(files1, a)

    def test_truncated_selected_file_fails(self):
        raw = export([('app/LICENSE', b'x' * 4096)]).getvalue()
        with self.assertRaises((tarfile.ReadError, ValueError)):
            evidence.collect(io.BytesIO(raw[:600]), IMAGE, 'api', REV)

if __name__ == '__main__':
    unittest.main()


class GeneratedGoLegalNamesTests(unittest.TestCase):
    def test_generated_notice_names_are_scoped_to_license_root(self):
        from runtime_notice_evidence import selection
        self.assertEqual(selection('usr/share/licenses/caddy/GO-LICENSE'), 'notice')
        self.assertEqual(selection('usr/share/licenses/gosu/dependency-notices.tar.gz'), 'notice')
        self.assertIsNone(selection('app/private/dependency-notices.tar.gz'))
        self.assertEqual(selection('opt/vardrtools/provenance/nuclei/openpgp-LICENSE'), 'notice')
        self.assertEqual(selection('opt/vardrtools/provenance/httpx/dependency-notices.tar.gz'), 'notice')
        self.assertIsNone(selection('opt/vardrtools/credentials/GO-LICENSE'))

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from libxml2_runtime_custody import API_PATCHES, API_SOURCES, LIBRARY, REQUIRED, sha, verify

IMAGE = 'sha256:' + 'a' * 64
REVISION = 'b' * 40


class RuntimeCustodyTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.source = self.root / 'source'
        (self.source / 'evidence').mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parents[1] / 'db/libxml2-CVE-2026-6653.patch',
                        self.source / 'CVE-2026-6653.patch')
        patch_names = ['vardr-CVE-2026-6653.patch']
        for patch in API_PATCHES:
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'db' / patch, self.source / patch)
            patch_names.append(patch.replace('libxml2-', 'vardr-'))
        (self.source / 'evidence/applied-patches.txt').write_text('\n'.join(patch_names) + '\n')
        (self.source / 'evidence/patched-source-SHA256SUMS').write_text(''.join(
            f'{digest}  {name}\n' for name, digest in API_SOURCES.items()))
        self.api_report = self.source / 'evidence/dictionary-xinclude-checks.txt'
        self.api_report.write_text('dictionary tests succeeded 20000 strings\n' + ''.join(
            f'api={api} noblanks={flag} verdict=PASS\n'
            for api in ('document', 'tree') for flag in (0, 1)))
        self.regression = self.source / 'evidence/entity-amplification-regression.txt'
        self.regression.write_text(''.join(
            f'case={case} huge={huge} verdict=PASS\n'
            for case in ('100000-byte-control', '20736000-byte-amplification')
            for huge in (0, 1)))
        self.digest = hashlib.sha256(b'regression-tested-library').hexdigest()
        (self.source / 'evidence/entity-regression-library-SHA256SUMS').write_text(
            f'{self.digest}  {LIBRARY}\n')
        self.seal()
        self.manifest = {'schema': 'vardr.runtime-notice-evidence/1', 'service': 'db',
                         'image_id': IMAGE, 'distribution_commit': REVISION,
                         'component_inventory_export_completed': True,
                         'native_files': [{'path': LIBRARY, 'sha256': self.digest}]}
        self.runtime = self.root / 'runtime.tar'
        self.bundle()

    def seal(self):
        (self.source / 'SHA256SUMS').write_text(''.join(
            f'{sha(self.source / name)}  ./{name}\n' for name in sorted(REQUIRED)))

    def bundle(self, duplicate=False):
        data = json.dumps(self.manifest).encode()
        with tarfile.open(self.runtime, 'w') as archive:
            for _ in range(2 if duplicate else 1):
                member = tarfile.TarInfo('manifest.json')
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def check(self):
        return verify(self.source, self.runtime, IMAGE, REVISION)

    def test_matches_tested_payload_without_granting_clearance(self):
        receipt = self.check()
        self.assertEqual(receipt['library_sha256'], self.digest)
        self.assertEqual(receipt['image_id'], IMAGE)
        self.assertFalse(receipt['release_clearance'])
        self.assertFalse(receipt['vulnerability_gate_changed'])

    def test_replaced_missing_and_duplicate_runtime_library_refused(self):
        original = self.manifest['native_files'][0].copy()
        for rows in ([{**original, 'sha256': 'c' * 64}], [], [original, original]):
            with self.subTest(rows=rows):
                self.manifest['native_files'] = rows
                self.bundle()
                with self.assertRaisesRegex(ValueError, 'differs from regression-tested'):
                    self.check()

    def test_wrong_image_revision_service_and_incomplete_export_refused(self):
        for field, wrong in [('image_id', 'sha256:' + 'c' * 64),
                             ('distribution_commit', 'c' * 40), ('service', 'api'),
                             ('component_inventory_export_completed', False)]:
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = wrong
                self.bundle()
                with self.assertRaisesRegex(ValueError, 'identity or completed-export'):
                    self.check()
                self.manifest[field] = original

    def test_tampered_source_and_resealed_unreviewed_patch_refused(self):
        patch = self.source / 'CVE-2026-6653.patch'
        patch.write_bytes(b'unreviewed patch')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.check()
        self.seal()
        with self.assertRaisesRegex(ValueError, 'Unreviewed backport'):
            self.check()

    def test_resealed_missing_or_failed_regression_cases_refused(self):
        original = self.regression.read_text()
        for content in (original.replace('verdict=PASS', 'verdict=FAIL', 1),
                        '\n'.join(original.splitlines()[:-1]) + '\n'):
            with self.subTest(content=content):
                self.regression.write_text(content)
                self.seal()
                with self.assertRaisesRegex(ValueError, 'bounded entity regression'):
                    self.check()

    def test_resealed_missing_patch_ledger_refused(self):
        (self.source / 'evidence/applied-patches.txt').write_text('unrelated.patch\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'applied patch ledger'):
            self.check()

    def test_resealed_incomplete_api_checks_and_replaced_sources_refused(self):
        original = self.api_report.read_text()
        self.api_report.write_text('\n'.join(original.splitlines()[:-1]) + '\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'Incomplete dictionary'):
            self.check()
        self.api_report.write_text(original)
        (self.source / 'evidence/patched-source-SHA256SUMS').write_text('0' * 64 + '  dict.c\n')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'source differs'):
            self.check()

    def test_historical_receipt_is_scoped_and_current_ci_requires_api_checks(self):
        sums = self.source / 'SHA256SUMS'
        sums.write_text(''.join(line for line in sums.read_text().splitlines(True)
                                if 'dictionary-xinclude-checks' not in line))
        self.assertFalse(self.check()['dictionary_and_xinclude_api_checks'])
        with self.assertRaisesRegex(ValueError, 'Incomplete source evidence'):
            verify(self.source, self.runtime, IMAGE, REVISION, require_api_checks=True)

    def test_duplicate_manifest_and_unsafe_checksum_paths_refused(self):
        self.bundle(duplicate=True)
        with self.assertRaisesRegex(ValueError, 'unsafe runtime manifest'):
            self.check()
        self.bundle()
        with (self.source / 'SHA256SUMS').open('a') as stream:
            stream.write('c' * 64 + '  ../outside\n')
        with self.assertRaisesRegex(ValueError, 'Unsafe source evidence path'):
            self.check()


if __name__ == '__main__':
    unittest.main()

"""No network or compiled code: exercise inert notice/source packaging."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/release/canonical_module_archive.sh'

class CanonicalModuleArchives(unittest.TestCase):
    def test_build_context_helpers_match_canonical_copy(self):
        root = SCRIPT.parents[2]
        for context in ('db', 'proxy'):
            self.assertEqual((root / context / 'canonical_module_archive.sh').read_bytes(), SCRIPT.read_bytes())

    def run_archive(self, mode, root, output, success=True):
        result = subprocess.run(['bash', str(SCRIPT), mode, str(root), str(output)], capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stderr.decode())

    def test_notices_are_byte_identical_with_preserved_content(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            expected = {'./module/LICENSE': b'legal text\x00\n', './module/LICENCE': b'British spelling', './module/NOTICE with spaces': b'notice'}
            outputs = []
            for n in (1, 2):
                root = base / str(n)
                (root / 'module').mkdir(parents=True)
                for name, data in list(expected.items())[::1 if n == 1 else -1]:
                    p = root / name
                    p.write_bytes(data)
                    os.chmod(p, 0o400 if n == 1 else 0o755)
                    os.utime(p, (1000 * n, 1000 * n))
                (root / 'module/not-selected').write_bytes(b'not legal material')
                output = base / f'{n}.tar.gz'
                self.run_archive('notices', root, output)
                outputs.append(output.read_bytes())
                with tarfile.open(output) as archive:
                    self.assertEqual(archive.getnames(), sorted(expected))
                    for member in archive:
                        self.assertEqual(archive.extractfile(member).read(), expected[member.name])
                        self.assertEqual((member.mtime, member.uid, member.gid, member.mode), (0, 0, 0, 0o644))
            self.assertEqual(outputs[0], outputs[1])

    def test_hardlink_layout_does_not_change_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            outputs = []
            for n in (1, 2):
                root = base / str(n)
                root.mkdir()
                (root / 'LICENSE').write_bytes(b'same content')
                if n == 1:
                    (root / 'NOTICE').write_bytes(b'same content')
                else:
                    os.link(root / 'LICENSE', root / 'NOTICE')
                out = base / f'{n}.tar'
                self.run_archive('notices', root, out)
                outputs.append(out.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_sources_preserve_long_paths_and_binary_zip_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / 'source'
            module = root / ('x' * 110)
            module.mkdir(parents=True)
            for name in ('v1.zip', 'v1.mod', 'v1.info', 'v1.ziphash'):
                (module / name).write_bytes(b'unchanged\x00\xff' + name.encode())
            (module / 'lock').write_text('excluded')
            output = base / 'source.tar'
            self.run_archive('sources', root, output)
            with tarfile.open(output) as archive:
                self.assertEqual(len(archive.getmembers()), 4)
                for member in archive:
                    self.assertEqual(archive.extractfile(member).read(), (root / member.name).read_bytes())

    def test_refuses_overwrite_and_output_inside_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / 'source'
            root.mkdir()
            out = base / 'old.tar'
            out.write_bytes(b'keep me')
            self.run_archive('sources', root, out, False)
            self.assertEqual(out.read_bytes(), b'keep me')
            self.run_archive('sources', root, root / 'archive.tar', False)

if __name__ == '__main__':
    unittest.main()

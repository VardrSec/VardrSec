import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('finalize',ROOT/'db/kerberos-vm/finalize.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class Finalize(unittest.TestCase):
    def fixture(self, root, *, seeded=False):
        work=root/'work';out=root/'out';helper=root/'helper'
        (work/'result-build/packages').mkdir(parents=True);(work/'result-build/source').mkdir();(work/'result-build/vm').mkdir();helper.mkdir();out.mkdir()
        receipt={'full_debian_package_build_passed':True,'offline_build_boot':True,'distribution_commit':None,'source_inputs_sha256':'a'*64}
        if seeded:
            receipt['compiler_cache_sha256'] = 'c' * 64
        (work/'verified.json').write_text(json.dumps(receipt))
        for name in ('qualification-inputs.json','prepared-disk.sha256','prepare-command.json','build-command.json'):(work/name).write_text('fixture')
        for name in ('prepared-packages.txt','keyring-prerequisite.txt'):(work/'result-build/vm'/name).write_text('fixture')
        (work/'result-build/vm/build.exit').write_text('0')
        for name in ('run.py', 'guest.sh', 'inputs.json', 'finalize.py',
                     'build-deps.sh', 'compiler-cache.sh', 'seed.sh'):
            (helper / name).write_text(name)
        pins=[]
        for i in range(4):
            data=f'package{i}'.encode();name=f'lib{i}.deb';(work/'result-build/packages'/name).write_bytes(data);pins.append(f'{hashlib.sha256(data).hexdigest()}  {name}')
        (helper/'qualified-packages.sha256').write_text('\n'.join(pins))
        (work/'result-build/source/source.txt').write_text('source')
        (work/'result-build/source/SHA256SUMS').write_text(hashlib.sha256(b'source').hexdigest()+'  ./source.txt\n')
        return work,out,helper

    def test_verified_bytes_and_builder_source_delivered(self):
        with tempfile.TemporaryDirectory() as d:
            w,o,h=self.fixture(Path(d))
            with patch.object(f,'HERE',h):f.finalize(w,o)
            self.assertEqual(len(list((o/'packages').iterdir())),4)
            self.assertTrue((o/'source/vm-builder/verified.json').exists())
            builder = o / 'source/vm-builder'
            for name in ('build-deps.sh', 'compiler-cache.sh', 'seed.sh'):
                self.assertEqual((builder / name).read_text(), name)
            self.assertFalse((builder / 'compiler-cache-stats.txt').exists())
            for line in (o/'source/SHA256SUMS').read_text().splitlines():
                digest,name=line.split(None,1);self.assertEqual(f.digest(o/'source'/name),digest)

    def test_compiler_cache_evidence_is_included_in_the_source_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            work, out, helper = self.fixture(Path(d), seeded=True)
            stats = work / 'result-build/vm/compiler-cache-stats.txt'
            stats.write_text('remote_storage_hit 3\n')
            with patch.object(f, 'HERE', helper):
                f.finalize(work, out)
            builder = out / 'source/vm-builder'
            self.assertEqual(json.loads((builder / 'verified.json').read_text())['compiler_cache_sha256'], 'c' * 64)
            self.assertEqual((builder / stats.name).read_bytes(), stats.read_bytes())
            ledger = (out / 'source/SHA256SUMS').read_text().splitlines()
            self.assertIn(f'{f.digest(stats)}  ./vm-builder/{stats.name}', ledger)

    def test_changed_binary_rejected(self):
        for seeded in (False, True):
            with self.subTest(seeded=seeded), tempfile.TemporaryDirectory() as d:
                work, out, helper = self.fixture(Path(d), seeded=seeded)
                (work / 'result-build/packages/lib0.deb').write_bytes(b'changed')
                with patch.object(f, 'HERE', helper), self.assertRaisesRegex(AssertionError, 'package bytes changed'):
                    f.finalize(work, out)
                self.assertFalse((out / 'packages').exists())

    def test_failed_guest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            w,o,h=self.fixture(Path(d));(w/'result-build/vm/build.exit').write_text('1')
            with patch.object(f,'HERE',h),self.assertRaises(AssertionError):f.finalize(w,o)

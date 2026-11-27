import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2] / 'db/kerberos-vm'
spec = importlib.util.spec_from_file_location('krb_vm', ROOT / 'run.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class HarnessTests(unittest.TestCase):
    def test_offline_second_boot_has_no_forwarding_or_host_share(self):
        work = Path('/fresh')
        for source_only in (False, True):
            with self.subTest(source_only=source_only):
                command = vm.qemu_command(work, 'build', source_only=source_only)
                self.assertEqual(command[-2:], ['-nic', 'none'])
                self.assertIn(f'file={work / "inputs.iso"},media=cdrom,format=raw,readonly=on', command)
                joined = ' '.join(command)
                for forbidden in ('hostfwd', '-virtfs', '-enable-kvm', 'unconfined', 'seccomp=off'):
                    self.assertNotIn(forbidden, joined)
                self.assertIn('tcg,thread=multi', command)
                self.assertIn('4096', command)

    def test_prepare_network_is_only_default_user_network(self):
        self.assertEqual(vm.qemu_command(Path('/fresh'), 'prepare')[-1], 'user,model=virtio-net-pci')
        with self.assertRaises(ValueError):
            vm.qemu_command(Path('/fresh'), 'other')

    def test_source_build_cpu_budget_requires_spare_capacity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / 'builder' / 'job'
            job.mkdir(parents=True)
            (root / 'cgroup.controllers').write_text('cpu')
            membership = root / 'membership'
            membership.write_text('0::/builder/job\n')
            (job / 'cpu.max').write_text('max 100000')
            for affinity, parent_limit, expected in (
                    (4, 'max 100000', 2), (8, 'max 100000', 4),
                    (12, '800000 100000', 4), (12, '799999 100000', 2),
                    (8, 'broken', 2)):
                with self.subTest(affinity=affinity, parent_limit=parent_limit):
                    (job.parent / 'cpu.max').write_text(parent_limit)
                    with patch.object(vm.os, 'sched_getaffinity', return_value=range(affinity), create=True):
                        self.assertEqual(vm.source_build_cpus(root, membership), expected)
            membership.write_text('0::/\n')
            with patch.object(vm.os, 'sched_getaffinity', return_value=range(8), create=True):
                # Missing capacity data and fully visible container quotas.
                self.assertEqual(vm.source_build_cpus(root, membership), 2)
                (root / 'cpu.max').write_text('400000 100000')
                self.assertEqual(vm.source_build_cpus(root, membership), 2)
                (root / 'cpu.max').write_text('max 100000')
                self.assertEqual(vm.source_build_cpus(root, membership), 4)
                membership.write_text('2:cpu:/\n')
                self.assertEqual(vm.source_build_cpus(root, membership), 2)

    def test_only_source_build_boot_uses_available_capacity(self):
        with patch.object(vm, 'source_build_cpus', return_value=4) as budget:
            for phase, source_only, expected in (
                    ('prepare', True, 2), ('build', False, 2), ('build', True, 4)):
                command = vm.qemu_command(Path('/fresh'), phase, source_only=source_only)
                self.assertEqual(command[command.index('-smp') + 1], str(expected))
                self.assertEqual(command[command.index('-m') + 1], '4096')
            budget.assert_called_once_with()

    def test_checksum_and_plain_http_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'bytes'
            path.write_bytes(b'fixture')
            self.assertEqual(len(vm.sha(path)), 64)
            self.assertEqual(len(vm.sha(path, 'sha512')), 128)
            with self.assertRaises(ValueError):
                vm.download('http://example.invalid/', Path(d) / 'download')

    def test_already_downloaded_sources_must_match_the_pin(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / 'upstream.dsc'
            source.write_bytes(b'checked source')
            inputs = {'source_base': 'https://example.invalid/', 'sources': {source.name: vm.sha(source)}}
            build = root / 'build'
            build.mkdir()
            with patch.object(vm, 'download') as download:
                vm.copy_sources(inputs, build, root)
                self.assertEqual((build / source.name).read_bytes(), b'checked source')
                (build / source.name).unlink()
                source.write_bytes(b'tampered source')
                with self.assertRaisesRegex(ValueError, 'Pinned checksum mismatch'):
                    vm.copy_sources(inputs, build, root)
                download.assert_not_called()

    def test_only_a_completed_compiler_seed_is_staged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            native = root / 'native-inputs'
            native.mkdir()
            iso = root / 'input'
            iso.mkdir()
            self.assertIsNone(vm.stage_compiler_cache(None, iso))
            cache = native / 'compiler-cache'
            cache.mkdir()
            blob = cache / 'object'
            blob.write_bytes(b'compiled object')
            self.assertIsNone(vm.stage_compiler_cache(native, iso))
            self.assertEqual(list(iso.iterdir()), [])

            manifest = native / 'compiler-cache.sha256'
            manifest.write_bytes(f'{vm.sha(blob)}  ./object\n'.encode())
            self.assertEqual(vm.stage_compiler_cache(native, iso), vm.sha(manifest))
            self.assertEqual((iso / manifest.name).read_bytes(), manifest.read_bytes())
            self.assertEqual((iso / 'compiler-cache/object').read_bytes(), blob.read_bytes())

            second_iso = root / 'second-input'
            second_iso.mkdir()
            blob.write_bytes(b'changed object')
            with self.assertRaisesRegex(ValueError, 'Compiler cache checksum mismatch'):
                vm.stage_compiler_cache(native, second_iso)
            self.assertFalse((second_iso / manifest.name).exists())

    def test_standalone_qualification_rejects_native_build_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / 'work'
            argv = ['run.py', '--work', str(work), '--native-inputs', d]
            with patch.object(sys, 'argv', argv), patch.object(sys, 'stderr', new_callable=io.StringIO), \
                    patch.object(vm, 'download') as download, self.assertRaises(SystemExit) as error:
                vm.main()
            self.assertEqual(error.exception.code, 2)
            download.assert_not_called()

    def test_explicit_failed_guest_verdict_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            with patch.object(vm, 'run'):
                with self.assertRaises(RuntimeError):
                    vm.extract(work, 'build')

    def test_nonzero_guest_verdict_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            def fake_extract(*args):
                output = work / 'result-build' / 'vm'
                output.mkdir()
                (output / 'build.exit').write_text('1\n')
            with patch.object(vm, 'run', side_effect=fake_extract):
                with self.assertRaises(RuntimeError):
                    vm.extract(work, 'build')

    def test_unchanged_source_and_checks_required(self):
        guest = (ROOT / 'guest.sh').read_text()
        self.assertIn('sh /build/build-krb5.sh', guest)
        self.assertIn('keyctl add user', guest)
        self.assertIn('keyctl pipe', guest)
        self.assertNotIn('nocheck', guest)
        self.assertNotIn('seccomp', guest)
        self.assertIn('INPUT-SHA256SUMS', guest)
        inputs = json.loads((ROOT / 'inputs.json').read_text())
        self.assertEqual(len(inputs['image_sha512']), 128)
        self.assertEqual(set(inputs['sources']), {
            'krb5_1.21.3.orig.tar.gz', 'krb5_1.21.3.orig.tar.gz.asc',
            'krb5_1.21.3-5+deb13u2.dsc', 'krb5_1.21.3-5+deb13u2.debian.tar.xz',
        })


class BuildContextTests(unittest.TestCase):
    def test_source_build_uses_guest_without_security_bypass(self):
        dockerfile = (ROOT.parent / 'Dockerfile').read_text()
        self.assertIn('USER 65534:65534',dockerfile)
        self.assertIn('--source-only --work /work/qualification',dockerfile)
        self.assertIn('kerberos-vm/finalize.py',dockerfile)
        stages = re.split(r'(?im)^[ \t]*FROM[ \t]+', dockerfile)[1:]
        krb5_stages = [stage for stage in stages
                       if stage.partition('\n')[0].lower().split()[-2:] == ['as', 'krb5-backport']]
        self.assertEqual(len(krb5_stages), 1, 'expected one krb5-backport stage')
        self.assertNotIn('nocheck', krb5_stages[0])
        for forbidden in ('--privileged', 'seccomp=unconfined', '--security=insecure'):
            self.assertNotIn(forbidden,dockerfile)
        self.assertNotIn('distribution_commit\': revision,', (ROOT/'run.py').read_text())


if __name__ == '__main__':
    unittest.main()

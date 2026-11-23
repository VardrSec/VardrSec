import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2] / 'db/kerberos-vm'
spec = importlib.util.spec_from_file_location('krb_vm', ROOT / 'run.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class HarnessTests(unittest.TestCase):
    def test_offline_second_boot_has_no_forwarding_or_host_share(self):
        command = vm.qemu_command(Path('/fresh'), 'build')
        self.assertEqual(command[-2:], ['-nic', 'none'])
        joined = ' '.join(command)
        for forbidden in ('hostfwd', '-virtfs', '-enable-kvm', 'unconfined', 'seccomp=off'):
            self.assertNotIn(forbidden, joined)
        self.assertIn('tcg,thread=multi', command)
        self.assertIn('4096', command)

    def test_prepare_network_is_only_default_user_network(self):
        self.assertEqual(vm.qemu_command(Path('/fresh'), 'prepare')[-1], 'user,model=virtio-net-pci')
        with self.assertRaises(ValueError):
            vm.qemu_command(Path('/fresh'), 'other')

    def test_build_cpu_count_honors_affinity_and_nested_v2_quotas(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / 'builder' / 'job'
            child.mkdir(parents=True)
            membership = root / 'membership'
            membership.write_text('0::/builder/job')
            (root / 'cgroup.controllers').write_text('cpu')
            (child / 'cpu.max').write_text('max 100000')
            for affinity, parent_limit, expected in (
                    (8, 'max 100000', 4), (4, '400000 100000', 4),
                    (8, '399999 100000', 2), (3, 'max 100000', 2),
                    (8, 'bad quota', 2)):
                with self.subTest(affinity=affinity, parent_limit=parent_limit):
                    (child.parent / 'cpu.max').write_text(parent_limit)
                    with patch.object(vm.os, 'sched_getaffinity', return_value=range(affinity), create=True):
                        self.assertEqual(vm.docker_build_cpus(root, membership), expected)
            with patch.object(vm.os, 'sched_getaffinity', return_value=range(8), create=True):
                membership.write_text('0::/')
                self.assertEqual(vm.docker_build_cpus(root, membership), 4)
                (root / 'cpu.max').write_text('200000 100000')
                self.assertEqual(vm.docker_build_cpus(root, membership), 2)
                membership.write_text('0::/missing')
                self.assertEqual(vm.docker_build_cpus(root, membership), 2)

    def test_build_cpu_count_honors_legacy_cpu_quota(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cpu = root / 'cpu,cpuacct'
            cpu.mkdir()
            membership = root / 'membership'
            membership.write_text('5:cpu,cpuacct:/')
            (cpu / 'cpu.cfs_period_us').write_text('100000')
            with patch.object(vm.os, 'sched_getaffinity', return_value=range(8), create=True):
                for quota, expected in (('-1', 4), ('400000', 4), ('350000', 2)):
                    with self.subTest(quota=quota):
                        (cpu / 'cpu.cfs_quota_us').write_text(quota)
                        self.assertEqual(vm.docker_build_cpus(root, membership), expected)

    def test_guest_cpu_and_memory_budget(self):
        for phase, cpus in (('prepare', 2), ('build', 2), ('build', 4)):
            command = vm.qemu_command(Path('/fresh'), phase, cpus) if cpus == 4 else vm.qemu_command(Path('/fresh'), phase)
            self.assertEqual(command[command.index('-smp') + 1], str(cpus))
            self.assertEqual(command[command.index('-m') + 1], '4096')

    def test_checksum_and_plain_http_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'bytes'
            path.write_bytes(b'fixture')
            self.assertEqual(len(vm.sha(path)), 64)
            self.assertEqual(len(vm.sha(path, 'sha512')), 128)
            with self.assertRaises(ValueError):
                vm.download('http://example.invalid/', Path(d) / 'download')

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
        self.assertEqual(len(inputs['sources']), 3)


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

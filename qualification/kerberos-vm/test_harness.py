import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
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


if __name__ == '__main__':
    unittest.main()

"""Generate a real bundle; run its restore in an isolated interpreter with fake I/O."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery


class PortableRecoveryTests(unittest.TestCase):
    def test_generated_bundle_restores_without_checkout_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            repository = Path(recovery.__file__).parent
            for name in recovery.FULL_FILES:
                data = (b'POSTGRES_APP_PASSWORD=' + b'a' * 64 + b'\n'
                        if name == '.env' else (repository / name).read_bytes())
                (source / name).write_bytes(data)
            configuration = {'name': 'synthetic', 'services': {
                service: {'environment': {name: 'synthetic' for name in names}}
                for service, names in recovery.PERSISTED_ENV.items()}}
            def container(_root, service):
                return {'Image': 'sha256:' + 'a' * 64,
                        'Config': {'Env': [name + '=synthetic' for name in
                                          recovery.PERSISTED_ENV.get(service, ())]}}
            def archive(_image, _volume, _operation, output):
                with tarfile.open(fileobj=output, mode='w:gz') as tar:
                    item = tarfile.TarInfo('synthetic')
                    item.size = 4
                    tar.addfile(item, io.BytesIO(b'test'))
            process = MagicMock()
            process.__enter__.return_value = process
            process.stdout = io.BytesIO(b'synthetic image archive')
            process.wait.return_value = 0
            bundle = root / 'bundle'
            with patch.object(recovery, 'compose', return_value=subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(configuration))), \
                 patch.object(recovery, 'container', side_effect=container), \
                 patch.object(recovery, 'command', return_value=subprocess.CompletedProcess([], 0, stdout='')), \
                 patch.object(recovery, 'volume_name', return_value='synthetic'), \
                 patch.object(recovery, 'volume_stream', side_effect=archive), \
                 patch.object(recovery, 'volume_fingerprint', return_value='synthetic-volume'), \
                 patch.object(recovery, 'database_fingerprint', return_value='synthetic-database'), \
                 patch.object(recovery.subprocess, 'Popen', return_value=process):
                recovery.backup(source, bundle)
            metadata = recovery.validate(bundle)
            self.assertEqual(metadata['schema_version'], 5)
            self.assertEqual((bundle / 'database_roles.py').read_bytes(),
                             (repository / 'database_roles.py').read_bytes())
            # -I excludes PYTHONPATH/cwd/site-user imports. Only this generated
            # bundle is added; no checkout path is supplied to the child.
            script = r'''
import io, json, pathlib, sys
from unittest.mock import MagicMock, patch
bundle = pathlib.Path.cwd()
sys.path.insert(0, str(bundle))
import recovery, database_roles, updater, backup_crypto, vardrsec, installation_mode
for module in (recovery, database_roles, updater, backup_crypto, vardrsec, installation_mode):
    assert pathlib.Path(module.__file__).parent == bundle
assert 'database_roles.py' in backup_crypto.ALLOWED
process = MagicMock()
process.__enter__.return_value = process
process.stdin = io.BytesIO()
process.wait.return_value = 0
metadata = recovery.validate(bundle)
restored = bundle.parent / 'restored'
# Real restore copies the generated files, validates archives, reads config,
# imports/calls restore_role, and writes its receipt. Every Docker boundary is mocked.
with patch.object(recovery, 'command') as command, \
     patch.object(recovery, 'compose'), \
     patch.object(recovery, 'container'), \
     patch.object(recovery, 'volume_name', return_value='synthetic'), \
     patch.object(recovery, 'volume_stream'), \
     patch.object(recovery, 'volume_fingerprint', return_value='synthetic-volume'), \
     patch.object(recovery, 'database_fingerprint', return_value='synthetic-database'), \
     patch.object(recovery.subprocess, 'Popen', return_value=process), \
     patch.object(database_roles, 'apply') as apply:
    command.return_value.stdout = ''
    recovery.restore(bundle, bundle, restored, 'vardrsec-restore-portable')
    # Windows TEMP may use its 8.3 alias; restore deliberately resolves its root.
    apply.assert_called_once_with(restored.resolve(), 'vardrsec-restore-portable', restoring=True)
assert (restored / 'database_roles.py').read_bytes() == (bundle / 'database_roles.py').read_bytes()
assert json.loads((restored / 'restore-receipt.json').read_text())['database_verified'] is True
assert recovery.validate(bundle) == metadata
'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script],
                                    cwd=bundle, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

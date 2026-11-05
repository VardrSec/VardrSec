"""Legacy pending-update cancellation with real manifests and mocked Docker only."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import recovery
import updater
import test_recovery as fixtures


class SnapshotVersionUpdateTests(unittest.TestCase):
    def fixture(self, root, version):
        backup = root / 'backup'
        backup.mkdir()
        fixtures.RecoveryTests().snapshot(backup)
        metadata = json.loads((backup / 'snapshot.json').read_text())
        scripts = {1: recovery.LEGACY_FILES, 2: recovery.UPDATE_FILES,
                   3: recovery.CRYPTO_FILES, 4: recovery.FILES}[version]
        for name in set(recovery.FILES) - set(scripts):
            metadata['files'].pop(name)
        metadata.update(schema_version=version, database='synthetic-database')
        (backup / 'snapshot.json').write_text(json.dumps(metadata))
        for name in scripts:
            (root / name).write_bytes((backup / name).read_bytes())
        record = {'phase': 'rehearsal', 'project': 'synthetic', 'backup': str(backup),
                  'baseline_images': metadata['images'],
                  'snapshot_sha256': recovery.digest(backup / 'snapshot.json')}
        updater.save(root / updater.STATE, record)
        return backup, record

    def docker(self, stack):
        stack.enter_context(patch.object(recovery, 'container', return_value={'State': {'Running': False}}))
        stack.enter_context(patch.object(recovery, 'command', return_value=subprocess.CompletedProcess([], 0, stdout='')))
        stack.enter_context(patch.object(recovery, 'database_fingerprint', return_value='synthetic-database'))
        stack.enter_context(patch.object(recovery, 'volume_name', return_value='synthetic'))
        stack.enter_context(patch.object(recovery, 'volume_fingerprint', return_value='fixture'))
        return stack.enter_context(patch.object(recovery, 'compose'))

    def test_legacy_and_current_rehearsal_cancel_resume_only_pinned_baseline(self):
        for version in (1, 2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)
                backup, record = self.fixture(root, version)
                before = {p.name: p.read_bytes() for p in backup.iterdir()}
                compose = self.docker(stack)
                with self.assertRaisesRegex(ValueError, 'pending or failed'):
                    with updater.operation_guard(root, 'start'):
                        self.fail('Pending update allowed startup')
                with self.assertRaisesRegex(ValueError, 'Resolve the pending'):
                    updater.update(root, root / 'candidate', root / 'new-backup',
                                   root / 'rehearsal', 'vardrsec-restore-test')
                updater.cancel(root)
                self.assertFalse((root / updater.STATE).exists())
                self.assertEqual(json.loads((root / '.last-update.json').read_text())['status'], 'cancelled')
                self.assertEqual(json.loads((root / '.active-images.json').read_text()),
                                 {'services': {k: {'image': v} for k, v in record['baseline_images'].items()}})
                compose.assert_called_once()
                self.assertIn('--no-build', compose.call_args.args)
                self.assertIn('never', compose.call_args.args)
                self.assertEqual(before, {p.name: p.read_bytes() for p in backup.iterdir()})

    def test_tamper_and_source_drift_retain_pending_record_without_startup(self):
        for version, target in ((3, 'source-script'), (4, 'source-helper'),
                                (4, 'backup-helper'), (4, 'manifest')):
            with self.subTest(version=version, target=target), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)
                backup, _ = self.fixture(root, version)
                if target == 'source-script':
                    (root / 'recovery.py').write_bytes(b'changed')
                elif target == 'source-helper':
                    (root / 'database_roles.py').write_bytes(b'changed')
                elif target == 'backup-helper':
                    (backup / 'database_roles.py').write_bytes(b'changed')
                else:
                    path = backup / 'snapshot.json'
                    data = json.loads(path.read_text())
                    data['created_at'] = 'changed'
                    path.write_text(json.dumps(data))
                pending = (root / updater.STATE).read_bytes()
                compose = self.docker(stack)
                with self.assertRaises(ValueError):
                    updater.cancel(root)
                compose.assert_not_called()
                self.assertFalse((root / '.active-images.json').exists())
                self.assertEqual((root / updater.STATE).read_bytes(), pending)

    def test_preparing_cancels_but_mutating_phases_require_restore(self):
        for phase in ('preparing', 'applying', 'publishing'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)
                _, record = self.fixture(root, 3)
                record['phase'] = phase
                updater.save(root / updater.STATE, record)
                compose = self.docker(stack)
                validate = stack.enter_context(patch.object(recovery, 'validate'))
                if phase == 'preparing':
                    updater.cancel(root)
                    compose.assert_called_once()
                    self.assertFalse((root / updater.STATE).exists())
                else:
                    with self.assertRaisesRegex(ValueError, 'Original mutation'):
                        updater.cancel(root)
                    compose.assert_not_called()
                    self.assertTrue((root / updater.STATE).exists())
                validate.assert_not_called()

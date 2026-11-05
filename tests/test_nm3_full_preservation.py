"""Synthetic protocol checks only; never invoke a daemon or real installation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import nm3_full_preservation as lane


class PreservationTests(unittest.TestCase):
    def scenario(self, returncode=2, mutate=False, capacity=True):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder); root = private / 'fixture'; root.mkdir()
            snapshot = {'database': {'fixture': 'synthetic-hash'}, 'volumes': {'fixture': 'synthetic-hash'},
                        'images': {'api': 'sha256:' + 'a' * 64}}
            baseline = {'database': snapshot['database'], 'volumes': snapshot['volumes'], 'config': {}}
            def restore(_backup, destination):
                destination.mkdir()
                (destination / '.active-images.json').write_text(json.dumps({'services': {'api': {'image': snapshot['images']['api']}}}))
            with patch.dict(os.environ, {'COMPOSE_PROJECT_NAME': 'nm3-full-fixture'}, clear=True), \
                 patch.object(lane.recovery, 'command', return_value=SimpleNamespace(stdout='1')), \
                 patch.object(lane.ci.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12 if capacity else 0)), \
                 patch.object(lane.recovery, 'sql') as sql, patch.object(lane.recovery, 'backup') as backup, \
                 patch.object(lane.recovery, 'validate', return_value=snapshot), \
                 patch.object(lane, 'bundled_restore', side_effect=restore), \
                 patch.object(lane, 'state', side_effect=[baseline, baseline, {} if mutate else baseline, baseline]), \
                 patch.object(lane.subprocess, 'run', return_value=subprocess.CompletedProcess(
                     [], returncode, stdout='', stderr='This installation has been started before')) as install:
                if returncode != 2 or mutate or not capacity:
                    with self.assertRaises(ValueError): lane.exercise(root, private)
                else:
                    self.assertEqual(lane.exercise(root, private), {key: True for key in lane.FLAGS})
                    self.assertNotIn('COMPOSE_PROJECT_NAME', install.call_args.kwargs['env'])
                    self.assertEqual(install.call_args.args[0][1:], ['vardrsec.py', 'install'])
                    self.assertEqual(install.call_args.kwargs['cwd'], private / 'restored')
                    backup.assert_called_once_with(root, private / 'backup')
                if not capacity:
                    sql.assert_not_called(); backup.assert_not_called(); install.assert_not_called()

    def test_restored_project_uses_dotenv_and_preserves_fingerprints(self):
        self.scenario()

    def test_unexpected_install_success_or_state_mutation_cannot_pass(self):
        self.scenario(returncode=0)
        self.scenario(mutate=True)

    def test_insufficient_capacity_refuses_before_seeding_or_backup(self):
        self.scenario(capacity=False)

    def test_existing_backup_destination_is_not_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder); (private / 'backup').mkdir()
            (private / 'backup/retained').write_bytes(b'synthetic')
            with patch.object(lane.recovery, 'command') as command, self.assertRaises(ValueError):
                lane.exercise(private / 'fixture', private)
            command.assert_not_called()
            self.assertEqual((private / 'backup/retained').read_bytes(), b'synthetic')

    def test_bundle_source_binding_and_isolated_child_failure(self):
        for case in ('ok', 'modified-code', 'extra-code', 'child-failed'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); bundle = root / 'bundle'; source = root / 'source'
                bundle.mkdir(); source.mkdir()
                for name in lane.recovery.snapshot_files(4):
                    (bundle / name).write_bytes(b'synthetic')
                    (source / name).write_bytes(b'synthetic')
                metadata = {'schema_version': 4, 'files': {name: 'hash' for name in lane.recovery.snapshot_files(4)}}
                (bundle / 'snapshot.json').write_text('{}')
                if case == 'modified-code':
                    (bundle / 'database_roles.py').write_bytes(b'changed')
                elif case == 'extra-code':
                    (bundle / 'subprocess.py').write_bytes(b'not trusted')
                with patch.object(lane.recovery, 'validate', return_value=metadata), \
                     patch.object(lane.ci, 'SOURCE', source), \
                     patch.dict(os.environ, {'COMPOSE_PROJECT_NAME': 'source'}, clear=True), \
                     patch.object(lane.subprocess, 'run', return_value=SimpleNamespace(returncode=1 if case == 'child-failed' else 0)) as child:
                    if case == 'ok':
                        lane.bundled_restore(bundle, root / 'restored')
                        self.assertEqual(child.call_args.args[0][1:4], ['-I', '-B', '-c'])
                        self.assertEqual(child.call_args.kwargs['cwd'], bundle)
                        self.assertNotIn('COMPOSE_PROJECT_NAME', child.call_args.kwargs['env'])
                    else:
                        with self.assertRaises(ValueError):
                            lane.bundled_restore(bundle, root / 'restored')
                    if case in ('modified-code', 'extra-code'):
                        child.assert_not_called()

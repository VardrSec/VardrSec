"""Synthetic orchestration tests: no Docker, credentials or local services."""
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import nm3_full_update as lane


class UpdateLaneTests(unittest.TestCase):
    def test_interrupt_requires_real_rehearsal_success_and_preapply_record(self):
        for mode in ('ok', 'real-failure', 'wrong-phase'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); rehearsal = root / 'rehearsal'
                def update(*args):
                    try:
                        lane.updater.verify_private(rehearsal, 'vardrsec-restore-nm3-interrupted')
                    except (KeyboardInterrupt, ValueError):
                        (root / lane.updater.STATE).write_text(json.dumps({
                            'phase': 'applying' if mode == 'wrong-phase' else 'rehearsal', 'status': 'failed'}))
                        raise ValueError('Synthetic update failure') from None
                with patch.object(lane.updater, 'verify_private', side_effect=ValueError('real failure') if mode == 'real-failure' else None) as verify, \
                     patch.object(lane.updater, 'update', side_effect=update), \
                     patch.object(lane.recovery, 'container', return_value={'State': {'Running': False}}):
                    if mode == 'ok':
                        lane.interrupted_update(root, root / 'candidate', root / 'backup', rehearsal)
                    else:
                        with self.assertRaises(ValueError):
                            lane.interrupted_update(root, root / 'candidate', root / 'backup', rehearsal)
                    verify.assert_called_once_with(rehearsal, 'vardrsec-restore-nm3-interrupted')

    def test_capacity_refuses_before_authentication_and_state_seeding(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(lane.recovery, 'command', return_value=SimpleNamespace(stdout='1')), \
             patch.object(lane.ci.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)), \
             patch.object(lane, 'authenticate') as auth, patch.object(lane.recovery, 'sql') as sql:
            with self.assertRaises(ValueError):
                lane.exercise(Path(folder) / 'fixture', Path(folder))
            auth.assert_not_called(); sql.assert_not_called()

    def test_completed_cycle_requires_retained_state_and_same_images(self):
        for drift in (False, True):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as folder:
                private = Path(folder); root = private / 'fixture'; root.mkdir()
                images = {'api': 'sha256:' + 'a' * 64}
                def manifest(*args):
                    path = private / 'candidate.json'
                    path.write_text(json.dumps({'images': images}))
                    return path
                def record(*args):
                    (root / '.last-update.json').write_text(json.dumps({'phase': 'complete', 'status': 'success'}))
                def cancel(*args):
                    (root / '.last-update.json').write_text(json.dumps({'status': 'cancelled'}))
                states = ['stable'] * 3 + ['changed' if drift else 'stable']
                with patch.object(lane.recovery, 'command', return_value=SimpleNamespace(stdout='1')), \
                     patch.object(lane.ci.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)), \
                     patch.object(lane, 'authenticate', return_value='synthetic'), \
                     patch.object(lane.recovery, 'sql'), patch.object(lane, 'retained_state', side_effect=states), \
                     patch.object(lane.updater, 'image_set', return_value=({}, images)), \
                     patch.object(lane.existing, 'manifest', side_effect=manifest), \
                     patch.object(lane, 'interrupted_update'), \
                     patch.object(lane.recovery, 'validate', return_value={'schema_version': 4}), \
                     patch.object(lane.updater, 'cancel', side_effect=cancel), \
                     patch.object(lane.updater, 'update', side_effect=record):
                    if drift:
                        with self.assertRaises(ValueError): lane.exercise(root, private)
                    else:
                        self.assertEqual(lane.exercise(root, private), {k: True for k in lane.FLAGS})

"""Offline orchestration checks; historical helpers own retention assertions."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nm3_exact_upgrade as lane


class ExactUpgradeTests(unittest.TestCase):
    def test_success_requires_real_revision_and_completed_updater_outcome(self):
        for scenario in ('passed', 'wrong-revision', 'wrong-outcome'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                private = Path(folder); root = private / 'fixture'; root.mkdir()
                baseline = {s: 'sha256:' + 'a' * 64 for s in lane.recovery.SERVICES}
                images = {**baseline, 'api': 'sha256:' + 'b' * 64}
                candidate = {'schema_version': 1, 'public_origin': 'https://localhost:8443',
                             'images': images, 'components': lane.historical.CURRENT}
                def build(_root, destination, stage):
                    destination.mkdir()
                    path = destination / 'candidate.json'; path.write_text(json.dumps(candidate))
                    return path
                def update(*args):
                    (root / '.last-update.json').write_text(json.dumps({
                        'phase': 'complete', 'status': 'failed' if scenario == 'wrong-outcome' else 'success',
                        'candidate': candidate}))
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(lane.recovery, 'sql', side_effect=['0031localauth', '',
                    '0031localauth' if scenario == 'wrong-revision' else '0038managedstops'])
                mock(lane.recovery, 'digest', return_value='unchanged')
                mock(lane.recovery, 'validate', return_value={'schema_version': 4})
                mock(lane.historical_build, 'source_receipt')
                mock(lane.historical_build, 'recovery_capacity')
                mock(lane.historical_build, 'build_candidate', side_effect=build)
                mock(lane.updater, 'image_set', side_effect=[({'name': lane.PROJECT}, baseline), ({}, images)])
                mock(lane.updater, 'candidate_set', return_value=candidate)
                updated = mock(lane.updater, 'update', side_effect=update)
                mock(lane, 'authenticate', return_value={'id': 'synthetic', 'token': 'synthetic'})
                initialized = mock(lane, 'initialize_baseline_runner')
                for name in ('key_telemetry', 'columns', 'projected_rows', 'sequences', 'state_fingerprints'):
                    mock(lane.historical, name, return_value={})
                retained = mock(lane.historical, 'assert_retained')
                mock(lane.historical, 'assert_key_telemetry')
                mock(lane.historical, 'assert_sequences_retained')
                denied = mock(lane.historical, 'verify_anonymous_denied')
                mock(lane.database_roles, 'read_password', return_value='synthetic')
                roles = mock(lane.database_roles, 'verify')
                if scenario == 'passed':
                    self.assertEqual(lane.exercise(root, private), {k: True for k in lane.FLAGS})
                    retained.assert_called_once(); denied.assert_called_once()
                    self.assertEqual(roles.call_count, 2)
                else:
                    with self.assertRaises(ValueError): lane.exercise(root, private)
                    denied.assert_not_called()
                initialized.assert_called_once_with(root, 'synthetic')
                updated.assert_called_once()
                self.assertEqual(updated.call_args.args[-1], 'vardrsec-restore-nm3-final-upgrade')

    def test_wrong_baseline_schema_refuses_before_build_and_authentication(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(lane.recovery, 'sql', return_value='unexpected'), \
             patch.object(lane.historical_build, 'build_candidate') as build, \
             patch.object(lane, 'authenticate') as auth:
            with self.assertRaises(ValueError): lane.exercise(Path(folder), Path(folder))
            build.assert_not_called(); auth.assert_not_called()

    def test_baseline_diagnostic_requires_healthy_success_without_printing_token(self):
        for code, healthy in ((0, True), (1, True), (0, False)):
            with self.subTest(code=code, healthy=healthy), patch.object(
                lane.recovery, 'compose', return_value=SimpleNamespace(
                    returncode=code, stdout=json.dumps({'healthy': healthy}))) as compose:
                if code == 0 and healthy:
                    lane.initialize_baseline_runner(Path('/synthetic'), 'private-token')
                else:
                    with self.assertRaises(ValueError):
                        lane.initialize_baseline_runner(Path('/synthetic'), 'private-token')
                self.assertEqual(compose.call_args.args[1:],
                                 ('run', '--rm', '--no-deps', 'runner', 'doctor', '--platform', '--offline', '--json'))
                self.assertNotIn('private-token', compose.call_args.args)
                self.assertEqual(compose.call_args.kwargs['env']['VARDRMAP_API_KEY'], 'private-token')

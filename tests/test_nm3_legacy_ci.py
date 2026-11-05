"""Offline verification of hosted acceptance guard boundaries; no Docker calls."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nm3_legacy_ci as ci


class HostedGuardTests(unittest.TestCase):
    def environment(self):
        return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': 'VardrSec/VardrSec', 'GITHUB_REF': ci.BRANCH,
                'GITHUB_EVENT_NAME': 'push', 'GITHUB_WORKSPACE': str(ci.SOURCE)}

    def test_host_guard_and_remote_config_secret_override_refusal(self):
        with patch.object(ci.platform, 'system', return_value='Linux'), \
             patch.object(ci.platform, 'machine', return_value='x86_64'), \
             patch.object(ci.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)):
            ci.host_guard(self.environment())
            preservation_env = {**self.environment(), 'GITHUB_REF':
                                'refs/heads/codex/nm3-target-budget-verification'}
            ci.host_guard(preservation_env, preservation=True)
            with self.assertRaises(ValueError):
                ci.host_guard(preservation_env)
            with self.assertRaises(ValueError):
                ci.host_guard(self.environment(), preservation=True)
            for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_TLS_VERIFY',
                        'COMPOSE_ENV_FILES', 'COMPOSE_FILE', 'MAP_SOURCE', 'POSTGRES_PASSWORD',
                        'VARDRMAP_API_KEY'):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    ci.host_guard({**self.environment(), key: 'synthetic'})
            for key, value in (('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_REF', 'refs/heads/main'),
                               ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REPOSITORY', 'other/repo')):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    ci.host_guard({**self.environment(), key: value})

    def test_daemon_must_be_local_named_and_empty(self):
        valid = {'OSType': 'linux', 'Name': 'fixture-host', 'DockerRootDir': '/var/lib/docker', 'Swarm': {'LocalNodeState': 'inactive'}}
        for field, value in ((None, None), ('Name', 'other'), ('OSType', 'windows'), ('DockerRootDir', '/other'), ('Swarm', {'LocalNodeState': 'active'})):
            info = dict(valid)
            if field: info[field] = value
            with patch.object(ci.socket, 'gethostname', return_value='fixture-host'), \
                 patch.object(ci, 'docker', side_effect=[json.dumps(info), '', '', 'bridge\nhost\nnone\n']):
                if field:
                    with self.assertRaises(ValueError): ci.empty_daemon_guard({})
                else: ci.empty_daemon_guard({})
        for index in (1, 2, 3):
            replies = [json.dumps(valid), '', '', 'bridge\nhost\nnone\n']
            replies[index] = 'existing-resource\n'
            with patch.object(ci.socket, 'gethostname', return_value='fixture-host'), \
                 patch.object(ci, 'docker', side_effect=replies), self.assertRaises(ValueError):
                ci.empty_daemon_guard({})

    def test_failed_isolation_exports_only_fixed_receipt_and_never_installs(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'RUNNER_TEMP': folder}, clear=True), \
             patch.object(ci, 'host_guard'), patch.object(ci, 'empty_daemon_guard', side_effect=ValueError('synthetic-private-value')), \
             patch.object(ci.subprocess, 'run') as command, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ci.run(), 1)
            path = Path(folder) / 'nm3-full-fresh/public/receipt.json'
            text = path.read_text()
            self.assertNotIn('synthetic-private-value', text + output.getvalue())
            receipt = json.loads(text)
            self.assertEqual(set(receipt), {'schema', 'installer_commit', 'component_pins', 'fixture_component_pins', 'status', 'stage', 'raw_output_uploaded', 'scope'})
            self.assertEqual(receipt['stage'], 'isolation')
            self.assertEqual(receipt['status'], 'failed_or_unproven')
            command.assert_not_called()

    def test_existing_fixture_is_never_reused_or_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'nm3-full-fresh'; root.mkdir()
            retained = root / 'retained'; retained.write_bytes(b'synthetic-retained')
            with patch.dict(os.environ, {'RUNNER_TEMP': folder}, clear=True), patch.object(ci, 'host_guard'), \
                 patch.object(ci, 'empty_daemon_guard') as daemon, self.assertRaises(ValueError):
                ci.run()
            daemon.assert_not_called()
            self.assertEqual(retained.read_bytes(), b'synthetic-retained')

    def test_copy_preserves_exact_candidate_pins_and_refuses_source_delta(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'source'; source.mkdir()
            (source / 'versions.json').write_text(json.dumps({'components': {k: {'commit': v} for k, v in ci.PINS.items()}}))
            for diff in (0, 1):
                destination = root / ('copy-' + str(diff))
                with patch.object(ci, 'SOURCE', source), patch.object(ci, 'capture', side_effect=[
                    'a' * 40, '', '100644 blob ' + 'b' * 40 + '\tversions.json\n'
                ]), patch.object(ci.subprocess, 'run', side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=diff)]):
                    if diff:
                        with self.assertRaises(ValueError): ci.copy_candidate(destination, {'GITHUB_SHA': 'a' * 40})
                        self.assertFalse(destination.exists())
                    else:
                        ci.copy_candidate(destination, {'GITHUB_SHA': 'a' * 40})
                        self.assertEqual((destination / 'versions.json').read_bytes(), (source / 'versions.json').read_bytes())

    def test_workflow_is_branch_only_and_artifact_path_is_exact(self):
        workflow = (ci.SOURCE / '.github/workflows/nm3-target-budget.yml').read_text()
        self.assertIn('branches: [codex/nm3-target-budget-verification]', workflow)
        self.assertNotIn('pull_request:', workflow)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertIn('runs-on: ubuntu-24.04', workflow)
        self.assertIn('path: ${{ runner.temp }}/nm3-full-fresh/public/receipt.json', workflow)
        self.assertIn('contents: read', workflow)

    def test_checkpoint_exports_only_fixed_allowlisted_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'checkpoint.json'
            self.assertIsNone(ci.read_upgrade_checkpoint(path))
            path.write_text(json.dumps({'stage': 'ownership'}))
            self.assertEqual(ci.read_upgrade_checkpoint(path), {'stage': 'ownership'})
            for value in ({'stage': 'private-secret'}, {'stage': 'rows', 'secret': 'private'}, {'stage': []}, {'stage': 'rows', 'failure_category': 'private-error'}):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): ci.read_upgrade_checkpoint(path)

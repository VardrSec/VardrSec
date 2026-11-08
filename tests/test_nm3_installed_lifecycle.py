"""Private lifecycle orchestration tests; no Docker, scanners or network calls."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import nm3_development_full_ci as hosted
import nm3_installed_lifecycle as lifecycle


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.private = self.root / 'nm3-community-full/private'
        self.fixture = self.private / 'fixture'
        self.fixture.mkdir(parents=True)
        self.summary = self.private / 'lifecycle/summary.json'
        self.env = {'RUNNER_TEMP': str(self.root), 'GITHUB_ACTIONS': 'true',
            'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_REPOSITORY': 'VardrSec/VardrSec',
            'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': lifecycle.BRANCH,
            'COMPOSE_PROJECT_NAME': lifecycle.PROJECT, 'DOCKER_HOST': 'unix:///var/run/docker.sock',
            'DOCKER_CONFIG': str(self.private / 'docker-config')}

    def test_child_refuses_wrong_host_project_or_fixture_before_any_command(self):
        for key, value in (('GITHUB_REF', 'refs/heads/main'),
                           ('RUNNER_ENVIRONMENT', 'self-hosted'),
                           ('COMPOSE_PROJECT_NAME', 'retained-project'),
                           ('DOCKER_HOST', 'tcp://foreign')):
            with self.subTest(key=key), patch.dict(os.environ, {**self.env, key: value}, clear=True), \
                 patch.object(lifecycle, 'command') as command:
                with self.assertRaises(ValueError):
                    lifecycle.run(self.fixture, self.summary)
                command.assert_not_called()
                self.assertFalse(self.summary.parent.exists())

    def test_ui_journey_owns_bootstrap_and_recovery_runs_only_after_success(self):
        def recovered(fixture, private, env, mark):
            self.assertEqual(fixture, self.fixture)
            self.assertEqual(private, self.summary.parent)
            self.assertNotIn('PYTHONPATH', env)
            mark('restore'); mark('restored_checks')
            return {name: True for name in lifecycle.CHECKS}
        with patch.dict(os.environ, {**self.env, 'PYTHONPATH': 'synthetic-untrusted'}, clear=True), \
             patch.object(sys, 'path', list(sys.path)), \
             patch.object(lifecycle, 'command', return_value='') as command, \
             patch.object(lifecycle, 'verify_recovery', side_effect=recovered) as recovery, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(lifecycle.run(self.fixture, self.summary), 0)
        self.assertEqual(command.call_args_list[0].args[0][:2], ['docker', 'build'])
        self.assertEqual(command.call_args_list[1].args[0],
                         [sys.executable, str(self.fixture / 'tests/compose_acceptance.py')])
        self.assertEqual(command.call_count, 2)
        recovery.assert_called_once()
        receipt = json.loads(self.summary.read_text())
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual(receipt['checks'], {name: True for name in lifecycle.CHECKS})

    def test_child_failure_has_fixed_substage_without_private_exception(self):
        secret = 'synthetic-password-do-not-publish'
        def refused(_fixture, _private, _env, mark):
            mark('restore')
            raise subprocess.CalledProcessError(1, ['synthetic'], output=secret, stderr=secret)
        output = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), patch.object(sys, 'path', list(sys.path)), \
             patch.object(lifecycle, 'command', return_value=''), \
             patch.object(lifecycle, 'verify_recovery', side_effect=refused), redirect_stdout(output):
            self.assertEqual(lifecycle.run(self.fixture, self.summary), 1)
        raw = self.summary.read_text()
        receipt = json.loads(raw)
        self.assertEqual((receipt['stage'], receipt['failure_code']), ('restore', 'command_exit_nonzero'))
        self.assertEqual(receipt['checks'], {})
        self.assertNotIn(secret, raw + output.getvalue())

    def test_command_refuses_nonzero_and_secret_on_stderr(self):
        for code, stdout, stderr in ((1, 'private stdout', 'private stderr'), (0, '{}', 'synthetic-key')):
            with self.subTest(code=code), patch.object(lifecycle.subprocess, 'run', return_value=
                subprocess.CompletedProcess([], code, stdout, stderr)):
                with self.assertRaises((lifecycle.CommandFailure, ValueError)):
                    lifecycle.command(['synthetic'], cwd=self.root, env={}, forbidden=('synthetic-key',))

    def controller(self, payload, code):
        def child(_args, **_kwargs):
            self.summary.parent.mkdir()
            self.summary.write_text(payload)
            return subprocess.CompletedProcess([], code)
        receipt = {}
        with patch.object(hosted.subprocess, 'run', side_effect=child):
            try:
                checks = hosted.verify_installed_lifecycle(self.fixture, self.private, self.env, receipt)
            except ValueError:
                checks = None
        return receipt, checks

    def test_parent_accepts_only_fixed_success_checks(self):
        payload = {'status': 'passed', 'stage': 'complete',
                   'checks': {name: True for name in lifecycle.CHECKS}, 'raw': 'private ignored value'}
        receipt, checks = self.controller(json.dumps(payload), 0)
        self.assertEqual(checks, {name: True for name in lifecycle.CHECKS})
        self.assertEqual(receipt, {'lifecycle_stage': 'complete'})

    def test_parent_retains_whitelisted_failure_diagnostics_on_nonzero(self):
        receipt, checks = self.controller(json.dumps({'status': 'failed_or_unproven', 'stage': 'unseal',
            'failure_code': 'operation_refused', 'exception': 'private secret'}), 1)
        self.assertIsNone(checks)
        self.assertEqual(receipt, {'lifecycle_stage': 'unseal',
                                  'lifecycle_failure_code': 'operation_refused'})

    def test_parent_does_not_publish_untrusted_or_oversized_summary_fields(self):
        payload = json.dumps({'stage': 'synthetic-private-stage', 'failure_code': 'private-secret',
                              'status': 'failed_or_unproven'})
        receipt, checks = self.controller(payload, 1)
        self.assertEqual(receipt, {'lifecycle_stage': 'unavailable'})
        self.assertIsNone(checks)
        self.summary.unlink(); self.summary.parent.rmdir()
        (self.private / 'lifecycle.log').unlink()
        receipt, checks = self.controller('x' * (16 * 1024 + 1), 1)
        self.assertEqual(receipt, {'lifecycle_stage': 'unavailable'})
        self.assertIsNone(checks)


if __name__ == '__main__':
    unittest.main()

"""Hosted Full guard tests: local synthetic files only, never a Docker daemon."""

from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import nm3_development_full_ci as hosted


class HostedGuardTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.env = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REPOSITORY": "VardrSec/VardrSec", "GITHUB_REF": hosted.BRANCH,
            "GITHUB_EVENT_NAME": "push", "GITHUB_WORKSPACE": str(self.root),
        }

    @contextmanager
    def supported_host(self, uid=0):
        original_stat = Path.stat
        def observed(path, *args, **kwargs):
            if path == Path('/var/run/docker.sock'):
                return SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=uid)
            return original_stat(path, *args, **kwargs)
        with patch.object(hosted, 'SOURCE', self.root), \
             patch.object(hosted.platform, 'freedesktop_os_release', return_value={
                 'ID': 'ubuntu', 'VERSION_ID': '24.04'}), \
             patch.object(hosted.platform, 'system', return_value='Linux'), \
             patch.object(hosted.platform, 'machine', return_value='x86_64'), \
             patch.object(Path, 'stat', observed):
            yield

    def test_only_expected_fresh_host_branch_and_unmodified_selection_are_allowed(self):
        with self.supported_host():
            hosted.host_guard(self.env)
            for key, value in (
                ('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                ('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_REF', 'refs/heads/main'),
                ('GITHUB_EVENT_NAME', 'pull_request'), ('DOCKER_HOST', 'synthetic'),
                ('MAP_SOURCE', 'synthetic'), ('VARDRRUNNER_API_KEY', 'synthetic-secret'),
            ):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'no acceptance claimed'):
                    hosted.host_guard({**self.env, key: value})
        with self.supported_host(uid=1000), self.assertRaises(ValueError):
            hosted.host_guard(self.env)

    def test_nonempty_or_foreign_daemon_refuses_using_only_read_commands(self):
        info = {'OSType': 'linux', 'Name': 'fresh-vm', 'DockerRootDir': '/var/lib/docker',
                'Swarm': {'LocalNodeState': 'inactive'}}
        variants = [({}, '', '', 'bridge\nhost\nnone\n')]
        for change in ({'OSType': 'windows'}, {'Name': 'foreign-vm'},
                       {'DockerRootDir': '/other'}, {'Swarm': {'LocalNodeState': 'active'}}):
            variants.append((change, '', '', 'bridge\nhost\nnone\n'))
        variants += [({}, 'retained-stopped-container', '', 'bridge\nhost\nnone\n'),
                     ({}, '', 'retained-volume', 'bridge\nhost\nnone\n'),
                     ({}, '', '', 'bridge\nhost\nnone\nretained-network\n')]
        for index, (change, containers, volumes, networks) in enumerate(variants):
            calls = []
            def docker(_env, *args):
                calls.append(args)
                return {('info', '--format', '{{json .}}'): json.dumps({**info, **change}),
                        ('ps', '-aq'): containers, ('volume', 'ls', '-q'): volumes,
                        ('network', 'ls', '--format', '{{.Name}}'): networks}[args]
            with self.subTest(index=index), patch.object(hosted, 'docker', side_effect=docker), \
                 patch.object(hosted.socket, 'gethostname', return_value='fresh-vm'):
                if index == 0:
                    hosted.empty_daemon_guard({})
                else:
                    with self.assertRaises(ValueError):
                        hosted.empty_daemon_guard({})
            self.assertTrue(all(args[0] in ('info', 'ps', 'volume', 'network') for args in calls))


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.repo = self.root / 'checkout'; self.repo.mkdir()
        empty_config = self.root / 'git-config'; empty_config.write_text('')
        hooks = self.root / 'hooks'; hooks.mkdir()
        self.git_env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        self.git_env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(empty_config))
        self.git('init', '--template=' + str(hooks))
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'core.hooksPath', str(hooks))

    def git(self, *args):
        return subprocess.run([shutil.which('git'), *args], cwd=self.repo, env=self.git_env,
                              capture_output=True, text=True, check=True).stdout.strip()

    def prepare(self, stale_pins=False):
        pins = dict(hosted.BASE_PINS)
        if stale_pins:
            pins['runner'] = '0' * 40
        manifest = {'components': {name: {'commit': commit} for name, commit in pins.items()}}
        (self.repo / 'versions.json').write_text(json.dumps(manifest))
        (self.repo / 'application.txt').write_text('candidate source\n')
        (self.repo / 'CHANGELOG.md').write_text('candidate notes\n')
        self.git('add', '.'); self.git('commit', '-m', 'candidate')
        candidate = self.git('rev-parse', 'HEAD')
        tree = self.git('rev-parse', 'HEAD^{tree}')
        (self.repo / 'verification-only.txt').write_text('workflow overlay\n')
        (self.repo / 'CHANGELOG.md').write_text('verification notes\n')
        self.git('add', '.'); self.git('commit', '-m', 'verification overlay')
        return candidate, tree

    @contextmanager
    def candidate(self, candidate, tree):
        capture = hosted.capture
        def scoped(args, cwd=None, env=None):
            return capture(args, cwd=self.repo if cwd is None else cwd,
                           env=self.git_env if env is None else env)
        with patch.object(hosted, 'SOURCE', self.repo), patch.object(hosted, 'CANDIDATE', candidate), \
             patch.dict(hosted.TREES, {'distribution': tree}), \
             patch.object(hosted, 'capture', side_effect=scoped), \
             patch.dict(os.environ, self.git_env, clear=True):
            yield

    def test_copied_fixture_uses_exact_cohort_without_changing_source_manifest(self):
        candidate, tree = self.prepare()
        original = (self.repo / 'versions.json').read_bytes()
        destination = self.root / 'fixture'
        head = self.git('rev-parse', 'HEAD')
        with self.candidate(candidate, tree):
            self.assertEqual(hosted.copy_candidate(destination, {'GITHUB_SHA': head}), head)
        pins = json.loads((destination / 'versions.json').read_text())['components']
        self.assertEqual({name: item['commit'] for name, item in pins.items()}, {
            'map': 'aad63c8151789cd9bf56864456b5fdf1fdcfde41',
            'runner': '440ebda7405d9f19f2e5c6f954996b525f0ac5da',
            'gate': '54536ea1d900d0e35adf93b4e026962c4d45d34a',
        })
        self.assertEqual((self.repo / 'versions.json').read_bytes(), original)
        self.assertEqual((destination / 'CHANGELOG.md').read_text(), 'candidate notes\n')
        self.assertFalse((destination / 'verification-only.txt').exists())

    def test_wrong_workflow_ref_or_candidate_tree_refuses_before_copy(self):
        candidate, tree = self.prepare()
        head = self.git('rev-parse', 'HEAD')
        for selected_tree, selected_head in ((tree, '0' * 40), ('0' * 40, head)):
            destination = self.root / ('fixture-' + selected_head[:1] + selected_tree[:1])
            with self.subTest(tree=selected_tree), self.candidate(candidate, selected_tree), \
                 self.assertRaises(ValueError):
                hosted.copy_candidate(destination, {'GITHUB_SHA': selected_head})
            self.assertFalse(destination.exists())

    def test_changed_candidate_source_refuses_even_with_clean_committed_head(self):
        candidate, tree = self.prepare()
        (self.repo / 'application.txt').write_text('different source\n')
        self.git('add', '.'); self.git('commit', '-m', 'source drift')
        destination = self.root / 'fixture'
        with self.candidate(candidate, tree), self.assertRaises(ValueError):
            hosted.copy_candidate(destination, {'GITHUB_SHA': self.git('rev-parse', 'HEAD')})
        self.assertFalse(destination.exists())

    def test_unrelated_head_refuses_even_when_candidate_files_match(self):
        candidate, tree = self.prepare()
        unrelated = self.git('commit-tree', self.git('rev-parse', 'HEAD^{tree}'),
                             '-m', 'unrelated verification history')
        self.git('update-ref', 'HEAD', unrelated)
        destination = self.root / 'fixture'
        with self.candidate(candidate, tree), self.assertRaises(ValueError):
            hosted.copy_candidate(destination, {'GITHUB_SHA': unrelated})
        self.assertFalse(destination.exists())

    def test_unexpected_base_pins_refuse_without_modifying_original(self):
        candidate, tree = self.prepare(stale_pins=True)
        original = (self.repo / 'versions.json').read_bytes()
        with self.candidate(candidate, tree), self.assertRaises(ValueError):
            hosted.copy_candidate(self.root / 'fixture', {'GITHUB_SHA': self.git('rev-parse', 'HEAD')})
        self.assertEqual((self.repo / 'versions.json').read_bytes(), original)


class ReceiptSafetyTests(unittest.TestCase):
    def test_install_failure_diagnostics_include_only_fixed_steps_and_exit_codes(self):
        secret = 'synthetic-private-value-do-not-upload'
        for timeout in (False, True):
            with tempfile.TemporaryDirectory() as folder, self.subTest(timeout=timeout):
                root = Path(folder)
                def fixture(destination, _env):
                    destination.mkdir()
                    (destination / 'versions.json').write_text(json.dumps({'components': hosted.PINS}))
                    return 'synthetic-workflow'
                def failed_install(*args, **kwargs):
                    kwargs['stdout'].write('== build\n' + secret + '\n== ' + secret + '\n')
                    kwargs['stdout'].flush()
                    if timeout:
                        raise subprocess.TimeoutExpired(secret, 5400, output=secret, stderr=secret)
                    return subprocess.CompletedProcess([], 17)
                output = io.StringIO()
                with patch.dict(os.environ, {'RUNNER_TEMP': str(root)}, clear=True), \
                     patch.object(hosted, 'host_guard'), patch.object(hosted, 'empty_daemon_guard'), \
                     patch.object(hosted, 'copy_candidate', side_effect=fixture), \
                     patch.object(hosted, 'capture', return_value='synthetic-tree'), \
                     patch.object(hosted.shutil, 'disk_usage', return_value=SimpleNamespace(free=13 * 1024**3)), \
                     patch.object(hosted.subprocess, 'run', side_effect=failed_install), redirect_stdout(output):
                    self.assertEqual(hosted.run(), 1)
                raw = (root / 'nm3-community-full/public/receipt.json').read_text()
                receipt = json.loads(raw)
                self.assertEqual(receipt['stage'], 'install')
                self.assertEqual(receipt['observed_install_steps'], ['build'])
                self.assertEqual(receipt['failure_code'], 'operation_timed_out' if timeout else 'installer_exit_nonzero')
                if not timeout:
                    self.assertEqual(receipt['installer_exit_code'], 17)
                self.assertNotIn(secret, raw + output.getvalue())

    def test_refusal_receipts_never_include_raw_errors_or_private_output(self):
        secret = 'synthetic-private-value-do-not-upload'
        for stage in ('isolation', 'source'):
            with tempfile.TemporaryDirectory() as folder, self.subTest(stage=stage):
                root = Path(folder)
                def refuse_copy(destination, _env):
                    (destination.parent / 'private-config.txt').write_text(secret)
                    raise ValueError(secret)
                output = io.StringIO()
                with patch.dict(os.environ, {'RUNNER_TEMP': str(root)}, clear=True), \
                     patch.object(hosted, 'host_guard'), \
                     patch.object(hosted, 'empty_daemon_guard',
                                  side_effect=ValueError(secret) if stage == 'isolation' else None), \
                     patch.object(hosted, 'copy_candidate', side_effect=refuse_copy), \
                     patch.object(hosted.shutil, 'disk_usage', return_value=SimpleNamespace(free=13 * 1024**3)), \
                     patch.object(hosted.subprocess, 'run') as command, redirect_stdout(output):
                    self.assertEqual(hosted.run(), 1)
                command.assert_not_called()
                public = root / 'nm3-community-full' / 'public'
                self.assertEqual([item.name for item in public.iterdir()], ['receipt.json'])
                raw = (public / 'receipt.json').read_text()
                receipt = json.loads(raw)
                self.assertEqual(receipt['stage'], stage)
                self.assertEqual(receipt['status'], 'failed_or_unproven')
                self.assertIs(receipt['raw_output_uploaded'], False)
                self.assertNotIn(secret, raw + output.getvalue())
                self.assertNotIn('private-config.txt', raw)


if __name__ == '__main__':
    unittest.main()

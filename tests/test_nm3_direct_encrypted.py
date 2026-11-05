"""Direct CLI contract and private staging failure checks, without a daemon."""
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import nm3_full_preservation as lane
import updater


class DirectBackupTests(unittest.TestCase):
    def test_cli_arguments_success_and_fail_closed_results(self):
        for case in ('ok', 'command-failed', 'staging-retained', 'no-output', 'symlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                private = Path(folder); root = private / 'fixture'; root.mkdir()
                sealed = private / 'snapshot.age'
                def command(args, **kwargs):
                    self.assertEqual(args, [lane.sys.executable, 'vardrsec.py', 'backup',
                                           '--destination', str(sealed), '--recipient', 'synthetic-public-recipient'])
                    self.assertEqual(kwargs['cwd'], root)
                    self.assertTrue(kwargs['capture_output'])
                    if case == 'symlink':
                        sealed.symlink_to(root)
                    elif case != 'no-output':
                        sealed.write_bytes(b'synthetic-ciphertext')
                    if case == 'staging-retained':
                        (private / '.vardrsec-backup-synthetic').mkdir()
                    return SimpleNamespace(returncode=1 if case == 'command-failed' else 0)
                with patch.object(lane.subprocess, 'run', side_effect=command), \
                     patch.object(updater, 'installation_lock', return_value=nullcontext()) as lock:
                    if case == 'ok':
                        lane.direct_backup(root, private, sealed, 'synthetic-public-recipient')
                        lock.assert_called_once_with(root)
                    else:
                        with self.assertRaises(ValueError):
                            lane.direct_backup(root, private, sealed, 'synthetic-public-recipient')
                        lock.assert_not_called()

    def test_existing_output_or_staging_refuses_without_command(self):
        for existing in ('snapshot.age', '.vardrsec-backup-existing'):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as folder:
                private = Path(folder); (private / existing).write_bytes(b'retained')
                with patch.object(lane.subprocess, 'run') as command, self.assertRaises(ValueError):
                    lane.direct_backup(private, private, private / 'snapshot.age', 'public')
                command.assert_not_called()
                self.assertEqual((private / existing).read_bytes(), b'retained')

    def test_new_workflow_is_separate_and_keeps_official_tool_pins(self):
        workflow = (lane.ci.SOURCE / '.github/workflows/nm3-full-direct-encrypted.yml').read_text()
        self.assertIn('branches: [codex/nm3-direct-encrypted-verification]', workflow)
        self.assertNotIn('pull_request:', workflow)
        self.assertIn('b74dce4cdbe35b5e5f66c06d9612b72f89028758', workflow)
        self.assertIn('path: ${{ runner.temp }}/nm3-full-fresh/public/receipt.json', workflow)

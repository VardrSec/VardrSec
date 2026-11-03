"""Local synthetic diagnostics tests; retained scratch, no Docker/network."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import acceptance_diagnostics as diagnostics


class DiagnosticsTests(unittest.TestCase):
    def owned_root(self):
        # Portable fresh scratch; deliberately retained, including failure cases.
        return Path(tempfile.mkdtemp(prefix='vardrsec-diagnostics-test-',
                                     dir=os.environ.get('RUNNER_TEMP')))

    def capture(self, root, cohort='upgrade'):
        stack = ExitStack()
        stack.enter_context(patch.object(diagnostics.retention, 'enabled', return_value=True))
        stack.enter_context(patch.object(diagnostics, '_owned_root', return_value=root))
        stack.enter_context(diagnostics.diagnostics(root, cohort))
        return stack

    def test_disabled_has_no_io_or_patching(self):
        with patch.object(diagnostics.retention, 'enabled', return_value=False), patch.object(
            diagnostics, '_Recorder') as recorder:
            with diagnostics.diagnostics('/unused', 'upgrade'), diagnostics.wrap_shared():
                diagnostics.mark('upgrade.preflight.images')
                with diagnostics.step('upgrade.update'):
                    result = 42
        self.assertEqual(result, 42)
        recorder.assert_not_called()

    def test_safe_failure_preserves_identity_and_innermost_failure(self):
        root = self.owned_root()
        error = ValueError('private-token-path-message-sentinel')
        try:
            with self.capture(root):
                diagnostics.mark('upgrade.preflight.images')
                with diagnostics.step('upgrade.update'):
                    raise error
        except ValueError as observed:
            self.assertIs(observed, error)
        raw = (root / 'artifacts/community-diagnostics.json').read_bytes()
        self.assertNotIn(b'private-token-path-message-sentinel', raw)
        data = diagnostics.validate_public_bytes(raw)
        failed = [e for e in data['events'] if e['state'] == 'failed']
        self.assertEqual([e['stage'] for e in failed], ['upgrade.update', 'upgrade'])
        self.assertEqual([e['code'] for e in failed], ['E_VALUE', 'E_VALUE'])

    def test_success_and_checkpoint_preserve_return_value(self):
        root = self.owned_root()
        value = object()
        with self.capture(root):
            diagnostics.mark('upgrade.preflight.schema')
            with diagnostics.step('upgrade.post.schema'):
                result = value
        self.assertIs(result, value)
        data = diagnostics.validate_public_bytes((root / 'artifacts/community-diagnostics.json').read_bytes())
        self.assertEqual(data['events'][-1], {'stage': 'upgrade', 'state': 'passed', 'code': 'none'})

    def test_exact_error_mapping_never_formats_exception(self):
        for service in ('db', 'api', 'web', 'proxy', 'runner'):
            self.assertEqual(diagnostics.error_code(ValueError(f'Expected exactly one {service} container')),
                             'E_CONTAINER_CARDINALITY')
        self.assertEqual(diagnostics.error_code(ValueError('Expected exactly one private-secret container')), 'E_VALUE')
        self.assertEqual(diagnostics.error_code(ValueError('Persist the matching web AUTH_SECRET configuration before backup')), 'E_CONFIG_MISMATCH')
        self.assertEqual(diagnostics.error_code(ValueError('Persist the matching web private-secret configuration before backup')), 'E_VALUE')
        self.assertEqual(diagnostics.error_code(subprocess.TimeoutExpired('private-command', 1)), 'E_TIMEOUT')
        self.assertEqual(diagnostics.error_code(subprocess.CalledProcessError(1, 'private-command', output='private-output')), 'E_SUBPROCESS')
        class Unprintable(Exception):
            def __str__(self):
                raise AssertionError('Must not format exceptions')
        self.assertEqual(diagnostics.error_code(Unprintable()), 'E_UNKNOWN')

    def test_existing_diagnostics_not_overwritten(self):
        root = self.owned_root()
        path = root / 'artifacts/community-diagnostics.json'
        path.parent.mkdir()
        path.write_bytes(b'existing-private-artifact')
        with patch.object(diagnostics, '_owned_root', return_value=root):
            with self.assertRaises(FileExistsError):
                diagnostics._Recorder(root)
        self.assertEqual(path.read_bytes(), b'existing-private-artifact')

    def test_atomic_write_failure_preserves_operation_and_refuses_local_export(self):
        root = self.owned_root()
        with self.capture(root), patch.object(diagnostics.os, 'replace', side_effect=OSError('private-message')):
            with diagnostics.step('upgrade.update'):
                result = 42
            with self.assertRaises(ValueError):
                diagnostics.read_public(root)
        self.assertEqual(result, 42)

    def test_shared_wrappers_restore_on_exception_and_avoid_rewrapping(self):
        import recovery
        import updater
        root = self.owned_root()
        error = ValueError('Expected exactly one db container')
        original = Mock(side_effect=error)
        with patch.object(recovery, 'container', original):
            with self.assertRaises(ValueError) as observed:
                with self.capture(root), diagnostics.wrap_shared():
                    first_wrapper = recovery.container
                    with diagnostics.wrap_shared():
                        self.assertIs(recovery.container, first_wrapper)
                        recovery.container('/private-path', 'db')
            self.assertIs(recovery.container, original)
        self.assertIs(observed.exception, error)
        data = diagnostics.validate_public_bytes((root / 'artifacts/community-diagnostics.json').read_bytes())
        inner = next(e for e in data['events'] if e['state'] == 'failed')
        self.assertEqual(inner, {'stage':'shared.recovery.container.db','state':'failed','code':'E_CONTAINER_CARDINALITY'})

    def test_validator_rejects_extra_fields_unknown_values_and_wrong_types(self):
        event = {'stage':'upgrade', 'state':'checkpoint', 'code':'none'}
        valid = {'schema':1,'events':[event]}
        cases = [dict(valid, credentials='private-secret'), dict(valid, schema=True),
                 {'schema':1,'events':[dict(event, message='private-secret')]},
                 {'schema':1,'events':[dict(event, stage='private-secret')]},
                 {'schema':1,'events':[dict(event, code='private-secret')]},
                 {'schema':1,'events':[dict(event, state='private-secret')]},
                 {'schema':1,'events':[dict(event, state='failed')]},
                 {'schema':1,'events':[dict(event, state='passed')]},
                 {'schema':1,'events':[event] * (diagnostics.MAX_EVENTS+1)}]
        for value in cases:
            with self.subTest(value_index=cases.index(value)):
                with self.assertRaisesRegex(ValueError, '^Invalid diagnostics export$'):
                    diagnostics.validate_public_bytes(json.dumps(value).encode())
        self.assertEqual(diagnostics.validate_public_bytes(json.dumps(valid).encode()), valid)

    def test_validator_rejects_duplicate_keys_and_oversize(self):
        for raw in [b'{"schema":1,"schema":1,"events":[]}', b'[' * 10000,
                    b'x' * (diagnostics.MAX_BYTES+1)]:
            with self.assertRaisesRegex(ValueError, '^Invalid diagnostics export$'):
                diagnostics.validate_public_bytes(raw)

    def test_bounded_read_and_symlink_export_refusal(self):
        root = self.owned_root()
        with self.capture(root):
            diagnostics.mark('upgrade.preflight.images')
        with patch.object(diagnostics, '_owned_root', return_value=root):
            with patch.object(Path, 'is_symlink', return_value=True):
                with self.assertRaises(ValueError):
                    diagnostics.read_public(root)
            self.assertEqual(diagnostics.read_public(root)['schema'], 1)

    def test_quota_failure_preserves_operation_and_incomplete_export_refused(self):
        root = self.owned_root()
        with self.capture(root), patch.object(diagnostics, 'MAX_EVENTS', 2):
            diagnostics.mark('upgrade.preflight.images')
            diagnostics.mark('upgrade.preflight.schema')
            result = 42
        self.assertEqual(result, 42)
        # Simulate the reader in a new process with no in-memory failure state.
        with patch.object(diagnostics, '_owned_root', return_value=root), patch.object(
            diagnostics, '_FAILED_PATHS', set()):
            with self.assertRaises(ValueError):
                diagnostics.read_public(root)

    def test_public_reader_refuses_fifo_without_blocking(self):
        import os
        if not hasattr(os, 'mkfifo'):
            self.skipTest('OS does not support FIFO creation')
        root = self.owned_root()
        path = root / 'artifacts/community-diagnostics.json'
        path.parent.mkdir()
        os.mkfifo(path, mode=0o600)
        with patch.object(diagnostics, '_owned_root', return_value=root):
            with self.assertRaises(ValueError):
                diagnostics.read_public(root)

    def test_reader_refuses_nonregular_descriptor_on_every_platform(self):
        import stat
        from types import SimpleNamespace
        root = self.owned_root()
        path = root / 'regular-fixture.json'
        path.write_bytes(b'{}')
        with patch.object(diagnostics.os, 'fstat',
                          return_value=SimpleNamespace(st_mode=stat.S_IFIFO)):
            with self.assertRaises(ValueError):
                diagnostics._read_bounded(path)

    def test_public_reader_refuses_valid_partial_schema(self):
        root = self.owned_root()
        path = root / 'artifacts/community-diagnostics.json'
        path.parent.mkdir()
        path.write_text('{"schema":1,"events":[{"stage":"upgrade","state":"started","code":"none"}]}')
        with patch.object(diagnostics, '_owned_root', return_value=root):
            with self.assertRaises(ValueError):
                diagnostics.read_public(root)


if __name__ == '__main__':
    unittest.main()

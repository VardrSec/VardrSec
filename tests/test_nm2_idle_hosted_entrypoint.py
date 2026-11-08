"""Bounded outside-checkout idle projections with permanent inner I/O denials."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_nm2_worker_idle_limit as vectors

SOURCE = Path(__file__).resolve().parents[1]
CHILD = r"""
import sys
sys.dont_write_bytecode = True
import importlib.abc, json, os, pathlib, runpy, socket, ssl
from unittest.mock import patch
scripts, kind, sidecar = sys.argv[1:]
assert kind in {'idle-success', 'idle-failure'}
source = pathlib.Path(scripts).parent.resolve()
outside = pathlib.Path(sidecar).parent.resolve()
assert str(source) not in sys.path
assert not outside.is_relative_to(source)
blocked = []
class GuardDenied(BaseException):
    pass
def denied(reason):
    blocked.append(reason)
    raise GuardDenied(reason)
allowed = [source, outside, pathlib.Path(sys.base_prefix).resolve(), pathlib.Path(sys.prefix).resolve()]
def audit(event, args):
    if event.startswith(('socket.', 'winreg.')) or event in {'subprocess.Popen', 'os.system', 'os.posix_spawn', 'sqlite3.connect'}:
        denied('network_process_registry_sqlite_refused')
    if event == 'ctypes.dlopen' and args and type(args[0]) is str and any(name in args[0].lower() for name in ('advapi32', 'crypt32', 'vaultcli')):
        denied('native_provider_refused')
    if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
        path = pathlib.Path(os.fsdecode(args[0])).resolve()
        if not any(path.is_relative_to(parent) for parent in allowed):
            denied('outside_source_stdlib_sidecar_refused')
        mode = args[1] if len(args)>1 else None
        flags = args[2] if len(args)>2 else 0
        write = (type(mode) is str and any(c in mode for c in 'wax+')) or (type(flags) is int and bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
        if write and not path.is_relative_to(outside):
            denied('write_outside_private_sidecar_refused')
class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'vardrrunner', 'keyring', 'keyrings', 'win32cred'}:
            denied('runner_or_credential_import_refused')
        return None
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
sys.path.insert(0, scripts)
with patch('socket.socket', side_effect=AssertionError('no network')), patch('subprocess.run', side_effect=AssertionError('no child process')):
    module = runpy.run_path(str(pathlib.Path(scripts) / 'nm2_worker_hosted.py'), run_name='isolated_idle_hosted_entrypoint')
    data = module['decode_receipt'](pathlib.Path(sidecar).read_bytes())
    if kind == 'idle-success':
        public = module['public_projection'](data['raw'], data['selection'])
        assert public['schema'] == 'vardr.nm2-worker-idle-public/1'
        assert public['status'] == 'selected_idle_control_slice_passed'
        assert public['measurements']['issued_attempts'] == 1
        assert public['measurements']['target_request_count'] == 5
        assert public['measurements']['native_exit_code'] == 124
        assert public['measurements']['operator_stop_requested'] is False
        assert public['measurements']['limits'] == {'max_attempts':None,'idle_timeout_seconds':60}
    else:
        public = module['failure_projection'](data['raw'], data['selection'])
        assert public == {'stage':'idle_control_observation','reason':'idle_native_exit_not_observed'}
assert not blocked
assert not any(name == 'vardrrunner' or name.startswith('vardrrunner.') for name in sys.modules)
print(json.dumps({'kind':kind,'projection':'passed','blocked_attempts':0,'runner_modules':0}))
"""


class IdleHostedEntrypoint(unittest.TestCase):
    def isolated(self, kind):
        raw, selection, *_ = vectors.vector()
        if kind == "idle-failure":
            raw.update(
                status="held",
                stage="idle_control_observation",
                reason="idle_native_exit_not_observed",
                error="private-canary",
            )
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve()
            self.assertFalse(outside.is_relative_to(SOURCE))
            sidecar = outside / "idle-sidecar.json"
            sidecar.write_text(
                json.dumps({"raw": raw, "selection": selection}), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    CHILD,
                    str(SOURCE / "tests"),
                    kind,
                    str(sidecar),
                ],
                executable=sys.executable,
                cwd=outside,
                capture_output=True,
                timeout=20,
            )
        self.assertEqual(result.returncode, 0, "bounded_idle_entrypoint_failed")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            json.loads(result.stdout),
            {
                "kind": kind,
                "projection": "passed",
                "blocked_attempts": 0,
                "runner_modules": 0,
            },
        )

    def test_idle_success_loads_real_independent_reader_outside_checkout(self):
        self.isolated("idle-success")

    def test_idle_failure_remains_fixed_and_redacted_outside_checkout(self):
        self.isolated("idle-failure")

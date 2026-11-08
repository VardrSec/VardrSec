"""Bounded outside-checkout count projections with permanent inner I/O denials."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_nm2_worker_count_projection as vectors

SOURCE = Path(__file__).resolve().parents[1]
CHILD = r"""
import importlib.abc, json, os, pathlib, runpy, socket, ssl, sys
from unittest.mock import patch
scripts, kind, sidecar = sys.argv[1:]
source = pathlib.Path(scripts).parent.resolve()
outside = pathlib.Path(sidecar).parent.resolve()
assert str(source) not in sys.path
assert not outside.is_relative_to(source)
sys.dont_write_bytecode = True
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
    if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
        path = pathlib.Path(os.fsdecode(args[0])).resolve()
        if not any(path.is_relative_to(parent) for parent in allowed):
            denied('outside_source_stdlib_sidecar_refused')
class Imports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'vardrrunner', 'keyring', 'keyrings'}:
            denied('runner_or_credential_import_refused')
        return None
sys.meta_path.insert(0, Imports())
sys.addaudithook(audit)
sys.path.insert(0, scripts)
with patch('socket.socket', side_effect=AssertionError('no network')),      patch('subprocess.run', side_effect=AssertionError('no child process')):
    module = runpy.run_path(str(pathlib.Path(scripts) / 'nm2_worker_hosted.py'), run_name='isolated_count_hosted_entrypoint')
    data = module['decode_receipt'](pathlib.Path(sidecar).read_bytes())
    if kind == 'count-success':
        public = module['public_projection'](data['raw'], data['selection'])
        assert public['schema'] == 'vardr.nm2-worker-count-public/1'
        assert public['status'] == 'selected_count_control_slice_passed'
        assert public['measurements']['issued_attempts'] == 1
        assert 'idle_seconds' not in public['measurements']
    else:
        assert kind == 'count-failure'
        public = module['failure_projection'](data['raw'], data['selection'])
        assert public == {'stage':'count_control_eligibility','reason':'count_second_job_not_eligible'}
assert not blocked
assert not any(name == 'vardrrunner' or name.startswith('vardrrunner.') for name in sys.modules)
print(json.dumps({'kind':kind,'projection':'passed','blocked_attempts':0,'runner_modules':0}))
"""


class CountHostedEntrypoint(unittest.TestCase):
    def isolated(self, kind):
        raw, selection = vectors.vector()
        if kind == "count-failure":
            raw.update(
                status="held",
                stage="count_control_eligibility",
                reason="count_second_job_not_eligible",
                error="private-canary",
            )
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve()
            self.assertFalse(outside.is_relative_to(SOURCE))
            sidecar = outside / "count-sidecar.json"
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
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
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

    def test_count_success_loads_real_independent_reader_outside_checkout(self):
        self.isolated("count-success")

    def test_count_failure_remains_fixed_and_redacted_outside_checkout(self):
        self.isolated("count-failure")

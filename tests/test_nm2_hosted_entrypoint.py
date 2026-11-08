"""Exercise real hosted projections under isolated, outside-checkout imports."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_nm2_worker_persistent_projection as vectors


SOURCE = Path(__file__).resolve().parents[1]
CHILD = r"""
import json, pathlib, runpy, socket, ssl, sys
from unittest.mock import patch
scripts, kind, sidecar = sys.argv[1:]
source = pathlib.Path(scripts).parent
assert str(source) not in sys.path
sys.path.insert(0, scripts)
with patch('socket.socket', side_effect=AssertionError('no network')), \
     patch('subprocess.run', side_effect=AssertionError('no child process')):
    module = runpy.run_path(str(pathlib.Path(scripts) / 'nm2_worker_hosted.py'),
                            run_name='isolated_hosted_entrypoint')
    data = module['decode_receipt'](pathlib.Path(sidecar).read_bytes())
    if kind == 'failure':
        projected = module['failure_projection'](data['raw'], data['selection'])
        assert projected['command_failure'] == data['raw']['command_failure']
        assert projected['stage'] == 'operator_worker_enable'
    else:
        projected = module['public_projection'](data['raw'], data['selection'])
        assert projected['schema'] == 'vardr.nm2-worker-persistent-public/1'
        assert projected['status'] == 'selected_availability_slice_passed'
        assert projected['measurements']['last_sequence'] == '35'
print(json.dumps({'kind': kind, 'projection': 'passed'}))
"""


class HostedEntrypointTests(unittest.TestCase):
    def isolated_projection(self, kind):
        raw, selection = vectors.vector()
        if kind == "failure":
            raw.update(
                status="held",
                stage="operator_worker_enable",
                reason="fixture_command_failed",
                command_failure={
                    "failure_phase": "enable_registration",
                    "failure_code": "host_refused",
                    "registration_failure": {
                        "checkpoint": "request",
                        "request_stage": "status",
                        "http_status": 409,
                    },
                },
            )
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve()
            self.assertFalse(outside.is_relative_to(SOURCE))
            sidecar = outside / "public-fixture.json"
            sidecar.write_text(
                json.dumps({"raw": raw, "selection": selection}), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    CHILD,
                    str(SOURCE / "tests"),
                    kind,
                    str(sidecar),
                ],
                cwd=outside,
                capture_output=True,
                timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertEqual(result.stderr, b"")
        self.assertEqual(
            json.loads(result.stdout), {"kind": kind, "projection": "passed"}
        )

    def test_isolated_failure_sidecar_keeps_registration_diagnostic(self):
        self.isolated_projection("failure")

    def test_isolated_success_uses_the_real_persistent_projector(self):
        self.isolated_projection("success")


if __name__ == "__main__":
    unittest.main()

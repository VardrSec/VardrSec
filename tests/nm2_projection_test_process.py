"""Run a hosted receipt reader in an isolated interpreter outside the checkout."""
import importlib.abc
import json
import os
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import sys
import tempfile
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent


def check_projection(test, raw, selection, projector, check, *, bounded_error=False):
    with tempfile.TemporaryDirectory() as temporary:
        outside = Path(temporary).resolve()
        test.assertFalse(outside.is_relative_to(SCRIPTS.parent))
        sidecar = outside / "receipt.json"
        sidecar.write_text(json.dumps({"raw": raw, "selection": selection}), encoding="utf-8")
        command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                   str(sidecar), projector, sys.modules[check.__module__].__file__, check.__name__]
        result = subprocess.run(command, cwd=outside, capture_output=True, timeout=20)
    error = "bounded_idle_entrypoint_failed" if bounded_error else result.stderr.decode("utf-8", "replace")
    test.assertEqual(result.returncode, 0, error)
    test.assertEqual(result.stderr, b"")
    test.assertEqual(result.stdout.splitlines(), [b"projection passed"])


def run_child(sidecar, projector, check_file, check):
    source = SCRIPTS.parent
    outside = Path(sidecar).resolve().parent
    assert str(source) not in sys.path
    assert not outside.is_relative_to(source)
    blocked = []
    allowed = (source, outside, Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve())

    class GuardDenied(BaseException):
        pass

    def deny(reason):
        blocked.append(reason)
        raise GuardDenied(reason)

    def audit(event, args):
        if event.startswith(("socket.", "winreg.")) or event in {
            "subprocess.Popen", "os.system", "os.posix_spawn", "sqlite3.connect"
        }:
            deny("network_process_registry_sqlite_refused")
        if event == "ctypes.dlopen" and args and isinstance(args[0], str):
            if any(name in args[0].lower() for name in ("advapi32", "crypt32", "vaultcli")):
                deny("native_provider_refused")
        if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(args[0])).resolve()
            if not any(path.is_relative_to(parent) for parent in allowed):
                deny("outside_source_stdlib_sidecar_refused")
            mode, flags = args[1:3]
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            if (isinstance(mode, str) and any(c in mode for c in "wax+")) or flags & write_flags:
                if not path.is_relative_to(outside):
                    deny("write_outside_private_sidecar_refused")

    class GuardImports(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {"vardrrunner", "keyring", "keyrings", "win32cred"}:
                deny("runner_or_credential_import_refused")
            return None

    sys.meta_path.insert(0, GuardImports())
    sys.addaudithook(audit)
    sys.path.insert(0, str(SCRIPTS))
    with patch("socket.socket", side_effect=AssertionError("no network")), \
         patch("subprocess.run", side_effect=AssertionError("no child process")):
        hosted = runpy.run_path(str(SCRIPTS / "nm2_worker_hosted.py"))
        receipt = hosted["decode_receipt"](Path(sidecar).read_bytes())
        projected = hosted[projector](receipt["raw"], receipt["selection"])
        runpy.run_path(check_file)[check](projected, receipt["raw"])
    assert not blocked
    assert not any(name == "vardrrunner" or name.startswith("vardrrunner.") for name in sys.modules)
    print("projection passed")


if __name__ == "__main__":
    run_child(*sys.argv[1:])

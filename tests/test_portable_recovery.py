"""Exercise recovery module closure outside the checkout; Docker is never invoked."""

import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_crypto
import recovery
import test_recovery as fixtures


ROOT = Path(__file__).resolve().parents[1]


class PortableRecoveryTests(unittest.TestCase):
    def test_current_bundle_restores_with_only_its_own_modules_then_runs_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            fixtures.RecoveryTests().snapshot(bundle)
            for name in recovery.FILES:
                if name == ".env":
                    (bundle / name).write_text("# synthetic pre-role configuration\n")
                else:
                    shutil.copyfile(ROOT / name, bundle / name)
            with gzip.open(bundle / "images.tar.gz", "wb") as output:
                output.write(b"synthetic image transport fixture")
            metadata = json.loads((bundle / "snapshot.json").read_text())
            metadata["files"] = {
                name: recovery.digest(bundle / name) for name in metadata["files"]
            }
            metadata["database"] = {"_sequences": "synthetic fingerprint"}
            (bundle / "snapshot.json").write_text(json.dumps(metadata))
            restored = root / "restored"
            # Stub only external Docker/image/state transport. Real validation,
            # copy, import and restore_role's legacy-config branch still run.
            code = r'''
import io,json,pathlib,subprocess,sys
bundle=pathlib.Path(sys.argv[1]); destination=pathlib.Path(sys.argv[2])
sys.path.insert(0,str(bundle))
import recovery
metadata=recovery.validate(bundle)
def command(*args,**kwargs):
    assert args[0]=='docker', args
    assert args[1:3] in [('container','ls'),('volume','ls'),('network','ls'),('image','inspect')],args
    return subprocess.CompletedProcess(args,0,stdout='')
def compose(*args,**kwargs):
    return subprocess.CompletedProcess(args,0,stdout='')
class ImageLoad:
    def __init__(self,*args,**kwargs):
        assert args[0]==['docker','image','load','--quiet']
        self.stdin=io.BytesIO()
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def wait(self):return 0
recovery.command=command
recovery.compose=compose
recovery.container=lambda *args: {'Mounts':[{'Type':'volume','Destination':mount,'Name':name} for name,(_,mount) in recovery.VOLUMES.items()]}
recovery.volume_stream=lambda *args: args[-1].read()
recovery.volume_fingerprint=lambda image,volume: metadata['volumes'][volume]
recovery.database_fingerprint=lambda *args: metadata['database']
recovery.subprocess.Popen=ImageLoad
recovery.restore(bundle,bundle,destination,'vardrsec-restore-portable')
import database_roles
assert pathlib.Path(database_roles.__file__).parent==bundle
assert (destination/'database_roles.py').read_bytes()==(bundle/'database_roles.py').read_bytes()
assert json.loads((destination/'restore-receipt.json').read_text())['database_verified']
print('portable restore dependency reached')
'''
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(bundle), str(restored)],
                cwd=root, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("portable restore dependency reached", result.stdout)
            # Exercise the restored CLI's imports/dispatch and refusal boundary,
            # with no original checkout or inherited PYTHONPATH on sys.path.
            cli = r'''
import pathlib,runpy,sys
destination=pathlib.Path(sys.argv[1]); bundle=sys.argv[2]
sys.path.insert(0,str(destination))
sys.argv=[str(destination/'vardrsec.py'),'restore','--backup',bundle,'--destination',str(destination),'--project','vardrsec-restore-portable']
try:runpy.run_path(sys.argv[0],run_name='__main__')
except SystemExit as error:
    assert error.code=='Restore destination must not exist',error.code
    print(error.code)
else:raise AssertionError('Existing installation was not refused')
'''
            result = subprocess.run(
                [sys.executable, "-I", "-c", cli, str(restored), str(bundle)],
                cwd=root, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Restore destination must not exist", result.stdout)

    def test_encrypted_package_allowlist_carries_new_role_module(self):
        # The encryption transport consumes the versioned validated manifest;
        # its outer allowlist must permit the new dependency without relaxing
        # the manifest's exact-member check for any historical format.
        self.assertIn("database_roles.py", backup_crypto.ALLOWED)
        self.assertEqual(
            backup_crypto.ALLOWED,
            set(recovery.FILES) | {"snapshot.json", "database.dump", "images.tar.gz"}
            | {f"{name}.tar.gz" for name in recovery.VOLUMES},
        )


if __name__ == "__main__":
    unittest.main()

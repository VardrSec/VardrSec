"""Synthetic restored-project install refusal, using unchanged recovery helpers."""
import json
import os
from pathlib import Path
import subprocess
import sys

import nm3_legacy_ci as ci
sys.path.insert(0, str(ci.SOURCE))
import recovery

RESTORE_PROJECT = 'vardrsec-restore-nm3-legacy'
FLAGS = {'backup_validated', 'restore_fingerprints_verified', 'restored_install_refused',
         'source_preserved_after_backup', 'restored_state_preserved_during_refusal',
         'bundled_recovery_cli_verified'}


def state(root, project):
    # Existing fingerprints cover logical database rows/sequences and named-volume
    # content/ownership/mode. This does not assert SQLite sidecar non-mutation.
    runner = recovery.container(root, 'runner', project)
    return {
        'database': recovery.database_fingerprint(root, project),
        'volumes': {name: recovery.volume_fingerprint(
            runner['Image'], recovery.volume_name(recovery.container(root, service, project), mount))
            for name, (service, mount) in recovery.VOLUMES.items()},
        'config': {name: recovery.digest(root / name) for name in recovery.FILES},
        'public_ca': recovery.digest(root / 'trust/root.crt') if (root / 'trust/root.crt').is_file() else None,
    }


# The parent validates data with the reviewed checkout before any bundled code
# executes. This child has no application import path except the generated bundle.
BUNDLED_RESTORE = r"""
import pathlib, runpy, sys
bundle = pathlib.Path.cwd().resolve()
sys.path.insert(0, str(bundle))
import recovery, database_roles, updater, backup_crypto
modules = (recovery, database_roles, updater, backup_crypto)
for module in modules:
    if pathlib.Path(module.__file__).resolve().parent != bundle:
        raise SystemExit('Unexpected recovery module origin')
destination, project = sys.argv[1:]
sys.argv = [str(bundle / 'vardrsec.py'), 'restore', '--backup', str(bundle),
            '--destination', destination, '--project', project]
namespace = runpy.run_path(str(bundle / 'vardrsec.py'), run_name='__main__')
if pathlib.Path(namespace['__file__']).resolve().parent != bundle:
    raise SystemExit('Unexpected CLI origin')
# The CLI creates and retains its own empty synthetic .update-lock. Reacquiring
# the existing lock verifies the CLI released it without deleting the file.
with updater.installation_lock(bundle):
    pass
lock = bundle / '.update-lock'
if not lock.is_file() or lock.is_symlink() or lock.read_bytes() != b'':
    raise SystemExit('Unexpected bundle lock state')
for module in modules:
    if pathlib.Path(module.__file__).resolve().parent != bundle:
        raise SystemExit('Unexpected recovery module origin')
"""


def bundled_restore(backup, restored):
    metadata = recovery.validate(backup)
    ci.require(metadata['schema_version'] == 4)
    ci.require(not backup.is_symlink())
    ci.require({path.name for path in backup.iterdir()} == set(metadata['files']) | {'snapshot.json'})
    ci.require(all(path.is_file() and not path.is_symlink() for path in backup.iterdir()))
    # Bind every executable file to this exact reviewed checkout, independently
    # of the self-reported manifest hashes. Never execute an arbitrary backup.
    for name in recovery.snapshot_files(4):
        if name.endswith('.py'):
            path, expected = backup / name, ci.SOURCE / name
            ci.require(path.is_file() and not path.is_symlink())
            ci.require(expected.is_file() and not expected.is_symlink())
            ci.require(path.read_bytes() == expected.read_bytes())
    ci.require(not (backup / '__pycache__').exists())
    env = {key: value for key, value in os.environ.items() if key != 'COMPOSE_PROJECT_NAME'}
    result = subprocess.run([sys.executable, '-I', '-B', '-c', BUNDLED_RESTORE,
                             str(restored), RESTORE_PROJECT], cwd=backup, env=env,
                            capture_output=True, text=True, timeout=1800)
    ci.require(result.returncode == 0)
    ci.require({path.name for path in backup.iterdir()} == set(metadata['files']) | {'snapshot.json', '.update-lock'})
    lock = backup / '.update-lock'
    ci.require(lock.is_file() and not lock.is_symlink() and lock.read_bytes() == b'')
    ci.require(recovery.validate(backup) == metadata)


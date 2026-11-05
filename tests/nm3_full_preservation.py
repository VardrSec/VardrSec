"""Synthetic restored-project install refusal, using unchanged recovery helpers."""
import json
import os
from pathlib import Path
import subprocess
import sys

import nm3_full_install_ci as ci
sys.path.insert(0, str(ci.SOURCE))
import recovery

RESTORE_PROJECT = 'vardrsec-restore-nm3-guard'
FLAGS = {'backup_validated', 'restore_fingerprints_verified', 'restored_install_refused',
         'source_preserved_after_backup', 'restored_state_preserved_during_refusal'}


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


def exercise(root, private):
    backup, restored = private / 'backup', private / 'restored'
    ci.require(not any(os.path.lexists(path) for path in (backup, restored)))
    # Reuse NM-2's conservative image/copy capacity estimate, with no pruning.
    total = sum(int(recovery.command('docker', 'image', 'inspect', tag, '--format', '{{.Size}}',
                                    capture_output=True, text=True).stdout.strip())
                for tag in ('vardrsec-db:development', 'vardrmap-api:development',
                            'vardrmap-web:development', 'vardrsec-proxy:development', 'vardrrunner:development'))
    ci.require(ci.shutil.disk_usage(private).free >= 4 * total + 2 * 1024**3)
    # Add only explicit synthetic rows/sequence in the owned fixture database.
    recovery.sql(root, "CREATE TABLE nm3_guard_fixture(id bigserial PRIMARY KEY, note text NOT NULL); "
                       "INSERT INTO nm3_guard_fixture(note) VALUES ('synthetic-one'),('synthetic-two')")
    recovery.backup(root, backup)
    snapshot = recovery.validate(backup)
    source_before = state(root, 'nm3-full-fixture')
    ci.require(source_before['database'] == snapshot['database'])
    ci.require(source_before['volumes'] == snapshot['volumes'])
    recovery.restore(root, backup, restored, RESTORE_PROJECT)
    restored_before = state(restored, RESTORE_PROJECT)
    ci.require(restored_before['database'] == snapshot['database'])
    ci.require(restored_before['volumes'] == snapshot['volumes'])
    ci.require(not (restored / '.sources').exists())
    # Critical regression: rely on the project recorded by recovery in .env,
    # not the source project's process override. No .env parsing or rewriting.
    env = {key: value for key, value in os.environ.items() if key != 'COMPOSE_PROJECT_NAME'}
    rejected = subprocess.run([sys.executable, 'vardrsec.py', 'install'], cwd=restored,
                              env=env, capture_output=True, text=True, timeout=120)
    ci.require(rejected.returncode == 2)
    ci.require('This installation has been started before' in rejected.stderr)
    ci.require(not (restored / '.sources').exists())
    ci.require(state(restored, RESTORE_PROJECT) == restored_before)
    ci.require(state(root, 'nm3-full-fixture') == source_before)
    ci.require(recovery.validate(backup) == snapshot)
    # The image override is separate from FILES and must also remain as restored.
    active = json.loads((restored / '.active-images.json').read_text())
    ci.require(active == {'services': {name: {'image': image} for name, image in snapshot['images'].items()}})
    return {name: True for name in sorted(FLAGS)}


def main():
    env = os.environ
    root = Path(env['RUNNER_TEMP']).resolve() / 'nm3-full-fresh'
    private = root / 'private'; fixture = private / 'fixture'
    ci.require(env.get('DOCKER_HOST') == 'unix:///var/run/docker.sock')
    ci.require(env.get('DOCKER_CONFIG') == str(private / 'docker-config'))
    ci.require(env.get('COMPOSE_PROJECT_NAME') == 'nm3-full-fixture')
    # The caller already established an empty dedicated daemon before installing.
    # Recheck all hosted guards without rejecting the three caller-owned selectors.
    ci.host_guard({k: v for k, v in env.items() if k not in
                   {'DOCKER_HOST', 'DOCKER_CONFIG', 'COMPOSE_PROJECT_NAME'}}, preservation=True)
    ci.require(Path.cwd() == fixture)
    result = exercise(fixture, private)
    with (private / 'preservation.json').open('x') as output:
        json.dump(result, output); output.write('\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Caller retains private logs, but even local errors never print values.
        print('Preservation verification failed; no acceptance claimed')
        raise SystemExit(1) from None

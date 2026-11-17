"""One disposable Ubuntu check extending the baseline's real Gate fixture."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

BASELINE = '25040b000e3a99c7c0218f58cb08ec73bc189373'
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import gate_acceptance as gate
import recovery
from ubuntu_installation import host


def command(*args, cwd=None, check=True, **kwargs):
    return subprocess.run([str(arg) for arg in args], cwd=cwd, check=check,
                          capture_output=True, text=True, timeout=kwargs.pop('timeout', 1800), **kwargs)


def cli(root, *args, check=True):
    result = command(sys.executable, root / 'vardrsec.py', *args, cwd=root, check=False)
    if check and result.returncode:
        # Keep private command output on this disposable VM, never in public receipts.
        (PRIVATE / 'last-cli-failure.txt').write_text(result.stdout + result.stderr)
        raise RuntimeError(f'CLI {args[0]} failed with exit {result.returncode}')
    return result


def stopped(root, project, image=None, fingerprint=None):
    info = recovery.container(root, 'runner', project)
    assert info['State']['Running'] is False
    if image is not None:
        assert info['Image'] == image
    volume = recovery.volume_name(info, recovery.VOLUMES['runner-state'][1])
    if fingerprint is not None:
        assert recovery.volume_fingerprint(info['Image'], volume) == fingerprint
    return volume


def export_same(root, name, receipt):
    destination = PRIVATE / name
    cli(root, 'runner', '--output-directory', destination, '--', 'audit', 'export-run',
        receipt['run_id'], '--output', '/exports/result')
    assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (destination / 'result').iterdir()} == receipt['exports']


def fixture_image(base, name, extra):
    folder = PRIVATE / name
    folder.mkdir()
    alias = 'vardrsec-mapless:qualification-base'
    command('docker', 'tag', base, alias)
    (folder / 'Dockerfile').write_text(f'FROM {alias}\n{extra}\n')
    command('docker', 'build', '--pull=false', '-t', f'vardrsec-mapless:{name}', folder)
    return command('docker', 'image', 'inspect', f'vardrsec-mapless:{name}',
                   '--format', '{{.Id}}').stdout.strip()


def lifecycle(root, project):
    # The existing gate fixture copies its minimal portable files; include the
    # unchanged public launchers to exercise the current full backup file set.
    for name in recovery.LAUNCHER_FILES:
        shutil.copy2(ROOT / name, root / name)
    receipt = json.loads((ROOT / 'artifacts/installed-gate/mapless.json').read_text())
    base = receipt['image_id']
    pins = json.loads((root / 'versions.json').read_text())
    assert receipt['sources'] == {k: pins['components'][k]['commit'] for k in ('runner', 'gate')}
    cli(root, 'doctor')
    volume = stopped(root, project, base)
    fingerprint = recovery.volume_fingerprint(base, volume)
    result = {'baseline': BASELINE, 'ubuntu': '24.04', 'architecture': platform.machine(),
              'baseline_runner_image': base, 'sources': receipt['sources'],
              'completed_run_id': receipt['run_id'], 'original_exports': receipt['exports']}

    print('Checking Mapless encrypted backup and restore', flush=True)
    bundle = PRIVATE / 'backup'
    cli(root, 'backup', '--destination', bundle)
    metadata = recovery.validate(bundle)
    assert metadata['images'] == {'runner': base}
    assert metadata['volumes']['runner-state'] == fingerprint
    identity = PRIVATE / 'recovery-identity.txt'
    command('age-keygen', '--output', identity)
    recipient = command('age-keygen', '-y', identity).stdout.strip()
    cli(root, 'seal-backup', '--backup', bundle, '--destination', PRIVATE / 'backup.age', '--recipient', recipient)
    cli(root, 'unseal-backup', '--backup', PRIVATE / 'backup.age', '--destination', PRIVATE / 'unsealed', '--identity', identity)
    assert recovery.digest(bundle / 'snapshot.json') == recovery.digest(PRIVATE / 'unsealed/snapshot.json')
    restored = PRIVATE / 'restored'
    cli(root, 'restore', '--backup', PRIVATE / 'unsealed', '--destination', restored,
        '--project', 'vardrsec-restore-alpha-backup')
    stopped(restored, 'vardrsec-restore-alpha-backup', base, fingerprint)
    assert json.loads((restored / 'restore-receipt.json').read_text())['runner_state_verified']
    export_same(restored, 'restored-export', receipt)
    stopped(root, project, base, fingerprint)
    result['encrypted_backup_restore'] = True

    def candidate(name, image):
        path = PRIVATE / f'{name}.json'
        path.write_text(json.dumps({'schema_version': 2, 'mode': 'mapless',
                                    'images': {'runner': image}, 'components': receipt['sources']}))
        return path

    def update(name, image, check=True):
        return cli(root, 'update', '--candidate', candidate(name, image),
                   '--backup', PRIVATE / (name + '-backup'), '--destination', PRIVATE / name,
                   '--project', 'vardrsec-restore-alpha-' + name, check=check)

    print('Checking Mapless rehearsal refusal and cancellation', flush=True)
    bad = fixture_image(base, 'bad-diagnostics', 'ENV PYTHONHOME=/intentional-qualification-failure')
    assert update('rejected', bad, check=False).returncode != 0
    assert json.loads((root / '.update-state.json').read_text())['phase'] == 'rehearsal'
    stopped(root, project, base, fingerprint)
    cli(root, 'cancel-update')
    assert not (root / '.update-state.json').exists()
    stopped(root, project, base, fingerprint)
    result['failed_rehearsal_and_cancellation'] = True

    print('Checking Mapless compatible image update', flush=True)
    good = fixture_image(base, 'compatible', 'LABEL qualification.fixture=compatible')
    assert good != base
    update('successful', good)
    assert not (root / '.update-state.json').exists()
    assert json.loads((root / '.last-update.json').read_text())['status'] == 'success'
    stopped(root, project, good, fingerprint)
    stopped(PRIVATE / 'successful', 'vardrsec-restore-alpha-successful', good, fingerprint)
    export_same(root, 'updated-export', receipt)
    result['compatible_update_state_and_exports'] = True
    result['updated_runner_image'] = good

    print('Checking Mapless interrupted apply and snapshot recovery', flush=True)
    # Interrupt the real updater only after its durable original-mutation phase.
    next_image = fixture_image(base, 'interrupted', 'LABEL qualification.fixture=interrupted')
    args = [sys.executable, str(root / 'vardrsec.py'), 'update', '--candidate', str(candidate('interrupted', next_image)),
            '--backup', str(PRIVATE / 'interrupted-backup'), '--destination', str(PRIVATE / 'interrupted'),
            '--project', 'vardrsec-restore-alpha-interrupted']
    with (PRIVATE / 'interrupted-output.txt').open('w') as log:
        process = subprocess.Popen(args, cwd=root, stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 600
        while True:
            pending = root / '.update-state.json'
            if pending.exists() and json.loads(pending.read_text())['phase'] == 'applying':
                os.killpg(process.pid, signal.SIGKILL)
                break
            assert process.poll() is None, 'Updater exited before the intended interruption'
            assert time.monotonic() < deadline, 'Updater did not reach applying phase'
            time.sleep(0.02)
        process.wait(timeout=30)
    assert json.loads((root / '.update-state.json').read_text())['phase'] == 'applying'
    assert cli(root, 'cancel-update', check=False).returncode != 0
    recovery_backup = PRIVATE / 'interrupted-backup'
    recovery_metadata = recovery.validate(recovery_backup)
    recovered = PRIVATE / 'recovered'
    cli(root, 'restore', '--backup', recovery_backup, '--destination', recovered,
        '--project', 'vardrsec-restore-alpha-recovered')
    stopped(recovered, 'vardrsec-restore-alpha-recovered', good,
            recovery_metadata['volumes']['runner-state'])
    export_same(recovered, 'recovered-export', receipt)
    assert not (recovered / '.update-state.json').exists()
    result['interrupted_apply_refuses_cancel_and_restores'] = True
    result['status'] = 'passed'
    (ROOT / 'artifacts/mapless-lifecycle-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: Mapless backup/restore, update, cancellation and interrupted-apply recovery', flush=True)


host()
assert platform.machine() == 'x86_64'
assert command('git', 'rev-parse', 'HEAD').stdout.strip() == BASELINE
assert not command('git', 'status', '--porcelain').stdout.strip()
assert not command('docker', 'ps', '-aq').stdout.strip()
assert not command('docker', 'volume', 'ls', '-q').stdout.strip()
PRIVATE = Path(os.environ['RUNNER_TEMP']) / 'alpha-mapless-lifecycle'
PRIVATE.mkdir(mode=0o700)
original_docker = gate.docker
extended = False


def extend_before_cleanup(*args, **kwargs):
    global extended
    # Reuse the completed fixture before its normal final volume cleanup. Every
    # Docker command remains real; no product source or fixture verdict is mocked.
    if args[:2] == ('compose', '-f') and '--volumes' in args and 'down' in args:
        assert not extended
        extended = True
        lifecycle(Path(args[2]).parent, args[args.index('-p') + 1])
    return original_docker(*args, **kwargs)


gate.docker = extend_before_cleanup
gate.run_mapless_workflow()
assert extended

"""Private fresh-VM journey; imported helpers and raw output never become artifacts."""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.request

PROJECT = 'vardrsec-compose-review'
RESTORE_PROJECT = 'vardrsec-restore-nm3-lifecycle'
SCHEMA = '0038managedstops'
BRANCH = 'refs/heads/codex/nm3-community-full-verification'
CHECKS = (
    'installed_reviewed_assessment', 'hashed_evidence', 'write_readback_retest_reports',
    'trusted_browser_csrf_and_scoped_key', 'stop_start_retention', 'encrypted_backup',
    'authenticated_unseal', 'separate_restore', 'exact_image_ids', 'schema_0038',
    'source_state_preserved', 'restored_evidence_and_ca', 'password_reset_revokes_sessions',
    'authenticated_restored_doctor', 'no_runner_service_started',
)
STAGES = ('browser_build', 'assessment', 'encrypted_backup', 'unseal', 'restore',
          'start', 'restored_checks', 'complete')
FAILURE_CODES = ('command_exit_nonzero', 'operation_timed_out', 'operation_refused',
                 'validation_refused', 'unexpected_result', 'operation_failed')
MARKER = b'nm3 synthetic retained runner evidence'


class CommandFailure(RuntimeError):
    """Fixed child-command failure without its private output."""


def require(condition):
    if not condition:
        raise ValueError('Installed lifecycle verification refused')


def command(args, *, cwd, env, forbidden=()):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise CommandFailure('command_exit_nonzero')
    require(not any(value in result.stdout + result.stderr for value in forbidden))
    return result.stdout


def session(restored, password):
    client = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(restored / 'trust/root.crt'))))

    def request(path, data=None, csrf=None):
        headers = {'Origin': 'https://localhost:8443', 'Content-Type': 'application/json'}
        if csrf:
            headers['X-CSRF-Token'] = csrf
        message = urllib.request.Request('https://localhost:8443/backend' + path, headers=headers,
            data=None if data is None else json.dumps(data).encode())
        with client.open(message, timeout=20) as response:
            return json.load(response)

    request('/auth/local/login', {'username': 'operator', 'password': password})
    return request


def verify_recovery(fixture, private, env, mark):
    # These modules must come from the exact exported distribution candidate.
    import recovery
    import backup_crypto
    from gate_acceptance import verify_retained

    accepted = json.loads((fixture / 'artifacts/installed-gate/accepted.json').read_text())
    expected = ['blocked', 'vulnerable', 'fixed', 'unavailable', 'write-vulnerable', 'write-fixed']
    require(accepted['rendered'] == expected and len(accepted['jobs']) == 6)
    require(recovery.sql(fixture, 'SELECT version_num FROM alembic_version', PROJECT) == SCHEMA)
    original_ca = recovery.digest(fixture / 'trust/root.crt')
    recovery.compose(fixture, 'run', '--rm', '--no-deps', '--entrypoint', 'python', 'runner', '-c',
        "from pathlib import Path; (Path.home()/'.vardrmap'/'nm3-lifecycle-evidence').write_bytes(" + repr(MARKER) + ")",
        project=PROJECT, capture_output=True, text=True)
    identity = private / 'identity.txt'
    command(['age-keygen', '--output', str(identity)], cwd=private, env=env)
    identity.chmod(0o600)
    recipient = command(['age-keygen', '-y', str(identity)], cwd=private, env=env).strip()
    encrypted = private / 'snapshot.age'
    mark('encrypted_backup')
    backup_crypto.encrypted_backup(fixture, encrypted, recipient)
    require(not list(private.glob('.vardrsec-backup-*')))
    unsealed = private / 'unsealed'
    mark('unseal')
    backup_crypto.unseal(encrypted, unsealed, identity)
    metadata = recovery.validate(unsealed)
    require(metadata['schema_version'] == 4)
    require(set(metadata['images']) == recovery.SERVICES)

    # Exercise the actual bundled restore entrypoint outside the source checkout.
    restored = private / 'restored'
    mark('restore')
    command([sys.executable, str(unsealed / 'vardrsec.py'), 'restore', '--backup', str(unsealed),
             '--destination', str(restored), '--project', RESTORE_PROJECT], cwd=private, env=env)
    restore_env = {**env, 'COMPOSE_PROJECT_NAME': RESTORE_PROJECT}
    mark('start')
    command([sys.executable, str(restored / 'vardrsec.py'), 'start'], cwd=private, env=restore_env)
    command([sys.executable, str(restored / 'vardrsec.py'), 'export-ca'], cwd=private, env=restore_env)
    mark('restored_checks')
    require(recovery.digest(restored / 'trust/root.crt') == original_ca)
    require(recovery.sql(restored, 'SELECT version_num FROM alembic_version', RESTORE_PROJECT) == SCHEMA)
    for service, image in metadata['images'].items():
        require(recovery.container(restored, service, RESTORE_PROJECT)['Image'] == image)
    require(recovery.database_fingerprint(fixture, PROJECT) == metadata['database'])
    for name, (service, mount) in recovery.VOLUMES.items():
        volume = recovery.volume_name(recovery.container(fixture, service, PROJECT), mount)
        require(recovery.volume_fingerprint(metadata['images']['runner'], volume) == metadata['volumes'][name])
    require(recovery.digest(fixture / 'trust/root.crt') == original_ca)
    retained_marker = recovery.compose(restored, 'run', '--rm', '--no-deps', '--entrypoint',
        'python', 'runner', '-c', "import hashlib; from pathlib import Path; "
        "print(hashlib.sha256((Path.home()/'.vardrmap'/'nm3-lifecycle-evidence').read_bytes()).hexdigest())",
        project=RESTORE_PROJECT, capture_output=True, text=True).stdout.strip()
    require(retained_marker == hashlib.sha256(MARKER).hexdigest())
    require(recovery.sql(restored, "SELECT count(*) FROM pg_tables WHERE schemaname='public' "
                         "AND tableowner <> 'vardrmap_app'", RESTORE_PROJECT) == '0')

    reset = recovery.compose(restored, 'exec', '-T', 'api', 'python', '-m', 'local_accounts',
        'reset-password', '--username', 'operator', '--generate-password', project=RESTORE_PROJECT,
        capture_output=True, text=True)
    marker = 'Generated password (store securely; shown once): '
    require(reset.stdout.count(marker) == 1)
    password = reset.stdout.split(marker, 1)[1].strip()
    require(recovery.sql(restored, 'SELECT count(*) FROM local_sessions', RESTORE_PROJECT) == '0')
    request = session(restored, password)
    verify_retained(request, accepted)
    csrf = request('/auth/local/session')['csrfToken']
    created = request('/auth/apikeys', {'label': 'Synthetic restored Runner', 'scope': 'runner'}, csrf)
    require(created['scope'] == 'runner')
    doctor = command([sys.executable, str(restored / 'vardrsec.py'), 'doctor'], cwd=private,
                     env={**restore_env, 'VARDRMAP_API_KEY': created['token']},
                     forbidden=(created['token'], password))
    require(created['token'] not in doctor and json.loads(doctor)['healthy'] is True)
    running = recovery.compose(restored, 'ps', '--status', 'running', '--services',
                               project=RESTORE_PROJECT, capture_output=True, text=True).stdout
    require(set(running.splitlines()) == {'db', 'api', 'web', 'proxy'})
    return {name: True for name in CHECKS}


def run(fixture, summary):
    env = dict(os.environ)
    root = Path(env['RUNNER_TEMP']).resolve() / 'nm3-community-full' / 'private'
    require(__debug__ and env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_REPOSITORY') == 'VardrSec/VardrSec'
            and env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REF') == BRANCH
            and env.get('COMPOSE_PROJECT_NAME') == PROJECT
            and env.get('DOCKER_HOST') == 'unix:///var/run/docker.sock'
            and env.get('DOCKER_CONFIG') == str(root / 'docker-config'))
    require(fixture.resolve() == root / 'fixture' and summary == root / 'lifecycle/summary.json')
    private = summary.parent
    require(not os.path.lexists(private))
    private.mkdir(mode=0o700)
    # Ignore ambient Python import paths for bundled child commands.
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    sys.path[:0] = [str(fixture), str(fixture / 'tests')]
    receipt = {'status': 'failed_or_unproven', 'stage': 'browser_build', 'checks': {}}
    def mark(stage):
        require(stage in STAGES)
        receipt['stage'] = stage
        print('NM3_LIFECYCLE_STAGE ' + stage, flush=True)
    try:
        command(['docker', 'build', '-t', 'vardrsec-browser:acceptance', str(fixture / 'tests/browser')],
                cwd=fixture, env=env)
        mark('assessment')
        command([sys.executable, str(fixture / 'tests/compose_acceptance.py')], cwd=fixture, env=env)
        mark('encrypted_backup')
        receipt['checks'] = verify_recovery(fixture, private, env, mark)
        receipt.update(status='passed', stage='complete')
    except subprocess.TimeoutExpired:
        receipt['failure_code'] = 'operation_timed_out'
    except (CommandFailure, subprocess.CalledProcessError):
        receipt['failure_code'] = 'command_exit_nonzero'
    except AssertionError:
        receipt['failure_code'] = 'validation_refused'
    except (ValueError, OSError):
        receipt['failure_code'] = 'operation_refused'
    except (KeyError, TypeError):
        receipt['failure_code'] = 'unexpected_result'
    except Exception:
        receipt['failure_code'] = 'operation_failed'
    finally:
        with summary.open('x') as output:
            json.dump(receipt, output, indent=2); output.write('\n')
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    args = parser.parse_args()
    try:
        raise SystemExit(run(args.fixture, args.summary))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('Installed lifecycle verification refused; no acceptance claimed')
        raise SystemExit(1) from None

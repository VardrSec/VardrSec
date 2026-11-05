"""Candidate-specific same-image update/cancellation in the guarded hosted fixture."""
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.request
from unittest.mock import patch

import nm3_full_install_ci as ci
sys.path.insert(0, str(ci.SOURCE))
import recovery
import updater
import update_acceptance as existing

PROJECT = 'nm3-full-fixture'
FLAGS = {'real_private_rehearsal_verified', 'preapply_interruption_retained',
         'verified_cancellation_resumed_baseline', 'same_image_update_completed',
         'synthetic_rows_sequence_ca_preserved', 'version4_backups_retained'}


def authenticate(root, *, details=False):
    # Reuse the established local-account and CSRF/API-key journey. No real key,
    # external endpoint, account reset, target execution or authorization bypass.
    ci.require(recovery.sql(root, 'SELECT count(*) FROM local_credentials', PROJECT) == '0')
    result = recovery.compose(root, 'exec', '-T', 'api', 'python', '-m', 'local_accounts',
                              'init', '--username', 'operator', '--generate-password',
                              project=PROJECT, capture_output=True, text=True)
    password = result.stdout.split('Generated password (store securely; shown once): ', 1)[1].strip()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(root / 'trust/root.crt'))))
    def request(path, data=None, csrf=None):
        headers = {'Origin': 'https://localhost:8443', 'Content-Type': 'application/json'}
        if csrf:
            headers['X-CSRF-Token'] = csrf
        req = urllib.request.Request('https://localhost:8443/backend' + path, headers=headers,
                                     data=None if data is None else json.dumps(data).encode())
        with client.open(req, timeout=20) as response:
            return json.load(response)
    request('/auth/local/login', {'username': 'operator', 'password': password})
    csrf = request('/auth/local/session')['csrfToken']
    key = request('/auth/apikeys', {'label': 'Synthetic update diagnostics', 'scope': 'runner'}, csrf)
    return key if details else key['token']


def retained_state(root):
    # Authentication/diagnostic records may legitimately change during startup.
    # Scope retention to the seeded rows, their sequence and public CA bytes.
    fingerprints = recovery.database_fingerprint(root, PROJECT)
    return (fingerprints['nm3_update_fixture'],
            recovery.sql(root, 'SELECT last_value,is_called FROM nm3_update_fixture_id_seq', PROJECT),
            recovery.digest(root / 'trust/root.crt'))


def interrupted_update(root, candidate, backup, rehearsal):
    real_verify = updater.verify_private
    verified = []
    def interrupt_after_real_rehearsal(directory, project):
        ci.require(directory == rehearsal and project == 'vardrsec-restore-nm3-interrupted')
        real_verify(directory, project)
        verified.append(True)
        raise KeyboardInterrupt('Synthetic interruption before source mutation')
    with patch.object(updater, 'verify_private', side_effect=interrupt_after_real_rehearsal):
        try:
            updater.update(root, candidate, backup, rehearsal, 'vardrsec-restore-nm3-interrupted')
        except ValueError:
            ci.require(verified == [True])
        else:
            ci.require(False)
    record = json.loads((root / updater.STATE).read_text())
    ci.require(record['phase'] == 'rehearsal' and record['status'] == 'failed')
    try:
        with updater.operation_guard(root, 'start'):
            ci.require(False)
    except ValueError as error:
        ci.require('pending or failed' in str(error))
    ci.require(all(not recovery.container(root, service, PROJECT)['State']['Running']
                   for service in ('api', 'web', 'proxy')))


def exercise(root, private):
    artifacts = private / 'updates'
    ci.require(not os.path.lexists(artifacts)); artifacts.mkdir(mode=0o700)
    total = sum(int(recovery.command('docker', 'image', 'inspect', tag, '--format', '{{.Size}}',
                                    capture_output=True, text=True).stdout.strip())
                for tag in ('vardrsec-db:development', 'vardrmap-api:development',
                            'vardrmap-web:development', 'vardrsec-proxy:development', 'vardrrunner:development'))
    ci.require(ci.shutil.disk_usage(private).free >= 8 * total + 4 * 1024**3)
    token = authenticate(root)
    recovery.sql(root, "CREATE TABLE nm3_update_fixture(id bigserial PRIMARY KEY, note text NOT NULL); "
                       "INSERT INTO nm3_update_fixture(note) VALUES ('synthetic-one'),('synthetic-two')", PROJECT)
    baseline_state = retained_state(root)
    _, baseline_images = updater.image_set(root)
    existing.ROOT, existing.PROJECT, existing.ARTIFACTS = root, PROJECT, artifacts
    candidate = existing.manifest('same-images', baseline_images['api'])
    ci.require(json.loads(candidate.read_text())['images'] == baseline_images)
    with patch.dict(os.environ, {'VARDRMAP_API_KEY': token}):
        interrupted_update(root, candidate, artifacts / 'interrupted-backup', artifacts / 'interrupted')
        before = recovery.validate(artifacts / 'interrupted-backup')
        ci.require(before['schema_version'] == 4)
        ci.require(retained_state(root) == baseline_state)
        updater.cancel(root)
        ci.require(not (root / updater.STATE).exists())
        ci.require(json.loads((root / '.last-update.json').read_text())['status'] == 'cancelled')
        ci.require(retained_state(root) == baseline_state)
        updater.update(root, candidate, artifacts / 'completed-backup', artifacts / 'completed',
                       'vardrsec-restore-nm3-completed')
    ci.require(not (root / updater.STATE).exists())
    record = json.loads((root / '.last-update.json').read_text())
    ci.require(record['phase'] == 'complete' and record['status'] == 'success')
    ci.require(retained_state(root) == baseline_state)
    ci.require(updater.image_set(root)[1] == baseline_images)
    ci.require(recovery.validate(artifacts / 'interrupted-backup') == before)
    ci.require(recovery.validate(artifacts / 'completed-backup')['schema_version'] == 4)
    return {name: True for name in sorted(FLAGS)}


def main():
    env = os.environ
    private = Path(env['RUNNER_TEMP']).resolve() / 'nm3-full-fresh/private'
    ci.require(env.get('DOCKER_HOST') == 'unix:///var/run/docker.sock')
    ci.require(env.get('DOCKER_CONFIG') == str(private / 'docker-config'))
    ci.require(env.get('COMPOSE_PROJECT_NAME') == PROJECT)
    ci.host_guard({k: v for k, v in env.items() if k not in
                   {'DOCKER_HOST', 'DOCKER_CONFIG', 'COMPOSE_PROJECT_NAME'}}, preservation=True)
    ci.require(Path.cwd() == private / 'fixture')
    result = exercise(private / 'fixture', private)
    with (private / 'preservation.json').open('x') as output:
        json.dump(result, output); output.write('\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Update verification failed; no acceptance claimed')
        raise SystemExit(1) from None

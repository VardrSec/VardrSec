"""Legacy API-created control metadata only; no tool or managed issuer is invoked."""
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

import nm3_legacy_ci as ci
sys.path.insert(0, str(ci.SOURCE))
import database_roles
import recovery
import community_ci as historical_build
from nm3_legacy_recovery import bundled_restore, state, RESTORE_PROJECT

PROJECT = 'nm3-full-fixture'
ORIGIN = 'https://localhost:8443'
FLAGS = {'ownership_hashes_preserved', 'duration_concurrency_preserved',
         'wrong_principal_refused', 'expired_permission_not_renewed',
         'v4_bundle_restore_verified', 'source_snapshot_preserved'}


class API:
    def __init__(self, ca):
        self.client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
        self.csrf = None

    def request(self, path, data=None, *, method=None, key=None, expected=200):
        ci.require(path.startswith('/') and not path.startswith('//'))
        headers = {'Origin': ORIGIN, 'Content-Type': 'application/json'}
        if key:
            headers['Authorization'] = 'Bearer ' + key
        elif self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        request = urllib.request.Request(ORIGIN + '/backend' + path, headers=headers,
            data=None if data is None else json.dumps(data).encode(), method=method)
        try:
            with self.client.open(request, timeout=20) as response:
                ci.require(response.status == expected)
                return json.load(response)
        except urllib.error.HTTPError as error:
            # Never emit HTTP bodies/headers, credentials or arbitrary error strings.
            ci.require(error.code == expected and expected >= 400)
            return None


def authenticate(root):
    ci.require(recovery.sql(root, 'SELECT count(*) FROM local_credentials', PROJECT) == '0')
    result = recovery.compose(root, 'exec', '-T', 'api', 'python', '-m', 'local_accounts',
        'init', '--username', 'operator', '--generate-password', project=PROJECT,
        capture_output=True, text=True)
    password = result.stdout.split('Generated password (store securely; shown once): ', 1)[1].strip()
    api = API(root / 'trust/root.crt')
    api.request('/auth/local/login', {'username': 'operator', 'password': password})
    api.csrf = api.request('/auth/local/session')['csrfToken']
    keys = [api.request('/auth/apikeys', {'label': 'Synthetic legacy ' + label, 'scope': 'runner'})
            for label in ('owner', 'other-principal')]
    ci.require(keys[0]['token'] != keys[1]['token'])
    return api, keys


def seed(api, keys):
    engagement = api.request('/engagements', {'name': 'Synthetic legacy retention',
                                              'engagement_type': 'internal', 'engagement_status': 'active'})
    eid = str(uuid.UUID(engagement['id']))
    api.request(f'/engagements/{eid}/duration-policy', {'limit_seconds': 120}, method='PUT')
    api.request(f'/engagements/{eid}/concurrency-policy', {'limit': 1}, method='PUT')
    # An unmarked legacy metadata job with no scope/targets. No worker or HTTP tool runs.
    job = api.request(f'/engagements/{eid}/jobs', {'tool_type': 'httpx', 'target_source': 'scope'})
    jid = str(uuid.UUID(job['id']))
    binding = {'runner_id': str(uuid.uuid4()), 'origin': ORIGIN,
               'concurrency_budget': True, 'duration_seconds': 30}
    claimed = api.request(f'/jobs/{jid}/claim', binding, key=keys[0]['token'])
    control = claimed['execution_control']
    ci.require(claimed['status'] == 'running' and control['capacity_reserved'] is True)
    ci.require(control['duration_budget']['allocated_seconds'] == 30)
    body = {**binding, 'token': control['token']}
    api.request(f'/jobs/{jid}/control', body, key=keys[1]['token'], expected=404)
    return eid, jid, body


def records(root, project):
    # Read-only exact metadata checks; creation is exclusively via authenticated API.
    execution = json.loads(recovery.sql(root,
        'SELECT coalesce(json_agg(row_to_json(e)),\'[]\'::json) FROM job_executions e', project))
    budgets = json.loads(recovery.sql(root,
        'SELECT coalesce(json_agg(row_to_json(p)),\'[]\'::json) FROM '
        '(SELECT id,owner_github_id,duration_limit,duration_allocated,concurrency_limit,'
        'target_limit,targets_spent FROM programs) p', project))
    ci.require(len(execution) == len(budgets) == 1)
    return {'execution': execution[0], 'budget': budgets[0]}


def verify_records(value, eid, jid, body, key):
    row, budget = value['execution'], value['budget']
    ci.require(row['job_id'] == jid and row['runner_id'] == body['runner_id']
               and row['origin'] == ORIGIN and row['owner'] == budget['owner_github_id'])
    ci.require(row['principal_hash'] == hashlib.sha256(('Bearer ' + key).encode()).hexdigest())
    ci.require(row['token_hash'] == hashlib.sha256(body['token'].encode()).hexdigest())
    ci.require(row['state'] == 'active' and row['capacity_reserved'] is True and row['duration_seconds'] == 30)
    ci.require(budget['id'] == eid and budget['duration_allocated'] == 30
               and budget['duration_limit'] == 120 and budget['concurrency_limit'] == 1)
    ci.require(budget['target_limit'] is None and budget['targets_spent'] == row['target_charge'] == 0)


def start_restored(restored):
    # Explicit isolated test startup, using only images restored by the real bundle.
    # The source apps remain stopped, so the same loopback endpoint is available.
    env = {k: v for k, v in os.environ.items() if k != 'COMPOSE_PROJECT_NAME'}
    for action in ('start', 'export-ca'):
        result = subprocess.run([sys.executable, 'vardrsec.py', action], cwd=restored,
            env=env, capture_output=True, text=True, timeout=300)
        ci.require(result.returncode == 0)


def exercise(root, private):
    checkpoint = private / 'upgrade-checkpoint.json'
    ci.require(not os.path.lexists(checkpoint))
    def mark(stage):
        ci.require(stage in ci.UPGRADE_CHECKPOINTS)
        checkpoint.write_text(json.dumps({'stage': stage}) + '\n')
    mark('preflight')
    ci.require(ci.UPGRADE_TARGET_PINS == historical_build.PINS['current'])
    historical_build.source_receipt(root, 'current')
    ci.require(recovery.sql(root, 'SELECT version_num FROM alembic_version', PROJECT) == '0038managedstops')
    historical_build.recovery_capacity(root, generations=1)
    mark('authenticate')
    api, keys = authenticate(root)
    mark('seed')
    eid, jid, body = seed(api, keys)
    mark('ownership')
    before = records(root, PROJECT)
    verify_records(before, eid, jid, body, keys[0]['token'])
    backup, restored = private / 'legacy-backup', private / 'legacy-restored'
    ci.require(not any(os.path.lexists(p) for p in (backup, restored)))
    mark('backup')
    recovery.backup(root, backup)
    snapshot = recovery.validate(backup)
    ci.require(snapshot['schema_version'] == 4)
    source = state(root, PROJECT)
    ci.require(source['database'] == snapshot['database'] and source['volumes'] == snapshot['volumes'])
    ci.require(records(root, PROJECT) == before)
    mark('restore')
    bundled_restore(backup, restored)
    mark('fingerprints')
    after_restore = state(restored, RESTORE_PROJECT)
    ci.require(after_restore['database'] == snapshot['database'] and after_restore['volumes'] == snapshot['volumes'])
    ci.require(records(restored, RESTORE_PROJECT) == before)
    database_roles.verify(restored, RESTORE_PROJECT, database_roles.read_password(restored))
    mark('startup')
    start_restored(restored)
    ci.require(recovery.digest(restored / 'trust/root.crt') == source['public_ca'])
    # Do not reuse the browser's cookie session; prove the retained API keys work.
    restored_api = API(restored / 'trust/root.crt')
    mark('denial')
    restored_api.request(f'/jobs/{jid}/control', body, key=keys[1]['token'], expected=404)
    ci.require(records(restored, RESTORE_PROJECT) == before)
    mark('expiry')
    # Backup/restore has elapsed the 10s lease; fail rather than wait/renew/fake time.
    status = restored_api.request(f'/jobs/{jid}/execution', key=keys[0]['token'])
    ci.require(status['state'] == 'uncertain' and status['termination_confirmed'] is False)
    result = restored_api.request(f'/jobs/{jid}/control', body, key=keys[0]['token'])
    ci.require(result['action'] == 'cancel')
    expected = {'execution': {**before['execution'], 'state': 'uncertain'}, 'budget': before['budget']}
    ci.require(records(restored, RESTORE_PROJECT) == expected)
    ci.require(state(root, PROJECT) == source and recovery.validate(backup) == snapshot)
    mark('complete')
    return {flag: True for flag in sorted(FLAGS)}


def main():
    env = os.environ
    private = Path(env['RUNNER_TEMP']).resolve() / 'nm3-full-fresh/private'
    ci.require(env.get('DOCKER_HOST') == 'unix:///var/run/docker.sock')
    ci.require(env.get('DOCKER_CONFIG') == str(private / 'docker-config'))
    ci.require(env.get('COMPOSE_PROJECT_NAME') == PROJECT)
    ci.host_guard({k: v for k, v in env.items() if k not in
                  {'DOCKER_HOST', 'DOCKER_CONFIG', 'COMPOSE_PROJECT_NAME'}}, preservation=True)
    ci.require(Path.cwd() == private / 'fixture')
    try:
        result = exercise(private / 'fixture', private)
    except Exception as error:
        checkpoint = ci.read_upgrade_checkpoint(private / 'upgrade-checkpoint.json')
        if checkpoint:
            category = ('timeout' if isinstance(error, subprocess.TimeoutExpired) else
                        'subprocess' if isinstance(error, subprocess.SubprocessError) else
                        'filesystem' if isinstance(error, OSError) else
                        'validation' if isinstance(error, ValueError) else 'unexpected')
            checkpoint['failure_category'] = category
            (private / 'upgrade-checkpoint.json').write_text(json.dumps(checkpoint) + '\n')
        raise
    with (private / 'preservation.json').open('x') as output:
        json.dump(result, output); output.write('\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Legacy ownership verification failed; no acceptance claimed')
        raise SystemExit(1) from None

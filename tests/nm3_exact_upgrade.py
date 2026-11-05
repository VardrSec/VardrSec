"""Final distribution-head checkpoint using the verified historical Full cohorts."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import nm3_full_install_ci as ci
sys.path.insert(0, str(ci.SOURCE))
import database_roles
import recovery
import updater
import community_ci as historical_build
import community_upgrade_acceptance as historical
from nm3_full_update import authenticate

PROJECT = 'nm3-full-fixture'
FLAGS = {'actual_0031_to_0038_verified', 'original_rows_sequences_retained',
         'restricted_role_verified', 'ca_runner_proxy_state_retained',
         'updater_outcome_and_v4_backup_verified', 'source_cohorts_bound'}



def initialize_baseline_runner(root, token):
    # Establish normal identity/journal/runs state before measuring retention.
    # This is the same explicit local diagnostic used by the updater, not a scan.
    result = recovery.compose(
        root, 'run', '--rm', '--no-deps', 'runner', 'doctor', '--platform', '--offline', '--json',
        project=PROJECT, env={**os.environ, 'VARDRMAP_API_KEY': token},
        capture_output=True, text=True, check=False)
    ci.require(result.returncode == 0 and json.loads(result.stdout).get('healthy') is True)


def exercise(root, private):
    ci.require(historical.OLD == ci.PINS == historical_build.PINS['baseline'])
    ci.require(historical.CURRENT == historical_build.PINS['current'] == ci.UPGRADE_TARGET_PINS)
    ci.require(recovery.sql(root, 'SELECT version_num FROM alembic_version', PROJECT) == '0031localauth')
    pin_hash = recovery.digest(root / 'versions.json')
    historical_build.source_receipt(root, 'baseline')
    historical_build.recovery_capacity(root, generations=2)
    candidate_root = private / 'candidate'
    output = private / 'upgrade'
    ci.require(not any(os.path.lexists(p) for p in (candidate_root, output)))
    output.mkdir(mode=0o700)
    def stage(name, arguments, cwd):
        ci.require(name in ('candidate-sources', 'candidate-images'))
        with (output / (name + '.log')).open('x') as log:
            os.chmod(log.name, 0o600)
            completed = subprocess.run(arguments, cwd=cwd, stdout=log,
                                       stderr=subprocess.STDOUT, timeout=3600)
        ci.require(completed.returncode == 0)
    candidate_path = historical_build.build_candidate(root, candidate_root, stage)
    historical_build.source_receipt(candidate_root, 'current')
    historical_build.recovery_capacity(root, generations=2)
    candidate = json.loads(candidate_path.read_text())
    config, baseline_images = updater.image_set(root)
    ci.require(config['name'] == PROJECT)
    ci.require(candidate['components'] == historical.CURRENT)
    ci.require(candidate['images']['db'] == baseline_images['db'])
    ci.require(candidate['images']['api'] != baseline_images['api'])
    updater.candidate_set(candidate_path, baseline_images, 'https://localhost:8443')
    key = authenticate(root, details=True)
    initialize_baseline_runner(root, key['token'])
    recovery.sql(root, "CREATE TABLE nm3_final_upgrade_fixture(id bigserial PRIMARY KEY, note text NOT NULL); "
                       "INSERT INTO nm3_final_upgrade_fixture(note) VALUES ('synthetic-one'),('synthetic-two')", PROJECT)
    telemetry = historical.key_telemetry(root, PROJECT, key['id'])
    columns = historical.columns(root, PROJECT)
    rows = historical.projected_rows(root, PROJECT, columns, key['id'])
    sequences = historical.sequences(root, PROJECT)
    state = historical.state_fingerprints(root, PROJECT, baseline_images)
    password = database_roles.read_password(root)
    ci.require(password is not None)
    database_roles.verify(root, PROJECT, password)
    ca = recovery.digest(root / 'trust/root.crt')
    with patch.dict(os.environ, {'VARDRMAP_API_KEY': key['token']}):
        updater.update(root, candidate_path, output / 'backup', output / 'rehearsal',
                       'vardrsec-restore-nm3-final-upgrade')
    ci.require(recovery.sql(root, 'SELECT version_num FROM alembic_version', PROJECT) == '0038managedstops')
    historical.assert_retained(rows, historical.projected_rows(root, PROJECT, columns, key['id']))
    historical.assert_key_telemetry(telemetry, historical.key_telemetry(root, PROJECT, key['id']))
    historical.assert_sequences_retained(sequences, historical.sequences(root, PROJECT))
    database_roles.verify(root, PROJECT, password)
    ci.require(recovery.digest(root / 'trust/root.crt') == ca)
    ci.require(historical.state_fingerprints(root, PROJECT, candidate['images']) == state)
    ci.require(recovery.digest(root / 'versions.json') == pin_hash)
    historical_build.source_receipt(root, 'baseline')
    historical_build.source_receipt(candidate_root, 'current')
    ci.require(updater.image_set(root)[1] == candidate['images'])
    ci.require(not (root / updater.STATE).exists())
    record = json.loads((root / '.last-update.json').read_text())
    ci.require(record['status'] == 'success' and record['phase'] == 'complete'
               and record['candidate'] == candidate)
    ci.require(recovery.validate(output / 'backup')['schema_version'] == 4)
    historical.verify_anonymous_denied('https://localhost:8443', root / 'trust/root.crt')
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
        print('Exact-head upgrade verification failed; no acceptance claimed')
        raise SystemExit(1) from None

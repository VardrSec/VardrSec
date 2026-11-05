"""Branch-only Full installer acceptance on an empty GitHub-hosted VM daemon.

Never invoke locally against an operator daemon. Private logs/config stay on the
job VM. Only the fixed public receipt is eligible for upload; no teardown.
"""
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
CANDIDATE = '4998e5dfd1554beec88690880c4ac269d4f12240'
BRANCH = 'refs/heads/codex/nm3-full-hosted-verification'
PINS = {
    'map': '41d3ef6475f1b81f973dd4a73944b6e549500fd6',
    'runner': '668dc56f8685dc6a6225438ad443e26901828069',
    'gate': '7f82e499ec407eba072e129e3f3b94f1a4eabe94',
}

UPGRADE_TARGET_PINS = {
    'map': '9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045',
    'runner': '602a5423dcede0e37dacad52aab3bdad900c9021',
    'gate': '7f82e499ec407eba072e129e3f3b94f1a4eabe94',
}

UPGRADE_FAILURES = frozenset({'validation', 'subprocess', 'timeout', 'filesystem', 'unexpected'})
UPGRADE_CHECKPOINTS = frozenset({
    'preflight', 'candidate_build', 'baseline_diagnostics', 'seed', 'snapshots',
    'baseline_roles', 'update', 'migration', 'rows', 'sequences', 'roles',
    'volumes', 'outcome', 'complete',
})


def read_upgrade_checkpoint(path):
    if not path.exists():
        return None
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 128)
    value = json.loads(path.read_text())
    require(isinstance(value, dict) and set(value) in ({'stage'}, {'stage', 'failure_category'}))
    require(isinstance(value['stage'], str) and value['stage'] in UPGRADE_CHECKPOINTS)
    if 'failure_category' in value:
        require(isinstance(value['failure_category'], str) and value['failure_category'] in UPGRADE_FAILURES)
    return value


def require(condition):
    if not condition:
        raise ValueError('Hosted verification prerequisite failed; no acceptance claimed')


def host_guard(env, preservation=False):
    release = platform.freedesktop_os_release()
    require(env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_REPOSITORY') == 'VardrSec/VardrSec'
            and env.get('GITHUB_REF') == (
                'refs/heads/codex/nm3-exact-upgrade-verification' if preservation else BRANCH)
            and env.get('GITHUB_EVENT_NAME') == 'push'
            and platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '24.04')
    forbidden = {'MAP_SOURCE', 'RUNNER_SOURCE', 'GATE_SOURCE', 'POSTGRES_PASSWORD',
                 'POSTGRES_APP_PASSWORD', 'BACKEND_JWT_SECRET', 'AUTH_SECRET',
                 'HTTPS_PORT', 'APPLICATION_SUBNET', 'APPLICATION_IP_RANGE', 'PROXY_IP'}
    require(not any(k.startswith(('DOCKER_', 'COMPOSE_', 'VARDRMAP_', 'VARDRRUNNER_'))
                    or k in forbidden for k in env))
    require(SOURCE.resolve() == Path(env['GITHUB_WORKSPACE']).resolve())
    require(stat.S_ISSOCK(Path('/var/run/docker.sock').stat().st_mode))
    require(Path('/var/run/docker.sock').stat().st_uid == 0)


def capture(args, cwd=SOURCE, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0)
    return result.stdout


def docker(env, *args):
    return capture(['docker', '--host=unix:///var/run/docker.sock', *args], env=env)


def empty_daemon_guard(env):
    info = json.loads(docker(env, 'info', '--format', '{{json .}}'))
    require(info.get('OSType') == 'linux' and info.get('Name') == socket.gethostname())
    require(info.get('DockerRootDir') == '/var/lib/docker')
    require(info.get('Swarm', {}).get('LocalNodeState') == 'inactive')
    require(not docker(env, 'ps', '-aq').strip())
    require(not docker(env, 'volume', 'ls', '-q').strip())
    require(set(docker(env, 'network', 'ls', '--format', '{{.Name}}').splitlines()) <= {'bridge', 'host', 'none'})


def copy_candidate(destination, env):
    require(not os.path.lexists(destination))
    head = capture(['git', 'rev-parse', 'HEAD']).strip()
    require(head == env['GITHUB_SHA'])
    require(not capture(['git', 'status', '--porcelain', '--untracked-files=no']).strip())
    require(subprocess.run(['git', 'merge-base', '--is-ancestor', CANDIDATE, head], cwd=SOURCE,
                           capture_output=True).returncode == 0)
    entries = capture(['git', 'ls-tree', '-r', CANDIDATE]).splitlines()
    files = []
    for entry in entries:
        metadata, name = entry.split('\t', 1)
        require(metadata.split()[0] in ('100644', '100755'))
        require(not Path(name).is_absolute() and '..' not in Path(name).parts)
        require(not (SOURCE / name).is_symlink())
        files.append(name)
    require(subprocess.run(['git', 'diff', '--quiet', CANDIDATE, head, '--', *files],
                           cwd=SOURCE, capture_output=True).returncode == 0)
    destination.mkdir(mode=0o700)
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, target)
    require(not (destination / '.env').exists() and not (destination / '.sources').exists())
    pins = json.loads((destination / 'versions.json').read_text())
    require({k: v['commit'] for k, v in pins['components'].items()} == PINS)
    return head


def run(preservation=False):
    host_guard(os.environ, preservation=preservation)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    require(temporary.is_absolute() and temporary.is_dir())
    root = temporary / 'nm3-full-fresh'
    require(not os.path.lexists(root))
    root.mkdir(mode=0o700)
    private = root / 'private'; private.mkdir(mode=0o700)
    public = root / 'public'; public.mkdir(mode=0o700)
    docker_config = private / 'docker-config'; docker_config.mkdir(mode=0o700)
    env = {**os.environ, 'DOCKER_HOST': 'unix:///var/run/docker.sock',
           'DOCKER_CONFIG': str(docker_config), 'COMPOSE_PROJECT_NAME': 'nm3-full-fixture'}
    receipt = {'schema': 1, 'installer_commit': CANDIDATE, 'component_pins': PINS,
               'upgrade_target_pins': UPGRADE_TARGET_PINS,
               'status': 'unproven', 'stage': 'isolation', 'raw_output_uploaded': False,
               'scope': 'Exact distribution head, historical Full 0031-to-0038 upgrade; not final NM3 cohort/managed-state/Mapless/Windows/SQLite safety'}
    try:
        empty_daemon_guard(env)
        require(shutil.disk_usage(root).free >= 12 * 1024**3)
        receipt['stage'] = 'source'
        fixture = private / 'fixture'
        receipt['workflow_commit'] = copy_candidate(fixture, os.environ)
        receipt['stage'] = 'install'
        with (private / 'install.log').open('x') as log:
            os.chmod(log.name, 0o600)
            result = subprocess.run([sys.executable, 'vardrsec.py', 'install'], cwd=fixture,
                                    env=env, stdout=log, stderr=subprocess.STDOUT, timeout=5400)
        require(result.returncode == 0)
        receipt['stage'] = 'verify'
        require((fixture / '.env').is_file() and (fixture / 'trust/root.crt').is_file())
        for name, expected in PINS.items():
            source = fixture / '.sources' / name
            require(capture(['git', 'rev-parse', 'HEAD'], cwd=source).strip() == expected)
            require(not capture(['git', 'status', '--porcelain'], cwd=source).strip())
        # The standard start path already waits for Compose health. Confirm its
        # expected services are running and the explicit-only Runner is absent.
        services = capture(['docker', 'compose', '-f', str(fixture / 'compose.yaml'),
                            'ps', '--status', 'running', '--services'], cwd=fixture, env=env)
        require(set(services.splitlines()) == {'db', 'api', 'web', 'proxy'})
        if preservation:
            receipt['stage'] = 'preservation'
            with (private / 'preservation.log').open('x') as log:
                os.chmod(log.name, 0o600)
                result = subprocess.run(
                    [sys.executable, str(SOURCE / 'tests/nm3_exact_upgrade.py')],
                    cwd=fixture, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=3600,
                )
            checkpoint = read_upgrade_checkpoint(private / 'upgrade-checkpoint.json')
            if checkpoint is not None:
                receipt['upgrade_checkpoint'] = checkpoint['stage']
                if 'failure_category' in checkpoint:
                    receipt['upgrade_failure_category'] = checkpoint['failure_category']
            require(result.returncode == 0)
            verified = json.loads((private / 'preservation.json').read_text())
            expected = {'actual_0031_to_0038_verified', 'original_rows_sequences_retained',
                        'restricted_role_verified', 'ca_runner_proxy_state_retained',
                        'updater_outcome_and_v4_backup_verified', 'source_cohorts_bound'}
            require(set(verified) == expected and all(value is True for value in verified.values()))
            receipt['preservation'] = verified
        receipt['status'] = 'passed'
        receipt['stage'] = 'complete'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        receipt['status'] = 'failed_or_unproven'
    finally:
        with (public / 'receipt.json').open('x') as out:
            json.dump(receipt, out, indent=2); out.write('\n')
        print('Full fresh verification: ' + receipt['status'])
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    # Do not expose raw exceptions, subprocess output, paths or configuration.
    try:
        require(sys.argv[1:] in ([], ['--preservation']))
        raise SystemExit(run(preservation=sys.argv[1:] == ['--preservation']))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('Full fresh verification refused; no acceptance claimed')
        raise SystemExit(1) from None

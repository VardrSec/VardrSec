"""Branch-only Full installer acceptance on an empty GitHub-hosted VM daemon.

Never invoke locally against an operator daemon. Private logs/config stay on the
job VM. Only the fixed public receipt is eligible for upload; no teardown.
"""
import argparse
import hashlib
import http.cookiejar
import ssl
import urllib.request
import urllib.error
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
CANDIDATE = 'befe929870107c5a27d291078088fbceaeb58512'
BRANCH = 'refs/heads/codex/nm3-community-full-verification'
BASE_PINS = {
    'map': '41d3ef6475f1b81f973dd4a73944b6e549500fd6',
    'runner': '668dc56f8685dc6a6225438ad443e26901828069',
    'gate': '7f82e499ec407eba072e129e3f3b94f1a4eabe94',
}
PINS = {
    'map': 'aad63c8151789cd9bf56864456b5fdf1fdcfde41',
    'runner': '440ebda7405d9f19f2e5c6f954996b525f0ac5da',
    'gate': '54536ea1d900d0e35adf93b4e026962c4d45d34a',
}
TREES = {
    'distribution': '108948257cc3325f3c223757cf9abbfc7b11c44b',
    'map': '3cda816378b8862ece82dc70aa6ad3667be0273c',
    'runner': '0109814200968bebd055ef2629aa45b3dc6ade15',
    'gate': '211b1eec890ff910ee7f381da435897fe3feb15d',
}



def require(condition):
    if not condition:
        raise ValueError('Hosted verification prerequisite failed; no acceptance claimed')


def host_guard(env):
    release = platform.freedesktop_os_release()
    require(env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_REPOSITORY') == 'VardrSec/VardrSec'
            and env.get('GITHUB_REF') == BRANCH
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
    require(capture(['git', 'rev-parse', CANDIDATE + '^{tree}']).strip() == TREES['distribution'])
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
    notes = {name for name in files if name == 'CHANGELOG.md' or name.startswith('docs/')}
    require(subprocess.run(['git', 'diff', '--quiet', CANDIDATE, head, '--', *[name for name in files if name not in notes]],
                           cwd=SOURCE, capture_output=True).returncode == 0)
    destination.mkdir(mode=0o700)
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, target)
        if name in notes:
            target.write_text(capture(['git', 'show', CANDIDATE + ':' + name]))
    require(not (destination / '.env').exists() and not (destination / '.sources').exists())
    pins = json.loads((destination / 'versions.json').read_text())
    require({k: v['commit'] for k, v in pins['components'].items()} == BASE_PINS)
    for name, revision in PINS.items():
        pins['components'][name]['commit'] = revision
    (destination / 'versions.json').write_text(json.dumps(pins, indent=2) + '\n')
    return head


def verify_authorization(fixture, env):
    """Existing local-session/key/doctor contracts, only against this VM's stack."""
    url = 'https://localhost:8443/backend'
    context = ssl.create_default_context(cafile=str(fixture / 'trust/root.crt'))
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context))

    def request(path, data=None, csrf=None, expected=200):
        headers = {'Origin': 'https://localhost:8443'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if csrf is not None:
            headers['X-CSRF-Token'] = csrf
        req = urllib.request.Request(url + path, headers=headers,
                                     data=None if data is None else json.dumps(data).encode())
        try:
            with client.open(req, timeout=20) as response:
                require(response.status == expected)
                return json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                require(error.code == expected)
                return None

    require(request('/ready')['status'] == 'ready')
    request('/auth/local/session', expected=401)
    bootstrap = capture([sys.executable, 'vardrsec.py', 'bootstrap', '--username',
                         'synthetic-operator', '--generate-password'], cwd=fixture, env=env)
    marker = 'Generated password (store securely; shown once): '
    require(bootstrap.count(marker) == 1)
    password = bootstrap.split(marker, 1)[1].strip()
    request('/auth/local/login', {'username': 'synthetic-operator', 'password': password})
    session = request('/auth/local/session')
    require(session['authMethod'] == 'local')
    payload = {'label': 'synthetic-full-ci', 'scope': 'runner'}
    request('/auth/apikeys', payload, expected=403)
    require(request('/auth/apikeys')['keys'] == [])
    created = request('/auth/apikeys', payload, csrf=session['csrfToken'])
    require(created['scope'] == 'runner' and created['token'].startswith('vmap_'))
    stored = request('/auth/apikeys')['keys']
    require(len(stored) == 1 and stored[0]['id'] == created['id'] and 'token' not in stored[0])
    result = subprocess.run([sys.executable, 'vardrsec.py', 'doctor'], cwd=fixture,
                            env={**env, 'VARDRMAP_API_KEY': created['token']},
                            capture_output=True, text=True, timeout=180)
    require(result.returncode == 0)
    require(created['token'] not in result.stdout + result.stderr)
    doctor = json.loads(result.stdout)
    require(doctor['healthy'] is True)
    for name in ('platform database', 'platform migrations', 'api auth'):
        require(any(c['name'] == name and c['status'] == 'ok' for c in doctor['checks']))
    return {'trusted_https_ready': True, 'unauthenticated_session_denied': True,
            'csrf_write_denied_without_mutation': True, 'synthetic_local_login': True,
            'runner_scoped_key': True, 'authenticated_runner_doctor': True,
            'database_migrations_ready': True, 'no_runner_service_started': True}


def observed_install_steps(path):
    """Fixed step names only; never copy arbitrary installation output."""
    allowed = {'== ' + name: name for name in
               ('configure', 'sources', 'build', 'database-role', 'start', 'export-ca')}
    steps = []
    try:
        with path.open(encoding='utf-8', errors='replace') as stream:
            for line in iter(lambda: stream.readline(256), ''):
                step = allowed.get(line.strip())
                if step is not None and step not in steps:
                    steps.append(step)
    except OSError:
        pass
    return steps


def verify_installed_lifecycle(fixture, private, env, receipt):
    from nm3_installed_lifecycle import CHECKS, STAGES, FAILURE_CODES
    summary = private / 'lifecycle/summary.json'
    with (private / 'lifecycle.log').open('x') as log:
        os.chmod(log.name, 0o600)
        result = subprocess.run([sys.executable, str(SOURCE / 'tests/nm3_installed_lifecycle.py'),
            '--fixture', str(fixture), '--summary', str(summary)], cwd=private, env=env,
            stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    observed = {}
    try:
        with summary.open('rb') as stream:
            raw = stream.read(16 * 1024 + 1)
        if len(raw) <= 16 * 1024:
            observed = json.loads(raw)
            require(isinstance(observed, dict))
    except (OSError, ValueError, RecursionError):
        observed = {}
    receipt['lifecycle_stage'] = observed.get('stage') if observed.get('stage') in STAGES else 'unavailable'
    code = observed.get('failure_code')
    if code in FAILURE_CODES:
        receipt['lifecycle_failure_code'] = code
    require(result.returncode == 0)
    require(observed.get('status') == 'passed' and observed.get('stage') == 'complete')
    require(set(observed['checks']) == set(CHECKS)
            and all(observed['checks'][name] is True for name in CHECKS))
    return {name: True for name in CHECKS}


def run(*, installed_lifecycle=False):
    host_guard(os.environ)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    require(temporary.is_absolute() and temporary.is_dir())
    root = temporary / 'nm3-community-full'
    require(not os.path.lexists(root))
    root.mkdir(mode=0o700)
    private = root / 'private'; private.mkdir(mode=0o700)
    public = root / 'public'; public.mkdir(mode=0o700)
    docker_config = private / 'docker-config'; docker_config.mkdir(mode=0o700)
    env = {**os.environ, 'DOCKER_HOST': 'unix:///var/run/docker.sock',
           'DOCKER_CONFIG': str(docker_config),
           'COMPOSE_PROJECT_NAME': 'vardrsec-compose-review' if installed_lifecycle else 'nm3-full-fixture'}
    receipt = {'schema': 1, 'installer_commit': CANDIDATE, 'component_pins': PINS, 'source_trees': TREES,
               'status': 'unproven', 'stage': 'isolation', 'raw_output_uploaded': False,
               'scope': 'Exact synthetic development Full cohort only; not Windows/Mapless/snapshot/journal/grant/upgrade/no-loss acceptance'}
    try:
        empty_daemon_guard(env)
        require(shutil.disk_usage(root).free >= 12 * 1024**3)
        receipt['stage'] = 'source'
        fixture = private / 'fixture'
        receipt['workflow_commit'] = copy_candidate(fixture, os.environ)
        receipt['workflow_tree'] = capture(['git', 'rev-parse', 'HEAD^{tree}']).strip()
        receipt['fixture_manifest_sha256'] = hashlib.sha256((fixture / 'versions.json').read_bytes()).hexdigest()
        receipt['stage'] = 'install'
        with (private / 'install.log').open('x') as log:
            os.chmod(log.name, 0o600)
            result = subprocess.run([sys.executable, 'vardrsec.py', 'install'], cwd=fixture,
                                    env=env, stdout=log, stderr=subprocess.STDOUT, timeout=5400)
        receipt['installer_exit_code'] = result.returncode
        if result.returncode != 0:
            receipt['failure_code'] = 'installer_exit_nonzero'
        require(result.returncode == 0)
        receipt['stage'] = 'verify'
        require((fixture / '.env').is_file() and (fixture / 'trust/root.crt').is_file())
        for name, expected in PINS.items():
            source = fixture / '.sources' / name
            require(capture(['git', 'rev-parse', 'HEAD'], cwd=source).strip() == expected)
            require(not capture(['git', 'status', '--porcelain'], cwd=source).strip())
            require(capture(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source).strip() == TREES[name])
        # The standard start path already waits for Compose health. Confirm its
        # expected services are running and the explicit-only Runner is absent.
        services = capture(['docker', 'compose', '-f', str(fixture / 'compose.yaml'),
                            'ps', '--status', 'running', '--services'], cwd=fixture, env=env)
        require(set(services.splitlines()) == {'db', 'api', 'web', 'proxy'})
        receipt['stage'] = 'authorization'
        if installed_lifecycle:
            receipt['stage'] = 'installed_lifecycle'
            receipt['checks'] = verify_installed_lifecycle(fixture, private, env, receipt)
            receipt['scope'] = 'Exact synthetic Full UI/explicit assessment/evidence and encrypted recovery cohort; not Windows/Mapless/managed-worker/snapshot acceptance'
        else:
            receipt['checks'] = verify_authorization(fixture, env)
            services = capture(['docker', 'compose', 'ps', '--status', 'running', '--services'], cwd=fixture, env=env)
            require(set(services.splitlines()) == {'db', 'api', 'web', 'proxy'})
        receipt['status'] = 'passed'
        receipt['stage'] = 'complete'
    except subprocess.TimeoutExpired:
        receipt['status'] = 'failed_or_unproven'
        receipt['failure_code'] = 'operation_timed_out'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        receipt['status'] = 'failed_or_unproven'
        receipt.setdefault('failure_code', 'operation_refused')
    finally:
        receipt['observed_install_steps'] = observed_install_steps(private / 'install.log')
        with (public / 'receipt.json').open('x') as out:
            json.dump(receipt, out, indent=2); out.write('\n')
        print('Full fresh verification: ' + receipt['status'])
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    # Do not expose raw exceptions, subprocess output, paths or configuration.
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--installed-lifecycle', action='store_true')
        args = parser.parse_args()
        raise SystemExit(run(installed_lifecycle=args.installed_lifecycle))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('Full fresh verification refused; no acceptance claimed')
        raise SystemExit(1) from None

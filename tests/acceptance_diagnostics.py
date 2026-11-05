"""Opt-in acceptance diagnostics: static identifiers, never exception text.

Checkpoint and operation outcomes are diagnostic facts, not acceptance results.
Expected negative-test operations may therefore have failed operation records.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

import acceptance_retention as retention

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 128 * 1024
MAX_EVENTS = 1024
COHORTS = frozenset({"upgrade", "recovery", "clean"})
STAGES = frozenset({
    "upgrade", "recovery", "clean",
    *('upgrade.' + part for part in (
        'preflight.images', 'preflight.ownership', 'preflight.candidate',
        'preflight.schema', 'preflight.paths', 'preflight.pins', 'preflight.receipts',
        'operator.reset', 'operator.login', 'operator.readback', 'operator.key',
        'snapshot.telemetry', 'snapshot.columns', 'snapshot.rows', 'snapshot.sequences',
        'snapshot.state', 'snapshot.role', 'update', 'post.schema', 'post.rows',
        'post.telemetry', 'post.sequences', 'post.role', 'post.ca', 'post.state',
        'post.pins', 'post.readback', 'post.anonymous', 'post.receipt', 'post.report',
        'post.operator.reset', 'post.operator.login')),
    *('recovery.' + part for part in (
        'preflight', 'statefixture', 'backup', 'validate', 'age.keygen', 'age.seal',
        'age.unseal', 'migration.success', 'migration.failure',
        'migration.failure-verify', 'restore', 'restoredapp')),
    *('shared.recovery.' + name for name in (
        'backup', 'restore', 'validate', 'safe_archive', 'database_fingerprint',
        'volume_fingerprint', 'container')),
    *('shared.recovery.container.' + service for service in ('db', 'api', 'web', 'proxy', 'runner')),
    *('shared.updater.' + name for name in (
        'update', 'verify_private', 'assert_quiesced', 'image_set', 'candidate_set')),
})
STATES = frozenset({'started', 'passed', 'failed', 'checkpoint'})
CODES = frozenset({'none', 'E_UNKNOWN', 'E_VALUE', 'E_TIMEOUT', 'E_SUBPROCESS',
                   'E_CONTAINER_CARDINALITY', 'E_CONFIG_MISMATCH', 'E_INTERRUPTED'})
_ACTIVE = ContextVar('acceptance_diagnostics', default=None)
_WRAPPED = ContextVar('acceptance_shared_wrapped', default=False)
_FAILED_PATHS = set()
_CONFIG_NAMES = {
    'db': ('POSTGRES_PASSWORD',),
    'api': ('DATABASE_URL', 'BACKEND_JWT_SECRET', 'ALLOWED_ORIGINS'),
    'web': ('AUTH_SECRET', 'BACKEND_JWT_SECRET', 'AUTH_URL'),
    'proxy': ('HTTPS_PORT',),
}


def error_code(error):
    if isinstance(error, subprocess.TimeoutExpired):
        return 'E_TIMEOUT'
    if isinstance(error, subprocess.CalledProcessError):
        return 'E_SUBPROCESS'
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'E_INTERRUPTED'
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        text = error.args[0]
        if text in {f'Expected exactly one {s} container' for s in ('db', 'api', 'web', 'proxy', 'runner')}:
            return 'E_CONTAINER_CARDINALITY'
        if text in {f'Persist the matching {s} {name} configuration before backup'
                    for s, names in _CONFIG_NAMES.items() for name in names}:
            return 'E_CONFIG_MISMATCH'
    return 'E_VALUE' if isinstance(error, ValueError) else 'E_UNKNOWN'


def validate_public_bytes(raw):
    """Reject any unrecognized field/value; never silently filter input."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Invalid diagnostics export')

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Invalid diagnostics export')
            result[key] = value
        return result

    try:
        data = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid diagnostics export') from None
    if (type(data) is not dict or set(data) != {'schema', 'events'}
        or type(data['schema']) is not int or data['schema'] != 1
        or type(data['events']) is not list or len(data['events']) > MAX_EVENTS):
        raise ValueError('Invalid diagnostics export')
    stack = []
    for event in data['events']:
        if (type(event) is not dict or set(event) != {'stage', 'state', 'code'}
            or type(event['stage']) is not str or event['stage'] not in STAGES
            or type(event['state']) is not str or event['state'] not in STATES
            or type(event['code']) is not str or event['code'] not in CODES):
            raise ValueError('Invalid diagnostics export')
        state = event['state']
        if (state == 'failed') != (event['code'] != 'none'):
            raise ValueError('Invalid diagnostics export')
        if state == 'started':
            stack.append(event['stage'])
        elif state in ('passed', 'failed'):
            if not stack or stack.pop() != event['stage']:
                raise ValueError('Invalid diagnostics export')
    # An interrupted process may leave started records. Do not infer completion.
    return data


def _read_bounded(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Invalid diagnostics export')
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Invalid diagnostics export')
    return raw


def _finished(data):
    events = data['events']
    if not events or events[0]['stage'] not in COHORTS or events[0]['state'] != 'started':
        raise ValueError('Invalid diagnostics export')
    if (events[-1]['stage'] != events[0]['stage']
        or events[-1]['state'] not in ('passed', 'failed')):
        raise ValueError('Invalid diagnostics export')
    depth = 0
    for index, event in enumerate(events):
        if event['state'] == 'started':
            depth += 1
        elif event['state'] in ('passed', 'failed'):
            depth -= 1
        if depth == 0 and index != len(events) - 1:
            raise ValueError('Invalid diagnostics export')
    if depth:
        raise ValueError('Invalid diagnostics export')
    return data


def _owned_root(root):
    if not retention.enabled():
        raise ValueError('Diagnostics require owned retention mode')
    root = Path(root)
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('Invalid diagnostics root')
    if root.resolve() != ROOT.resolve():
        runner_temp = os.environ.get('RUNNER_TEMP')
        if not runner_temp or root != Path(runner_temp) / 'community-run':
            raise ValueError('Invalid diagnostics root')
        marker = root / '.community-ci-owned.json'
        if marker.is_symlink() or not marker.is_file():
            raise ValueError('Invalid diagnostics root')
        data = json.loads(marker.read_text())
        if any(data.get(k) != os.environ.get(k) for k in
               ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB')):
            raise ValueError('Invalid diagnostics root')
    return root


class _Recorder:
    def __init__(self, root):
        root = _owned_root(root)
        self.path = root / 'artifacts' / 'community-diagnostics.json'
        if self.path.parent.is_symlink():
            raise ValueError('Invalid diagnostics root')
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        self.events = []
        self.failed = False
        self.previous = b'{"schema":1,"events":[]}'
        with self.path.open('xb') as out:
            self.path.chmod(0o600)
            out.write(self.previous)

    def record(self, stage, state, code='none'):
        if self.failed:
            return
        try:
            event = {'stage': stage, 'state': state, 'code': code}
            proposed = {'schema': 1, 'events': [*self.events, event]}
            raw = json.dumps(proposed, separators=(',', ':')).encode()
            validate_public_bytes(raw)
            if self.path.is_symlink() or _read_bounded(self.path) != self.previous:
                raise ValueError('Diagnostics destination changed')
            temporary = self.path.parent / ('.community-diagnostics-' + uuid.uuid4().hex + '.json')
            with temporary.open('xb') as out:
                temporary.chmod(0o600)
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.path)
            self.previous, self.events = raw, proposed['events']
        except (OSError, ValueError, TypeError, RecursionError):
            # Preserve the instrumented operation's behavior, but forbid export.
            self.failed = True
            _FAILED_PATHS.add(self.path)


@contextmanager
def capture(root):
    if not retention.enabled():
        yield None
        return
    existing = _ACTIVE.get()
    if existing is not None:
        yield existing
        return
    recorder = _Recorder(root)
    token = _ACTIVE.set(recorder)
    try:
        yield recorder
    finally:
        _ACTIVE.reset(token)


@contextmanager
def step(stage):
    recorder = _ACTIVE.get()
    if recorder is None:
        yield
        return
    if type(stage) is not str or stage not in STAGES:
        raise ValueError('Invalid diagnostics stage')
    recorder.record(stage, 'started')
    try:
        yield
    except BaseException as error:
        recorder.record(stage, 'failed', error_code(error))
        raise
    else:
        recorder.record(stage, 'passed')


def mark(stage):
    recorder = _ACTIVE.get()
    if recorder is not None:
        if type(stage) is not str or stage not in STAGES:
            raise ValueError('Invalid diagnostics stage')
        recorder.record(stage, 'checkpoint')


@contextmanager
def diagnostics(root, cohort):
    with capture(root):
        if _ACTIVE.get() is not None and cohort not in COHORTS:
            raise ValueError('Invalid diagnostics cohort')
        with step(cohort):
            yield


@contextmanager
def wrap_shared():
    if _ACTIVE.get() is None or _WRAPPED.get():
        yield
        return
    import recovery
    import updater
    token = _WRAPPED.set(True)
    originals = []
    try:
        for module, names in [(recovery, ('backup', 'restore', 'validate', 'safe_archive',
                'database_fingerprint', 'volume_fingerprint', 'container')),
                (updater, ('update', 'verify_private', 'assert_quiesced', 'image_set',
                'candidate_set'))]:
            for name in names:
                original = getattr(module, name)
                def factory(function, module_name, function_name):
                    @wraps(function)
                    def wrapped(*args, **kwargs):
                        stage = 'shared.' + module_name + '.' + function_name
                        if module_name == 'recovery' and function_name == 'container':
                            service = args[1] if len(args) > 1 else kwargs.get('service')
                            if type(service) is str and service in ('db', 'api', 'web', 'proxy', 'runner'):
                                stage += '.' + service
                        with step(stage):
                            return function(*args, **kwargs)
                    return wrapped
                originals.append((module, name, original))
                setattr(module, name, factory(original, module.__name__, name))
        yield
    finally:
        for module, name, original in reversed(originals):
            setattr(module, name, original)
        _WRAPPED.reset(token)


def read_public(root):
    active = _ACTIVE.get()
    if active is not None and active.failed:
        raise ValueError('Diagnostics export unavailable')
    path = _owned_root(root) / 'artifacts' / 'community-diagnostics.json'
    if path in _FAILED_PATHS or path.parent.is_symlink() or path.is_symlink():
        raise ValueError('Invalid diagnostics export')
    return _finished(validate_public_bytes(_read_bounded(path)))

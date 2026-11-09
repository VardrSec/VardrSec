"""Explicit managed setup, human job approval and worker lifecycle controls.

Normal platform startup never calls these opt-in operations. Signing remains
outside workers; preparation and registration never launch jobs or workers.
"""

import argparse
from contextlib import contextmanager
from dataclasses import asdict
import getpass
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid
import warnings

import updater
import worker_host as host
import worker_runtime as runtime


class CLIRefused(ValueError):
    pass


CAPTURE_FAILURE_PHASES = {
    "daemon": "enable_capture_daemon",
    "inspect": "enable_capture_inspect",
    "identity": "enable_capture_identity",
    "mounts": "enable_capture_mounts",
    "tmpfs": "enable_capture_tmpfs",
    "profile": "enable_capture_profile",
    "volume_metadata": "enable_capture_volume_metadata",
    "network_binding": "enable_capture_network_binding",
    "running_state": "enable_capture_running_state",
    "readiness_copy": "enable_capture_readiness_copy",
    "readiness_archive": "enable_capture_readiness_archive",
    "readiness_schema": "enable_capture_readiness_schema",
    "incarnation_recheck": "enable_capture_incarnation_recheck",
}


FAILURE_PHASES = frozenset(
    {
        "arguments",
        "installation",
        "dispatch",
        "onboarding",
        "launch_inputs",
        "launch_preflight",
        "launch_core_inventory",
        "launch_state_inventory",
        "launch_network_inventory",
        "launch_readiness_inventory",
        "launch_compose_inventory",
        "launch_catalog",
        "launch_audit_image",
        "launch_audit_run",
        "launch_audit_recheck",
        "launch_intent",
        "launch_resources",
        "launch_create",
        "launch_start",
        "enable_inputs",
        "enable_observer_setup",
        "enable_api_setup",
        "enable_custody",
        "enable_owner_auth",
        "enable_capture",
        "enable_registration",
        "enable_publication_checks",
        "enable_recapture",
        "enable_mount_custody",
        "enable_publish_trust",
        "enable_publish_admission",
    }
    | set(CAPTURE_FAILURE_PHASES.values())
)
FAILURE_CODES = frozenset(
    {
        "validation_refused",
        "runtime_refused",
        "host_refused",
        "secret_custody_refused",
        "local_io_failed",
        "operation_failed",
        "interrupted",
    }
)


def failure_diagnostic(args, error):
    """Fixed operator diagnostics; never stringify an exception or input value."""
    phase = getattr(args, "_failure_phase", "arguments")
    if (
        type(phase) is not str
        or phase not in FAILURE_PHASES
        or phase in CAPTURE_FAILURE_PHASES.values()
    ):
        phase = "dispatch"
    if phase == "enable_capture" and isinstance(error, runtime.RuntimeRefused):
        checkpoint = getattr(error, "checkpoint", None)
        if type(checkpoint) is str and checkpoint in CAPTURE_FAILURE_PHASES:
            phase = CAPTURE_FAILURE_PHASES[checkpoint]
    code = "operation_failed"
    for kind, known in (
        (KeyboardInterrupt, "interrupted"),
        (CLIRefused, "validation_refused"),
        (runtime.RuntimeRefused, "runtime_refused"),
        (host.HostRefused, "host_refused"),
        (host.custody.SecretRefused, "secret_custody_refused"),
        (OSError, "local_io_failed"),
    ):
        if isinstance(error, kind):
            code = known
            break
    result = {"failure_phase": phase, "failure_code": code}
    if phase == "enable_registration" and code == "host_refused":
        detail = host.registration_diagnostic(error)
        if detail is not None:
            result["registration_failure"] = detail
    return result


def require(condition):
    if not condition:
        raise CLIRefused("worker_cli_refused")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # A mistaken argument may contain a pasted password or STOP capability.
        raise CLIRefused("worker_cli_arguments_refused")


def runtime_id(value):
    try:
        require(type(value) is str and str(uuid.UUID(value)) == value)
        return value
    except (ValueError, TypeError, AttributeError):
        raise CLIRefused("worker_cli_arguments_refused") from None


def parser():
    result = Parser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True, parser_class=Parser)
    prepare = actions.add_parser("prepare", help="Explicitly prepare issuer custody and public worker metadata; never start work")
    for name in ("private-root", "admission-root", "worker-image", "issuer-id", "context", "credential-file"):
        prepare.add_argument("--" + name)
    prepare.add_argument("--credential-name", action="append", default=[])
    for name in ("configure", "start", "job-review", "job-approve", "job-register"):
        action = actions.add_parser(name)
        action.add_argument("--setup", help="Prepared metadata; defaults to this installation's explicit setup pointer")
        if name in {"configure", "start", "job-review", "job-register"}:
            action.add_argument("--username", default="operator")
            action.add_argument("--password-stdin", action="store_true")
        if name == "configure":
            action.add_argument("--allow-plaintext-key", action="store_true",
                                help="Explicitly accept the restricted Runner API key in its protected Docker state")
        if name == "start":
            action.add_argument("--max-attempts")
            action.add_argument("--idle-timeout-seconds", type=int)
        if name == "job-review":
            action.add_argument("job_id", type=runtime_id)
            action.add_argument("--engagement-id")
            action.add_argument("--authorization-id")
            action.add_argument("--output", required=True)
            action.add_argument("--expires-in", type=int, default=300)
            action.add_argument("--duration-seconds", type=int, default=30)
            action.add_argument("--max-artifact-bytes", type=int, default=1024 * 1024)
            action.add_argument("--allow-private-targets", action="store_true")
        if name in {"job-approve", "job-register"}:
            action.add_argument("--review", required=True)
        if name == "job-approve":
            action.add_argument("--output", required=True)
        if name == "job-register":
            action.add_argument("--approval", required=True)
    prepare.add_argument("--username", default="operator")
    prepare.add_argument("--password-stdin", action="store_true")
    enable = actions.add_parser(
        "enable",
        aliases=["register"],
        help="Admit an exact already running worker; never start one",
    )
    launch = actions.add_parser(
        "launch", help="Explicitly create, start and admit one managed worker"
    )
    for name in (
        "api-url",
        "ca",
        "private-root",
        "context",
        "container-id",
        "image-id",
        "project",
        "trust-source",
        "admission-source",
        "state-volume",
        "readiness-volume",
        "enrollment-id",
        "runner-id",
        "origin",
        "public-trust",
    ):
        enable.add_argument("--" + name, required=True)
        if name not in {"container-id", "admission-source", "readiness-volume", "trust-source"}:
            launch.add_argument("--" + name, required=True)
    for name in ("admission-root", "runner-network", "launch-config"):
        launch.add_argument("--" + name, required=True)
    for action in (enable, launch):
        action.add_argument("--runtime-id", type=runtime_id)
        action.add_argument("--protocol", choices=("persistent-v3", "finite-v2", "legacy-v1"),
                            default="persistent-v3")
        action.add_argument("--max-attempts",
                            help="Optional v3 finite job limit; required1..32 for explicit finite-v2")
        action.add_argument("--idle-timeout-seconds", type=int,
                            help="Optional v3 finite idle limit1..86400")
        action.add_argument("--expires-in", type=int,
                            help="Legacy/finite admission seconds60..604800 (default900)")
        action.add_argument("--username", default="operator")
        action.add_argument("--password-stdin", action="store_true",
                            help="Explicitly read one bounded password line from stdin")
    for name in ("status", "disable", "stop", "report-exit", "reconcile", "revoke"):
        action = actions.add_parser(name)
        action.add_argument("--runtime-id", required=True, type=runtime_id)
        action.add_argument("--private-root", required=True)
        if name == "stop":
            action.add_argument(
                "--report",
                action="store_true",
                help="After actual exit, separately invoke the existing one-shot host reporter",
            )
        if name == "revoke":
            action.add_argument("--username", default="operator")
            action.add_argument("--password-stdin", action="store_true")
        if name == "report-exit":
            action.add_argument(
                "--continue-after-transition",
                action="store_true",
                help="One new report only after a verified irreversible runtime transition",
            )
    return result


def password(use_stdin):
    if use_stdin:
        require(not sys.stdin.isatty())
        raw = sys.stdin.buffer.readline(515)
        require(len(raw) <= 514 and raw.endswith(b"\n"))
        try:
            value = raw.removesuffix(b"\n").removesuffix(b"\r").decode("utf-8")
        except UnicodeError:
            raise CLIRefused("worker_cli_credentials_refused") from None
    else:
        require(sys.stdin.isatty())
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Existing local owner password (hidden): ")
    require(
        type(value) is str
        and 1 <= len(value) <= 128
        and "\n" not in value
        and "\r" not in value
        and "\0" not in value
    )
    return value


@contextmanager
def owner(client, args, *, expected_transport=None):
    value = password(args.password_stdin)
    try:
        with client.owner_session(
            args.username, value,
            **({} if expected_transport is None else {"expected_transport": expected_transport}),
        ) as session:
            value = None
            yield session
    finally:
        value = None



_PREPARED_ENABLE_OWNER = object()


class _PreparedEnableOwner:
    """One existing authenticated session, bound to its live host operation."""

    __slots__ = ("_records", "_operation", "_client", "_pin", "_session", "_stack", "_active", "_used")

    def __init__(self, records, operation, client, pin, session, stack, proof):
        require(proof is _PREPARED_ENABLE_OWNER)
        for name, value in (("_records", records), ("_operation", operation),
                            ("_client", client), ("_pin", pin), ("_session", session),
                            ("_stack", stack), ("_active", True), ("_used", False)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise CLIRefused("worker_cli_refused")

    def __copy__(self):
        raise CLIRefused("worker_cli_refused")

    def __deepcopy__(self, memo):
        raise CLIRefused("worker_cli_refused")

    def __reduce_ex__(self, protocol):
        raise CLIRefused("worker_cli_refused")

    def _match(self, records, operation, client):
        require(self._active and not self._used and records is self._records
                and operation is self._operation and client is self._client)
        records._require_operation(operation)
        require(client._owner_transport() == self._pin
                and type(self._session) is host.OwnerSession
                and self._session.client is client
                and self._session._cookie is not None and self._session._csrf is not None)

    @contextmanager
    def _take(self, records, operation, client):
        self._match(records, operation, client)
        object.__setattr__(self, "_used", True)
        # Close the original stack in the existing registration scope. The
        # outer context still owns cleanup if borrowing never reaches this body.
        try:
            yield self._session
            require(client._owner_transport() == self._pin)
        finally:
            self._stack.close()


@contextmanager
def _preauthenticate_enable_owner(records, operation, client, args):
    """Authenticate via the existing local session before a future start effect."""
    require(type(records) is host.HostRecords and type(client) is host.HostClient)
    records._require_operation(operation)
    pin = client._owner_transport()
    args._failure_phase = "enable_owner_auth"
    with host.ExitStack() as stack:
        session = stack.enter_context(owner(client, args, expected_transport=pin))
        selected = _PreparedEnableOwner(records, operation, client, pin, session, stack,
                                       _PREPARED_ENABLE_OWNER)
        try:
            selected._match(records, operation, client)
            yield selected
        finally:
            object.__setattr__(selected, "_active", False)
            object.__setattr__(selected, "_session", None)


def public_trust(path):
    path = Path(path)
    require(path.is_absolute())
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        raw = source.read(32769)
    require(0 < len(raw) <= 32768)

    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    anchors = json.loads(raw, object_pairs_hook=unique)
    require(type(anchors) is list and 1 <= len(anchors) <= 100)
    seen = set()
    purposes = set()
    for anchor in anchors:
        require(
            type(anchor) is dict
            and set(anchor)
            == {"issuer_id", "key_id", "public_key", "purposes", "origins", "revoked"}
        )
        for name in ("issuer_id", "key_id"):
            host._identifier(anchor[name])
        require(
            type(anchor["public_key"]) is str
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", anchor["public_key"])
        )
        # Exact 32-byte canonical base64url, matching Runner's public wire form.
        import base64

        decoded = base64.urlsafe_b64decode(anchor["public_key"] + "=")
        require(
            len(decoded) == 32
            and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
            == anchor["public_key"]
        )
        require(
            type(anchor["revoked"]) is bool
            and type(anchor["purposes"]) is list
            and anchor["purposes"]
            and set(anchor["purposes"]) <= {"approval", "contract"}
            and len(anchor["purposes"]) == len(set(anchor["purposes"]))
            and type(anchor["origins"]) is list
            and anchor["origins"]
            and set(anchor["origins"]) <= {"map", "standalone"}
            and len(anchor["origins"]) == len(set(anchor["origins"]))
        )
        key = (anchor["issuer_id"], anchor["key_id"])
        require(key not in seen)
        seen.add(key)
        if not anchor["revoked"] and "map" in anchor["origins"]:
            purposes.update(anchor["purposes"])
    require(purposes == {"approval", "contract"})
    return host.canonical(anchors)


def publish_public(path, data, *, publication_step=None):
    """Atomic exclusive public publication; no overwrite or implicit replay."""
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink())
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".prepared")
    if publication_step is not None:
        import worker_lifecycle_intent

        worker_lifecycle_intent.before_public_open(publication_step, path=path, data=data)
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            require(output.write(data) == len(data))
            output.flush()
            os.fsync(output.fileno())
        if os.name == "nt":
            # Windows rename refuses an existing destination. It also avoids
            # requiring hard-link permission in a restricted desktop process.
            os.rename(temporary, path)
        else:
            # POSIX rename would replace existing permission; link refuses it.
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    if publication_step is not None:
        worker_lifecycle_intent.complete_publication_step(publication_step)


def records_for(installation, private_root, *, existing=False):
    root = Path(private_root)
    require(root.is_absolute() and root.is_dir())
    if existing:
        require((root / "worker-host").is_dir())
    return host.HostRecords(installation, root)


def load(records, selected_id):
    with records.locked():
        record = records.read(selected_id)
    return record


def components(record, *, client=True):
    observer = runtime.LocalDocker(
        record["context"],
        runtime.WorkerLayout(**record["layout"]),
        **(
            {"protocol": "persistent-v3"}
            if "mode" in record["registration"]
            else {
                "protocol": "finite-v2",
                "max_attempts": record["registration"]["max_attempts"],
            }
            if "max_attempts" in record["registration"]
            else {"protocol": "legacy-v1"}
        ),
    )
    identity = runtime.RuntimeIdentity(**record["registration"]["identity"])
    api = (
        host.HostClient(record["client"]["base_url"], record["client"]["ca_file"])
        if client
        else None
    )
    if api is not None:
        host._client(record, api)
    host._observer(record, observer)
    return api, observer, identity


def _enable_options(args):
    """Validate the original registration options before an incarnation exists."""
    protocol = getattr(args, "protocol", "persistent-v3")
    maximum = getattr(args, "max_attempts", None)
    idle = getattr(args, "idle_timeout_seconds", None)
    if protocol == "persistent-v3":
        import worker_host_persistent

        require(args.expires_in is None)
        selected_limits = worker_host_persistent.limits(
            {"max_attempts": maximum, "idle_timeout_seconds": idle}
        )
        admission_options = {"protocol": protocol, "limits": selected_limits}
        observer_options = {"protocol": protocol}
    else:
        require(protocol in {"finite-v2", "legacy-v1"} and idle is None)
        expiry = 900 if args.expires_in is None else args.expires_in
        require(type(expiry) is int and 60 <= expiry <= 604800)
        if protocol == "finite-v2":
            require(maximum is not None)
            if type(maximum) is str:
                require(re.fullmatch(r"[1-9][0-9]?", maximum) is not None)
                maximum = int(maximum)
            require(type(maximum) is int and 1 <= maximum <= 32)
        else:
            require(maximum is None)
        admission_options = {
            "expires_in_seconds": expiry,
            **({"max_attempts": maximum} if maximum is not None else {}),
        }
        observer_options = {
            "protocol": protocol,
            **({"max_attempts": maximum} if maximum is not None else {}),
        }
    return admission_options, observer_options


def _enable_setup(args):
    """Keep the existing enable setup prefix; never acquire custody or a lock."""
    args._failure_phase = "enable_inputs"
    admission_options, observer_options = _enable_options(args)
    require(
        re.fullmatch(r"[0-9a-f]{64}", args.container_id or "")
        and re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id or "")
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", args.project or "")
    )
    runtime_id(args.runner_id)
    trust = public_trust(args.public_trust)
    public = Path(args.admission_source)
    require(
        public.is_absolute()
        and public.is_dir()
        and not (public / "admission.json").exists()
    )
    if (public / "trust.json").exists():
        require(public_trust(public / "trust.json") == trust)
    args._failure_phase = "enable_observer_setup"
    observer = runtime.LocalDocker(
        args.context,
        runtime.WorkerLayout(
            args.trust_source,
            args.admission_source,
            args.state_volume,
            args.readiness_volume,
        ),
        **observer_options,
    )
    args._failure_phase = "enable_api_setup"
    client = host.HostClient(args.api_url, args.ca)
    return observer, client, public, trust, admission_options


def _enable_owned(
    args, records, operation, setup, *, registration_capability=None,
    preauthenticated_owner=None,
):
    """Continue enablement only inside this exact records owner's live operation."""
    records._require_operation(operation)
    observer, client, public, trust, admission_options = setup
    if preauthenticated_owner is not None:
        require(registration_capability is not None
                and type(preauthenticated_owner) is _PreparedEnableOwner)
        preauthenticated_owner._match(records, operation, client)
    with records.locked(operation=operation):
        require(not (records.installation / updater.STATE).exists())
        require(not (public / "admission.json").exists())
    args._failure_phase = "enable_owner_auth"
    with (
        owner(client, args) if preauthenticated_owner is None
        else preauthenticated_owner._take(records, operation, client)
    ) as session:
        args._failure_phase = "enable_capture"
        identity = observer.capture_running(
            container_id=args.container_id, image_id=args.image_id, project=args.project
        )
        args._failure_phase = "enable_registration"
        admission = host.register_runtime(
            client,
            records,
            session,
            issuer_origin=args.origin,
            enrollment_id=args.enrollment_id,
            runner_id=args.runner_id,
            identity=identity,
            observer=observer,
            runtime_id=args.runtime_id,
            operation=operation,
            **admission_options,
            **({} if registration_capability is None else {"registration_capability": registration_capability}),
        )
    # The host receipt exists before public permission can enter the container.
    args._failure_phase = "enable_publication_checks"
    with records.locked(operation=operation):
        require(not (records.installation / updater.STATE).exists())
        record = records.read(args.runtime_id)
        host._client(record, client)
        host._observer(record, observer)
        require(
            record["registration_state"] == "acknowledged"
            and record["admission"] == admission
        )
        args._failure_phase = "enable_recapture"
        require(
            observer.capture_running(
                container_id=args.container_id,
                image_id=args.image_id,
                project=args.project,
            )
            == identity
        )
        args._failure_phase = "enable_mount_custody"
        records.outside_mounts(observer, identity)
        with host.ExitStack() as publications:
            sequence = None
            if registration_capability is not None:
                import worker_lifecycle_intent

                args._failure_phase = "enable_publication_checks"
                sequence = publications.enter_context(
                    worker_lifecycle_intent.publication_sequence(
                        registration_capability, public=public, trust=trust, admission=admission
                    )
                )
            args._failure_phase = "enable_publish_trust"
            if not (public / "trust.json").exists():
                publish_public(public / "trust.json", trust, **({} if sequence is None else {
                    "publication_step": worker_lifecycle_intent.publication_step(
                        sequence, kind="trust", path=public / "trust.json", data=trust
                    )
                }))
            else:
                validated = public_trust(public / "trust.json")
                require(validated == trust)
                if sequence is not None:
                    worker_lifecycle_intent.skip_existing_trust(
                        sequence, path=public / "trust.json", validated_trust=validated
                    )
            args._failure_phase = "enable_publish_admission"
            raw_admission = host.canonical(admission)
            publish_public(public / "admission.json", raw_admission, **({} if sequence is None else {
                "publication_step": worker_lifecycle_intent.publication_step(
                    sequence, kind="admission", path=public / "admission.json", data=raw_admission
                )
            }))
            if sequence is not None:
                worker_lifecycle_intent.finish_publication(sequence)
    return admission, identity


def enable(installation, args):
    setup = _enable_setup(args)
    args._failure_phase = "enable_custody"
    records = records_for(installation, args.private_root)
    with records.operation() as operation:
        admission, identity = _enable_owned(args, records, operation, setup)
    return {
        "schema": "vardr.worker-cli/1",
        "state": "enabled",
        "runtime_id": args.runtime_id,
        "runtime_sha256": admission["runtime_sha256"],
        "identity": asdict(identity),
        "local_runner_reconciliation": "required_after_terminal_exit",
    }


def stop(records, selected_id):
    with records.locked():
        record = records.read(selected_id)
        _, observer, identity = components(record, client=False)
        require(observer._observation_lock.acquire(blocking=False))
        try:
            observer._deadline = time.monotonic() + 30
            value = observer._bound(identity)
            if value["state"]["Status"] != "exited":
                require(
                    value["state"]["Status"] == "running"
                    and value["state"]["Running"] is True
                )
                signal = json.loads(
                    observer._command(
                        "container",
                        "inspect",
                        "--format",
                        "{{json .Config.StopSignal}}",
                        identity.container_id,
                    )
                )
                require(signal in (None, "", "SIGTERM"))
                # One aggregate pre-stop/stop deadline. The existing adapter
                # clips every subprocess timeout to its remaining duration.
                observer._bound(identity)
                observer._command(
                    "container", "stop", "-t", "10", identity.container_id, timeout=25
                )
        finally:
            observer._deadline = None
            observer._observation_lock.release()
        # Exit proof owns its separate bounded observation lock and deadline.
        proof = observer.observe_exit(identity)
        require(isinstance(proof, runtime.ObservedExit))
        return record, observer, proof


def setup_path(installation, args):
    if args.setup:
        return Path(args.setup).expanduser().resolve(strict=True)
    pointer = host._json((installation / ".managed-worker.json").read_bytes())
    require(pointer["schema"] == "vardr.worker-setup-pointer/1")
    return Path(pointer["preparation"]).resolve(strict=True)


def onboarding(installation, args):
    import recovery
    import worker_prepare
    import worker_job

    root = Path(installation).resolve(strict=True)
    if args.action == "start":
        # The existing launch path owns its lock and all admission/custody gates.
        import worker_launch
        args.setup = str(setup_path(root, args))
        selected, config, client = worker_job.setup(args.setup, root)
        binding = worker_job.read(Path(selected["private_root"]) / "enrollment.json")
        require(binding["setup_sha256"] == host.digest(selected)
                and binding["owner_id"] == selected["owner_id"])
        key = worker_prepare.read_runner_key(root, selected, client=client)
        previous = os.environ.get("VARDRMAP_API_KEY")
        try:
            os.environ["VARDRMAP_API_KEY"] = key
            args.action = "launch"
            args.api_url, args.ca = selected["api"]["base_url"], selected["api"]["ca_file"]
            for name in ("private_root", "project", "state_volume", "origin", "public_trust",
                         "admission_root", "runner_network", "launch_config"):
                setattr(args, name, selected[name])
            args.context, args.image_id = selected["context"], selected["worker_image"]
            args.enrollment_id, args.runner_id = binding["enrollment_id"], binding["runner_id"]
            args.protocol, args.expires_in = "persistent-v3", None
            return worker_launch.launch(root, args)
        finally:
            key = None
            if previous is None:
                os.environ.pop("VARDRMAP_API_KEY", None)
            else:
                os.environ["VARDRMAP_API_KEY"] = previous
    with updater.operation_guard(root, "start"):
        args._failure_phase = "onboarding"
        if args.action == "prepare":
            require(not (root / ".managed-worker.json").exists())
            client = worker_prepare.discover_client(root, context=args.context)
            model = host._json(worker_prepare._compose(client, root, "--profile", "tools", "config", "--format", "json"))
            port = int(model["services"]["proxy"]["environment"]["HTTPS_PORT"])
            api = host.HostClient(f"https://localhost:{port}/backend", root / "trust" / "root.crt")
            private = Path(args.private_root).expanduser().absolute() if args.private_root else root.parent / (model["name"] + "-operator")
            public = Path(args.admission_root).expanduser().absolute() if args.admission_root else root.parent / (model["name"] + "-worker-public")
            # Validate destinations before writing even empty credential placeholders.
            paths = (root.resolve(), private.resolve(), public.resolve())
            require(all(left != right and left not in right.parents and right not in left.parents
                        for index, left in enumerate(paths) for right in paths[index + 1:]))
            with owner(api, args, expected_transport=api._owner_transport()) as session:
                owner_id = session.owner_id()
                import worker_build
                worker_image = args.worker_image or worker_build.build(root, client=client)
                private.mkdir(mode=0o700, exist_ok=True)
                credentials = args.credential_file
                if credentials is None and args.credential_name:
                    require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
                                and not name.startswith(("VARDR", "DOCKER", "COMPOSE")) for name in args.credential_name))
                    credentials = private / "worker.env"
                    recovery.private_write(credentials, ("# Supply the named values privately before starting.\n" +
                                           "".join(name + "=\n" for name in args.credential_name)).encode())
                result = worker_prepare.prepare(
                    root, client=client, private_root=private, admission_root=public,
                    worker_image=worker_image,
                    owner_id=owner_id, issuer_id=args.issuer_id or "map:" + str(uuid.uuid4()),
                    credential_file=credentials, credential_names=args.credential_name, api_pin=api.pin(),
                )
            path = private / "preparation.json"
            recovery.private_write(root / ".managed-worker.json", host.canonical({
                "schema": "vardr.worker-setup-pointer/1", "preparation": str(path),
            }))
            return {"schema": "vardr.worker-cli/1", "state": "prepared", "runtime_id": None,
                    "preparation": str(path), "issuer_id": result["issuer_id"],
                    "origin": result["origin"], "credential_file": str(private / "worker.env")
                    if credentials is None else str(credentials),
                    "worker_started": False, "job_authorized": False}
        args.setup = str(setup_path(root, args))
        selected, _, client = worker_job.setup(args.setup, root)
        if args.action == "job-approve":
            return worker_job.approve(root, args)
        api = host.HostClient(selected["api"]["base_url"], selected["api"]["ca_file"])
        with owner(api, args, expected_transport=api._owner_transport()) as session:
            if args.action == "configure":
                receipt = worker_prepare.configure(root, selected, client=client, session=session,
                                                    allow_plaintext_key=args.allow_plaintext_key)
                return {"schema": "vardr.worker-cli/1", "state": "configured", "runtime_id": None,
                        "enrollment": receipt, "worker_started": False, "job_authorized": False}
            if args.action == "job-review":
                return worker_job.review(root, args, session)
            require(args.action == "job-register")
            return worker_job.register(root, args, session)


def dispatch(installation, args):
    if args.action in {"prepare", "configure", "start", "job-review", "job-approve", "job-register"}:
        return onboarding(installation, args)
    if args.action == "launch":
        import worker_launch

        return worker_launch.launch(installation, args)
    if args.action in {"enable", "register"}:
        return enable(installation, args)
    records = records_for(installation, args.private_root, existing=True)
    if args.action == "stop":
        selected = load(records, args.runtime_id)
        if "mode" in selected["registration"] and selected["disable_state"] == "none":
            import worker_host_persistent

            try:
                client, _, _ = components(selected)
                worker_host_persistent.disable(client, records, args.runtime_id)
            except (host.HostRefused, runtime.RuntimeRefused, OSError, ValueError):
                pass  # Exact physical emergency stop remains available offline.
        record, observer, proof = stop(records, args.runtime_id)
        if args.report:
            client, _, _ = components(record)
            receipt = host.report_observed_exit(
                client, records, args.runtime_id, proof, observer
            )
            return {
                "schema": "vardr.worker-cli/1",
                "state": "terminal_observed",
                "runtime_id": args.runtime_id,
                "receipt": receipt,
                "local_runner_reconciliation": "required",
            }
        return {
            "schema": "vardr.worker-cli/1",
            "state": "stopped_observed",
            "runtime_id": args.runtime_id,
            "identity": asdict(proof.identity),
            "exit_code": proof.exit_code,
            "finished_at": proof.finished_at,
            "local_runner_reconciliation": "required",
            **(
                {"new_work_disable_state": record["disable_state"]}
                if "mode" in record["registration"]
                else {}
            ),
        }
    record = load(records, args.runtime_id)
    if args.action == "status":
        _, observer, identity = components(record, client=False)
        if "mode" in record["registration"]:
            import worker_host_persistent

            return worker_host_persistent.status(
                records, args.runtime_id, observer, identity
            )
        with records.locked():
            require(records.read(args.runtime_id) == record)
            actual = observer._bound(identity)
        return {
            "schema": "vardr.worker-cli/1",
            "state": "observed",
            "runtime_id": args.runtime_id,
            "identity": asdict(identity),
            "container_state": actual["state"]["Status"],
            **{
                key: record[key]
                for key in ("registration_state", "stop_state", "revocation_state")
            },
            "receipt": record["receipt"],
            **(
                {
                    "configured_max_attempts": record["registration"]["max_attempts"],
                    "stop_report_cursors": [
                        entry["cursor"] for entry in record["report_cursors"]
                    ],
                }
                if "max_attempts" in record["registration"]
                else {}
            ),
        }
    client, observer, identity = components(record)
    if args.action == "disable":
        import worker_host_persistent

        require("mode" in record["registration"])
        reply = worker_host_persistent.disable(client, records, args.runtime_id)
        return {
            "schema": "vardr.worker-cli/1",
            "state": "new_work_disabled",
            "runtime_id": args.runtime_id,
            "receipt": reply,
        }
    if args.action == "reconcile":
        reply = host.reconcile_exit(client, records, args.runtime_id)
        sequenced = reply.get("schema") in {
            "vardr.worker-receipt-observation/2",
            "vardr.worker-receipt-observation/3",
        }
        terminal = reply["retirement"] if sequenced else reply["receipt"]
        if (
            reply.get("schema") == "vardr.worker-receipt-observation/3"
            and terminal is None
            and load(records, args.runtime_id)["disable_state"] == "observed"
        ):
            return {
                "schema": "vardr.worker-cli/1",
                "state": "new_work_disabled_observed",
                "runtime_id": args.runtime_id,
                "receipt": reply,
                "local_runner_reconciliation": "not_required_for_disable",
            }
        return {
            "schema": "vardr.worker-cli/1",
            "state": "terminal_observed"
            if terminal is not None
            else (
                "held_no_retirement_receipt"
                if sequenced
                else "held_no_terminal_receipt"
            ),
            "runtime_id": args.runtime_id,
            "receipt": reply,
            "local_runner_reconciliation": "required",
        }
    if args.action == "report-exit":
        proof = observer.observe_exit(identity)
        require(isinstance(proof, runtime.ObservedExit))
        report = (
            host.continue_observed_exit
            if getattr(args, "continue_after_transition", False)
            else host.report_observed_exit
        )
        reply = report(client, records, args.runtime_id, proof, observer)
        return {
            "schema": "vardr.worker-cli/1",
            "state": "terminal_observed",
            "runtime_id": args.runtime_id,
            "receipt": reply,
            "local_runner_reconciliation": "required",
        }
    require(args.action == "revoke")
    with owner(client, args) as session:
        reply = host.revoke_runtime(client, records, session, args.runtime_id)
    return {
        "schema": "vardr.worker-cli/1",
        "state": "revoked",
        "runtime_id": args.runtime_id,
        "receipt": reply,
        "local_runner_reconciliation": "required_if_attempt_exists",
    }


def main(argv=None, *, installation=None):
    selected_id = None
    args = None
    try:
        args = parser().parse_args(argv)
        args._failure_phase = "installation"
        installation = (
            Path(__file__).resolve().parent
            if installation is None
            else Path(installation)
        )
        require(installation.is_absolute() and installation.is_dir())
        if args.action in {"enable", "register", "launch", "start"} and getattr(args, "runtime_id", None) is None:
            args.runtime_id = str(uuid.uuid4())
        selected_id = getattr(args, "runtime_id", None)
        args._failure_phase = "dispatch"
        reply = dispatch(installation, args)
        print(json.dumps(reply, sort_keys=True))
        return (
            1 if reply["state"] == "held" or reply["state"].startswith("held_") else 0
        )
    except SystemExit as result:
        return result.code
    except KeyboardInterrupt as error:
        print(
            json.dumps(
                {
                    "schema": "vardr.worker-cli/1",
                    "state": "held_interrupted",
                    "runtime_id": selected_id,
                    **failure_diagnostic(args, error),
                }
            )
        )
        return 130
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema": "vardr.worker-cli/1",
                    "state": "held",
                    "runtime_id": selected_id,
                    **failure_diagnostic(args, error),
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

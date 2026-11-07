"""Explicit admission and stop controls for an already prepared managed worker.

No account/key/enrollment/approval generation, Compose start, daemon or replay.
The API's strict managed configuration and immutable worker must already exist.
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
    enable = actions.add_parser(
        "enable",
        aliases=["register"],
        help="Admit an exact already running worker; never start one",
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
    enable.add_argument("--runtime-id", type=runtime_id)
    enable.add_argument(
        "--protocol",
        choices=("persistent-v3", "finite-v2", "legacy-v1"),
        default="persistent-v3",
        help="Explicit matching image protocol; normal background availability uses v3",
    )
    enable.add_argument(
        "--max-attempts",
        help="Optional v3 finite job limit; required1..32 for explicit finite-v2",
    )
    enable.add_argument(
        "--idle-timeout-seconds",
        type=int,
        help="Optional v3 finite idle limit1..86400; omission leaves persistent idle unbounded",
    )
    enable.add_argument(
        "--expires-in",
        type=int,
        help="Legacy/finite admission seconds60..604800 (default900); not a v3 lifetime",
    )
    enable.add_argument("--username", default="operator")
    enable.add_argument(
        "--password-stdin",
        action="store_true",
        help="Explicitly read one bounded password line from stdin instead of hidden TTY input",
    )
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
def owner(client, args):
    value = password(args.password_stdin)
    try:
        with client.owner_session(args.username, value) as session:
            yield session
    finally:
        value = None


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


def publish_public(path, data):
    """Atomic exclusive public publication; no overwrite or implicit replay."""
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink())
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".prepared")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
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


def enable(installation, args):
    args._failure_phase = "enable_inputs"
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
    args._failure_phase = "enable_custody"
    records = records_for(installation, args.private_root)
    with records.operation() as operation:
        with records.locked(operation=operation):
            require(not (installation / updater.STATE).exists())
            require(not (public / "admission.json").exists())
        args._failure_phase = "enable_owner_auth"
        with owner(client, args) as session:
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
            )
        # The host receipt exists before public permission can enter the container.
        args._failure_phase = "enable_publication_checks"
        with records.locked(operation=operation):
            require(not (installation / updater.STATE).exists())
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
            args._failure_phase = "enable_publish_trust"
            if not (public / "trust.json").exists():
                publish_public(public / "trust.json", trust)
            else:
                require(public_trust(public / "trust.json") == trust)
            args._failure_phase = "enable_publish_admission"
            publish_public(public / "admission.json", host.canonical(admission))
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


def dispatch(installation, args):
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
        if args.action in {"enable", "register"} and args.runtime_id is None:
            args.runtime_id = str(uuid.uuid4())
        selected_id = args.runtime_id
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

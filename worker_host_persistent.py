"""Explicit v3 availability/reporting protocol; no execution or restart authority.

The proposed until-revoked STOP lifetime is inactive pending owner disposition.
Existing v1/v2 paths never negotiate or downgrade into this module.
"""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
import stat
import time
import uuid

import worker_host as host
import worker_runtime as runtime

MAX_SEQUENCE = 2**63 - 1
REPORT_LIMIT = 65
REPORT_BYTES = 8192
REPORT_PREFIX = b"vardr.worker-host-report-record/2\x00"
REPORTING_AUTHORITY = {"purpose": "worker-stop-only", "expires_at": None}
REGISTRATION = {
    "enrollment_id",
    "runner_id",
    "origin",
    "identity",
    "capability_sha256",
    "mode",
    "limits",
    "reporting_authority",
}


def decimal(value, *, minimum=0):
    host.require(
        type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is not None
    )
    number = int(value)
    host.require(minimum <= number <= MAX_SEQUENCE)
    return number


def limits(value):
    host.require(
        type(value) is dict and set(value) == {"max_attempts", "idle_timeout_seconds"}
    )
    maximum, idle = value["max_attempts"], value["idle_timeout_seconds"]
    if maximum is not None:
        decimal(maximum, minimum=1)
    host.require(idle is None or (type(idle) is int and 1 <= idle <= 86400))
    return dict(value)


def registration(value):
    host.require(
        type(value) is dict
        and set(value) == REGISTRATION
        and value["mode"] == "persistent"
    )
    limits(value["limits"])
    host.require(value["reporting_authority"] == REPORTING_AUTHORITY)
    host._identifier(value["enrollment_id"])
    host._uuid(value["runner_id"])
    host._url(value["origin"], external=True)
    host._hash(value["capability_sha256"])
    host.require(
        type(value["identity"]) is dict
        and set(value["identity"])
        == {
            "daemon_id",
            "container_id",
            "image_id",
            "project",
            "started_at",
            "owner_nonce",
        }
    )
    runtime.RuntimeIdentity(**value["identity"])
    return value


def expected_admission(record):
    selected = registration(record["registration"])
    value = {
        "schema": "vardr.worker-admission/3",
        "runtime_id": host._uuid(record["runtime_id"]),
        "runtime_sha256": host.digest(selected["identity"]),
        **selected,
    }
    return {**value, "admission_sha256": host.digest(value)}


def admission(record, value):
    host.require(
        type(value) is dict
        and host.canonical(value) == host.canonical(expected_admission(record))
    )
    return value


def cursor_key(value):
    host.require(type(value) is dict and set(value) == {"last_sequence", "phase"})
    number = decimal(value["last_sequence"])
    host.require(type(value["phase"]) is str and value["phase"] in {"active", "idle"})
    host.require(number > 0 or value["phase"] == "idle")
    return number, 0 if value["phase"] == "active" else 1


def _identity(record, value):
    expected = expected_admission(record)
    host.require(
        all(
            value[key] == expected[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256")
        )
    )
    return expected


def _within_limit(record, value):
    number = decimal(value)
    maximum = record["registration"]["limits"]["max_attempts"]
    host.require(maximum is None or number <= decimal(maximum, minimum=1))
    return number


def retirement(record, value):
    host.require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "admission_sha256",
            "origin",
            "runner_id",
            "enrollment_id",
            "runtime_sequence",
            "last_sequence",
            "binding",
            "attempt_receipt",
            "report_sha256",
            "retired",
            "receipt_sha256",
        }
    )
    _identity(record, value)
    selected = record["registration"]
    host.require(
        value["schema"] == "vardr.worker-retirement/3"
        and value["retired"] is True
        and all(
            value[key] == selected[key]
            for key in ("origin", "runner_id", "enrollment_id")
        )
    )
    _within_limit(record, value["last_sequence"])
    if value["runtime_sequence"] is None:
        host.require(value["binding"] is None and value["attempt_receipt"] is None)
    else:
        decimal(value["runtime_sequence"], minimum=1)
        host.require(value["runtime_sequence"] == value["last_sequence"])
        host._binding(record, value["binding"])
        host._terminal(value["binding"], value["attempt_receipt"])
    host._hash(value["report_sha256"])
    host.require(
        host._hash(value["receipt_sha256"])
        == host.digest(
            {key: item for key, item in value.items() if key != "receipt_sha256"}
        )
    )
    return value


def _stamp(value):
    host.require(
        type(value) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value,
        )
        is not None
    )
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise host.HostRefused("worker_host_refused") from None


def lookup(record, value):
    host.require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "admission_sha256",
            "cursor",
            "active",
            "retirement",
            "new_work_disabled",
            "reporting_revoked",
            "availability",
        }
    )
    _identity(record, value)
    host.require(
        value["schema"] == "vardr.worker-receipt-observation/3"
        and type(value["new_work_disabled"]) is type(value["reporting_revoked"]) is bool
    )
    number, phase = cursor_key(value["cursor"])
    _within_limit(record, value["cursor"]["last_sequence"])
    active = value["active"]
    if phase == 1:
        host.require(active is None)
    else:
        host.require(
            type(active) is dict
            and set(active) == {"runtime_sequence", "binding", "receipt"}
        )
        host.require(decimal(active["runtime_sequence"], minimum=1) == number)
        host._binding(record, active["binding"])
        if active["receipt"] is not None:
            host._terminal(active["binding"], active["receipt"])
    if value["retirement"] is not None:
        closed = retirement(record, value["retirement"])
        host.require(
            closed["last_sequence"] == value["cursor"]["last_sequence"]
            and closed["runtime_sequence"]
            == (active["runtime_sequence"] if active else None)
            and closed["binding"] == (active["binding"] if active else None)
            and closed["attempt_receipt"] == (active["receipt"] if active else None)
        )
    host.require(record["receipt"] is None or record["receipt"] == value["retirement"])
    host.require(
        record["revocation_state"] != "acknowledged" or value["reporting_revoked"]
    )
    host.require(
        record["disable_state"] not in {"acknowledged", "observed"}
        or value["new_work_disabled"]
    )
    presence = value["availability"]
    host.require(
        type(presence) is dict
        and set(presence) == {"state", "observed_at", "fresh_until", "cursor"}
        and type(presence["state"]) is str
        and presence["state"] in {"idle-ready", "active", "held", "stopped"}
        and presence["cursor"] == value["cursor"]
    )
    if presence["observed_at"] is None:
        host.require(
            presence["fresh_until"] is None and presence["state"] in {"held", "stopped"}
        )
    else:
        observed, end = _stamp(presence["observed_at"]), _stamp(presence["fresh_until"])
        host.require(timedelta(0) < end - observed <= timedelta(seconds=15))
    return value


def register_runtime(
    client,
    records,
    session,
    *,
    issuer_origin,
    enrollment_id,
    runner_id,
    identity,
    observer,
    runtime_id,
    selected_limits,
    operation=None,
    registration_capability=None,
):
    with host.registration_step("inputs"):
        host.require(
            isinstance(client, host.HostClient)
            and isinstance(session, host.OwnerSession)
            and session.client is client
        )
        host.require(
            isinstance(identity, runtime.RuntimeIdentity)
            and isinstance(observer, runtime.LocalDocker)
            and observer.protocol == "persistent-v3"
        )
        selected_limits = limits(selected_limits)
        runtime_id = str(uuid.uuid4()) if runtime_id is None else host._uuid(runtime_id)
    with host.registration_step("inputs"), records.locked(
        **({} if operation is None else {"operation": operation})
    ):
        with host.registration_step("secret_store"):
            host.require(
                not records._path(runtime_id).exists()
                and records.backend.read(runtime_id) is None
            )
        with host.registration_step("local_capture"):
            captured = observer.capture_running(
                container_id=identity.container_id,
                image_id=identity.image_id,
                project=identity.project,
            )
            with host.registration_step("local_identity_changed"):
                host.require(captured == identity)
        with host.registration_step("mount_custody"):
            records.outside_mounts(observer, identity)
        secret = secrets.token_hex(32)
        with host.registration_step("inputs"):
            selected = registration(
                {
                    "enrollment_id": enrollment_id,
                    "runner_id": runner_id,
                    "origin": issuer_origin,
                    "identity": asdict(identity),
                    "capability_sha256": hashlib.sha256(
                        host._CAPABILITY + secret.encode("ascii")
                    ).hexdigest(),
                    "mode": "persistent",
                    "limits": selected_limits,
                    "reporting_authority": dict(REPORTING_AUTHORITY),
                }
            )
        with host.registration_step("secret_store"):
            records.backend.create(runtime_id, secret)
        with host.registration_step("initial_store"):
            record = {
                "runtime_id": runtime_id,
                "installation": str(records.installation.resolve(strict=True)),
                "storage_root": str(records.private_root.resolve(strict=True)),
                "client": client.pin(),
                "context": observer.context,
                "layout": asdict(observer.layout),
                "registration": selected,
                "registration_state": "prepared",
                "admission": None,
                "stop_intent": None,
                "stop_state": "none",
                "receipt": None,
                "revocation_state": "none",
                "report_cursors": [],
                "disable_state": "none",
                "disable_intent": None,
                "disable_receipt": None,
            }
            records.write(record, create=True)
        try:
            with host.ExitStack() as attempts:
                with host.registration_step("request"):
                    if registration_capability is not None:
                        import worker_lifecycle_intent

                        attempt = attempts.enter_context(worker_lifecycle_intent.registration_fence(
                            registration_capability, records=records, operation=operation,
                            client=client, observer=observer, identity=identity,
                            runtime_id=runtime_id, protocol="persistent-v3",
                            selected=selected, record=record,
                        ))
                    reply = session.register(runtime_id, selected)
                with host.registration_step("ack"):
                    record["admission"] = admission(record, reply)
                record["registration_state"] = "acknowledged"
                with host.registration_step("final_store"):
                    records.write(record)
                if registration_capability is not None:
                    worker_lifecycle_intent.stage_original_ack(
                        attempt,
                        record=record, admission=record["admission"],
                    )
                return record["admission"]
        except Exception as error:
            record["registration_state"] = "unknown"
            with host.registration_step("unknown_store"):
                records.write(record)
            raise host.HostRefused(
                registration_failure=host.registration_diagnostic(error)
            ) from None


def _receipt(client, record, secret):
    expected = expected_admission(record)
    return lookup(
        record,
        client.receipt(
            record["runtime_id"],
            expected["runtime_sha256"],
            secret,
            admission_sha256=expected["admission_sha256"],
        ),
    )


def _disable_ack(record, value):
    expected = expected_admission(record)
    payload = {
        "schema": "vardr.worker-disable/1",
        **{
            key: expected[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256")
        },
        "new_work_disabled": True,
    }
    host.require(
        type(value) is dict
        and host.canonical(value)
        == host.canonical({**payload, "receipt_sha256": host.digest(payload)})
    )
    return value


def record_state(record):
    """Validate v3 local transition metadata without I/O or capability changes."""
    expected = expected_admission(record)
    for key, allowed in (
        ("registration_state", {"prepared", "unknown", "acknowledged"}),
        ("stop_state", {"none", "prepared", "unknown", "observed"}),
        ("revocation_state", {"none", "prepared", "unknown", "acknowledged"}),
        ("disable_state", {"none", "prepared", "unknown", "acknowledged", "observed"}),
    ):
        host.require(type(record.get(key)) is str and record[key] in allowed)
    if record.get("admission") is not None:
        admission(record, record["admission"])
    host.require(
        record["registration_state"] != "acknowledged"
        or record.get("admission") is not None
    )
    host.require(
        (record.get("receipt") is not None) == (record["stop_state"] == "observed")
    )
    if record.get("receipt") is not None:
        retirement(record, record["receipt"])
    intent = record.get("disable_intent")
    receipt = record.get("disable_receipt")
    if record["disable_state"] == "none":
        host.require(intent is None and receipt is None)
    else:
        host.require(
            type(intent) is dict
            and intent
            == {key: expected[key] for key in ("runtime_sha256", "admission_sha256")}
        )
        if record["disable_state"] == "acknowledged":
            _disable_ack(record, receipt)
        else:
            host.require(receipt is None)
    return record


def disable(client, records, runtime_id):
    """One new-work disable mutation; reporting authority is retained."""
    with records.locked():
        record = records.read(runtime_id)
        host._client(record, client)
        expected = expected_admission(record)
        if record["disable_state"] == "acknowledged":
            return _disable_ack(record, record["disable_receipt"])
        host.require(
            record["disable_state"] == "none"
            and record["disable_intent"] is None
            and record["disable_receipt"] is None
        )
        body = {key: expected[key] for key in ("runtime_sha256", "admission_sha256")}
        record.update(disable_intent=body, disable_state="prepared")
        records.write(record)
        try:
            reply = _disable_ack(
                record,
                client.disable(
                    runtime_id,
                    body["runtime_sha256"],
                    body["admission_sha256"],
                    records.secret(runtime_id),
                ),
            )
            record.update(disable_state="acknowledged", disable_receipt=reply)
            records.write(record)
            return reply
        except Exception:
            record["disable_state"] = "unknown"
            records.write(record)
            raise host.HostRefused("worker_host_refused") from None


def status(records, runtime_id, observer, identity, *, client=None):
    """Read-only availability observation; never a lease or terminal report."""
    with records.locked():
        record = records.read(runtime_id)
        host._observer(record, observer)
        host.require(
            isinstance(identity, runtime.RuntimeIdentity)
            and asdict(identity) == record["registration"]["identity"]
        )
        _reports(records, record)
        value = {
            "schema": "vardr.worker-status/1",
            "runtime_id": runtime_id,
            "protocol": "persistent-v3",
            "mode": "persistent",
            "limits": record["registration"]["limits"],
            "identity": asdict(identity),
            "state": "held",
            "reason": "physical_unconfirmed",
            "cursor": None,
            "availability": None,
            "new_work_disabled": None,
            "reporting_revoked": None,
            **{
                key: record[key]
                for key in (
                    "registration_state",
                    "disable_state",
                    "stop_state",
                    "revocation_state",
                )
            },
        }
        try:
            with observer._observation_lock:
                host.require(observer._deadline is None)
                observer._deadline = time.monotonic() + 30
                try:
                    actual = observer._bound(identity)
                    state = actual["state"]["Status"]
                    if state == "running":
                        try:
                            if client is None:
                                client = host.HostClient(
                                    record["client"]["base_url"],
                                    record["client"]["ca_file"],
                                )
                            host._client(record, client)
                            current = _receipt(
                                client, record, records.secret(runtime_id)
                            )
                        except (host.HostRefused, OSError, ValueError):
                            value["reason"] = "availability_unconfirmed"
                        else:
                            value.update(
                                cursor=current["cursor"],
                                availability=current["availability"],
                                new_work_disabled=current["new_work_disabled"],
                                reporting_revoked=current["reporting_revoked"],
                            )
                            final = observer._bound(identity)
                            runtime.require(final["state"]["Status"] == "running")
                            presence = current["availability"]
                            fresh = presence["observed_at"] is not None and _stamp(
                                presence["observed_at"]
                            ) <= datetime.now(timezone.utc) < _stamp(
                                presence["fresh_until"]
                            )
                            expected_state = (
                                "active"
                                if current["active"] is not None
                                else "idle-ready"
                            )
                            if (
                                fresh
                                and presence["state"] == expected_state
                                and not current["new_work_disabled"]
                                and not current["reporting_revoked"]
                                and record["registration_state"] == "acknowledged"
                                and record["stop_state"] == "none"
                                and record["disable_state"] == "none"
                            ):
                                value.update(state=expected_state, reason=None)
                            else:
                                value["reason"] = (
                                    "new_work_disabled"
                                    if current["new_work_disabled"]
                                    else "reporting_revoked"
                                    if current["reporting_revoked"]
                                    else "registration_unconfirmed"
                                    if record["registration_state"] != "acknowledged"
                                    else "terminal_unconfirmed"
                                    if record["stop_state"] != "none"
                                    else "disable_unconfirmed"
                                    if record["disable_state"] != "none"
                                    else "availability_stale"
                                    if not fresh
                                    else "availability_unconfirmed"
                                )
                    value["container_state"] = state
                finally:
                    observer._deadline = None
            if state == "exited":
                proof = observer.observe_exit(identity)
                host.require(isinstance(proof, runtime.ObservedExit))
                value.update(
                    state="stopped",
                    reason=None,
                    exit_code=proof.exit_code,
                    finished_at=proof.finished_at,
                )
        except (host.HostRefused, OSError, ValueError, runtime.RuntimeRefused):
            value.update(state="held", reason="physical_unconfirmed")
        return value


def _report_path(records, runtime_id, ordinal):
    host._uuid(runtime_id)
    host.require(type(ordinal) is int and 0 <= ordinal < REPORT_LIMIT)
    return records.directory / f"{runtime_id}.report-v3-{ordinal:02d}.json"


def _load_report(records, runtime_id, ordinal):
    records._directory()
    path = _report_path(records, runtime_id, ordinal)
    info = path.lstat()
    host.require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 0x400
    )
    if os.name != "nt":
        host.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
    with path.open("rb") as source:
        raw = source.read(REPORT_BYTES + 1)
    host.require(len(raw) <= REPORT_BYTES)
    wrapped = host._json(raw)
    host.require(
        set(wrapped) == {"schema", "payload", "mac"}
        and wrapped["schema"] == "vardr.worker-host-report-record/2"
    )
    value = wrapped["payload"]
    host.require(
        type(value) is dict
        and set(value)
        == {"runtime_id", "ordinal", "cursor", "intent", "state", "receipt"}
        and value["runtime_id"] == runtime_id
        and type(value["ordinal"]) is int
        and value["ordinal"] == ordinal
    )
    mac = hmac.new(
        bytes.fromhex(records.secret(runtime_id)),
        REPORT_PREFIX + host.canonical(value),
        hashlib.sha256,
    ).hexdigest()
    host.require(
        hmac.compare_digest(host._hash(wrapped["mac"]), mac)
        and value["state"] in {"prepared", "unknown", "observed"}
    )
    return value


def _store_report(records, value, *, create=False):
    records._directory()
    path = _report_path(records, value["runtime_id"], value["ordinal"])
    if create:
        host.require(not path.exists() and not path.is_symlink())
    else:
        old = _load_report(records, value["runtime_id"], value["ordinal"])
        host.require(
            old["intent"] == value["intent"]
            and old["cursor"] == value["cursor"]
            and (old["receipt"] is None or old["receipt"] == value["receipt"])
        )
    mac = hmac.new(
        bytes.fromhex(records.secret(value["runtime_id"])),
        REPORT_PREFIX + host.canonical(value),
        hashlib.sha256,
    ).hexdigest()
    raw = host.canonical(
        {"schema": "vardr.worker-host-report-record/2", "payload": value, "mac": mac}
    )
    host.require(len(raw) <= REPORT_BYTES)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        host._publish(temporary, path)
        if os.name != "nt":
            directory = os.open(
                records.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _intent(record, value):
    body = value["intent"]
    number, phase = cursor_key(value["cursor"])
    base = host._UNBOUND_INTENT | {"admission_sha256"}
    host.require(type(body) is dict)
    expected = expected_admission(record)
    host.require(
        body["runtime_sha256"] == expected["runtime_sha256"]
        and body["admission_sha256"] == expected["admission_sha256"]
    )
    if phase == 0:
        host.require(
            set(body) == base | host._BINDING | {"runtime_sequence"}
            and decimal(body["runtime_sequence"], minimum=1) == number
        )
        host._binding(record, {key: body[key] for key in host._BINDING})
    else:
        host.require(
            set(body) == base | {"last_sequence"}
            and decimal(body["last_sequence"]) == number
        )
    _within_limit(record, str(number))
    host._hash(body["observation_sha256"])
    host.require(type(body["exit_code"]) is int and 0 <= body["exit_code"] <= 255)
    runtime._timestamp(body["finished_at"])


def _reports(records, record):
    entries = record["report_cursors"]
    host.require(type(entries) is list and len(entries) <= REPORT_LIMIT)
    values = []
    for ordinal, entry in enumerate(entries):
        host.require(
            type(entry) is dict
            and set(entry) == {"ordinal", "cursor", "intent_sha256"}
            and type(entry["ordinal"]) is int
            and entry["ordinal"] == ordinal
        )
        value = _load_report(records, record["runtime_id"], ordinal)
        host.require(
            value["cursor"] == entry["cursor"]
            and host.digest(value["intent"]) == host._hash(entry["intent_sha256"])
        )
        _intent(record, value)
        if value["receipt"] is None:
            host.require(value["state"] in {"prepared", "unknown"})
        else:
            closed = retirement(record, value["receipt"])
            host.require(
                value["state"] == "observed"
                and closed["last_sequence"] == value["cursor"]["last_sequence"]
                and closed["runtime_sequence"]
                == (
                    value["cursor"]["last_sequence"]
                    if value["cursor"]["phase"] == "active"
                    else None
                )
                and closed["report_sha256"] == _purpose(record, value["intent"])
            )
            if closed["runtime_sequence"] is not None:
                host.require(
                    closed["binding"]
                    == {key: value["intent"][key] for key in host._BINDING}
                )
        host.require(
            not values or cursor_key(value["cursor"]) > cursor_key(values[-1]["cursor"])
        )
        values.append(value)
    actual = set()
    for path in records.directory.glob(record["runtime_id"] + ".report-v3-*.json"):
        host.require(len(actual) < REPORT_LIMIT)
        actual.add(path.name)
    host.require(
        actual
        == {
            _report_path(records, record["runtime_id"], ordinal).name
            for ordinal in range(len(values))
        }
    )
    if values:
        host.require(values[0]["intent"] == record["stop_intent"])
    else:
        host.require(record["stop_intent"] is None)
    return values


def history(client, record, selected_sequence, secret):
    decimal(selected_sequence, minimum=1)
    _within_limit(record, selected_sequence)
    expected = expected_admission(record)
    value = client.attempt_receipt(
        record["runtime_id"],
        selected_sequence,
        expected["runtime_sha256"],
        secret,
        admission_sha256=expected["admission_sha256"],
    )
    host.require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "admission_sha256",
            "runtime_sequence",
            "binding",
            "receipt",
            "release",
        }
    )
    _identity(record, value)
    host.require(
        value["schema"] == "vardr.worker-attempt-observation/2"
        and decimal(value["runtime_sequence"], minimum=1)
        == decimal(selected_sequence, minimum=1)
    )
    host._binding(record, value["binding"])
    if value["receipt"] is not None:
        host._terminal(value["binding"], value["receipt"])
    if value["release"] is not None:
        release = value["release"]
        host.require(
            type(release) is dict
            and set(release)
            == {
                "schema",
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "runtime_sequence",
                "binding",
                "terminal_receipt_sha256",
                "native_done_sha256",
                "released",
                "receipt_sha256",
            }
        )
        host.require(
            value["receipt"] is not None
            and value["receipt"]["schema"] == "vardr.managed-completion/1"
            and value["receipt"]["outcome"] in {"completed", "failed"}
        )
        payload = {
            "schema": "vardr.worker-idle-release/2",
            **{
                key: value[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "admission_sha256",
                    "runtime_sequence",
                    "binding",
                )
            },
            "terminal_receipt_sha256": host.digest(value["receipt"]),
            "native_done_sha256": host._hash(release["native_done_sha256"]),
            "released": True,
        }
        host.require(
            host.canonical(release)
            == host.canonical({**payload, "receipt_sha256": host.digest(payload)})
        )
    return value


def _progress(client, record, old, current, secret):
    before, after = cursor_key(old["cursor"]), cursor_key(current["cursor"])
    host.require(after > before and after[0] <= before[0] + 1)
    if before[1] == 0:
        previous = history(client, record, str(before[0]), secret)
        host.require(
            previous["binding"] == {key: old["intent"][key] for key in host._BINDING}
            and previous["release"] is not None
        )
    if after[0] > before[0]:
        following = history(client, record, str(after[0]), secret)
        if current["active"] is not None:
            host.require(following["binding"] == current["active"]["binding"])
        else:
            host.require(following["release"] is not None)


def _purpose(record, body):
    return host.digest(
        {
            "schema": "vardr.worker-exit-report/3"
            if "runtime_sequence" in body
            else "vardr.worker-unbound-exit-report/3",
            "runtime_id": record["runtime_id"],
            **body,
        }
    )


def reconcile(client, records, runtime_id):
    with records.locked():
        record = records.read(runtime_id)
        host._client(record, client)
        _reports(records, record)
        reply = _receipt(client, record, records.secret(runtime_id))
        if (
            record["disable_state"] in {"prepared", "unknown"}
            and reply["new_work_disabled"]
        ):
            record["disable_state"] = "observed"  # Never invent the original ACK.
        if reply["retirement"] is not None:
            record.update(receipt=reply["retirement"], stop_state="observed")
        records.write(record)
        return reply


def report(client, records, runtime_id, proof, observer, *, continuation=False):
    host.require(isinstance(proof, runtime.ObservedExit))
    with records.locked():
        record = records.read(runtime_id)
        host._client(record, client)
        host._observer(record, observer)
        host.require(record["registration"]["identity"] == asdict(proof.identity))
        records.outside_mounts(observer, proof.identity)
        reports = _reports(records, record)
        secret = records.secret(runtime_id)
        current = _receipt(client, record, secret)
        if current["retirement"] is not None:
            record.update(receipt=current["retirement"], stop_state="observed")
            records.write(record)
            return current
        host.require(not current["reporting_revoked"])
        if continuation:
            host.require(reports and reports[-1]["state"] in {"prepared", "unknown"})
            _progress(client, record, reports[-1], current, secret)
        else:
            host.require(not reports and record["stop_state"] == "none")
        host.require(len(reports) < REPORT_LIMIT)
        expected, active = expected_admission(record), current["active"]
        body = {
            **{key: expected[key] for key in ("runtime_sha256", "admission_sha256")},
            "finished_at": proof.finished_at,
            "exit_code": proof.exit_code,
            "observation_sha256": host.digest(
                {
                    "identity": asdict(proof.identity),
                    "finished_at": proof.finished_at,
                    "exit_code": proof.exit_code,
                }
            ),
            **(
                {**active["binding"], "runtime_sequence": active["runtime_sequence"]}
                if active
                else {"last_sequence": current["cursor"]["last_sequence"]}
            ),
        }
        host.require(
            all(
                all(
                    previous["intent"][key] == body[key]
                    for key in ("finished_at", "exit_code", "observation_sha256")
                )
                for previous in reports
            )
        )
        value = {
            "runtime_id": runtime_id,
            "ordinal": len(reports),
            "cursor": current["cursor"],
            "intent": body,
            "state": "prepared",
            "receipt": None,
        }
        _intent(record, value)
        observer.confirm_exit(proof)
        _store_report(records, value, create=True)
        record["report_cursors"].append(
            {
                "ordinal": value["ordinal"],
                "cursor": value["cursor"],
                "intent_sha256": host.digest(body),
            }
        )
        if record["stop_intent"] is None:
            record["stop_intent"] = body
        record["stop_state"] = "prepared"
        records.write(record)
        try:
            ack = (client.observed_exit if active else client.observed_unbound_exit)(
                runtime_id, body, secret
            )
            host.require(
                type(ack) is dict
                and set(ack) == {"schema", "runtime_id", "runtime_sha256", "receipt"}
                and ack["schema"] == "vardr.worker-host-stop/1"
                and ack["runtime_id"] == runtime_id
                and ack["runtime_sha256"] == expected["runtime_sha256"]
            )
            closed = retirement(record, ack["receipt"])
            host.require(
                closed["report_sha256"] == _purpose(record, body)
                and closed["last_sequence"] == current["cursor"]["last_sequence"]
                and closed["runtime_sequence"]
                == (active["runtime_sequence"] if active else None)
                and closed["binding"] == (active["binding"] if active else None)
            )
            if active:
                terminal = closed["attempt_receipt"]
                host.require(
                    terminal == active["receipt"]
                    if active["receipt"] is not None
                    else (
                        terminal["outcome"] == "failed"
                        and (
                            terminal["schema"] == "vardr.managed-completion/1"
                            or terminal.get("cause") == "observed_exit"
                        )
                    )
                )
            value.update(state="observed", receipt=closed)
            _store_report(records, value)
            record.update(receipt=closed, stop_state="observed")
            records.write(record)
            return ack
        except Exception:
            value["state"] = "unknown"
            _store_report(records, value)
            record["stop_state"] = "unknown"
            records.write(record)
            raise host.HostRefused("worker_host_refused") from None

"""Bounded per-cursor host reports; no execution or retry authority."""

import hashlib
import hmac
import os
import stat
import uuid

import worker_host as host
import worker_runtime as runtime

PREFIX = b"vardr.worker-host-report-record/1\x00"
LIMIT = 8192


def _path(records, runtime_id, cursor):
    host._uuid(runtime_id)
    host.require(type(cursor) is int and 0 <= cursor <= 64)
    return records.directory / f"{runtime_id}.report-{cursor:02d}.json"


def _load(records, runtime_id, cursor):
    records._directory()
    path = _path(records, runtime_id, cursor)
    info = path.lstat()
    host.require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 0x400
    )
    if os.name != "nt":
        host.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    host.require(len(raw) <= LIMIT)
    wrapped = host._json(raw)
    host.require(
        type(wrapped) is dict
        and set(wrapped) == {"schema", "payload", "mac"}
        and wrapped["schema"] == "vardr.worker-host-report-record/1"
    )
    value = wrapped["payload"]
    host.require(
        type(value) is dict
        and set(value) == {"runtime_id", "cursor", "intent", "state", "receipt"}
    )
    host.require(value["runtime_id"] == runtime_id and value["cursor"] == cursor)
    mac = hmac.new(
        bytes.fromhex(records.secret(runtime_id)),
        PREFIX + host.canonical(value),
        hashlib.sha256,
    ).hexdigest()
    host.require(hmac.compare_digest(host._hash(wrapped["mac"]), mac))
    host.require(
        value["state"] in {"prepared", "unknown", "observed"}
        and type(value["intent"]) is dict
    )
    return value


def _store(records, value, *, create=False):
    records._directory()
    path = _path(records, value["runtime_id"], value["cursor"])
    if create:
        host.require(not path.exists() and not path.is_symlink())
    else:
        old = _load(records, value["runtime_id"], value["cursor"])
        host.require(old["intent"] == value["intent"])
        host.require(old["receipt"] is None or old["receipt"] == value["receipt"])
    mac = hmac.new(
        bytes.fromhex(records.secret(value["runtime_id"])),
        PREFIX + host.canonical(value),
        hashlib.sha256,
    ).hexdigest()
    raw = host.canonical(
        {"schema": "vardr.worker-host-report-record/1", "payload": value, "mac": mac}
    )
    host.require(len(raw) <= LIMIT)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
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


def _reports(records, record):
    maximum = record["registration"].get("max_attempts", 1)
    host.require(type(maximum) is int and 1 <= maximum <= 32)
    entries = record.get("report_cursors", [])
    host.require(type(entries) is list and len(entries) <= 2 * maximum + 1)
    result = []
    for entry in entries:
        host.require(type(entry) is dict and set(entry) == {"cursor", "intent_sha256"})
        host.require(not result or entry["cursor"] > result[-1]["cursor"])
        host.require(
            type(entry["cursor"]) is int and 0 <= entry["cursor"] <= 2 * maximum
        )
        value = _load(records, record["runtime_id"], entry["cursor"])
        host.require(host.digest(value["intent"]) == entry["intent_sha256"])
        _intent(record, value)
        result.append(value)
    if result:
        host.require(result[0]["intent"] == record["stop_intent"])
    return result


def _intent(record, value):
    body, cursor = value["intent"], value["cursor"]
    base = host._UNBOUND_INTENT
    maximum = record["registration"].get("max_attempts")
    if maximum is None:
        host.require(set(body) == (base if cursor == 0 else base | host._BINDING))
        host.require(cursor in {0, 1})
        if cursor == 1:
            host._binding(record, {key: body[key] for key in host._BINDING})
    elif "runtime_sequence" in body:
        host.require(set(body) == base | host._BINDING | {"runtime_sequence"})
        number = body["runtime_sequence"]
        host.require(
            type(number) is int and 1 <= number <= maximum and cursor == 2 * number - 1
        )
        host._binding(record, {key: body[key] for key in host._BINDING})
    else:
        host.require(set(body) == base | {"last_sequence"})
        number = body["last_sequence"]
        host.require(
            type(number) is int and 0 <= number <= maximum and cursor == 2 * number
        )
    host.require(
        body["runtime_sha256"] == host.digest(record["registration"]["identity"])
    )
    host._hash(body["observation_sha256"])
    host.require(type(body["exit_code"]) is int and 0 <= body["exit_code"] <= 255)
    runtime._timestamp(body["finished_at"])


def retirement(record, value):
    host.require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
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
    registration = record["registration"]
    host.require(
        value["schema"] == "vardr.worker-retirement/2"
        and value["runtime_id"] == record["runtime_id"]
        and value["runtime_sha256"] == host.digest(registration["identity"])
    )
    host.require(
        all(
            value[key] == registration[key]
            for key in ("origin", "runner_id", "enrollment_id")
        )
    )
    last = value["last_sequence"]
    host.require(
        type(last) is int
        and 0 <= last <= registration["max_attempts"]
        and value["retired"] is True
    )
    host._hash(value["report_sha256"])
    host.require(
        host._hash(value["receipt_sha256"])
        == host.digest(
            {key: item for key, item in value.items() if key != "receipt_sha256"}
        )
    )
    if value["runtime_sequence"] is None:
        host.require(value["binding"] is None and value["attempt_receipt"] is None)
    else:
        host.require(
            type(value["runtime_sequence"]) is int
            and value["runtime_sequence"] == last
            and last > 0
        )
        host._binding(record, value["binding"])
        host.require(value["attempt_receipt"] is not None)
        host._terminal(value["binding"], value["attempt_receipt"])
    return value


def lookup(record, reply):
    host.require(
        type(reply) is dict
        and set(reply)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "last_sequence",
            "active",
            "retirement",
        }
    )
    host.require(
        reply["schema"] == "vardr.worker-receipt-observation/2"
        and reply["runtime_id"] == record["runtime_id"]
        and reply["runtime_sha256"] == host.digest(record["registration"]["identity"])
    )
    last = reply["last_sequence"]
    host.require(
        type(last) is int and 0 <= last <= record["registration"]["max_attempts"]
    )
    active = reply["active"]
    if active is not None:
        host.require(
            type(active) is dict
            and set(active) == {"runtime_sequence", "binding", "receipt"}
        )
        host.require(
            type(active["runtime_sequence"]) is int
            and active["runtime_sequence"] == last
            and last > 0
        )
        host._binding(record, active["binding"])
        if active["receipt"] is not None:
            host._terminal(active["binding"], active["receipt"])
    if reply["retirement"] is not None:
        retired = retirement(record, reply["retirement"])
        host.require(retired["last_sequence"] == last)
        host.require(
            retired["runtime_sequence"]
            == (active["runtime_sequence"] if active else None)
        )
        host.require(retired["binding"] == (active["binding"] if active else None))
        host.require(
            retired["attempt_receipt"] == (active["receipt"] if active else None)
        )
    host.require(record["receipt"] is None or record["receipt"] == reply["retirement"])
    return reply


def _history(client, record, sequence, secret):
    reply = client.attempt_receipt(
        record["runtime_id"],
        sequence,
        host.digest(record["registration"]["identity"]),
        secret,
    )
    host.require(
        type(reply) is dict
        and set(reply)
        == {
            "schema",
            "runtime_id",
            "runtime_sha256",
            "runtime_sequence",
            "binding",
            "receipt",
            "release",
        }
    )
    host.require(
        type(reply["runtime_sequence"]) is int
        and 1 <= reply["runtime_sequence"] <= 32
        and reply["schema"] == "vardr.worker-attempt-observation/1"
        and reply["runtime_id"] == record["runtime_id"]
        and reply["runtime_sha256"] == host.digest(record["registration"]["identity"])
        and reply["runtime_sequence"] == sequence
    )
    host._binding(record, reply["binding"])
    if reply["receipt"] is not None:
        host._terminal(reply["binding"], reply["receipt"])
    if reply["release"] is not None:
        release = reply["release"]
        host.require(
            type(release) is dict
            and set(release)
            == {
                "schema",
                "runtime_id",
                "runtime_sha256",
                "runtime_sequence",
                "binding",
                "terminal_receipt_sha256",
                "native_done_sha256",
                "released",
                "receipt_sha256",
            }
        )
        host.require(
            release["schema"] == "vardr.worker-idle-release/1"
            and release["released"] is True
        )
        host._binding(record, release["binding"])
        host.require(
            host.canonical(
                {
                    key: release[key]
                    for key in (
                        "runtime_id",
                        "runtime_sha256",
                        "runtime_sequence",
                        "binding",
                    )
                }
            )
            == host.canonical(
                {
                    key: reply[key]
                    for key in (
                        "runtime_id",
                        "runtime_sha256",
                        "runtime_sequence",
                        "binding",
                    )
                }
            )
        )
        host.require(
            reply["receipt"] is not None
            and reply["receipt"]["outcome"] == "completed"
            and release["terminal_receipt_sha256"] == host.digest(reply["receipt"])
        )
        expected = {
            "schema": "vardr.worker-idle-release/1",
            **{
                key: reply[key]
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "runtime_sequence",
                    "binding",
                )
            },
            "terminal_receipt_sha256": host.digest(reply["receipt"]),
            "native_done_sha256": host._hash(release["native_done_sha256"]),
            "released": True,
        }
        host.require(
            host.canonical(release)
            == host.canonical({**expected, "receipt_sha256": host.digest(expected)})
        )
    return reply


def _cursor(reply):
    return 2 * reply["last_sequence"] - (1 if reply["active"] is not None else 0)


def _purpose(record, intent):
    return host.digest(
        {
            "schema": "vardr.worker-exit-report/2"
            if "runtime_sequence" in intent
            else "vardr.worker-unbound-exit-report/2",
            "runtime_id": record["runtime_id"],
            **intent,
        }
    )


def reconcile(client, records, runtime_id):
    with records.locked():
        record = records.read(runtime_id)
        host._client(record, client)
        _reports(records, record)
        reply = lookup(
            record,
            client.receipt(
                runtime_id,
                host.digest(record["registration"]["identity"]),
                records.secret(runtime_id),
            ),
        )
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
        host.require(record["registration"]["identity"] == host.asdict(proof.identity))
        records.outside_mounts(observer, proof.identity)
        if record["registration"].get("max_attempts") is None:
            host.require(continuation)
            return _continue_v1(client, records, record, proof, observer)
        reports = _reports(records, record)
        secret = records.secret(runtime_id)
        sha = host.digest(record["registration"]["identity"])
        reply = lookup(record, client.receipt(runtime_id, sha, secret))
        if reply["retirement"] is not None:
            record.update(receipt=reply["retirement"], stop_state="observed")
            records.write(record)
            return reply
        cursor = _cursor(reply)
        if continuation:
            host.require(
                reports
                and reports[-1]["state"] in {"prepared", "unknown"}
                and cursor > reports[-1]["cursor"]
            )
            old = reports[-1]["intent"]
            sequence = old.get("runtime_sequence", reply["last_sequence"])
            history = _history(client, record, sequence, secret)
            if "runtime_sequence" in old:
                host.require(
                    history["binding"] == {key: old[key] for key in host._BINDING}
                    and history["release"] is not None
                )
            elif reply["active"] is None:
                host.require(history["release"] is not None)
            else:
                host.require(history["binding"] == reply["active"]["binding"])
        else:
            host.require(
                not reports
                and record["stop_intent"] is None
                and record["stop_state"] == "none"
            )
        active = reply["active"]
        body = {
            "runtime_sha256": sha,
            "finished_at": proof.finished_at,
            "exit_code": proof.exit_code,
            "observation_sha256": host.digest(
                {
                    "identity": host.asdict(proof.identity),
                    "finished_at": proof.finished_at,
                    "exit_code": proof.exit_code,
                }
            ),
        }
        body.update(
            {**active["binding"], "runtime_sequence": active["runtime_sequence"]}
            if active
            else {"last_sequence": reply["last_sequence"]}
        )
        if reports:
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
            "cursor": cursor,
            "intent": body,
            "state": "prepared",
            "receipt": None,
        }
        observer.confirm_exit(proof)
        _store(records, value, create=True)
        record["report_cursors"].append(
            {"cursor": cursor, "intent_sha256": host.digest(body)}
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
                and ack["runtime_sha256"] == sha
            )
            retired = retirement(record, ack["receipt"])
            host.require(
                retired["report_sha256"] == _purpose(record, body)
                and retired["runtime_sequence"]
                == (active["runtime_sequence"] if active else None)
                and retired["last_sequence"] == reply["last_sequence"]
            )
            if active:
                host.require(retired["binding"] == active["binding"])
                terminal = retired["attempt_receipt"]
                host.require(
                    terminal == active["receipt"]
                    or (
                        terminal["outcome"] == "failed"
                        and (
                            terminal["schema"] == "vardr.managed-completion/1"
                            or terminal.get("cause") == "observed_exit"
                        )
                    )
                )
            value.update(state="observed", receipt=retired)
            _store(records, value)
            record.update(receipt=retired, stop_state="observed")
            records.write(record)
            return ack
        except Exception:
            value["state"] = "unknown"
            _store(records, value)
            record["stop_state"] = "unknown"
            records.write(record)
            raise host.HostRefused("worker_host_refused") from None


def _continue_v1(client, records, record, proof, observer):
    """The one-way v1 unbound-to-bound case; retain its original intent."""
    runtime_id = record["runtime_id"]
    host.require(
        record["stop_state"] in {"prepared", "unknown"} and record["receipt"] is None
    )
    host.require(host._intent_kind(record) == "unbound")
    reports = _reports(records, record)
    host.require(not reports or (len(reports) == 1 and reports[0]["cursor"] == 0))
    sha = host.digest(record["registration"]["identity"])
    secret = records.secret(runtime_id)
    reply = host._lookup(record, client.receipt(runtime_id, sha, secret))
    binding = reply["binding"]
    host.require(binding is not None)
    if reply["receipt"] is not None:
        record.update(receipt=reply["receipt"], stop_state="observed")
        records.write(record)
        return reply
    body = {
        "runtime_sha256": sha,
        **binding,
        "finished_at": proof.finished_at,
        "exit_code": proof.exit_code,
        "observation_sha256": host.digest(
            {
                "identity": host.asdict(proof.identity),
                "finished_at": proof.finished_at,
                "exit_code": proof.exit_code,
            }
        ),
    }
    host.require(
        all(
            record["stop_intent"][key] == body[key]
            for key in ("finished_at", "exit_code", "observation_sha256")
        )
    )
    observer.confirm_exit(proof)
    if not reports:
        original = {
            "runtime_id": runtime_id,
            "cursor": 0,
            "intent": record["stop_intent"],
            "state": record["stop_state"],
            "receipt": None,
        }
        _store(records, original, create=True)
        record["report_cursors"] = [
            {"cursor": 0, "intent_sha256": host.digest(original["intent"])}
        ]
    value = {
        "runtime_id": runtime_id,
        "cursor": 1,
        "intent": body,
        "state": "prepared",
        "receipt": None,
    }
    _store(records, value, create=True)
    record["report_cursors"].append({"cursor": 1, "intent_sha256": host.digest(body)})
    record["stop_state"] = "prepared"
    records.write(record)
    try:
        ack = client.observed_exit(runtime_id, body, secret)
        host.require(
            type(ack) is dict
            and set(ack) == {"schema", "runtime_id", "runtime_sha256", "receipt"}
            and ack["schema"] == "vardr.worker-host-stop/1"
            and ack["runtime_id"] == runtime_id
            and ack["runtime_sha256"] == sha
        )
        terminal = host._terminal(binding, ack["receipt"])
        host.require(
            terminal["outcome"] == "failed"
            and (
                terminal["schema"] == "vardr.managed-completion/1"
                or terminal.get("cause") == "observed_exit"
            )
        )
        value.update(state="observed", receipt=terminal)
        _store(records, value)
        record.update(receipt=terminal, stop_state="observed")
        records.write(record)
        return ack
    except Exception:
        value["state"] = "unknown"
        _store(records, value)
        record["stop_state"] = "unknown"
        records.write(record)
        raise host.HostRefused("worker_host_refused") from None

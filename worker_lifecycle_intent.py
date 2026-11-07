"""Protected lifecycle metadata only; no launcher, replay or execution authority.

MACs and sticky updates discipline a trusted host's interrupted operations. They
are not attestation or protection against a key holder restoring older valid files.
"""

from dataclasses import asdict
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid

import worker_host as host
import worker_runtime as runtime


SCHEMA = "vardr.worker-lifecycle-intent/3"
_DOMAIN = b"vardr.worker-lifecycle-intent/3\0"
_LIMIT = 65536
_MAX_REVISION = 9223372036854775807
_FLAGS = frozenset(
    {
        "public_directory_may_have_been_created",
        "readiness_may_have_been_created",
        "container_create_may_have_sent",
        "start_may_have_sent",
        "registration_may_have_sent",
        "publication_may_have_happened",
    }
)
_OBSERVATIONS = frozenset(
    {
        "created",
        "running",
        "registration_sha256",
        "host_record_sha256",
        "admission_sha256",
    }
)
_IMMUTABLE = frozenset(
    {
        "operation_id",
        "future_runtime_id",
        "installation",
        "storage_root",
        "source",
        "binding",
        "predecessors",
        "resources",
        "registration_policy",
    }
)


class IntentRefused(ValueError):
    def __init__(self):
        super().__init__("worker_lifecycle_intent_refused")


def require(value):
    if not value:
        raise IntentRefused()


def fields(value, names):
    require(type(value) is dict and set(value) == names)
    return value


def text(value, maximum=4096):
    require(
        type(value) is str
        and 0 < len(value) <= maximum
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )
    return value


def integer(value, minimum=1):
    require(type(value) is int and minimum <= value <= _MAX_REVISION)
    return value


def image(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value))


def registration_policy(value):
    """Reviewed public registration inputs; no defaults, credentials or coercion."""
    fields(
        value,
        {
            "origin",
            "enrollment_id",
            "runner_id",
            "protocol",
            "expires_in_seconds",
            "limits",
            "reporting_authority",
        },
    )
    host._url(value["origin"], external=True)
    host._identifier(value["enrollment_id"])
    host._uuid(value["runner_id"])
    protocol = value["protocol"]
    require(
        type(protocol) is str
        and protocol in {"legacy-v1", "finite-v2", "persistent-v3"}
    )
    if protocol == "persistent-v3":
        import worker_host_persistent

        require(value["expires_in_seconds"] is None)
        worker_host_persistent.limits(value["limits"])
        fields(value["reporting_authority"], {"purpose", "expires_at"})
        require(
            value["reporting_authority"] == worker_host_persistent.REPORTING_AUTHORITY
        )
    else:
        require(
            type(value["expires_in_seconds"]) is int
            and 60 <= value["expires_in_seconds"] <= 604800
        )
        limits = fields(value["limits"], {"max_attempts", "idle_timeout_seconds"})
        require(
            limits["idle_timeout_seconds"] is None
            and value["reporting_authority"] is None
        )
        if protocol == "finite-v2":
            require(
                type(limits["max_attempts"]) is int
                and 1 <= limits["max_attempts"] <= 32
            )
        else:
            require(limits["max_attempts"] is None)
    return value


def _checked(payload):
    fields(
        payload,
        _IMMUTABLE
        | {"revision", "previous_sha256", "effects", "observations", "disposition"},
    )
    host._uuid(payload["operation_id"])
    registration_policy(payload["registration_policy"])
    host._uuid(payload["future_runtime_id"])
    require(payload["operation_id"] != payload["future_runtime_id"])
    for name in ("installation", "storage_root"):
        text(payload[name])
    revision = integer(payload["revision"])
    if revision == 1:
        require(payload["previous_sha256"] is None)
    else:
        host._hash(payload["previous_sha256"])
    source = fields(
        payload["source"],
        {
            "distribution_commit",
            "distribution_tree",
            "runner_commit",
            "runner_image",
            "map_commit",
            "gate_commit",
            "compose_version",
            "compose_executable_sha256",
            "unresolved_model_sha256",
            "closed_override_sha256",
            "environment_contract_sha256",
            "core_image_set_sha256",
        },
    )
    for name in (
        "distribution_commit",
        "distribution_tree",
        "runner_commit",
        "map_commit",
        "gate_commit",
    ):
        require(
            type(source[name]) is str and re.fullmatch(r"[0-9a-f]{40}", source[name])
        )
    image(source["runner_image"])
    require(
        type(source["compose_version"]) is str and source["compose_version"] == "5.6.1"
    )
    for name in (
        "compose_executable_sha256",
        "unresolved_model_sha256",
        "closed_override_sha256",
        "environment_contract_sha256",
        "core_image_set_sha256",
    ):
        host._hash(source[name])
    binding = fields(
        payload["binding"], {"context", "local_endpoint", "daemon_id", "project"}
    )
    for name in ("context", "daemon_id"):
        text(binding[name], 128)
    require(
        type(binding["local_endpoint"]) is str
        and binding["local_endpoint"].startswith(("unix:///", "npipe:////"))
    )
    text(binding["local_endpoint"])
    require(
        type(binding["project"]) is str
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", binding["project"])
    )
    predecessors = payload["predecessors"]
    require(type(predecessors) is list and bool(predecessors))
    ids, runtimes = set(), set()
    for ordinal, row in enumerate(predecessors, 1):
        fields(
            row,
            {
                "ordinal",
                "container_id",
                "image_id",
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "host_retirement_sha256",
                "original_local_audit_sha256",
            },
        )
        require(integer(row["ordinal"]) == ordinal)
        host._hash(row["container_id"])
        image(row["image_id"])
        host._uuid(row["runtime_id"])
        require(
            row["container_id"] not in ids
            and row["runtime_id"] not in runtimes
            and row["runtime_id"]
            not in {payload["operation_id"], payload["future_runtime_id"]}
        )
        ids.add(row["container_id"])
        runtimes.add(row["runtime_id"])
        for name in (
            "runtime_sha256",
            "admission_sha256",
            "host_retirement_sha256",
            "original_local_audit_sha256",
        ):
            host._hash(row[name])
    resources = fields(
        payload["resources"],
        {
            "core_containers",
            "runner_network",
            "runner_state",
            "trust_source",
            "trust_sha256",
            "signing_trust_sha256",
            "public_directory",
            "readiness_volume",
            "readiness_marker",
            "expected_ordinal",
        },
    )
    core = resources["core_containers"]
    require(type(core) is list and len(core) == 4)
    services = set()
    for row in core:
        fields(row, {"service", "container_id", "image_id"})
        require(
            type(row["service"]) is str
            and row["service"] in {"db", "api", "web", "proxy"}
            and row["service"] not in services
        )
        services.add(row["service"])
        host._hash(row["container_id"])
        require(row["container_id"] not in ids)
        ids.add(row["container_id"])
        image(row["image_id"])
    network = fields(resources["runner_network"], {"id", "name", "metadata_sha256"})
    host._hash(network["id"])
    text(network["name"], 128)
    host._hash(network["metadata_sha256"])
    state = fields(
        resources["runner_state"], {"name", "source", "created_at", "metadata_sha256"}
    )
    for name in ("name", "source", "created_at"):
        text(state[name], 128 if name != "source" else 4096)
    host._hash(state["metadata_sha256"])
    for name in (
        "trust_source",
        "public_directory",
        "readiness_volume",
        "readiness_marker",
    ):
        text(resources[name])
    require(resources["readiness_volume"] != state["name"])
    host._hash(resources["trust_sha256"])
    host._hash(resources["signing_trust_sha256"])
    require(integer(resources["expected_ordinal"]) == len(predecessors) + 1)
    effects = fields(payload["effects"], _FLAGS)
    require(all(type(value) is bool for value in effects.values()))
    observed = fields(payload["observations"], _OBSERVATIONS)
    for name in _OBSERVATIONS - {"created", "running"}:
        if observed[name] is not None:
            host._hash(observed[name])
    created, running = observed["created"], observed["running"]
    if created is not None:
        fields(
            created,
            {
                "container_id",
                "image_id",
                "project",
                "daemon_id",
                "ordinal",
                "readiness_volume",
            },
        )
        host._hash(created["container_id"])
        require(
            created["container_id"] not in ids
            and created["image_id"] == source["runner_image"]
            and all(created[k] == binding[k] for k in ("project", "daemon_id"))
            and integer(created["ordinal"]) == resources["expected_ordinal"]
            and created["readiness_volume"] == resources["readiness_volume"]
            and effects["container_create_may_have_sent"]
        )
    if running is not None:
        fields(
            running,
            {
                "daemon_id",
                "container_id",
                "image_id",
                "project",
                "started_at",
                "owner_nonce",
            },
        )
        require(
            created is not None
            and effects["start_may_have_sent"]
            and all(
                running[k] == created[k]
                for k in ("daemon_id", "container_id", "image_id", "project")
            )
        )
        runtime._timestamp(running["started_at"])
        host._hash(running["owner_nonce"])
    require(
        not effects["container_create_may_have_sent"]
        or (
            effects["public_directory_may_have_been_created"]
            and effects["readiness_may_have_been_created"]
        )
    )
    require(not effects["start_may_have_sent"] or created is not None)
    require(
        not effects["registration_may_have_sent"]
        or (running is not None and observed["registration_sha256"] is not None)
    )
    require(
        not effects["publication_may_have_happened"]
        or (
            effects["registration_may_have_sent"]
            and observed["host_record_sha256"] is not None
            and observed["admission_sha256"] is not None
        )
    )
    disposition = payload["disposition"]
    require(
        type(disposition) is str
        and disposition in {"active", "held", "enabled", "abandoned_preparation"}
    )
    if disposition == "enabled":
        require(effects["publication_may_have_happened"])
    if disposition == "abandoned_preparation":
        require(
            created is not None
            and not any(
                effects[k]
                for k in (
                    "start_may_have_sent",
                    "registration_may_have_sent",
                    "publication_may_have_happened",
                )
            )
        )
    require(
        len(host.canonical({"schema": SCHEMA, "payload": payload, "mac": "0" * 64}))
        <= _LIMIT
    )
    return payload


def _publish_new(temporary, destination, *, records, operation):
    require(
        type(records) is host.HostRecords
        and destination.parent == records._intent_access(operation)
        and temporary.parent == destination.parent
    )
    if os.name != "nt":
        os.link(
            temporary, destination
        )  # Atomic destination nonexistence, no overwrite.
        return
    import ctypes
    from ctypes import wintypes

    move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL

    def wide(path):
        value = str(path.absolute())
        if value.startswith("\\\\?\\"):
            return value
        return (
            "\\\\?\\UNC\\" + value[2:]
            if value.startswith("\\\\")
            else "\\\\?\\" + value
        )

    # Same-directory WRITE_THROUGH only. No replace/copy/reboot fallback.
    require(move(wide(temporary), wide(destination), 0x8))


def _write(path, raw, *, create, records, operation):
    require(
        type(records) is host.HostRecords
        and path.parent == records._intent_access(operation)
    )
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as output:
        require(output.write(raw) == len(raw))
        output.flush()
        os.fsync(output.fileno())
    if create:
        _publish_new(temporary, path, records=records, operation=operation)
    else:
        host._publish(temporary, path)
    temporary.unlink(missing_ok=True)
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    # On failure partial private artifacts are retained; no effect is retried.


def _inventory_entries(directory, deadline):
    """Classify every name before any key read; unknown or linked files hold."""
    entries = {}
    for path in directory.iterdir():
        require(time.monotonic() < deadline and path.name not in entries)
        selected, separator, suffix = path.name.partition(".")
        require(separator == ".")
        host._uuid(selected)
        ordinal = None
        if suffix == "json":
            kind = "record"
        elif suffix == "intent.json":
            kind = "intent"
        else:
            report = re.fullmatch(r"report-v3-([0-9]{2})\.json", suffix)
            require(report is not None)
            kind, ordinal = "report", int(report[1])
            require(0 <= ordinal <= 64)
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= _LIMIT
        )
        entries[path.name] = (
            kind,
            selected,
            ordinal,
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_mode,
        )
    return entries


class IntentStore:
    def __init__(self, records):
        # Inert: neither provider construction nor path/key/file access.
        self.records = records

    def inventory(self, *, operation):
        """Read original protected records and intents; no proof or effect is minted."""
        try:
            require(type(self.records) is host.HostRecords)
            directory = self.records._intent_access(operation)
            deadline = time.monotonic() + 30
            before = _inventory_entries(directory, deadline)
            available = {entry[1] for entry in before.values() if entry[0] == "record"}
            require(
                all(
                    entry[1] in available
                    for entry in before.values()
                    if entry[0] == "report"
                )
            )
            records, intents, reports = {}, {}, []
            for kind, selected, ordinal, *_ in sorted(before.values()):
                require(time.monotonic() < deadline)
                if kind == "record":
                    records[selected] = self.records.read(selected)
                elif kind == "intent":
                    intents[selected] = self.read(selected, operation=operation)
                else:
                    import worker_host_persistent

                    row = worker_host_persistent._load_report(
                        self.records, selected, ordinal
                    )
                    reports.append(
                        {
                            "runtime_id": selected,
                            "ordinal": ordinal,
                            "state": row["state"],
                        }
                    )
            future_ids = set()
            for row in intents.values():
                require(time.monotonic() < deadline)
                selected = row["future_runtime_id"]
                require(selected not in future_ids)
                future_ids.add(selected)
                if row["disposition"] == "enabled":
                    record = records[selected]
                    observed = row["observations"]
                    require(
                        record["registration_state"] == "acknowledged"
                        and record["admission"] is not None
                        and record["registration"]["identity"] == observed["running"]
                        and host.digest(record["registration"])
                        == observed["registration_sha256"]
                        and host.digest(record["admission"])
                        == observed["admission_sha256"]
                    )
            require(
                self.records._intent_access(operation) == directory
                and _inventory_entries(directory, deadline) == before
                and time.monotonic() < deadline
            )
            return {"records": records, "intents": intents, "reports": reports}
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OverflowError,
            RecursionError,
        ):
            raise IntentRefused() from None

    def registration_capability(
        self,
        operation_id,
        identity,
        client,
        observer,
        *,
        expected_revision,
        expected_sha256,
        operation,
    ):
        """Mint only before first preparation; retained JSON is not a live proof."""
        try:
            require(type(self) is IntentStore)
            require(type(self.records) is host.HostRecords)
            self.records._require_operation(operation)
            require(isinstance(identity, runtime.RuntimeIdentity))
            require(isinstance(client, host.HostClient))
            require(isinstance(observer, runtime.LocalDocker))
            selected = self.read(operation_id, operation=operation)
            require(
                integer(expected_revision) == selected["revision"]
                and host._hash(expected_sha256) == host.digest(selected)
                and selected["disposition"] == "active"
                and not selected["effects"]["registration_may_have_sent"]
                and not selected["effects"]["publication_may_have_happened"]
                and all(
                    selected["observations"][k] is None
                    for k in (
                        "registration_sha256",
                        "host_record_sha256",
                        "admission_sha256",
                    )
                )
                and host.canonical(selected["observations"]["running"])
                == host.canonical(asdict(identity))
            )
            layout = observer.layout
            resources = selected["resources"]
            require(
                observer.context == selected["binding"]["context"]
                and layout.trust_source == resources["trust_source"]
                and layout.admission_source == resources["public_directory"]
                and layout.state_volume == resources["runner_state"]["name"]
                and layout.readiness_volume == resources["readiness_volume"]
                and observer.protocol == selected["registration_policy"]["protocol"]
                and getattr(observer, "max_attempts", None)
                == (
                    selected["registration_policy"]["limits"]["max_attempts"]
                    if observer.protocol == "finite-v2"
                    else None
                )
            )
            network = getattr(observer, "network_binding", None)
            if network is not None:
                require(
                    network
                    == (
                        resources["runner_network"]["name"],
                        resources["runner_network"]["id"],
                    )
                )
            path = self.records._path(selected["future_runtime_id"])
            require(not path.exists() and not path.is_symlink())
            return _RegistrationCapability(
                self,
                self.records,
                operation,
                host.canonical(selected),
                host.canonical(asdict(identity)),
                client,
                host.canonical(client.pin()),
                observer,
                _observer_pin(observer),
                _REGISTRATION_PROOF,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OverflowError,
            RecursionError,
        ):
            raise IntentRefused() from None

    def _access(self, operation, operation_id):
        require(type(self.records) is host.HostRecords)
        directory = self.records._intent_access(operation)
        return directory / (host._uuid(operation_id) + ".intent.json")

    def _binding(self, payload, operation):
        self.records._intent_access(operation)
        require(
            payload["installation"]
            == str(self.records.installation.resolve(strict=True))
            and payload["storage_root"]
            == str(self.records.private_root.resolve(strict=True))
        )

    def _read(self, path, operation_id, operation):
        require(path == self._access(operation, operation_id))
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= _LIMIT
        )
        if os.name != "nt":
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            )
            raw = stream.read(_LIMIT + 1)
        after = path.lstat()
        require(
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and 0 < len(raw) <= _LIMIT
        )
        wrapped = fields(host._json(raw), {"schema", "payload", "mac"})
        require(wrapped["schema"] == SCHEMA)
        key = host._hash(
            self.records.backend.read_intent(
                operation_id, records=self.records, operation=operation
            )
        )
        expected = hmac.new(
            bytes.fromhex(key),
            _DOMAIN + host.canonical(wrapped["payload"]),
            hashlib.sha256,
        ).hexdigest()
        require(hmac.compare_digest(host._hash(wrapped["mac"]), expected))
        payload = _checked(wrapped["payload"])
        require(payload["operation_id"] == operation_id)
        self._binding(payload, operation)
        return payload

    def read(self, operation_id, *, operation):
        try:
            path = self._access(operation, operation_id)
            return self._read(path, operation_id, operation)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            raise IntentRefused() from None

    def _save(self, path, payload, operation, *, create):
        require(path == self._access(operation, payload["operation_id"]))
        key = host._hash(
            self.records.backend.read_intent(
                payload["operation_id"], records=self.records, operation=operation
            )
        )
        raw = host.canonical(
            {
                "schema": SCHEMA,
                "payload": payload,
                "mac": hmac.new(
                    bytes.fromhex(key),
                    _DOMAIN + host.canonical(payload),
                    hashlib.sha256,
                ).hexdigest(),
            }
        )
        require(len(raw) <= _LIMIT)
        _write(path, raw, create=create, records=self.records, operation=operation)
        require(
            host.canonical(self._read(path, payload["operation_id"], operation))
            == host.canonical(payload)
        )
        return host._json(host.canonical(payload))

    def create(self, payload, *, operation):
        try:
            require(type(payload) is dict)
            path = self._access(operation, payload["operation_id"])
            payload = host._json(host.canonical(payload))
            _checked(payload)
            self._binding(payload, operation)
            require(
                payload["revision"] == 1
                and payload["disposition"] == "active"
                and not any(payload["effects"].values())
                and all(value is None for value in payload["observations"].values())
            )
            require(
                not path.exists()
                and not path.is_symlink()
                and self.records.backend.read_intent(
                    payload["operation_id"], records=self.records, operation=operation
                )
                is None
            )
            self.records.backend.create_intent(
                payload["operation_id"],
                secrets.token_hex(32),
                records=self.records,
                operation=operation,
            )
            return self._save(path, payload, operation, create=True)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            raise IntentRefused() from None

    def advance(self, payload, *, expected_revision, expected_sha256, operation):
        try:
            require(type(payload) is dict)
            path = self._access(operation, payload["operation_id"])
            payload = host._json(host.canonical(payload))
            old = self._read(path, payload["operation_id"], operation)
            _checked(payload)
            self._binding(payload, operation)
            require(
                integer(expected_revision) == old["revision"]
                and host._hash(expected_sha256) == host.digest(old)
                and integer(payload["revision"]) == old["revision"] + 1
                and payload["previous_sha256"] == expected_sha256
            )
            require(
                all(
                    host.canonical(payload[k]) == host.canonical(old[k])
                    for k in _IMMUTABLE
                )
            )
            require(all(not old["effects"][k] or payload["effects"][k] for k in _FLAGS))
            require(
                all(
                    old["observations"][k] is None
                    or host.canonical(payload["observations"][k])
                    == host.canonical(old["observations"][k])
                    for k in _OBSERVATIONS
                )
            )
            require(
                old["disposition"] == "active"
                or payload["disposition"] == old["disposition"]
            )
            return self._save(path, payload, operation, create=False)
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            raise IntentRefused() from None


_REGISTRATION_PROOF = object()


def _observer_pin(observer):
    require(isinstance(observer, runtime.LocalDocker))
    network = getattr(observer, "network_binding", None)
    if network is not None:
        runtime._network_binding(network)
    return host.canonical(
        {
            "context": observer.context,
            "layout": asdict(observer.layout),
            "protocol": observer.protocol,
            "max_attempts": getattr(observer, "max_attempts", None),
            "network_binding": network,
        }
    )


def _actual_registration_policy(selected, protocol):
    """Project already validated engine inputs, without rebuilding registration."""
    persistent = protocol == "persistent-v3"
    if protocol is None:
        protocol = "finite-v2" if "max_attempts" in selected else "legacy-v1"
    return registration_policy(
        {
            "origin": selected["origin"],
            "enrollment_id": selected["enrollment_id"],
            "runner_id": selected["runner_id"],
            "protocol": protocol,
            "expires_in_seconds": None
            if persistent
            else selected["expires_in_seconds"],
            "limits": selected["limits"]
            if persistent
            else {
                "max_attempts": selected.get("max_attempts"),
                "idle_timeout_seconds": None,
            },
            "reporting_authority": selected["reporting_authority"]
            if persistent
            else None,
        }
    )


class _RegistrationCapability:
    __slots__ = (
        "_store",
        "_records",
        "_operation",
        "_intent",
        "_identity",
        "_client",
        "_client_pin",
        "_observer",
        "_observer_pin",
        "_proof",
        "_used",
        "_prepared_digest",
        "_fenced_digest",
        "_attempt",
        "_acknowledged",
        "_publication_claimed",
    )

    def __init__(
        self,
        store,
        records,
        operation,
        selected,
        identity,
        client,
        client_pin,
        observer,
        observer_pin,
        proof,
    ):
        require(proof is _REGISTRATION_PROOF)
        for name, value in (
            ("_store", store),
            ("_records", records),
            ("_operation", operation),
            ("_intent", selected),
            ("_identity", identity),
            ("_client", client),
            ("_client_pin", client_pin),
            ("_observer", observer),
            ("_observer_pin", observer_pin),
            ("_proof", proof),
            ("_used", False),
            ("_prepared_digest", None),
            ("_fenced_digest", None),
            ("_attempt", None),
            ("_acknowledged", None),
            ("_publication_claimed", False),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise IntentRefused()

    def __copy__(self):
        raise IntentRefused()

    def __deepcopy__(self, memo):
        raise IntentRefused()

    def __reduce_ex__(self, protocol):
        raise IntentRefused()

    def _fence(self, arguments):
        # Consumption precedes attempted validation or storage/provider I/O.
        require(not self._used)
        object.__setattr__(self, "_used", True)
        fields(
            arguments,
            {
                "records",
                "operation",
                "client",
                "observer",
                "identity",
                "runtime_id",
                "protocol",
                "selected",
                "record",
            },
        )
        (
            records,
            operation,
            client,
            observer,
            identity,
            runtime_id,
            protocol,
            selected,
            record,
        ) = (
            arguments[k]
            for k in (
                "records",
                "operation",
                "client",
                "observer",
                "identity",
                "runtime_id",
                "protocol",
                "selected",
                "record",
            )
        )
        require(
            self._proof is _REGISTRATION_PROOF
            and records is self._records
            and operation is self._operation
            and type(self._store) is IntentStore
            and self._store.records is records
            and client is self._client
            and observer is self._observer
        )
        records._require_operation(operation)
        require(
            isinstance(identity, runtime.RuntimeIdentity)
            and host.canonical(asdict(identity)) == self._identity
            and host.canonical(client.pin()) == self._client_pin
            and _observer_pin(observer) == self._observer_pin
        )
        expected = host._json(self._intent)
        require(host._uuid(runtime_id) == expected["future_runtime_id"])
        current = self._store.read(expected["operation_id"], operation=operation)
        require(host.canonical(current) == self._intent)
        require(
            current["disposition"] == "active"
            and not current["effects"]["registration_may_have_sent"]
            and not current["effects"]["publication_may_have_happened"]
            and all(
                current["observations"][k] is None
                for k in (
                    "registration_sha256",
                    "host_record_sha256",
                    "admission_sha256",
                )
            )
            and host.canonical(_actual_registration_policy(selected, protocol))
            == host.canonical(current["registration_policy"])
            and host.canonical(selected["identity"]) == self._identity
        )
        prepared = records.read(runtime_id)
        host._client(prepared, client)
        host._observer(prepared, observer)
        require(
            prepared["runtime_id"] == runtime_id
            and prepared["registration_state"] == "prepared"
            and prepared["admission"] is None
            and host.canonical(prepared) == host.canonical(record)
            and host.canonical(prepared["registration"]) == host.canonical(selected)
        )
        # ACK observation remains reserved. This digest never leaves the cap.
        object.__setattr__(self, "_prepared_digest", host.digest(prepared))
        updated = host._json(host.canonical(current))
        updated.update(
            revision=current["revision"] + 1, previous_sha256=host.digest(current)
        )
        updated["effects"]["registration_may_have_sent"] = True
        updated["observations"]["registration_sha256"] = host.digest(selected)
        observed = self._store.advance(
            updated,
            expected_revision=current["revision"],
            expected_sha256=host.digest(current),
            operation=operation,
        )
        require(host.canonical(observed) == host.canonical(updated))
        records._require_operation(operation)
        require(
            host.digest(records.read(runtime_id)) == self._prepared_digest
            and host.canonical(client.pin()) == self._client_pin
            and _observer_pin(observer) == self._observer_pin
        )
        object.__setattr__(self, "_fenced_digest", host.digest(observed))
        attempt = _OriginalRegistration(self, _REGISTRATION_PROOF)
        object.__setattr__(self, "_attempt", attempt)
        return attempt


def registration_fence(capability, **selected):
    """Fixed sealed-type dispatch only; never invoke a supplied callback."""
    try:
        require(type(capability) is _RegistrationCapability)
        return capability._fence(selected)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise IntentRefused() from None


class _OriginalRegistration:
    """A single original call's scope; exceptional exit grants no ACK marker."""

    __slots__ = ("_capability", "_entered", "_closed", "_stage_used", "_staged")

    def __init__(self, capability, proof):
        require(proof is _REGISTRATION_PROOF)
        object.__setattr__(self, "_capability", capability)
        for name, value in (
            ("_entered", False),
            ("_closed", False),
            ("_stage_used", False),
            ("_staged", None),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise IntentRefused()

    def __copy__(self):
        raise IntentRefused()

    def __deepcopy__(self, memo):
        raise IntentRefused()

    def __reduce_ex__(self, protocol):
        raise IntentRefused()

    def __enter__(self):
        require(not self._entered and not self._closed)
        object.__setattr__(self, "_entered", True)
        try:
            cap = self._capability
            require(
                type(cap) is _RegistrationCapability
                and cap._proof is _REGISTRATION_PROOF
                and cap._attempt is self
                and cap._used
                and cap._fenced_digest is not None
                and cap._acknowledged is None
            )
            cap._records._require_operation(cap._operation)
        except BaseException:
            object.__setattr__(self, "_closed", True)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # No I/O or raised cleanup error can obscure the original interruption.
        if self._entered and not self._closed:
            object.__setattr__(self, "_closed", True)
            if exc_type is None and self._staged is not None:
                object.__setattr__(self._capability, "_acknowledged", self._staged)
            else:
                object.__setattr__(self, "_staged", None)
        return False


def stage_original_ack(attempt, *, record, admission):
    """Stage authenticated original-call readback; retained records cannot mint it."""
    try:
        require(type(attempt) is _OriginalRegistration)
        require(attempt._entered and not attempt._closed and not attempt._stage_used)
        object.__setattr__(attempt, "_stage_used", True)
        cap = attempt._capability
        require(
            type(cap) is _RegistrationCapability
            and cap._proof is _REGISTRATION_PROOF
            and cap._attempt is attempt
            and cap._acknowledged is None
            and cap._used
            and cap._prepared_digest is not None
            and cap._fenced_digest is not None
        )
        records, operation = cap._records, cap._operation
        records._require_operation(operation)
        require(
            type(cap._store) is IntentStore
            and cap._store.records is records
            and host.canonical(cap._client.pin()) == cap._client_pin
            and _observer_pin(cap._observer) == cap._observer_pin
        )
        expected = host._json(cap._intent)
        current = cap._store.read(expected["operation_id"], operation=operation)
        require(
            host.digest(current) == cap._fenced_digest
            and current["disposition"] == "active"
            and current["effects"]["registration_may_have_sent"]
            and not current["effects"]["publication_may_have_happened"]
            and current["observations"]["host_record_sha256"] is None
            and current["observations"]["admission_sha256"] is None
        )
        observed = records.read(expected["future_runtime_id"])
        host._client(observed, cap._client)
        host._observer(observed, cap._observer)
        require(
            observed["registration_state"] == "acknowledged"
            and host.canonical(observed) == host.canonical(record)
            and host.canonical(observed["admission"]) == host.canonical(admission)
            and admission is not None
            and host.digest(observed["registration"])
            == current["observations"]["registration_sha256"]
        )
        prepared = host._json(host.canonical(observed))
        prepared.update(registration_state="prepared", admission=None)
        require(host.digest(prepared) == cap._prepared_digest)
        records._require_operation(operation)
        object.__setattr__(
            attempt, "_staged", (host.digest(observed), host.digest(admission))
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        RecursionError,
    ):
        raise IntentRefused() from None


def _publication_current(cap, expected_digest, *, started):
    """Authenticate the original ACK and exact live intent; never recover authority."""
    require(type(cap) is _RegistrationCapability and cap._proof is _REGISTRATION_PROOF)
    require(
        type(cap._attempt) is _OriginalRegistration
        and cap._attempt._closed
        and cap._attempt._stage_used
        and cap._acknowledged is not None
        and cap._acknowledged == cap._attempt._staged
    )
    records, operation = cap._records, cap._operation
    records._require_operation(operation)
    require(
        type(cap._store) is IntentStore
        and cap._store.records is records
        and host.canonical(cap._client.pin()) == cap._client_pin
        and _observer_pin(cap._observer) == cap._observer_pin
    )
    expected = host._json(cap._intent)
    current = cap._store.read(expected["operation_id"], operation=operation)
    require(
        host.digest(current) == expected_digest
        and current["disposition"] == "active"
        and current["effects"]["registration_may_have_sent"]
        and current["effects"]["publication_may_have_happened"] is started
    )
    observations = current["observations"]
    require(
        (observations["host_record_sha256"], observations["admission_sha256"])
        == (cap._acknowledged if started else (None, None))
    )
    record = records.read(expected["future_runtime_id"])
    host._client(record, cap._client)
    host._observer(record, cap._observer)
    require(
        record["registration_state"] == "acknowledged"
        and host.digest(record) == cap._acknowledged[0]
        and host.digest(record["admission"]) == cap._acknowledged[1]
    )
    return current


class _PublicationSequence:
    __slots__ = (
        "_cap",
        "_public",
        "_trust",
        "_admission",
        "_entered",
        "_closed",
        "_phase",
        "_step",
        "_fenced",
        "_finished",
    )
    __setattr__ = _RegistrationCapability.__setattr__
    __copy__ = _RegistrationCapability.__copy__
    __deepcopy__ = _RegistrationCapability.__deepcopy__
    __reduce_ex__ = _RegistrationCapability.__reduce_ex__

    def __init__(self, cap, public, trust, admission, proof):
        require(proof is _REGISTRATION_PROOF)
        for name, value in (
            ("_cap", cap),
            ("_public", public),
            ("_trust", trust),
            ("_admission", admission),
            ("_entered", False),
            ("_closed", False),
            ("_phase", "trust"),
            ("_step", None),
            ("_fenced", None),
            ("_finished", False),
        ):
            object.__setattr__(self, name, value)

    def __enter__(self):
        require(not self._entered and not self._closed)
        object.__setattr__(self, "_entered", True)
        try:
            self._cap._records._require_operation(self._cap._operation)
        except BaseException:
            object.__setattr__(self, "_closed", True)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        object.__setattr__(self, "_closed", True)
        return False


class _PublicationStep:
    __slots__ = (
        "_sequence",
        "_kind",
        "_path",
        "_data",
        "_opened",
        "_fenced",
        "_complete",
    )
    __setattr__ = _RegistrationCapability.__setattr__
    __copy__ = _RegistrationCapability.__copy__
    __deepcopy__ = _RegistrationCapability.__deepcopy__
    __reduce_ex__ = _RegistrationCapability.__reduce_ex__

    def __init__(self, sequence, kind, path, data, proof):
        require(proof is _REGISTRATION_PROOF)
        for name, value in (
            ("_sequence", sequence),
            ("_kind", kind),
            ("_path", path),
            ("_data", data),
            ("_opened", False),
            ("_fenced", False),
            ("_complete", False),
        ):
            object.__setattr__(self, name, value)


def publication_sequence(capability, *, public, trust, admission):
    """Claim one publication sequence from this original call's live ACK only."""
    require(
        type(capability) is _RegistrationCapability
        and capability._proof is _REGISTRATION_PROOF
    )
    require(not capability._publication_claimed)
    object.__setattr__(capability, "_publication_claimed", True)
    require(
        type(public) is type(Path())
        and public.is_absolute()
        and type(trust) is bytes
        and 0 < len(trust) <= 32768
    )
    expected = host._json(capability._intent)
    resources = expected["resources"]
    require(
        public == Path(resources["public_directory"])
        and hashlib.sha256(trust).hexdigest() == resources["signing_trust_sha256"]
    )
    # The expected digest alone grants nothing; original ACK checks precede I/O.
    _publication_current(capability, capability._fenced_digest, started=False)
    raw_admission = host.canonical(admission)
    require(host.digest(admission) == capability._acknowledged[1])
    return _PublicationSequence(
        capability, public, trust, raw_admission, _REGISTRATION_PROOF
    )


def _live_publication(sequence):
    require(
        type(sequence) is _PublicationSequence
        and sequence._entered
        and not sequence._closed
        and not sequence._finished
    )
    sequence._cap._records._require_operation(sequence._cap._operation)


def publication_step(sequence, *, kind, path, data):
    _live_publication(sequence)
    require(
        sequence._step is None
        and sequence._phase == kind
        and kind in {"trust", "admission"}
    )
    # Even a malformed reserved step cannot mint another attempt in this scope.
    object.__setattr__(sequence, "_step", object())
    require(
        type(path) is type(Path())
        and path == sequence._public / (kind + ".json")
        and type(data) is bytes
        and data == (sequence._trust if kind == "trust" else sequence._admission)
    )
    step = _PublicationStep(sequence, kind, path, data, _REGISTRATION_PROOF)
    object.__setattr__(sequence, "_step", step)
    return step


def skip_existing_trust(sequence, *, path, validated_trust):
    """Only the existing CLI validator's identical canonical trust may be reused."""
    _live_publication(sequence)
    require(sequence._phase == "trust" and sequence._step is None)
    object.__setattr__(sequence, "_step", object())
    require(
        type(path) is type(Path())
        and path == sequence._public / "trust.json"
        and type(validated_trust) is bytes
        and validated_trust == sequence._trust
    )
    object.__setattr__(sequence, "_phase", "admission")
    object.__setattr__(sequence, "_step", None)


def before_public_open(step, *, path, data):
    """Durable uncertainty immediately before the existing publisher's first open."""
    require(type(step) is _PublicationStep and not step._opened)
    object.__setattr__(step, "_opened", True)
    sequence = step._sequence
    _live_publication(sequence)
    require(
        sequence._step is step
        and sequence._phase == step._kind
        and type(path) is type(Path())
        and path == step._path
        and type(data) is bytes
        and data == step._data
    )
    cap = sequence._cap
    started = sequence._fenced is not None
    current = _publication_current(
        cap, sequence._fenced if started else cap._fenced_digest, started=started
    )
    if not started:
        updated = host._json(host.canonical(current))
        updated.update(
            revision=current["revision"] + 1, previous_sha256=host.digest(current)
        )
        updated["effects"]["publication_may_have_happened"] = True
        updated["observations"].update(
            host_record_sha256=cap._acknowledged[0],
            admission_sha256=cap._acknowledged[1],
        )
        observed = cap._store.advance(
            updated,
            expected_revision=current["revision"],
            expected_sha256=host.digest(current),
            operation=cap._operation,
        )
        require(host.canonical(observed) == host.canonical(updated))
        object.__setattr__(sequence, "_fenced", host.digest(observed))
        _publication_current(cap, sequence._fenced, started=True)
    object.__setattr__(step, "_fenced", True)


def complete_publication_step(step):
    """Called only after the existing publisher's write, publication and sync succeed."""
    require(
        type(step) is _PublicationStep
        and step._opened
        and step._fenced
        and not step._complete
    )
    sequence = step._sequence
    _live_publication(sequence)
    require(sequence._step is step and sequence._phase == step._kind)
    object.__setattr__(step, "_complete", True)
    object.__setattr__(
        sequence, "_phase", "admission" if step._kind == "trust" else "complete"
    )
    object.__setattr__(sequence, "_step", None)


def finish_publication(sequence):
    """Record completion only after both original publication steps succeeded."""
    _live_publication(sequence)
    require(
        sequence._phase == "complete"
        and sequence._step is None
        and sequence._fenced is not None
    )
    cap = sequence._cap
    current = _publication_current(cap, sequence._fenced, started=True)
    updated = host._json(host.canonical(current))
    updated.update(
        revision=current["revision"] + 1,
        previous_sha256=host.digest(current),
        disposition="enabled",
    )
    observed = cap._store.advance(
        updated,
        expected_revision=current["revision"],
        expected_sha256=host.digest(current),
        operation=cap._operation,
    )
    require(host.canonical(observed) == host.canonical(updated))
    cap._records._require_operation(cap._operation)
    object.__setattr__(sequence, "_finished", True)

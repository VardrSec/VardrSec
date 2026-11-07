"""Protected lifecycle metadata only; no launcher, replay or execution authority.

MACs and sticky updates discipline a trusted host's interrupted operations. They
are not attestation or protection against a key holder restoring older valid files.
"""

import hashlib
import hmac
import os
import re
import secrets
import stat
import uuid

import worker_host as host
import worker_runtime as runtime


SCHEMA = "vardr.worker-lifecycle-intent/2"
_DOMAIN = b"vardr.worker-lifecycle-intent/2\0"
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


class IntentStore:
    def __init__(self, records):
        # Inert: neither provider construction nor path/key/file access.
        self.records = records

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

"""Explicit managed-worker creation, start and original admission."""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

import updater
import worker_cli as cli
import worker_compose_inventory as compose
import worker_host as host
import worker_host_persistent as persistent
import worker_lifecycle_intent as intent
import worker_runtime as runtime
import worker_volumes as volumes

_JOURNAL = "/home/runner/.vardrmap/runner-journal.sqlite3"
_IDENTITY = "/home/runner/.vardrmap/runner-identity.json"
_VOLUME_TARGET = "/home/runner/.vardrmap"
_CONFIG_LIMIT = 16384
# Docker retries templates on the raw JSON map when a typed field differs.
# A map lookup must tolerate the omitted Volumes key without emitting Config.Env.
_AUDIT_IMAGE_FORMAT = (
    '{"id":{{json .Id}},"volumes":'
    '{{if eq (printf "%T" .Config) "map[string]interface {}"}}'
    '{{json (index .Config "Volumes")}}'
    "{{else}}{{json .Config.Volumes}}{{end}}}"
)


class _Engine(runtime.LocalDocker):
    """Use the same selected local client for all launch observations and effects."""

    def __init__(self, selected, installation, layout, *, network_binding=None):
        super().__init__(
            selected.context,
            layout,
            protocol="persistent-v3",
            network_binding=network_binding,
        )
        self._selected = selected
        self._installation = installation
        self._startup_deadline = None

    def _command(self, *args, timeout=15, binary=False):
        selected = self._selected
        deadline = time.monotonic() + timeout
        if self._deadline is not None:
            deadline = min(deadline, self._deadline)
        if self._startup_deadline is not None:
            deadline = min(deadline, self._startup_deadline)
        try:
            docker = compose._hash_executable(selected.docker, selected.docker_sha256)
            config = compose._local_path(
                compose._local_path(selected.config).resolve(strict=True)
            )
            runtime.require(config.is_dir() and self.context == selected.context)
            env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in compose._PLATFORM_ENV
            }
            output = compose._run(
                [
                    str(docker),
                    "--config",
                    str(config),
                    "--context",
                    self.context,
                    *args,
                ],
                cwd=self._installation,
                env=env,
                deadline=deadline,
                command_timeout=timeout,
            )
            return output if binary else output.decode("utf-8").strip()
        except (OSError, ValueError, subprocess.SubprocessError):
            raise runtime.RuntimeRefused("worker_runtime_refused") from None

    def _daemon_binding(self):
        endpoint = json.loads(
            self._command(
                "context",
                "inspect",
                self.context,
                "--format",
                "{{json .Endpoints.docker.Host}}",
            )
        )
        runtime.require(endpoint == self._selected.endpoint)
        daemon = json.loads(self._command("info", "--format", "{{json .ID}}"))
        runtime.require(type(daemon) is str and 1 <= len(daemon) <= 128)
        return endpoint, daemon

    def worker_state(self, image, command, selectors):
        """Run only the component-owned audit against the exact existing volume."""
        intent.image(image)
        cli.require(command in {"worker-bootstrap-state", "worker-state"})
        return self._command(
            "run",
            "--rm",
            "--pull",
            "never",
            "--user",
            "10001:10001",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--no-healthcheck",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--mount",
            f"type=volume,source={self.layout.state_volume},target={_VOLUME_TARGET},volume-nocopy",
            "--env",
            "HOME=/home/runner",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "vardrrunner",
            image,
            command,
            "--journal",
            _JOURNAL,
            "--identity",
            _IDENTITY,
            *selectors,
            timeout=45,
            binary=True,
        )


def _read(path, limit):
    selected, raw = compose._small(path, limit)
    info = path.lstat()
    cli.require(
        selected == path
        and stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 0x400
    )
    return raw


def _config(path):
    config = host._json(_read(Path(path), _CONFIG_LIMIT))
    intent.fields(
        config,
        {
            "docker",
            "docker_sha256",
            "compose",
            "compose_sha256",
            "docker_config",
            "local_endpoint",
            "daemon_id",
            "override",
            "empty_env",
            "source",
            "core_images",
            "credential_file",
            "credential_names",
            "https_port",
        },
    )
    intent.text(config["daemon_id"], 128)
    intent.fields(config["core_images"], {"api", "db", "proxy", "web"})
    for image in config["core_images"].values():
        intent.image(image)
    names = config["credential_names"]
    cli.require(
        type(names) is list
        and len(names) <= 32
        and all(
            type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
            for name in names
        )
        and len(set(names)) == len(names)
        and len(",".join(names)) <= 4096
    )
    port = config["https_port"]
    cli.require(type(port) is int and 1 <= port <= 65535)
    return config


def _binding(observation):
    return {key: observation[key] for key in ("context", "local_endpoint", "daemon_id")}


def _inventory(engine, selected, project, config, args):
    args._failure_phase = "launch_core_inventory"
    first = engine.capture_project_containers(project.name)
    args._failure_phase = "launch_state_inventory"
    state = volumes.capture_volume_resource(engine, project.name, "runner-state")
    args._failure_phase = "launch_network_inventory"
    network = engine.capture_runner_network(
        name=project.runner_network, project=project.name
    )
    args._failure_phase = "launch_readiness_inventory"
    readiness = volumes.capture_readiness_inventory(engine, project.name)
    args._failure_phase = "launch_compose_inventory"
    visible = compose.capture_visible_workers(selected, project)
    binding = {
        "context": selected.context,
        "local_endpoint": selected.endpoint,
        "daemon_id": config["daemon_id"],
    }
    cli.require(
        all(_binding(row) == binding for row in (first, state, network, readiness))
        and {key: visible[key] for key in ("context", "local_endpoint")}
        == {key: binding[key] for key in ("context", "local_endpoint")}
        and visible["project"] == project.name
        and visible["compose_worker_ids"] == first["all_worker_ids"]
        and {row["service"]: row["image_id"] for row in first["core"]}
        == config["core_images"]
        and state["daemon_root"] == readiness["daemon_root"]
        and engine.capture_project_containers(project.name) == first
    )
    return first, state, network, readiness["readiness"]


def _ordinal(engine, cid, *, created):
    row = engine.inspect(cid)
    labels = row["labels"]
    number = labels.get("com.docker.compose.container-number")
    cli.require(
        type(number) is str
        and re.fullmatch(r"[1-9][0-9]{0,2}", number)
        and labels.get("com.docker.compose.oneoff") == "False"
        and re.fullmatch(
            r"[0-9a-f]{64}", labels.get("com.docker.compose.config-hash", "")
        )
        and not any(key.startswith("com.docker.compose.hook") for key in labels)
        and row["state"]["Status"] == ("created" if created else "exited")
    )
    return int(number)


def _audit(engine, project, volume, image, command, selectors, args):
    args._failure_phase = "launch_audit_image"
    cli.require(
        volumes.capture_volume_resource(engine, project.name, "runner-state") == volume
    )
    layout = volumes.parse_document(
        engine._command(
            "image",
            "inspect",
            "--format",
            _AUDIT_IMAGE_FORMAT,
            image,
        )
    )
    cli.require(
        set(layout) == {"id", "volumes"}
        and layout["id"] == image
        and layout["volumes"] in (None, {})
    )
    args._failure_phase = "launch_audit_run"
    output = engine.worker_state(image, command, selectors)
    args._failure_phase = "launch_audit_recheck"
    cli.require(
        volumes.capture_volume_resource(engine, project.name, "runner-state") == volume
    )
    return output


def _retired(engine, selected, project, records, catalog, snapshot, api, args):
    inventory, state, network, ready = snapshot
    old = catalog["records"]
    intents = catalog["intents"]
    cli.require(
        len(old) == len(intents) == len(inventory["all_worker_ids"]) == len(ready)
        and {row["future_runtime_id"] for row in intents.values()} == set(old)
        and all(row["disposition"] == "enabled" for row in intents.values())
    )
    readiness = {row["name"]: row for row in ready}
    net = network["network"]
    predecessors, exits = [], []
    for operation_id, previous in intents.items():
        selected_id = previous["future_runtime_id"]
        record = old[selected_id]
        registration = record["registration"]
        identity = runtime.RuntimeIdentity(**registration["identity"])
        prior = previous["resources"]
        cli.require(
            identity.container_id in inventory["all_worker_ids"]
            and identity.daemon_id == inventory["daemon_id"]
            and identity.project == project.name
            and record["context"] == engine.context
            and registration["runner_id"] == args.runner_id
            and previous["binding"] == {**_binding(inventory), "project": project.name}
            and prior["runner_state"]["metadata_sha256"] == host.digest(state["volume"])
            and prior["runner_network"]["metadata_sha256"] == host.digest(net)
            and prior["trust_source"] == engine.layout.trust_source
            and readiness[prior["readiness_volume"]]["intent_id"] == operation_id
            and record["stop_state"] == "observed"
            and "mode" in registration
        )
        host._client(record, api)
        observer = _Engine(
            selected,
            engine._installation,
            runtime.WorkerLayout(**record["layout"]),
            network_binding=(net["name"], net["id"]),
        )
        ordinal = _ordinal(observer, identity.container_id, created=False)
        cli.require(ordinal == prior["expected_ordinal"])
        exit_proof = observer.observe_exit(identity)
        receipt = persistent.retirement(record, record["receipt"])
        reports = persistent._reports(records, record)
        cli.require(reports and reports[-1]["receipt"] == receipt)
        body = reports[-1]["intent"]
        observation = {
            "identity": asdict(identity),
            "finished_at": exit_proof.finished_at,
            "exit_code": exit_proof.exit_code,
        }
        cli.require(
            body["finished_at"] == observation["finished_at"]
            and body["exit_code"] == observation["exit_code"]
            and body["observation_sha256"] == host.digest(observation)
        )
        observed = persistent._receipt(api, record, records.secret(selected_id))
        admission = record["admission"]
        selectors = []
        for name in ("runner_id", "runtime_id", "runtime_sha256", "admission_sha256"):
            selectors.extend(("--" + name.replace("_", "-"), admission[name]))
        output = _audit(
            observer, project, state, identity.image_id, "worker-state", selectors, args
        )
        local = persistent.original_local_audit(
            record, observed, output=output, returncode=0
        )
        observer.confirm_exit(exit_proof)
        exits.append((observer, exit_proof))
        predecessors.append(
            {
                "ordinal": ordinal,
                "container_id": identity.container_id,
                "image_id": identity.image_id,
                "runtime_id": selected_id,
                "runtime_sha256": admission["runtime_sha256"],
                "admission_sha256": admission["admission_sha256"],
                "host_retirement_sha256": host.digest(receipt),
                "original_local_audit_sha256": local["original_local_audit_sha256"],
            }
        )
    predecessors.sort(key=lambda row: row["ordinal"])
    cli.require(
        [row["ordinal"] for row in predecessors]
        == list(range(1, len(predecessors) + 1))
        and sorted(row["container_id"] for row in predecessors)
        == inventory["all_worker_ids"]
    )
    return predecessors, exits


def _advance(store, operation, current, *, effect=None, **observations):
    digest = host.digest(current)
    updated = {
        **current,
        "revision": current["revision"] + 1,
        "previous_sha256": digest,
        "effects": dict(current["effects"]),
        "observations": {**current["observations"], **observations},
    }
    if effect is not None:
        cli.require(updated["effects"][effect] is False)
        updated["effects"][effect] = True
    return store.advance(
        updated,
        expected_revision=current["revision"],
        expected_sha256=digest,
        operation=operation,
    )


def _start(engine, identity, endpoint, fence):
    cli.require(
        engine.capture_created(
            daemon_id=identity.daemon_id,
            container_id=identity.container_id,
            image_id=identity.image_id,
            project=identity.project,
        )
        == identity
    )
    engine._network(identity.container_id, created=True)
    cli.require(engine._daemon_binding() == (endpoint, identity.daemon_id))
    fence()
    cli.require(
        engine._command("container", "start", identity.container_id)
        == identity.container_id
    )
    deadline = engine._startup_deadline = time.monotonic() + 25
    try:
        while True:
            try:
                return engine.capture_running(
                    container_id=identity.container_id,
                    image_id=identity.image_id,
                    project=identity.project,
                )
            except runtime.RuntimeRefused:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
    finally:
        engine._startup_deadline = None


def _public_inventory(root, catalog):
    expected = {}
    for previous in catalog["intents"].values():
        path = root / previous["future_runtime_id"]
        cli.require(
            str(path) == previous["resources"]["public_directory"]
            and previous["disposition"] == "enabled"
        )
        expected[path] = previous
    cli.require(set(root.iterdir()) == set(expected))
    for path, previous in expected.items():
        cli.require(path.resolve(strict=True) == path and path.is_dir())
        trust, admission = path / "trust.json", path / "admission.json"
        cli.require(
            set(path.iterdir()) == {trust, admission}
            and hashlib.sha256(_read(trust, 65536)).hexdigest()
            == previous["resources"]["signing_trust_sha256"]
            and host.digest(host._json(_read(admission, 65536)))
            == previous["observations"]["admission_sha256"]
        )


def _resource_fields(snapshot, engine, trust, ca, project, ordinal):
    inventory, state, network, _ = snapshot
    volume = state["volume"]
    net = network["network"]
    return {
        "core_containers": [
            {key: row[key] for key in ("service", "container_id", "image_id")}
            for row in inventory["core"]
        ],
        "runner_network": {
            "id": net["id"],
            "name": net["name"],
            "metadata_sha256": host.digest(net),
        },
        "runner_state": {
            **{key: volume[key] for key in ("name", "source", "created_at")},
            "metadata_sha256": host.digest(volume),
        },
        "trust_source": engine.layout.trust_source,
        "trust_sha256": hashlib.sha256(ca).hexdigest(),
        "signing_trust_sha256": hashlib.sha256(trust).hexdigest(),
        "public_directory": str(project.public_directory),
        "readiness_volume": project.ready_volume,
        "readiness_marker": "1",
        "expected_ordinal": ordinal,
    }


def _disjoint(*paths):
    for i, left in enumerate(paths):
        for right in paths[i + 1 :]:
            cli.require(
                not left.is_relative_to(right) and not right.is_relative_to(left)
            )


def _next_resources(before, after, expected_ready, *, new_container):
    previous, state, network, ready = before
    now, next_state, next_network, next_ready = after
    cli.require(
        state == next_state
        and network == next_network
        and _binding(now) == _binding(previous)
        and now["core"] == previous["core"]
        and {row["name"]: row for row in next_ready}
        == {row["name"]: row for row in [*ready, expected_ready]}
    )
    old, new = set(previous["all_worker_ids"]), set(now["all_worker_ids"])
    cli.require(old <= new and len(new - old) == int(new_container))
    return next(iter(new - old)) if new_container else None


def launch(installation, args):
    args._failure_phase = "launch_inputs"
    installation = installation.resolve(strict=True)
    config = _config(args.launch_config)
    source = config["source"]
    private = Path(args.private_root).resolve(strict=True)
    public_root = Path(args.admission_root)
    trust_root = installation / "trust"
    cli.require(
        public_root.is_absolute()
        and public_root.resolve(strict=True) == public_root
        and public_root.is_dir()
        and trust_root.resolve(strict=True) == trust_root
        and args.protocol == "persistent-v3"
        and args.origin == f"https://vardrsec.localhost:{config['https_port']}/backend"
        and source["runner_image"] == args.image_id
        and source["compose_executable_sha256"] == config["compose_sha256"]
        and source["unresolved_model_sha256"] == compose._MODEL_SHA256
        and source["closed_override_sha256"]
        == hashlib.sha256(_read(Path(config["override"]), 4096)).hexdigest()
        and source["environment_contract_sha256"]
        == host.digest(
            {
                "credential_names": config["credential_names"],
                "https_port": config["https_port"],
            }
        )
        and source["core_image_set_sha256"] == host.digest(config["core_images"])
    )
    _disjoint(private, public_root, trust_root)
    credentials = Path(config["credential_file"])
    empty = Path(config["empty_env"])
    cli.require(
        credentials.resolve(strict=True) == credentials
        and credentials.is_relative_to(private)
        and credentials.parent == private
        and empty.parent == private
        and _read(empty, 0) == b""
        and stat.S_ISREG(credentials.lstat().st_mode)
        and credentials.stat().st_nlink == 1
        and not getattr(credentials.lstat(), "st_file_attributes", 0) & 0x400
        and (
            os.name == "nt"
            or (
                credentials.stat().st_uid == os.getuid()
                and stat.S_IMODE(credentials.stat().st_mode) == 0o600
            )
        )
    )
    api_key = os.environ.get("VARDRMAP_API_KEY")
    compose._matches(api_key, r"vmap_[A-Za-z0-9_-]{1,256}")
    runtime_id = cli.runtime_id(args.runtime_id)
    operation_id = str(uuid.uuid4())
    public = public_root / runtime_id
    ready_name = f"{args.project}_worker-ready-{runtime_id}"
    project = compose.WorkerProject(
        args.project,
        installation,
        Path(config["override"]),
        empty,
        args.image_id,
        public,
        ready_name,
        args.state_volume,
        args.runner_network,
    )
    selected = compose.LocalClient(
        Path(config["docker"]),
        config["docker_sha256"],
        Path(config["compose"]),
        config["compose_sha256"],
        Path(config["docker_config"]),
        args.context,
        config["local_endpoint"],
    )
    cli.require(
        re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", args.project)
        and selected.endpoint.startswith(("unix:///", "npipe:////./pipe/"))
    )
    engine = _Engine(
        selected,
        installation,
        runtime.WorkerLayout(
            str(trust_root),
            str(public),
            project.state_volume,
            project.ready_volume,
        ),
    )
    trust = cli.public_trust(args.public_trust)
    ca_path = trust_root / "root.crt"
    ca = _read(ca_path, 65536)
    cli.require(Path(args.ca).resolve(strict=True) == ca_path)
    api = host.HostClient(args.api_url, args.ca)
    admission_options, _ = cli._enable_options(args)
    policy = intent.registration_policy(
        {
            "origin": args.origin,
            "enrollment_id": args.enrollment_id,
            "runner_id": args.runner_id,
            "protocol": "persistent-v3",
            "expires_in_seconds": None,
            "limits": admission_options["limits"],
            "reporting_authority": persistent.REPORTING_AUTHORITY,
        }
    )
    records = cli.records_for(installation, str(private))
    store = intent.IntentStore(records)

    with records.operation() as operation:
        args._failure_phase = "launch_preflight"
        cli.require(not (installation / updater.STATE).exists())
        cli.require(
            engine._daemon_binding() == (selected.endpoint, config["daemon_id"])
        )
        before = _inventory(engine, selected, project, config, args)
        args._failure_phase = "launch_catalog"
        core, state, network, _ = before
        cli.require(not public.exists() and not public.is_symlink())
        volume_names = engine._command("volume", "ls", "--format", "{{json .Name}}")
        cli.require(
            ready_name not in [json.loads(line) for line in volume_names.splitlines()]
        )
        catalog = store.inventory(operation=operation)
        _public_inventory(public_root, catalog)
        predecessors, exits = _retired(
            engine, selected, project, records, catalog, before, api, args
        )
        ordinal = len(predecessors) + 1
        cli.require(ordinal <= 256)
        audit = None
        if not predecessors:
            audit = _audit(
                engine,
                project,
                state,
                args.image_id,
                "worker-bootstrap-state",
                ("--runner-id", args.runner_id),
                args,
            )
        payload = {
            "operation_id": operation_id,
            "future_runtime_id": runtime_id,
            "installation": str(installation),
            "storage_root": str(private),
            "source": source,
            "binding": {**_binding(core), "project": args.project},
            "predecessors": predecessors,
            "resources": _resource_fields(before, engine, trust, ca, project, ordinal),
            "registration_policy": policy,
            "revision": 1,
            "previous_sha256": None,
            "effects": dict.fromkeys(intent._FLAGS, False),
            "observations": dict.fromkeys(intent._OBSERVATIONS),
            "disposition": "active",
        }
        if audit is not None:
            first = intent.bootstrap_audit(
                runner_id=args.runner_id, output=audit, returncode=0
            )
            payload["bootstrap_audit_sha256"] = first["sha256"]

        with cli._preauthenticate_enable_owner(records, operation, api, args) as owner:
            args._failure_phase = "launch_intent"
            cli.require(
                store.inventory(operation=operation) == catalog
                and _inventory(engine, selected, project, config, args) == before
                and _read(ca_path, 65536) == ca
            )
            _public_inventory(public_root, catalog)
            args._failure_phase = "launch_intent"
            current = store.create(payload, operation=operation, first_audit=audit)

            def record(effect=None, **observations):
                nonlocal current
                current = _advance(
                    store, operation, current, effect=effect, **observations
                )

            args._failure_phase = "launch_resources"
            record("public_directory_may_have_been_created")
            public.mkdir(mode=0o755)
            cli.require(
                engine._daemon_binding() == (selected.endpoint, config["daemon_id"])
            )
            record("readiness_may_have_been_created")
            cli.require(
                engine._command(
                    "volume",
                    "create",
                    "--driver",
                    "local",
                    "--label",
                    f"com.docker.compose.project={args.project}",
                    "--label",
                    "com.docker.compose.volume=worker-ready",
                    "--label",
                    "io.vardrsec.managed-worker-ready=1",
                    "--label",
                    f"io.vardrsec.managed-worker-intent={operation_id}",
                    ready_name,
                )
                == ready_name
            )
            ready = volumes.capture_volume_resource(
                engine, args.project, "worker-ready"
            )["volume"]
            cli.require(
                ready["intent_id"] == operation_id and ready["config_hash"] is None
            )
            _next_resources(
                before,
                _inventory(engine, selected, project, config, args),
                ready,
                new_container=False,
            )

            args._failure_phase = "launch_create"
            for observer, proof in exits:
                observer.confirm_exit(proof)

            def fence_create():
                cli.require(
                    engine._daemon_binding() == (selected.endpoint, config["daemon_id"])
                )
                record("container_create_may_have_sent")

            compose.create_worker(
                selected,
                project,
                ordinal,
                api_key=api_key,
                credentials=credentials,
                names=",".join(config["credential_names"]),
                port=config["https_port"],
                before_send=fence_create,
            )
            after = _inventory(engine, selected, project, config, args)
            args._failure_phase = "launch_create"
            cid = _next_resources(before, after, ready, new_container=True)
            net = network["network"]
            engine.network_binding = (net["name"], net["id"])
            created = engine.capture_created(
                daemon_id=config["daemon_id"],
                container_id=cid,
                image_id=args.image_id,
                project=args.project,
            )
            engine._network(cid, created=True)
            cli.require(
                _ordinal(engine, cid, created=True) == ordinal
                and not tuple(public.iterdir())
            )
            records.outside_mounts(engine, created)
            record(
                created={
                    "daemon_id": created.daemon_id,
                    "container_id": cid,
                    "image_id": created.image_id,
                    "project": created.project,
                    "ordinal": ordinal,
                    "readiness_volume": ready_name,
                }
            )

            args._failure_phase = "launch_start"
            for observer, proof in exits:
                observer.confirm_exit(proof)
            identity = _start(
                engine,
                created,
                selected.endpoint,
                lambda: record("start_may_have_sent"),
            )
            record(running=asdict(identity))
            capability = store.registration_capability(
                operation_id,
                identity,
                api,
                engine,
                expected_revision=current["revision"],
                expected_sha256=host.digest(current),
                operation=operation,
            )
            args.container_id = cid
            admission, identity = cli._enable_owned(
                args,
                records,
                operation,
                (engine, api, public, trust, admission_options),
                registration_capability=capability,
                preauthenticated_owner=owner,
            )

    return {
        "schema": "vardr.worker-cli/1",
        "state": "enabled",
        "runtime_id": runtime_id,
        "runtime_sha256": admission["runtime_sha256"],
        "identity": asdict(identity),
        "local_runner_reconciliation": "required_after_terminal_exit",
    }

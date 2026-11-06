"""Explicit coupled NM-2 fixture. Default: source validation, no Docker calls.

Run only against a new, separately named installation and reviewed immutable
image/source cohort. This is not a release, an old-candidate recovery tool, or a
second execution engine. Unknown mutations remain held; fixtures are retained.
"""

import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import http.cookiejar
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE_NAMES = {"distribution", "map", "runner", "gate"}
IMAGE_NAMES = {"db", "api", "web", "proxy", "worker"}
ORIGIN = "http://gate-fixture:8080"
EXECUTION = {
    "timeout_seconds": 20,
    "max_response_bytes": 65536,
    "allow_private_targets": True,
}
INITIAL_CASES = (
    "default_disabled",
    "strict_out_of_scope",
    "happy_fixed",
    "missing_local_grant",
)
_CONFIGURATION_ENV = {
    "HTTPS_PORT",
    "PROXY_IP",
    "APPLICATION_SUBNET",
    "APPLICATION_IP_RANGE",
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "BACKEND_JWT_SECRET",
    "AUTH_SECRET",
    "MAP_SOURCE",
    "RUNNER_SOURCE",
    "GATE_SOURCE",
    "PGPASSWORD",
}


class AcceptanceRefused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise AcceptanceRefused(reason)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def command(arguments, *, cwd=None, env=None, stdin=None, timeout=30):
    """Never echo a command's stdout/stderr or secret environment on failure."""
    if isinstance(stdin, str):
        stdin = stdin.encode()
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=env,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        require(len(result.stdout) <= 4 * 1024 * 1024, "fixture_output_bound")
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise AcceptanceRefused("fixture_command_failed") from None


def manifest(path):
    value = json.loads(Path(path).read_bytes())
    require(
        set(value)
        == {
            "schema",
            "sources",
            "images",
            "docker_context",
            "project",
            "installation",
            "private_root",
            "https_port",
            "application_subnet",
            "allow_empty_builtin_bridge_id_change",
        },
        "manifest_fields",
    )
    require(value["schema"] == "vardr.nm2-worker-cohort/1", "manifest_schema")
    require(
        set(value["sources"]) == SOURCE_NAMES and set(value["images"]) == IMAGE_NAMES,
        "manifest_cohort",
    )
    require(
        all(
            isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v)
            for v in value["images"].values()
        ),
        "immutable_image_required",
    )
    require(
        re.fullmatch(r"vardrsec-nm2-[a-z0-9]{8,24}", value["project"] or ""),
        "separate_project_required",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["docker_context"] or ""),
        "explicit_local_context_required",
    )
    require(
        type(value["https_port"]) is int and 1024 <= value["https_port"] <= 65535,
        "loopback_port_required",
    )
    require(
        type(value["allow_empty_builtin_bridge_id_change"]) is bool,
        "bridge_admission_required",
    )
    network = ipaddress.ip_network(value["application_subnet"])
    require(
        network.version == 4 and network.is_private and network.prefixlen == 24,
        "private_fixture_subnet_required",
    )
    roots = [Path(value[name]) for name in ("installation", "private_root")]
    require(
        all(p.is_absolute() and not p.exists() and not p.is_symlink() for p in roots),
        "new_fixture_directories_required",
    )
    require(
        roots[0] != roots[1]
        and not any(a in b.parents for a, b in (roots, roots[::-1])),
        "separate_host_custody_required",
    )
    for name, selection in value["sources"].items():
        require(
            set(selection) == {"path", "commit"}
            and re.fullmatch(r"[0-9a-f]{40}", selection["commit"] or ""),
            "source_selection_required",
        )
        source = Path(selection["path"])
        require(
            source.is_absolute() and source.is_dir() and not source.is_symlink(),
            "source_directory_required",
        )
        require(
            command(["git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip()
            == selection["commit"],
            "source_commit_mismatch",
        )
        require(
            not command(
                [
                    "git",
                    "-C",
                    str(source),
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                ]
            ),
            "tracked_source_changes_unreviewed",
        )
        require(
            source not in roots
            and not any(source in p.parents or p in source.parents for p in roots),
            "fixture_outside_sources_required",
        )
    distribution = Path(value["sources"]["distribution"]["path"])
    required_distribution = (
        "compose.yaml",
        "compose.worker.json",
        "vardrsec.py",
        "database_roles.py",
        "worker_host.py",
        "worker_runtime.py",
        "worker_secrets.py",
        "worker_volumes.py",
        "worker_cli.py",
        "tests/gate/target.py",
        "tests/nm2_worker_acceptance.py",
        "tests/nm2_worker_inventory.py",
        "tests/nm2_worker_target.py",
    )
    command(
        [
            "git",
            "-C",
            str(distribution),
            "ls-files",
            "--error-unmatch",
            "--",
            *required_distribution,
        ]
    )
    for relative in required_distribution:
        require((distribution / relative).is_file(), "required_public_source_missing")
    value["proxy_ip"] = str(network.network_address + 2)
    value["application_ip_range"] = str(network.network_address + 128) + "/25"
    return value


def private_directory(path):
    path.mkdir(mode=0o700)
    if os.name == "nt":
        raw = (
            command(["whoami", "/user", "/fo", "csv", "/nh"])
            .decode("utf-8-sig")
            .strip()
        )
        sid = next(csv.reader([raw]))[-1]
        require(re.fullmatch(r"S-1-[0-9-]+", sid), "current_user_sid_required")
        command(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ]
        )
    else:
        path.chmod(0o700)


def publish(path, data, *, mode=0o600):
    """Exclusive files; admission is atomically published after host ACK only."""
    require(not path.exists(), "fixture_file_already_exists")
    temporary = path.with_name(path.name + ".prepared")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.rename(path)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OwnerAPI:
    """Actual CA-validated local session and CSRF; no synthetic owner headers."""

    def __init__(self, url, ca):
        self.url, self.ca = url, ca
        self.ca_sha256 = digest(ca.read_bytes())
        self.jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context(cafile=str(ca))
        context.keylog_filename = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )
        self.csrf = None

    def request(self, path, body=None, *, method=None, csrf=True, expected=200):
        require(digest(self.ca.read_bytes()) == self.ca_sha256, "fixture_ca_changed")
        headers = {"Origin": self.url}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(
            self.url + "/backend" + path,
            data=None if body is None else canonical(body),
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.status == expected, "fixture_http_status")
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "fixture_http_bound")
            return json.loads(raw) if raw else None

    def login(self, username, password):
        self.request("/auth/local/login", {"username": username, "password": password})
        session = self.request("/auth/local/session")
        require(session["authMethod"] == "local", "actual_local_owner_required")
        self.csrf = session["csrfToken"]
        return session["user"]["githubId"]


def unchanged_inventory(before, after, project, *, admit_bridge=False):
    """Compare pre-existing public resource metadata, including stopped fixtures."""
    admitted = []
    for kind in ("containers", "volumes", "images"):
        for key, value in before[kind].items():
            require(after[kind].get(key) == value, "preexisting_" + kind + "_changed")
    for key, value in before["networks"].items():
        candidate = after["networks"].get(key)
        if (
            candidate != value
            and admit_bridge
            and value["name"] == "bridge"
            and not value["containers"]
        ):
            matches = [
                n
                for n in after["networks"].values()
                if n["name"] == "bridge" and not n["containers"]
            ]
            if len(matches) == 1 and {k: v for k, v in value.items() if k != "id"} == {
                k: v for k, v in matches[0].items() if k != "id"
            }:
                candidate = value
                admitted.append(
                    {
                        "kind": "empty_builtin_bridge_id",
                        "before": key,
                        "after": matches[0]["id"],
                    }
                )
        require(candidate == value, "preexisting_network_changed")
    for kind in ("containers", "volumes", "networks"):
        admitted_ids = (
            {item["after"] for item in admitted} if kind == "networks" else set()
        )
        require(
            all(
                key in before[kind]
                or key in admitted_ids
                or value.get("labels", {}).get("com.docker.compose.project") == project
                for key, value in after[kind].items()
            ),
            "unowned_new_resource",
        )
    return admitted


class Fixture:
    def __init__(self, selection):
        self.m = selection
        self.source = Path(selection["sources"]["distribution"]["path"])
        self.install = Path(selection["installation"])
        self.private = Path(selection["private_root"])
        self.project = selection["project"]
        # One physical incarnation per new fixture project; the preflight below
        # also refuses existing unlabeled resources at every exact volume name.
        self.ready_volume = self.project + "_worker-ready"
        self.images = selection["images"]
        self.url = "https://localhost:" + str(selection["https_port"])
        self.issuer_origin = (
            "https://vardrsec.localhost:" + str(selection["https_port"]) + "/backend"
        )
        self.environment = {
            k: v
            for k, v in os.environ.items()
            if not k.upper().startswith(("COMPOSE_", "DOCKER_", "VARDR"))
            and k.upper() not in _CONFIGURATION_ENV
        }
        self.environment.update(
            DOCKER_CONTEXT=selection["docker_context"],
            COMPOSE_PROJECT_NAME=self.project,
            VARDRSEC_WORKER_READY_VOLUME=self.ready_volume,
            NO_COLOR="1",
            TERM="dumb",
        )
        self.receipt = {
            "schema": "vardr.nm2-worker-acceptance/1",
            "platform": sys.platform,
            "project": self.project,
            "readiness_volume": self.ready_volume,
            "sources": selection["sources"],
            "images": self.images,
            "cases": {name: {"status": "not_run"} for name in INITIAL_CASES},
            "status": "prepared",
            "retained": True,
        }
        self.secrets = []

    def docker(self, *args, env=None, **kwargs):
        return command(
            ["docker", "--context", self.m["docker_context"], *args],
            env=self.environment if env is None else env,
            **kwargs,
        )

    def compose(self, *args, worker=False, **kwargs):
        flags = [
            "-f",
            str(self.install / "compose.yaml"),
            "-f",
            str(self.install / "fixture.compose.json"),
        ]
        if worker:
            flags += ["-f", str(self.install / "compose.worker.json")]
        return self.docker(
            "compose",
            "--project-directory",
            str(self.install),
            "-p",
            self.project,
            *flags,
            *args,
            cwd=self.install,
            **kwargs,
        )

    def snapshot(self):
        specs = {
            "containers": (
                "container",
                ["ps", "-aq", "--no-trunc"],
                '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"state":{"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"exit_code":{{json .State.ExitCode}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}}},"restarts":{{json .RestartCount}},"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}}}',
            ),
            "networks": (
                "network",
                ["network", "ls", "-q", "--no-trunc"],
                '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"internal":{{json .Internal}},"attachable":{{json .Attachable}},"ipv6":{{json .EnableIPv6}},"ingress":{{json .Ingress}},"options":{{json .Options}},"ipam":{{json .IPAM}},"labels":{{json .Labels}},"containers":{{json .Containers}}}',
            ),
            "volumes": (
                "volume",
                ["volume", "ls", "-q"],
                '{"id":{{json .Name}},"driver":{{json .Driver}},"labels":{{json .Labels}},"options":{{json .Options}}}',
            ),
            "images": (
                "image",
                ["image", "ls", "-q", "--no-trunc"],
                '{"id":{{json .Id}},"tags":{{json .RepoTags}},"digests":{{json .RepoDigests}}}',
            ),
        }
        result = {}
        for kind, (noun, listing, template) in specs.items():
            rows = {}
            for identifier in sorted(set(self.docker(*listing).decode().split())):
                row = json.loads(
                    self.docker(noun, "inspect", "--format", template, identifier)
                )
                row["labels"] = row.get("labels") or {}
                rows[row["id"]] = row
            result[kind] = rows
        return result

    def stop_owned(self, before):
        """Stop only newly created exact fixture IDs; retain every resource."""
        current = self.snapshot()
        owned = {
            key: row
            for key, row in current["containers"].items()
            if key not in before["containers"]
            and row["labels"].get("com.docker.compose.project") == self.project
        }
        running = []
        for container_id, row in sorted(owned.items()):
            require(re.fullmatch(r"[0-9a-f]{64}", container_id), "fixture_stop_id")
            observed = json.loads(
                self.docker(
                    "container",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"image":{{json .Image}},"project":{{json (index .Config.Labels "com.docker.compose.project")}}}',
                    container_id,
                )
            )
            require(
                observed
                == {"id": container_id, "image": row["image"], "project": self.project},
                "fixture_stop_identity_changed",
            )
            if row["state"]["running"]:
                running.append(container_id)
        if running:
            self.docker("container", "stop", "-t", "10", *running, timeout=90)
        stopped = self.snapshot()
        require(
            all(
                key in stopped["containers"]
                and stopped["containers"][key]["labels"].get(
                    "com.docker.compose.project"
                )
                == self.project
                and stopped["containers"][key]["state"]["running"] is False
                for key in owned
            ),
            "fixture_stop_not_observed",
        )
        self.receipt["fixture_stop"] = {
            "status": "stopped_retained",
            "container_ids": sorted(owned),
            "stop_requested_ids": running,
        }

    def image_sources(self):
        """Read files in ordinary network-none helpers, without invoking tools."""
        inventory = {}
        program = """import hashlib,json,pathlib,sys
selection=json.load(sys.stdin)
base=pathlib.Path('/app')
if selection['component']=='runner':
 import vardrrunner
 base=pathlib.Path(vardrrunner.__file__).parent
hashes={path.relative_to(base).as_posix():hashlib.sha256(path.read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for path in base.rglob('*.py') if not {'tests','postgres_tests'} & set(path.relative_to(base).parts)}
executables={name:hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() for name in selection['executables']}
print(json.dumps({'files':hashes,'executables':executables}))
"""
        for component, prefix, image in (
            ("map", "backend", self.images["api"]),
            ("runner", "vardrrunner", self.images["worker"]),
        ):
            source = Path(self.m["sources"][component]["path"])
            files = {}
            tracked = command(
                ["git", "-C", str(source), "ls-files", "-z", "--", prefix]
            )
            for raw in tracked.split(b"\0"):
                if not raw:
                    continue
                relative = Path(os.fsdecode(raw))
                if relative.suffix != ".py" or {"tests", "postgres_tests"} & set(
                    relative.parts
                ):
                    continue
                require(
                    relative.parts[0] == prefix and ".." not in relative.parts,
                    "image_source_path_refused",
                )
                files[relative.relative_to(prefix).as_posix()] = digest(
                    (source / relative).read_bytes().replace(b"\r\n", b"\n")
                )
            require(files, "image_source_inventory_empty")
            executables = (
                ["/usr/local/bin/vardr-worker-owner", "/usr/local/bin/vardrgate"]
                if component == "runner"
                else []
            )
            measured = json.loads(
                self.docker(
                    "run",
                    "--rm",
                    "-i",
                    "--network",
                    "none",
                    "--user",
                    "10001:10001",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--read-only",
                    "--label",
                    "com.docker.compose.project=" + self.project,
                    "--entrypoint",
                    "/usr/local/bin/python",
                    image,
                    "-I",
                    "-c",
                    program,
                    stdin=canonical(
                        {
                            "component": component,
                            "files": sorted(files),
                            "executables": executables,
                        }
                    ),
                )
            )
            require(measured["files"] == files, "image_source_inventory_mismatch")
            inventory[component] = {
                "image_id": image,
                "python_file_count": len(files),
                "python_inventory_sha256": digest(canonical(files)),
                "executables": measured["executables"],
                "line_endings": "CRLF-normalized-to-LF",
            }
        return inventory

    def stage(self):
        private_directory(self.install)
        private_directory(self.private)
        for raw in command(["git", "-C", str(self.source), "ls-files", "-z"]).split(
            b"\0"
        ):
            if not raw:
                continue
            relative = Path(os.fsdecode(raw))
            require(
                not relative.is_absolute() and ".." not in relative.parts,
                "tracked_source_path_refused",
            )
            if relative.parts[0] in {"artifacts", ".sources", ".git"}:
                continue
            source = self.source / relative
            require(
                source.is_file() and not source.is_symlink(),
                "tracked_source_link_refused",
            )
            target = self.install / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        sys.path.insert(0, str(self.install))
        self.lifecycle = load_module(
            "nm2_fixture_lifecycle", self.install / "vardrsec.py"
        )
        self.lifecycle.ROOT = self.install
        values = self.lifecycle.configuration_values()
        values.update(
            HTTPS_PORT=str(self.m["https_port"]),
            APPLICATION_SUBNET=self.m["application_subnet"],
            APPLICATION_IP_RANGE=self.m["application_ip_range"],
            PROXY_IP=self.m["proxy_ip"],
        )
        self.secrets += [
            values[k]
            for k in (
                "POSTGRES_PASSWORD",
                "POSTGRES_APP_PASSWORD",
                "BACKEND_JWT_SECRET",
                "AUTH_SECRET",
            )
        ]
        self.lifecycle.configure(values)
        # Shell values take precedence over .env in Compose. Pin this fixture's
        # fresh configuration before any role setup or container creation.
        self.environment.update(values)
        self.overlay = {
            "services": {
                name: {"image": self.images[name], "pull_policy": "never"}
                for name in ("db", "api", "web", "proxy")
            }
        }
        self.overlay["services"]["api"]["environment"] = {
            "VARDRMAP_MANAGED_WORKER": "0"
        }
        self.overlay["services"]["runner"] = {
            "image": self.images["worker"],
            "pull_policy": "never",
            "user": "10001:10001",
            "environment": {
                "HOME": "/home/runner",
                "VARDRRUNNER_ALLOW_PRIVATE_TARGETS": "1",
                "VARDRRUNNER_TOOLS_DIR": "/opt/vardrtools",
            },
        }
        self.write_overlay()
        roles = load_module("nm2_fixture_roles", self.install / "database_roles.py")

        def role_compose(root, *args, project=None, **kwargs):
            require(
                root == self.install and project == self.project,
                "database_role_fixture_scope",
            )
            environment = dict(self.environment)
            supplied = kwargs.pop("env", None)
            if supplied and "PGPASSWORD" in supplied:
                environment["PGPASSWORD"] = supplied["PGPASSWORD"]
            source = kwargs.pop("input", None)
            kwargs.pop("capture_output", None)
            text_output = kwargs.pop("text", False)
            output = self.compose(
                *args, env=environment, stdin=source, timeout=180, **kwargs
            )
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=output.decode() if text_output else output,
                stderr="" if text_output else b"",
            )

        roles.recovery.compose = role_compose
        roles.apply(self.install, project=self.project)
        self.compose(
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "180",
            "db",
            "api",
            "web",
            "proxy",
            timeout=240,
        )
        self.compose(
            "cp",
            "proxy:/data/caddy/pki/authorities/local/root.crt",
            str(self.install / "trust" / "root.crt"),
        )
        (self.install / "trust" / "root.crt").chmod(0o644)
        bootstrap = self.compose(
            "exec",
            "-T",
            "api",
            "python",
            "-m",
            "local_accounts",
            "init",
            "--username",
            "operator",
            "--generate-password",
        ).decode()
        self.password = bootstrap.split(
            "Generated password (store securely; shown once): ", 1
        )[1].strip()
        self.secrets.append(self.password)
        self.api = OwnerAPI(self.url, self.install / "trust" / "root.crt")
        self.owner = self.api.login("operator", self.password)
        self.receipt["public_ca_der_sha256"] = digest(
            ssl.PEM_cert_to_DER_cert(
                (self.install / "trust" / "root.crt").read_text(encoding="utf-8")
            )
        )

    def write_overlay(self):
        (self.install / "fixture.compose.json").write_bytes(canonical(self.overlay))

    def helper(self, *args, python=False, stdin=None):
        return self.compose(
            "run",
            "--rm",
            "--no-deps",
            "--user",
            "10001:10001",
            "--entrypoint",
            "/usr/local/bin/python" if python else "vardrrunner",
            "runner",
            *args,
            stdin=stdin,
            timeout=60,
        )

    def inventory(self, engagement, job):
        source = (self.install / "tests" / "nm2_worker_inventory.py").read_text(
            encoding="utf-8"
        )
        return json.loads(
            self.compose(
                "exec",
                "-T",
                "api",
                "python",
                "-c",
                source,
                stdin=canonical({"engagement_id": engagement, "job_id": job}),
            )
        )

    def traffic(self):
        code = "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/observations',timeout=3).read().decode())"
        return json.loads(
            self.compose("exec", "-T", "gate-fixture", "python", "-c", code)
        )["requests"]

    def enable(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sys.path.insert(0, self.m["sources"]["runner"]["path"])
        from vardrrunner.authorization.codec import b64

        self.operator_key, contract_key = (
            secrets.token_bytes(32),
            secrets.token_bytes(32),
        )

        def public(key):
            return b64(
                Ed25519PrivateKey.from_private_bytes(key)
                .public_key()
                .public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            )

        self.issuer_id = "nm2-fixture-" + self.project.removeprefix("vardrsec-nm2-")
        # Readable by Map UID10001 inside its single-file read-only mount; the
        # containing host directory has owner-only access and is never mounted.
        publish(self.private / "contract.key", contract_key, mode=0o444)
        publish(
            self.private / "operators.json",
            canonical(
                [
                    {
                        "issuer_id": self.issuer_id,
                        "key_id": "operator",
                        "approver_id": self.owner,
                        "public_key": public(self.operator_key),
                        "revoked": False,
                    }
                ]
            ),
            mode=0o444,
        )
        self.trust = [
            {
                "issuer_id": self.issuer_id,
                "key_id": key_id,
                "public_key": public(key),
                "purposes": [purpose],
                "origins": ["map"],
                "revoked": False,
            }
            for key_id, key, purpose in (
                ("operator", self.operator_key, "approval"),
                ("contract", contract_key, "contract"),
            )
        ]
        self.secrets += [b64(self.operator_key), b64(contract_key)]
        config = self.overlay["services"]["api"]
        config["environment"].update(
            VARDRMAP_MANAGED_WORKER="1",
            VARDRMAP_MANAGED_ORIGIN=self.issuer_origin,
            VARDRMAP_MANAGED_ISSUER_ID=self.issuer_id,
            VARDRMAP_MANAGED_CONTRACT_KEY_ID="contract",
            VARDRMAP_MANAGED_CONTRACT_KEY_FILE="/run/nm2-map/contract.key",
            VARDRMAP_MANAGED_OPERATOR_TRUST_FILE="/run/nm2-map/operators.json",
        )
        config["volumes"] = [
            {
                "type": "bind",
                "source": str(self.private / name),
                "target": "/run/nm2-map/" + name,
                "read_only": True,
            }
            for name in ("contract.key", "operators.json")
        ]
        self.write_overlay()
        self.compose(
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "--wait-timeout",
            "120",
            "api",
            timeout=150,
        )
        self.key = self.api.request(
            "/auth/apikeys", {"label": "owned NM2 fixture", "scope": "runner"}
        )
        self.environment["VARDRMAP_API_KEY"] = self.key["token"]
        self.secrets.append(self.key["token"])
        self.tokens = {
            f"FIXTURE_{name.upper()}_TOKEN": secrets.token_urlsafe(32)
            for name in ("owner", "peer", "reader")
        }
        self.secrets += list(self.tokens.values())
        publish(
            self.private / "worker.env",
            (
                "\n".join(k + "=" + v for k, v in self.tokens.items())
                + "\nVARDRRUNNER_ALLOW_PRIVATE_TARGETS=1\n"
            ).encode(),
        )
        target = {
            "image": self.images["worker"],
            "pull_policy": "never",
            "user": "10001:10001",
            "entrypoint": [
                "/usr/local/bin/python",
                "-I",
                "/fixture/nm2_worker_target.py",
            ],
            "env_file": [str(self.private / "worker.env")],
            "volumes": [
                {
                    "type": "bind",
                    "source": str(self.install / "tests"),
                    "target": "/fixture",
                    "read_only": True,
                }
            ],
            "networks": {"runner": {"aliases": ["gate-fixture"]}},
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "read_only": True,
            "restart": "no",
            "labels": {"io.vardrsec.nm2-fixture": self.project},
        }
        self.overlay["services"]["gate-fixture"] = target
        self.write_overlay()
        self.compose("up", "-d", "--no-build", "--pull", "never", "gate-fixture")
        until = time.monotonic() + 20
        while True:
            try:
                health = self.compose(
                    "exec",
                    "-T",
                    "gate-fixture",
                    "python",
                    "-c",
                    "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/health',timeout=3).read().decode())",
                    timeout=min(5, max(0.001, until - time.monotonic())),
                )
                require(
                    json.loads(health) == {"ready": True}, "fixture_health_not_ready"
                )
                break
            except AcceptanceRefused:
                require(time.monotonic() < until, "fixture_health_not_ready")
                time.sleep(0.2)
        self.receipt["doctor_sha256"] = digest(
            self.helper("doctor", "--platform", "--offline", "--json")
        )

    def new_job(self, name, *, in_scope=True):
        from gate_acceptance import reviewed_cases

        now = datetime.now(timezone.utc)

        def stamp(moment):
            return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

        engagement = self.api.request(
            "/engagements",
            {
                "name": "NM2 " + name,
                "starts_at": stamp(now - timedelta(minutes=1)),
                "ends_at": stamp(now + timedelta(minutes=15)),
            },
        )["id"]
        base = "/engagements/" + engagement
        authorization = self.api.request(
            base + "/authorizations",
            {
                "permits": "Owned synthetic fixture only",
                "authorized_by": "Fixture local owner",
                "reference": self.project,
                "window_start": stamp(now - timedelta(minutes=1)),
                "window_end": stamp(now + timedelta(minutes=15)),
            },
            expected=201,
        )["id"]
        self.api.request(
            base + "/scope/in",
            {
                "kind": "url",
                "value": ORIGIN + "/" if in_scope else ORIGIN + "/unapproved/",
            },
            expected=200,
        )
        for endpoint, body in (
            ("concurrency-policy", {"limit": 1}),
            ("target-policy", {"limit": 5}),
            ("duration-policy", {"limit_seconds": 120}),
        ):
            self.api.request(base + "/" + endpoint, body, method="PUT")
        case = next(case for case in reviewed_cases() if case["name"] == "fixed")
        case["spec"]["id"] = "nm2-" + name
        stored = self.api.request(base + "/test-cases", case, expected=201)
        job = self.api.request(
            base + "/jobs",
            {
                "tool_type": "vardrgate_api_test",
                "target_source": "scope",
                "config": {
                    "test_case_id": stored["id"],
                    "timeout": EXECUTION["timeout_seconds"],
                },
                "authorization_contract_required": True,
            },
        )["id"]
        return engagement, authorization, job, stored

    def approve(
        self,
        name,
        engagement,
        authorization,
        job,
        case,
        *,
        local_grants=True,
        expected=200,
    ):
        from vardrrunner.authorization.contracts import approve
        from vardrrunner.authorization.plan import compile_gate_plan

        identity = self.helper("identity", "show").decode()
        runner_id = re.search(r"Runner ID:\s*([0-9a-f-]{36})", identity).group(1)
        enrollment = json.loads(
            self.compose(
                "exec",
                "-T",
                "api",
                "python",
                "-m",
                "managed_enrollment",
                "bind",
                "--owner",
                self.owner,
                "--api-key-id",
                self.key["id"],
                "--runner-id",
                runner_id,
                "--origin",
                self.issuer_origin,
                "--key-stdin",
                stdin=(self.key["token"] + "\n").encode(),
            )
        )
        if local_grants:
            for who in ("owner", "peer"):
                self.helper(
                    "credentials",
                    "approve",
                    "--engagement",
                    engagement,
                    "--origin",
                    ORIGIN,
                    "--env",
                    f"FIXTURE_{who.upper()}_TOKEN",
                    "--issuer",
                    self.issuer_origin,
                    "--expires-in",
                    "600",
                )
        tool_sha256 = (
            self.helper(
                "-I",
                "-c",
                "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/usr/local/bin/vardrgate').read_bytes()).hexdigest())",
                python=True,
            )
            .decode()
            .strip()
        )
        plan = compile_gate_plan(case["spec"], EXECUTION, tool_sha256=tool_sha256)
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        selection = {
            "enrollment_id": enrollment["enrollment_id"],
            "authorization_id": authorization,
            "plan": plan,
        }
        review = self.api.request(
            f"/jobs/{job}/managed/approval/review",
            {
                **selection,
                "expires_at": expiry,
                "max_executions": 1,
                "max_duration_seconds": 30,
                "max_artifact_bytes": 1024 * 1024,
                "credential_grants": [
                    {**reference, "revision": 1, "expires_at": expiry}
                    for reference in plan["credential_references"]
                ],
            },
            expected=expected,
        )
        if expected != 200:
            return None
        approval = approve(
            review["context"],
            {"id": self.issuer_id, "key_id": "operator"},
            "map",
            self.owner,
            "fixture-" + name,
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            self.operator_key,
        )
        self.api.request(
            f"/jobs/{job}/managed/approval/register",
            {**selection, "approval": approval},
        )
        return runner_id, enrollment["enrollment_id"]

    def worker(self, runner_id, enrollment_id):
        import worker_runtime

        public = self.install / "worker-public"
        public.mkdir(mode=0o755)
        publish(public / "trust.json", canonical(self.trust), mode=0o444)
        self.environment.update(
            VARDRSEC_WORKER_IMAGE=self.images["worker"],
            VARDRSEC_WORKER_CREDENTIAL_FILE=str(self.private / "worker.env"),
            VARDRSEC_WORKER_PUBLIC_DIR=str(public),
            VARDRRUNNER_WORKER_CREDENTIAL_ENV="FIXTURE_OWNER_TOKEN,FIXTURE_PEER_TOKEN",
            VARDRRUNNER_WORKER_WAIT_SECONDS="10",
            VARDRRUNNER_WORKER_ADMISSION_WAIT_SECONDS="60",
        )
        self.compose(
            "--profile",
            "managed-worker",
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "managed-worker",
            worker=True,
        )
        container_id = (
            self.compose(
                "--profile",
                "managed-worker",
                "ps",
                "-aq",
                "managed-worker",
                worker=True,
            )
            .decode()
            .strip()
        )
        observer = worker_runtime.LocalDocker(
            self.m["docker_context"],
            worker_runtime.WorkerLayout(
                str(self.install / "trust"),
                str(public),
                self.project + "_runner-state",
                self.ready_volume,
            ),
        )
        entered = time.monotonic()
        while True:
            try:
                identity = observer.capture_running(
                    container_id=container_id,
                    image_id=self.images["worker"],
                    project=self.project,
                )
                break
            except worker_runtime.RuntimeRefused:
                require(
                    time.monotonic() - entered < 15,
                    "actual_owner_readiness_not_observed",
                )
                time.sleep(0.2)
        self.receipt["stage"] = "operator_worker_enable"
        enabled = json.loads(
            command(
                [
                    sys.executable,
                    str(self.install / "vardrsec.py"),
                    "worker",
                    "enable",
                    "--api-url",
                    self.url + "/backend",
                    "--ca",
                    str(self.install / "trust" / "root.crt"),
                    "--private-root",
                    str(self.private),
                    "--context",
                    self.m["docker_context"],
                    "--container-id",
                    container_id,
                    "--image-id",
                    self.images["worker"],
                    "--project",
                    self.project,
                    "--trust-source",
                    str(self.install / "trust"),
                    "--admission-source",
                    str(public),
                    "--state-volume",
                    self.project + "_runner-state",
                    "--readiness-volume",
                    self.ready_volume,
                    "--enrollment-id",
                    enrollment_id,
                    "--runner-id",
                    runner_id,
                    "--origin",
                    self.issuer_origin,
                    "--public-trust",
                    str(public / "trust.json"),
                    "--expires-in",
                    "900",
                    "--username",
                    "operator",
                    "--password-stdin",
                ],
                cwd=self.install,
                env=self.environment,
                stdin=self.password + "\n",
                timeout=90,
            )
        )
        admission = json.loads((public / "admission.json").read_bytes())
        require(
            enabled["schema"] == "vardr.worker-cli/1"
            and enabled["state"] == "enabled"
            and enabled["identity"] == asdict(identity)
            and enabled["runtime_id"] == admission["runtime_id"]
            and enabled["runtime_sha256"] == admission["runtime_sha256"],
            "operator_enable_not_bound",
        )
        # Direct host observation of exact incarnation exit, never an exec or
        # a caller-generated JSON object passed off as physical proof.
        proof = observer.observe_exit(identity)
        return {
            "identity": asdict(identity),
            "runtime_id": admission["runtime_id"],
            "runtime_sha256": admission["runtime_sha256"],
            "exit_code": proof.exit_code,
            "finished_at": proof.finished_at,
            "operator_enable_state": enabled["state"],
        }

    def run(self):
        sys.path.insert(0, str(self.source))
        import worker_runtime

        # Validate the explicitly selected local endpoint before any container
        # creation. A caller's context name is not proof of local observation.
        observer = worker_runtime.LocalDocker(
            self.m["docker_context"],
            worker_runtime.WorkerLayout(
                str(self.install / "trust"),
                str(self.install / "worker-public"),
                self.project + "_runner-state",
                self.ready_volume,
            ),
        )
        self.receipt["daemon_id"] = observer.daemon()
        require(
            json.loads(self.docker("info", "--format", "{{json .OSType}}")) == "linux",
            "linux_container_engine_required",
        )
        self.receipt["docker_architecture"] = json.loads(
            self.docker("info", "--format", "{{json .Architecture}}")
        )
        before = self.snapshot()
        expected_volumes = {
            self.project + "_" + name
            for name in ("database", "proxy-data", "proxy-config", "runner-state")
        } | {self.ready_volume}
        require(
            not expected_volumes.intersection(before["volumes"]),
            "fixture_volume_name_exists",
        )
        expected_networks = {
            self.project + "_" + name for name in ("database", "application", "runner")
        }
        require(
            not expected_networks.intersection(
                {row["name"] for row in before["networks"].values()}
            ),
            "fixture_network_name_exists",
        )
        require(
            not any(
                row.get("labels", {}).get("com.docker.compose.project") == self.project
                for kind in ("containers", "networks", "volumes")
                for row in before[kind].values()
            ),
            "fixture_project_exists",
        )
        for image in self.images.values():
            require(image in before["images"], "reviewed_local_image_missing")
        self.receipt["before_sha256"] = digest(canonical(before))
        try:
            self.receipt["image_sources"] = self.image_sources()
            self.stage()
            publish(self.install / "nm2-inventory-before.json", canonical(before))
            OwnerAPI(self.url, self.install / "trust" / "root.crt").request(
                "/engagements", expected=401
            )
            self.api.request("/jobs/managed/pending", {}, expected=404)
            services = self.compose("ps", "--all", "--services").decode().split()
            require(
                set(services) == {"db", "api", "web", "proxy"}, "default_started_worker"
            )
            original_engagements = self.api.request("/engagements")
            self.api.request(
                "/engagements", {"name": "CSRF must refuse"}, csrf=False, expected=403
            )
            require(
                self.api.request("/engagements") == original_engagements,
                "csrf_denial_mutated_state",
            )
            self.receipt["cases"]["default_disabled"] = {
                "status": "passed",
                "services": sorted(services),
                "managed_pending_status": 404,
                "csrf_write_status": 403,
                "unauthenticated_read_status": 401,
            }
            self.enable()
            engagement, authorization, job, case = self.new_job(
                "strict-denial", in_scope=False
            )
            zero = self.traffic()
            self.approve(
                "strict-denial", engagement, authorization, job, case, expected=403
            )
            inventory = self.inventory(engagement, job)
            require(
                self.traffic() == zero
                and inventory["contracts"] == []
                and inventory["execution"] is None
                and inventory["targets_spent"] == inventory["duration_allocated"] == 0,
                "strict_denial_mutated_or_dispatched",
            )
            self.receipt["cases"]["strict_out_of_scope"] = {
                "status": "passed",
                "inventory": inventory,
                "traffic_delta": 0,
            }
            # Single container/attempt first slice. Later cases use a fresh
            # installation; retained state or unknown receipts are never cleared.
            engagement, authorization, job, case = self.new_job("happy-fixed")
            binding = self.approve("happy-fixed", engagement, authorization, job, case)
            traffic = self.traffic()
            before_worker = self.inventory(engagement, job)
            require(
                traffic == zero
                and before_worker["job_status"] == "pending"
                and before_worker["execution"] is None
                and not before_worker["contracts"]
                and before_worker["targets_spent"]
                == before_worker["duration_allocated"]
                == 0
                and before_worker["approvals"][0]["issued"] == 0,
                "approved_queue_executed_before_worker_enablement",
            )
            physical = self.worker(*binding)
            inventory = self.inventory(engagement, job)
            requests = self.traffic()[len(traffic) :]
            require(
                inventory["schema_revision"] == "0039managedruntime"
                and inventory["database_user"] == "vardrmap_app",
                "normal_database_readiness_required",
            )
            require(
                physical["exit_code"] == 0
                and inventory["job_status"] == "done"
                and len(inventory["contracts"]) == len(inventory["results"]) == 1
                and not inventory["stops"],
                "happy_terminal_receipt_missing",
            )
            require(
                inventory["execution"]["capacity_reserved"] is False
                and inventory["targets_spent"] == 1
                and inventory["duration_allocated"] == 30
                and inventory["contracts"][0]["consumed"] is True
                and inventory["contracts"][0]["ordinal"] == 1
                and inventory["contracts"][0]["fence"] == 1
                and inventory["results"][0]["outcome"] == "completed",
                "happy_retained_allowance_mismatch",
            )
            require(
                len(requests) == 5
                and {r["identity"] for r in requests} == {"owner", "peer", "anonymous"},
                "happy_fixed_traffic_mismatch",
            )
            base = "/engagements/" + engagement
            completed_job = next(
                row
                for row in self.api.request(base + "/jobs")["jobs"]
                if row["id"] == job
            )
            assessment = completed_job["assessment"]
            require(
                assessment["status"] == "conclusive"
                and assessment["baseline_valid"] is True
                and assessment["case_snapshot_verified"] is True
                and assessment["preflight"]["status"] == "passed"
                and assessment["case_hash"] == digest(canonical(case["spec"]))
                and assessment["candidate_findings"] == 0,
                "fixed_assessment_not_proven",
            )
            require(
                self.api.request(base + "/scans?job_id=" + job)["scans"] == []
                and len(inventory["runtimes"]) == 1
                and inventory["runtimes"][0]["confirmed"] is True
                and inventory["results"][0]["evidence_created"] == 5
                and inventory["results"][0]["scan_items_created"] == 0,
                "fixed_result_runtime_binding_not_proven",
            )
            evidence = self.api.request(base + "/evidence?job_id=" + job)["evidence"]
            require(
                len(evidence) == 5
                and all(
                    digest(row["body"].encode()) == row["content_hash"]
                    for row in evidence
                ),
                "evidence_hash_mismatch",
            )
            retained = canonical(evidence)
            require(
                not any(
                    secret.encode() in retained
                    for secret in (
                        *self.secrets,
                        "disposable-private-response-canary",
                        "disposable-response-cookie-canary",
                    )
                ),
                "evidence_redaction_failed",
            )
            self.receipt["cases"]["happy_fixed"] = {
                "status": "passed",
                "physical": physical,
                "before_worker": before_worker,
                "inventory": inventory,
                "requests": requests,
                "case_sha256": assessment["case_hash"],
                "evidence_count": len(evidence),
                "evidence_sha256": digest(retained),
            }
            self.receipt["status"] = "initial_stages_passed"
        except Exception as error:
            self.receipt["status"] = "held"
            self.receipt["reason"] = (
                str(error)
                if isinstance(error, AcceptanceRefused)
                else "fixture_stage_failed"
            )
            raise
        finally:
            # Preserve stopped/failed fixtures and custody; never down/prune or
            # retry a claim, consume, binding, result or lost runtime admission.
            after = None
            try:
                self.stop_owned(before)
            except Exception:
                self.receipt["status"] = "held"
                self.receipt["fixture_stop"] = {"status": "unknown_preserve_resources"}
            try:
                after = self.snapshot()
                self.receipt["after_sha256"] = digest(canonical(after))
                self.receipt["admitted_inventory_diffs"] = unchanged_inventory(
                    before,
                    after,
                    self.project,
                    admit_bridge=self.m["allow_empty_builtin_bridge_id_change"],
                )
            except AcceptanceRefused as error:
                self.receipt["status"], self.receipt["inventory_reason"] = (
                    "held",
                    str(error),
                )
            except Exception:
                self.receipt["status"] = "held"
                self.receipt["inventory_reason"] = "inventory_observation_unavailable"
            if self.install.is_dir():
                if not (self.install / "nm2-inventory-before.json").exists():
                    publish(
                        self.install / "nm2-inventory-before.json", canonical(before)
                    )
                if after is not None:
                    publish(self.install / "nm2-inventory-after.json", canonical(after))
                raw = canonical(self.receipt)
                require(
                    not any(secret.encode() in raw for secret in self.secrets),
                    "receipt_redaction_failed",
                )
                publish(self.install / "nm2-worker-receipt.json", raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", required=True, type=Path)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Run the reviewed explicit fixture; creates and retains owned Docker resources",
    )
    args = parser.parse_args(argv)
    selection = manifest(args.cohort)
    if not args.execute:
        print(
            json.dumps(
                {
                    "schema": "vardr.nm2-worker-source-validation/1",
                    "status": "sources_validated_runtime_not_run",
                    "project": selection["project"],
                    "sources": selection["sources"],
                    "images": selection["images"],
                    "initial_cases": INITIAL_CASES,
                    "docker_calls": 0,
                },
                indent=2,
            )
        )
        return 0
    fixture = Fixture(selection)
    try:
        fixture.run()
    except Exception:
        print(
            "NM2 fixture held; preserve its installation, host custody and Docker resources.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(fixture.receipt, indent=2))
    return 0 if fixture.receipt["status"] == "initial_stages_passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

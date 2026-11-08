"""Development distribution lifecycle. Diagnostics remain in VardrRunner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import uuid

from installation_mode import MARKER, compose_files, read_mode, read_project, validate_runner_subnet, write_mode

ROOT = Path(__file__).resolve().parent


def run(*args, **kwargs):
    if kwargs.get("text"):
        kwargs.setdefault("encoding", "utf-8")
    try:
        return subprocess.run(args, cwd=ROOT, check=kwargs.pop("check", True), **kwargs)
    except FileNotFoundError:
        raise ValueError(
            f"Required command {args[0]!r} is unavailable. Install it and follow docs/installation.md."
        ) from None


def require_command(name):
    if not shutil.which(name):
        raise ValueError(
            f"Required command {name!r} is unavailable. Install it and follow docs/installation.md."
        )


def build_prerequisites():
    require_command("docker")
    try:
        version = run(
            "docker", "compose", "version", "--short", capture_output=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        raise ValueError(
            "Docker Compose is unavailable. Install the Compose plugin; see docs/installation.md."
        ) from None
    match = re.match(r"v?(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < (2, 17):
        raise ValueError(
            "Compose 2.17+ is required for named build contexts. Update Compose and retry build."
        )
    try:
        system = run(
            "docker", "info", "--format", "{{.OSType}}", capture_output=True, text=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        raise ValueError(
            "Cannot access Docker. Check that Engine/Desktop is running and your account has daemon access; see docs/installation.md."
        ) from None
    if system != "linux":
        raise ValueError(
            "VardrSec requires Linux containers. Select Linux containers in Docker Desktop before building."
        )


def compose(*args, **kwargs):
    selected = compose_files(ROOT, mode=kwargs.pop("installation_mode", None))
    if kwargs.pop("controlled", False):
        selected.append(ROOT / "compose.local-worker.json")
    flags = [part for path in selected for part in ("-f", str(path))]
    project = read_project(ROOT)
    if project:
        flags += ["-p", project]
    return run("docker", "compose", *flags, *args, **kwargs)


# Exact shipped Full model, normalized for checkout line endings. Updating the
# model requires reviewing this fresh-install boundary alongside its tests.
STANDARD_FULL_SHA256 = "f37b23086000958ca23e1244109457f7fd5949dd9fb5bacfc601b4d51c967d0b"
STANDARD_MAPLESS_SHA256 = "80653a1435ab148ec6943a4145e0a0d52675a51a3f2eef245c95100cfc921e6f"


def require_standard_fresh_layout():
    error = (
        "Fresh install requires the shipped Full Compose layout and standard .env selection. "
        "Preserve existing state; use the reviewed recovery procedure for an existing installation "
        "or a separate clean standard checkout for a new installation."
    )
    try:
        if os.path.lexists(ROOT / ".env") or os.path.lexists(ROOT / ".active-images.json"):
            raise ValueError(error)
        if any(key.startswith("COMPOSE_") and key != "COMPOSE_PROJECT_NAME" for key in os.environ):
            raise ValueError(error)
        path = ROOT / "compose.yaml"
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(error)
        if hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != STANDARD_FULL_SHA256:
            raise ValueError(error)
    except OSError:
        raise ValueError(error) from None


def configuration_values():
    project = os.environ.get("COMPOSE_PROJECT_NAME")
    if project is not None and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
        raise ValueError("COMPOSE_PROJECT_NAME must be a lowercase project name of at most 63 characters")
    return {
        "HTTPS_PORT": "8443",
        # Keep a fresh installation's build aliases separate from other projects.
        # Existing .env files retain their original development aliases.
        "VARDRSEC_IMAGE_TAG": "local-" + uuid.uuid4().hex,
        **({"COMPOSE_PROJECT_NAME": project} if project is not None else {}),
        **{name: secrets.token_hex(32) for name in (
            "POSTGRES_PASSWORD", "POSTGRES_APP_PASSWORD", "BACKEND_JWT_SECRET", "AUTH_SECRET"
        )},
    }


def configure(prepared=None):
    if prepared is not None:
        # Recheck immediately before exclusive publication; this is not a claim
        # of protection from arbitrary concurrent filesystem/environment writers.
        require_standard_fresh_layout()
    path = ROOT / ".env"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(
            "Existing .env preserved. Skip configure for an existing installation; do not reset credentials to repair startup. See docs/installation.md."
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        for name, value in (configuration_values() if prepared is None else prepared).items():
            output.write(f"{name}={value}\n")
    (ROOT / "trust").mkdir(exist_ok=True)
    print("Created .env without displaying secrets. Keep it private and back it up.")


def _refuse_source_link(path):
    """Refuse observed links in the managed cache; not a concurrent-race guarantee."""
    try:
        info = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Linked source cache refused; preserve it and use a fresh source directory")


def _require_source_git_binding(path):
    """Refuse observed Git worktree/metadata redirects without rewriting config."""
    try:
        result = run(
            "git", "-C", str(path), "rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir",
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Cannot validate source Git binding; preserve the source directory") from None
    reported = result.stdout.splitlines()
    expected = (path.resolve(), (path / ".git").resolve())
    if result.returncode != 0 or len(reported) != 3 or any(
        not Path(value).is_absolute() or Path(value) != wanted
        for value, wanted in zip(reported[:2], expected)
    ) or Path(reported[2]) not in {Path(".git"), expected[1]}:
        raise ValueError("Source Git binding differs from the managed cache; preserve the source directory")


def sources(*, mapless=False):
    require_command("git")
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    names = ("runner", "gate") if mapless else ("map", "runner", "gate")
    cache = ROOT / ".sources"
    _refuse_source_link(cache)
    # Inspect all selected paths before the first Git call, including .git files
    # that redirect Git to an external worktree/metadata directory.
    for name in names:
        _refuse_source_link(cache / name)
        metadata = cache / name / ".git"
        _refuse_source_link(metadata)
        if metadata.exists() and not metadata.is_dir():
            raise ValueError("External Git metadata refused; preserve it and use a fresh source directory")
    # Validate every existing repository before preparing any selected component.
    for name in names:
        if (cache / name / ".git").is_dir():
            _require_source_git_binding(cache / name)
    for name in names:
        item = manifest["components"][name]
        repo, revision = item["repository"], item["commit"]
        if (
            repo
            != {
                "map": "VardrSec/VardrMap",
                "runner": "VardrSec/VardrRunner",
                "gate": "VardrSec/VardrGate",
            }[name]
        ):
            raise ValueError("Unexpected component repository")
        if not re.fullmatch("[0-9a-f]{40}", revision):
            raise ValueError("A full source commit is required")
        path = ROOT / ".sources" / name
        if path.exists() and not path.is_dir():
            raise ValueError(
                f"{name} source path is not a directory; preserve it and use a fresh source directory"
            )
        if (path / ".git").exists():
            head = run(
                "git",
                "-C",
                str(path),
                "rev-parse",
                "HEAD",
                capture_output=True,
                text=True,
                check=False,
            )
            dirty = run(
                "git",
                "-C",
                str(path),
                "status",
                "--porcelain",
                capture_output=True,
                text=True,
            ).stdout.strip()
            if dirty or (head.returncode == 0 and head.stdout.strip() != revision):
                raise ValueError(
                    f"{name} source differs from the pin; preserve it and use a fresh source directory"
                )
            if head.returncode == 0:
                continue
            # Retry an interrupted initial fetch only when no user files exist.
            if (
                not (path / ".git").is_dir()
                or (path / ".git").is_symlink()
                or any(item.name != ".git" for item in path.iterdir())
            ):
                raise ValueError(
                    f"{name} has no checked-out revision but contains files; preserve it and use a fresh source directory"
                )
        else:
            if path.exists() and any(path.iterdir()):
                raise ValueError(
                    f"{name} source directory is not empty; preserve it and use a fresh source directory"
                )
            path.mkdir(parents=True, exist_ok=True)
            run("git", "-C", str(path), "init")
            _require_source_git_binding(path)
        run(
            "git",
            "-C",
            str(path),
            "fetch",
            "--depth=1",
            f"https://github.com/{repo}.git",
            revision,
        )
        run("git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD")


def main():
    if sys.argv[1:2] == ["worker"]:
        if read_mode(ROOT) == "mapless":
            raise ValueError("Mapless has no Map queue worker; use runner --controlled for an explicitly authorized local job")
        # Host primitives own the installation lock. The ordinary outer guard
        # must not acquire it again, and no normal startup enters this branch.
        import worker_cli

        result = worker_cli.main(sys.argv[2:], installation=ROOT)
        if result:
            raise SystemExit(result)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "install",
            "configure",
            "sources",
            "build",
            "start",
            "stop",
            "export-ca",
            "bootstrap",
            "database-role",
            "doctor",
            "backup",
            "restore",
            "update",
            "cancel-update",
            "seal-backup",
            "unseal-backup",
            "runner",
            "worker",
        ),
    )
    parser.add_argument("--username", default="operator")
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Bootstrap with a securely generated password, shown once",
    )
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--project")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--recipient")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--input-directory", type=Path, help="Runner-only flat host input directory, staged read-only at /inputs")
    parser.add_argument("--output-directory", type=Path, help="Runner-only new private host directory receiving /exports after completion")
    parser.add_argument("--authority-volume", help="Private issuer volume, only for workspace authority-init/authorize; never execution")
    parser.add_argument("--controlled", action="store_true", help="Runner-only explicit one-job contained local execution")
    parser.add_argument("--runner-subnet", help="Optional unused private IPv4 /24 for the Mapless Runner bridge")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--full", action="store_true", help="Explicitly select a Full installation")
    modes.add_argument(
        "--mapless",
        action="store_true",
        help="Install standalone Runner and Gate without Map, database or proxy",
    )
    args, extra = parser.parse_known_args()
    if args.action == "runner":
        # Everything after `--` belongs to Runner, so none of its options can be
        # taken as one of ours (for example `--destination`).
        if "--" not in sys.argv[2:]:
            parser.error(
                "separate Runner's arguments with --, for example: "
                "python3 vardrsec.py runner -- jobs run"
            )
        args.runner_args = extra
    elif extra:
        parser.error("unrecognized arguments: " + " ".join(extra))
    if args.generate_password and args.action != "bootstrap":
        parser.error("--generate-password is only valid with bootstrap")
    if args.action != "runner" and (args.input_directory or args.output_directory or args.controlled or args.authority_volume):
        parser.error("Input, output, authority-volume and controlled options require runner")
    selected = read_mode(ROOT)
    if args.full and (args.action != "install" or selected == "mapless"):
        parser.error("--full requires install in a Full or clean checkout; preserve Mapless state in its original installation")
    if args.runner_subnet:
        if args.action not in ("install", "start") or not (selected == "mapless" or args.mapless):
            parser.error("--runner-subnet is only valid with Mapless install/start")
        validate_runner_subnet(args.runner_subnet)
    if args.mapless and args.action != "sources":
        if args.action == "install":
            if (ROOT / MARKER).exists() and selected != "mapless":
                parser.error("Use a separate checkout for a Mapless installation; preserve existing Full state")
        elif selected != "mapless":
            parser.error("Install Mapless first with install --mapless; existing Full state is retained")
    if args.action in ("update", "cancel-update"):
        return dispatch(args, parser)
    import updater

    with updater.operation_guard(ROOT, args.action):
        return dispatch(args, parser)


INSTALL_STEPS = ("configure", "sources", "build", "database-role", "start", "export-ca")


def select_full_installation():
    """Freeze a fresh Full install before its first stateful startup."""
    import ipaddress
    import recovery

    path = ROOT / ".active-images.json"
    network_keys = {"APPLICATION_SUBNET", "APPLICATION_IP_RANGE", "PROXY_IP"}

    def model(environment=None):
        return json.loads(compose("--profile", "tools", "config", "--format", "json",
                                  capture_output=True, text=True, env=environment).stdout)

    def application(configuration):
        entry = configuration["networks"]["application"]["ipam"]["config"][0]
        return (entry["subnet"], entry["ip_range"],
                configuration["services"]["proxy"]["networks"]["application"]["ipv4_address"])

    current = model()
    if set(current["services"]) != recovery.SERVICES:
        raise ValueError("Full installation requires the shipped five-service model")
    project = current["name"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
        raise ValueError("Invalid Full installation project")
    file_environment = {key: value for key, value in os.environ.items()
                        if key not in network_keys | {"COMPOSE_PROJECT_NAME"}}
    if os.path.lexists(path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
                or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 16384):
            raise ValueError("Frozen Full image selection must be a small regular file")
        selected = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(selected, dict) or set(selected) != {"services", "networks"}
                or not isinstance(selected["services"], dict)
                or set(selected["services"]) != recovery.SERVICES
                or not isinstance(selected["networks"], dict)
                or set(selected["networks"]) != {"database", "runner"}):
            raise ValueError("Existing Full selection is not an interrupted fresh installation")
        for service, definition in selected["services"].items():
            if (not isinstance(definition, dict) or set(definition) != {"image"}
                    or not recovery.IMAGE_ID.fullmatch(str(definition["image"]))):
                raise ValueError("Frozen Full selection requires exact image IDs")
            run("docker", "image", "inspect", definition["image"], capture_output=True)
        subnets = [ipaddress.ip_network(validate_runner_subnet(application(current)[0]))]
        for definition in selected["networks"].values():
            try:
                subnet = validate_runner_subnet(definition["ipam"]["config"][0]["subnet"])
            except (KeyError, TypeError, IndexError):
                raise ValueError("Invalid frozen Full network selection") from None
            if definition != {"ipam": {"config": [{"subnet": subnet}]}}:
                raise ValueError("Invalid frozen Full network selection")
            subnets.append(ipaddress.ip_network(subnet))
        if any(left.overlaps(right) for index, left in enumerate(subnets) for right in subnets[index + 1:]):
            raise ValueError("Frozen Full networks overlap")
        persisted = model(file_environment)
        if persisted["name"] != project or application(persisted) != application(current):
            raise ValueError("Persist the matching Full project and application network before resuming")
        return

    images = {}
    for service in sorted(recovery.SERVICES):
        image = run("docker", "image", "inspect", "--format", "{{.Id}}",
                    current["services"][service]["image"], capture_output=True, text=True).stdout.strip()
        if not recovery.IMAGE_ID.fullmatch(image):
            raise ValueError("Cannot freeze the built Full image set")
        images[service] = {"image": image}
    assignments = {match[1] for match in re.finditer(
        r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", (ROOT / ".env").read_text(encoding="utf-8"))}
    explicit = bool(network_keys & (assignments | set(os.environ)))
    subnet_text, ip_range, proxy_ip = application(current)
    subnet_text = validate_runner_subnet(subnet_text)
    if explicit:
        subnet = recovery.available_subnet(subnet_text)
    else:
        try:
            subnet = recovery.available_subnet(subnet_text)
        except ValueError as error:
            if "overlaps" not in str(error):
                raise
            subnet = recovery.available_subnet()
            prefix = str(subnet.network_address).rsplit(".", 1)[0]
            ip_range, proxy_ip = prefix + ".128/25", prefix + ".2"
    if (not ipaddress.ip_network(ip_range, strict=True).subnet_of(subnet)
            or ipaddress.ip_address(proxy_ip) not in subnet):
        raise ValueError("Full application address range and proxy must belong to its subnet")
    database = recovery.available_subnet(reserved=(subnet,))
    runner = recovery.available_subnet(reserved=(subnet, database))
    with (ROOT / ".env").open("a", encoding="utf-8") as output:
        output.write(f"\nCOMPOSE_PROJECT_NAME={project}\nAPPLICATION_SUBNET={subnet}\n"
                     f"APPLICATION_IP_RANGE={ip_range}\nPROXY_IP={proxy_ip}\n")
    persisted = model(file_environment)
    if persisted["name"] != project or application(persisted) != (str(subnet), ip_range, proxy_ip):
        raise ValueError("Full project/network selection was not durably configured; startup refused")
    recovery.json_write(path, {"services": images, "networks": {
        name: {"ipam": {"config": [{"subnet": str(value)}]}}
        for name, value in (("database", database), ("runner", runner))}})


def install_mapless(args, parser):
    """Prepare the existing toolkit and stopped state container, without Map."""
    error = "Mapless install requires the shipped layout in a separate checkout; preserve existing installation state"
    if any(os.path.lexists(ROOT / name) for name in (".env", ".active-images.json", ".active-images.mapless.json")):
        raise ValueError(error)
    if any(key.startswith("COMPOSE_") and key != "COMPOSE_PROJECT_NAME" for key in os.environ):
        raise ValueError(error)
    model = ROOT / "compose.mapless.json"
    info = model.lstat()
    if (not stat.S_ISREG(info.st_mode) or model.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400
            or hashlib.sha256(model.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != STANDARD_MAPLESS_SHA256):
        raise ValueError(error)
    build_prerequisites()
    if has_installation_data(mapless=True):
        raise ValueError("Installation volumes already exist. Use start, runner or backup; install will not overwrite their state")
    write_mode(ROOT, "mapless")
    sources(mapless=True)
    compose("--profile", "tools", "build", "runner")
    select_mapless_image(getattr(args, "runner_subnet", None))
    compose("--profile", "tools", "create", "--no-build", "runner")
    print("Mapless installed. Runner is stopped; no Map, database, proxy, job or background worker was started. See docs/mapless.md for authorization, execution and export.")


def select_mapless_image(subnet=None):
    """Keep installed image/project selection and optional bridge configuration together."""
    import updater

    path = ROOT / ".active-images.mapless.json"
    record = None
    if os.path.lexists(path):
        compose_files(ROOT)  # Refuse malformed or broadened selections first.
        record = json.loads(path.read_text(encoding="utf-8"))
        if subnet is None:
            return
        selected = record.get("networks", {}).get("runner", {}).get("ipam", {}).get("config", [])
        if selected and selected[0]["subnet"] == validate_runner_subnet(subnet):
            return
    model = json.loads(compose(
        "--profile", "tools", "config", "--format", "json", capture_output=True, text=True,
    ).stdout)
    if record is None:
        image = run("docker", "image", "inspect", "--format", "{{.Id}}",
                    model["services"]["runner"]["image"], capture_output=True, text=True).stdout.strip()
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise ValueError("Cannot pin the built toolkit image; preserve the interrupted installation")
        record = {"name": model["name"], "services": {"runner": {"image": image}}}
    if subnet is not None:
        subnet = validate_runner_subnet(subnet)
        names = run("docker", "network", "ls", "--format", "{{.Name}}",
                    capture_output=True, text=True).stdout.splitlines()
        if model["networks"]["runner"]["name"] in names:
            raise ValueError("The existing Runner network is preserved; subnet selection requires an installation without that network")
        # Reuse recovery's inventory before publishing an unusable selection.
        import recovery
        recovery.available_subnet(subnet)
        record["networks"] = {"runner": {"ipam": {"config": [{"subnet": subnet}]}}}
    updater.save(path, record)


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def runner_invocation(arguments):
    """Split `[--env NAME]... [--] COMMAND...` into Compose `-e` flags and Runner's argv.

    `--env NAME` passes one variable from the caller's environment, such as an
    identity token a reviewed case references. Only the name reaches the command
    line; Compose reads the value from this process's environment.
    """
    flags, rest = [], list(arguments)
    if rest and rest[0] == "--":
        rest.pop(0)
    while rest and (rest[0] == "--env" or rest[0].startswith("--env=")):
        item = rest.pop(0)
        if item == "--env":
            if not rest:
                raise ValueError("--env needs a variable name")
            name = rest.pop(0)
        else:
            name = item.split("=", 1)[1]
        if not _ENV_NAME.fullmatch(name):
            raise ValueError(f"--env takes an environment variable name, not {name!r}")
        flags += ["-e", name]
    if rest and rest[0] == "--":
        rest.pop(0)
    return flags, rest


def invoke_runner(args):
    """Transfer selected files without exposing a host home or private issuer to tools."""
    flags, command = runner_invocation(args.runner_args)
    controlled = getattr(args, "controlled", False)
    inputs = getattr(args, "input_directory", None)
    output = getattr(args, "output_directory", None)
    authority = getattr(args, "authority_volume", None)
    if controlled and (not inputs or command or authority):
        raise ValueError("Controlled execution requires a public --input-directory, no authority volume, and an empty command after --")
    if authority:
        if (not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", authority)
                or command[:2] not in (["workspace", "authority-init"], ["workspace", "authorize"])):
            raise ValueError("Issuer volumes are available only to workspace authority-init and authorize")
        flags += ["--volume", f"{authority}:/issuer"]
    if output is not None:
        output = output.expanduser().resolve()
        if os.path.lexists(output) or not output.parent.is_dir():
            raise ValueError("Export destination must be new with an existing parent; execution was not started")
    with tempfile.TemporaryDirectory(prefix="vardrsec-input-") as private:
        if inputs is not None:
            inputs = inputs.expanduser().resolve(strict=True)
            if not inputs.is_dir():
                raise ValueError("Input directory does not exist")
            entries = list(inputs.iterdir())
            if controlled and {p.name for p in entries} != {
                "approval.json", "contract.json", "plan.json", "case.json", "execution.json", "trust.json"
            }:
                raise ValueError("Controlled input must contain exactly the six public authorization documents")
            staged = Path(private) / "inputs"
            staged.mkdir(mode=0o755)
            staged.chmod(0o755)
            for source in entries:
                info = source.lstat()
                if (not stat.S_ISREG(info.st_mode) or source.is_symlink() or info.st_nlink != 1
                        or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 16 * 1024 * 1024
                        or source.name in ("signing.key", "authority.json")):
                    raise ValueError("Select a flat directory of regular input documents; private issuer files are not execution inputs")
                destination = staged / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o644)
            # The 0700 host parent protects these copies from other host users.
            # Only its child is mounted, read-only; source permissions stay intact.
            flags += ["--volume", f"{staged}:{'/run/vardr-local' if controlled else '/inputs'}:ro"]
        name = "vardrsec-invocation-" + uuid.uuid4().hex if output else None
        export_volume = "vardrsec-export-" + uuid.uuid4().hex if output else None
        if export_volume:
            run("docker", "volume", "create", export_volume, capture_output=True)
            flags += ["--volume", f"{export_volume}:/exports"]
        retention = ["--name", name] if name else ["--rm"]
        result = compose(
            "run", *retention, "--no-deps", *flags, "runner", *(["--local"] if controlled else command),
            **({"controlled": True} if controlled else {}), check=False,
        )
        if result.returncode:
            if name:
                print(f"Invocation stopped with retained container {name} and export volume {export_volume}; inspect audit evidence before recovery. No automatic replay.", file=sys.stderr)
            raise subprocess.CalledProcessError(result.returncode, "Runner invocation")
        if output:
            output.mkdir(mode=0o700)
            try:
                # Default docker cp gives the invoking host user ownership; keep
                # the stopped container if transfer fails rather than rerun a job.
                run("docker", "cp", f"{name}:/exports/.", str(output))
            except BaseException:
                print(f"Execution completed; export transfer failed. Retained container: {name}; export volume: {export_volume}. Do not replay the job.", file=sys.stderr)
                raise
            run("docker", "rm", name)
            run("docker", "volume", "rm", export_volume)
            print(f"Export copied to {output}. Runner journal and original evidence remain in Runner state.")


def installation_volume_names(environment=None, *, mapless=False):
    """Resolve the existing Full layout with installation interpolation semantics.

    Compose remains the trusted configuration reader. Never surface its output:
    env_file and literal configuration may still contain secrets. This validates
    only the selected Compose model, not unrelated native/external state or races.
    """
    error = "Cannot resolve supported installation state mappings; installation refused"
    try:
        result = compose(
            "--profile", "*", "config", "--format", "json",
            capture_output=True, text=True, check=False, timeout=30, env=environment,
            **({"installation_mode": "mapless"} if mapless else {}),
        )
        if result.returncode != 0:
            raise ValueError(error)
        model = json.loads(result.stdout)
        project = model["name"]
        if not isinstance(project, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ValueError(error)
        if mapless and len(project) > 63:
            raise ValueError(error)
        volumes = model["volumes"]
        expected = {"runner-state"} if mapless else {"database", "runner-state", "proxy-data", "proxy-config"}
        if set(volumes) != expected:
            raise ValueError(error)
        for name, definition in volumes.items():
            # Custom names, external volumes and driver mappings are unsupported.
            if definition != {"name": f"{project}_{name}"}:
                raise ValueError(error)
        services = model["services"]
        mounts = {
            "db": [("volume", "database", "/var/lib/postgresql", False)],
            "runner": [
                ("volume", "runner-state", "/home/runner/.vardrmap", False),
                ("bind", str(ROOT / "trust"), "/trust", True),
            ],
            "proxy": [
                ("bind", str(ROOT / "Caddyfile"), "/etc/caddy/Caddyfile", True),
                ("volume", "proxy-data", "/data", False),
                ("volume", "proxy-config", "/config", False),
            ],
            "api": [], "web": [],
        }
        if mapless:
            mounts = {"runner": [("volume", "runner-state", "/home/runner/.vardrmap", False)]}
        if set(services) != set(mounts):
            raise ValueError(error)
        for service, expected_mounts in mounts.items():
            observed = []
            for mount in services[service].get("volumes", []):
                if set(mount) - {"type", "source", "target", "read_only", "bind", "volume"}:
                    raise ValueError(error)
                if mount.get("volume", {}) != {} or mount.get("bind", {}) not in ({}, {"create_host_path": True}):
                    raise ValueError(error)
                observed.append((mount["type"], mount["source"], mount["target"], mount.get("read_only", False)))
            if sorted(observed) != sorted(expected_mounts):
                raise ValueError(error)
        names = {definition["name"] for definition in volumes.values()}
        # A Mapless install must also refuse to adopt an existing Full project's
        # state; shared Runner state is not an implicit migration mechanism.
        if mapless:
            names.update(f"{project}_{name}" for name in ("database", "proxy-data", "proxy-config"))
        return names
    except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError):
        raise ValueError(error) from None


def has_installation_data(configuration=None, *, mapless=False):
    """Recognize selected Full state volumes; unresolved mappings/inventory refuse."""
    # Process values have the same precedence over the prospective .env as they
    # will after exclusive creation. Never modify the process environment itself.
    environment = None if configuration is None else {**configuration, **os.environ}
    names = installation_volume_names(environment, **({"mapless": True} if mapless else {}))
    try:
        result = subprocess.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Cannot inspect installation volumes; installation refused") from None
    if result.returncode != 0:
        raise ValueError("Cannot inspect installation volumes; installation refused")
    return bool(names & set(result.stdout.splitlines()))

INSTALL_NEXT = """
Installed. Remaining manual steps (they change your machine, so they are never automatic):
  1. Trust the public CA after checking the fingerprint above:
       sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
       sudo update-ca-certificates
     Firefox keeps its own store; see docs/installation.md. Restart the browser.
  2. Create the first account:  python3 vardrsec.py bootstrap --username operator
  3. Open https://localhost:8443 and follow the first-assessment walkthrough in docs/installation.md.
No scans were started."""


def installation_instructions():
    if os.name == "nt":
        return """
Installed. Remaining manual steps in PowerShell:
  1. Compare the public CA fingerprint above before explicitly trusting it:
       $cert = Import-Certificate -FilePath .\\trust\\root.crt -CertStoreLocation Cert:\\CurrentUser\\Root
       $cert.Thumbprint
     Record the thumbprint for removal. Firefox keeps its own store; see docs/installation.md.
  2. Create the first account:  python vardrsec.py bootstrap --username operator
  3. Open https://localhost:8443 and follow the first-assessment walkthrough in docs/installation.md.
No scans were started."""
    if sys.platform == "darwin":
        return "Installed. Follow docs/installation.md for explicit macOS CA enrollment, then run python3 vardrsec.py bootstrap --username operator. No scans were started."
    return INSTALL_NEXT


def dispatch(args, parser):
    mapless = read_mode(ROOT) == "mapless" or (args.action in ("install", "sources") and getattr(args, "mapless", False))
    if mapless and args.action in ("configure", "database-role", "bootstrap", "export-ca"):
        raise ValueError(f"{args.action} is a Full installation operation; Mapless state is retained. See docs/mapless.md")
    if args.action == "install":
        if mapless:
            return install_mapless(args, parser)
        # One command for a brand-new checkout. It only chains the existing steps, in
        # order, and refuses to run over an existing installation's credentials.
        # Safe to rerun after an interruption: an existing .env is kept (never
        # regenerated), source checkouts are resumed and never reset, and image builds
        # reuse their cache. Any state volume may hold data or a retained CA;
        # refuse installation rather than treat partial state as empty.
        prospective = None
        if not os.path.lexists(ROOT / ".env"):
            require_standard_fresh_layout()
            prospective = configuration_values()
        if has_installation_data(configuration=prospective):
            parser.error(
                "This installation has been started before and may hold data. Use start, "
                "stop or the controlled updater; install is only for a new or interrupted install."
            )
        if prospective is not None:
            # A newly appeared file was not the configuration used by preflight;
            # never reinterpret this attempt as a resume with different secrets.
            require_standard_fresh_layout()
        elif not os.path.lexists(ROOT / ".env"):
            raise ValueError("Configuration disappeared during preflight; installation refused; preserve existing state")
        steps = list(INSTALL_STEPS)
        if prospective is None:
            print("Resuming: the existing .env is kept and its secrets are not regenerated.")
            steps.remove("configure")
        for step in steps:
            print(f"== {step}", flush=True)
            try:
                if step == "build" and os.path.lexists(ROOT / ".active-images.json"):
                    select_full_installation()
                    print("Reusing the frozen Full image/network selection; build skipped.")
                    continue
                dispatch(argparse.Namespace(**{
                    **vars(args), "action": step,
                    "prepared_configuration": prospective if step == "configure" else None,
                }), parser)
                if step == "build":
                    select_full_installation()
            except Exception as error:
                python = "python" if os.name == "nt" else "python3"
                print(
                    f"\nInstall stopped at '{step}': {error}\n"
                    "Nothing was deleted and your credentials are untouched. Fix the cause "
                    f"(network, disk space, Docker) and run `{python} vardrsec.py install` again "
                    "to resume. If it stopped at database-role or later, the database volume "
                    f"exists: run the failed step yourself (`{python} vardrsec.py database-role`, "
                    "then `start` and `export-ca`).",
                    file=sys.stderr,
                )
                raise
        print(installation_instructions())
    elif args.action == "configure":
        configure(getattr(args, "prepared_configuration", None))
    elif args.action == "sources":
        sources(mapless=mapless)
    elif args.action == "build":
        if not mapless and os.path.lexists(ROOT / ".active-images.json"):
            raise ValueError("Full images are frozen; build in a separate workspace and use the controlled updater")
        if mapless and os.path.lexists(ROOT / ".active-images.mapless.json"):
            raise ValueError("Mapless images are frozen; build in a separate workspace and use the controlled updater")
        build_prerequisites()
        compose("--profile", "tools", "build")
    elif args.action == "database-role":
        import database_roles

        result = database_roles.apply(ROOT, backup=args.backup)
        if result["created_password"]:
            print("Added POSTGRES_APP_PASSWORD to .env (value not shown). Keep .env private.")
        print(
            "Application database role ready: the API will use non-superuser "
            f"{database_roles.APP}; {result['reassigned']} existing object(s) reassigned."
        )
    elif args.action == "start":
        if mapless:
            select_mapless_image(getattr(args, "runner_subnet", None))
            compose("--profile", "tools", "create", "--no-build", "runner")
            print("Mapless Runner prepared and stopped. Invoke runner explicitly; no background execution was started.")
            return
        compose(
            "up", "-d", "--wait", "--wait-timeout", "180", "db", "api", "web", "proxy"
        )
        print(
            "Services started. Export/enroll the CA before signing in. No scans were started."
        )
    elif args.action == "stop":
        compose("stop")
        print("Services stopped; volumes retained.")
    elif args.action == "export-ca":
        (ROOT / "trust").mkdir(exist_ok=True)
        compose(
            "cp", "proxy:/data/caddy/pki/authorities/local/root.crt", "trust/root.crt"
        )
        # Caddy's public certificate is root-only inside its storage. Runner's
        # different UID must be able to read this public Linux bind-mount export.
        (ROOT / "trust" / "root.crt").chmod(0o644)
        der = ssl.PEM_cert_to_DER_cert(
            (ROOT / "trust/root.crt").read_text(encoding="utf-8")
        )
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        print(
            "Public CA SHA256 fingerprint: "
            + ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
        )
        print(
            "Exported only the public root certificate. Follow docs/installation.md to enroll trust explicitly."
        )
    elif args.action == "bootstrap":
        generated = args.generate_password
        compose(
            "exec",
            *(["-T"] if generated else []),
            "api",
            "python",
            "-m",
            "local_accounts",
            "init",
            "--username",
            args.username,
            *(["--generate-password"] if generated else []),
        )
    elif args.action == "runner":
        # The installed image set (.active-images.json after an update or restore)
        # is selected by compose(), unlike a plain `docker compose run`.
        invoke_runner(args)
    elif args.action == "doctor":
        compose(
            "run",
            "--rm",
            "--no-deps",
            "runner",
            "doctor",
            *(["--standalone"] if mapless else ["--platform"]),
            "--offline",
            "--json",
        )
        print(
            "Runner diagnostics completed successfully. " + (
                "Use the standalone workspace workflow in docs/mapless.md." if mapless else
                "Sign in at the installation URL shown in docs/installation.md."
            ),
            file=sys.stderr,
        )
    elif args.action in ("backup", "restore"):
        import recovery

        if args.destination is None:
            parser.error("--destination is required")
        if args.action == "backup":
            if args.recipient:
                import backup_crypto

                backup_crypto.encrypted_backup(ROOT, args.destination, args.recipient)
            else:
                recovery.backup(ROOT, args.destination)
        else:
            if args.backup is None or not args.project:
                parser.error(
                    "restore requires --backup and a new --project vardrsec-restore-NAME"
                )
            recovery.restore(ROOT, args.backup, args.destination, args.project)
    elif args.action in ("update", "cancel-update"):
        import updater

        if args.action == "cancel-update":
            updater.cancel(ROOT)
        else:
            if not all((args.candidate, args.backup, args.destination, args.project)):
                parser.error(
                    "update requires --candidate, --backup, --destination and --project"
                )
            updater.update(
                ROOT, args.candidate, args.backup, args.destination, args.project
            )
    elif args.action in ("seal-backup", "unseal-backup"):
        import backup_crypto

        if args.backup is None or args.destination is None:
            parser.error("--backup and --destination are required")
        if args.action == "seal-backup":
            if args.recipient is None:
                parser.error("seal-backup requires --recipient")
            backup_crypto.seal(args.backup, args.destination, args.recipient)
        else:
            if args.identity is None:
                parser.error("unseal-backup requires --identity")
            backup_crypto.unseal(args.backup, args.destination, args.identity)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileExistsError) as exc:
        raise SystemExit(str(exc)) from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from None

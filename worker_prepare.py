"""Explicit Full managed metadata preparation; never starts a worker or job.

Keys remain in operator-selected external custody. Applying API configuration,
binding an existing API key, signing jobs and launching workers are separate acts.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import shutil
import uuid

from installation_mode import compose_files, read_mode
import recovery
import updater
import worker_compose_inventory as inventory
import worker_host as host
import worker_lifecycle_intent as intent


class PrepareRefused(ValueError):
    pass


def require(value):
    if not value:
        raise PrepareRefused("worker_prepare_refused")


def _run(argv, *, cwd, env, data=b"", timeout=30):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, input=data,
                                capture_output=True, timeout=timeout, check=False)
    except subprocess.SubprocessError:
        raise PrepareRefused("worker_prepare_refused") from None
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024)
    return result.stdout


def _platform(client):
    return {**{k: v for k, v in os.environ.items()
               if k.upper() in inventory._PLATFORM_ENV},
            "DOCKER_CONFIG": str(client.config)}


def _docker(client, root, *args, data=b"", timeout=30):
    executable = inventory._hash_executable(client.docker, client.docker_sha256)
    prefix = [str(executable), "--config", str(client.config), "--context", client.context]
    endpoint = json.loads(_run(prefix + ["context", "inspect", client.context,
                                        "--format", "{{json .Endpoints.docker.Host}}"],
                               cwd=root, env=_platform(client)))
    require(endpoint == client.endpoint
            and endpoint.startswith(("unix:///", "npipe:////./pipe/")))
    return _run(prefix + list(args), cwd=root, env=_platform(client), data=data, timeout=timeout)


def _compose(client, root, *args, timeout=30):
    executable = inventory._hash_executable(client.compose, client.compose_sha256)
    prefix = [str(executable), "--context", client.context]
    version = _run(prefix + ["version", "--short"], cwd=root,
                   env=_platform(client)).decode("ascii").strip().removeprefix("v")
    require(version == inventory._VERSION)
    flags = [v for path in compose_files(root) for v in ("-f", str(path))]
    return _run(prefix + flags + list(args), cwd=root, env=_platform(client), timeout=timeout)


def _write(path, raw):
    recovery.private_write(path, raw)


def _existing_private(root):
    require(root.is_dir() and root.resolve(strict=True) == root)
    for path in (root, *root.parents):
        info = path.lstat()
        require(not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400)
    if os.name != "nt":
        require(root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700)
    # Existing private-root custody is supplied by the caller. Signing keys are
    # never written to this host directory, on Windows or POSIX.


_KEY_HELPER = r"""
import base64,json,os,pathlib,stat,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path('/issuer');info=root.lstat()
assert info.st_uid==10001 and stat.S_IMODE(info.st_mode)==0o700 and not list(root.iterdir())
context=json.load(sys.stdin)
key=Ed25519PrivateKey.generate()
public=base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).rstrip(b'=').decode()
def write(name,data):
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
write('signing.key',key.private_bytes_raw())
write('authority.json',json.dumps({**context,'public_key':public},sort_keys=True).encode())
if context['role']=='contract':
    write('operator-trust.json',json.dumps(context['operator_trust'],sort_keys=True).encode())
print(json.dumps({'public_key':public,'issuer_id':context['issuer_id'],'role':context['role']}))
"""


def _provision_key(client, root, *, image, volume, project, context):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume))
    names = _docker(client, root, "volume", "ls", "--format", "{{.Name}}").decode().splitlines()
    require(volume not in names)
    labels = {"io.vardrsec.managed-authority": context["role"],
              "io.vardrsec.managed-authority-project": project,
              "io.vardrsec.managed-authority-owner": context["owner_id"]}
    flags = [v for k, value in labels.items() for v in ("--label", k + "=" + value)]
    _docker(client, root, "volume", "create", "--driver", "local", *flags, volume)
    observed = json.loads(_docker(client, root, "volume", "inspect", volume))[0]
    require(observed["Name"] == volume and observed["Driver"] == "local"
            and observed.get("Options") in (None, {}) and observed.get("Labels") == labels)
    # Existing image-owned /issuer0700 initial copy, as used by authority-init.
    # Only one authority volume is mounted; no API, target, state or socket access.
    output = _docker(client, root, "run", "--rm", "--pull", "never", "-i",
                     "--network", "none", "--read-only", "--user", "10001:10001",
                     "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                     "--pids-limit", "32", "--memory", "256m", "--cpus", "1",
                     "--mount", f"type=volume,source={volume},target=/issuer",
                     "--entrypoint", "python", image, "-I", "-c", _KEY_HELPER,
                     data=host.canonical(context))
    receipt = json.loads(output)
    require(set(receipt) == {"public_key", "issuer_id", "role"}
            and receipt["issuer_id"] == context["issuer_id"] and receipt["role"] == context["role"]
            and re.fullmatch(r"[A-Za-z0-9_-]{43}", receipt["public_key"])
            and len(base64.urlsafe_b64decode(receipt["public_key"] + "=")) == 32)
    return receipt["public_key"]


def prepare(installation, *, client, private_root, admission_root, worker_image,
            owner_id, issuer_id, credential_file=None, credential_names=(),
            operator_volume=None, contract_volume=None, api_pin=None):
    """Materialize one new explicit preparation, not API/worker enablement.

    Caller owns the installation lock and supplies the existing protected host
    root. owner_id comes from an authenticated Map owner session. Private signing
    keys are generated only inside two fresh external authority volumes. A failed
    preparation retains partial state for inspection and is never automatically
    adopted, retried or cleaned up. API config and worker launch remain separate.
    """
    root = Path(installation).resolve(strict=True)
    private, public = Path(private_root).absolute(), Path(admission_root).absolute()
    require(type(client) is inventory.LocalClient and read_mode(root) == "full")
    require((root / ".active-images.json").is_file() and not (root / updater.STATE).exists())
    require(not any(a == b or a.is_relative_to(b) for a, b in
                    ((private, root), (root, private), (public, private), (private, public))))
    require(public.parent.resolve(strict=True) == public.parent and not public.exists())
    trust = root / "trust"
    require(not public.is_relative_to(trust) and not trust.is_relative_to(public))
    for value in (owner_id, issuer_id):
        require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value))
    _existing_private(private)
    require(not (private / "preparation.json").exists() and not (private / "prepare-intent.json").exists())
    credentials = Path(credential_file).absolute() if credential_file else private / "worker.env"
    require(credentials.parent == private)
    if credential_file:
        info = credentials.lstat()
        require(credentials.is_file() and not credentials.is_symlink() and info.st_nlink == 1
                and not getattr(info, "st_file_attributes", 0) & 0x400)
        if os.name != "nt":
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
    else:
        require(not credentials.exists() and not credentials.is_symlink() and not credential_names)
    credential_names = list(credential_names)
    require(len(credential_names) <= 32 and len(set(credential_names)) == len(credential_names))
    for name in credential_names:
        require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
                and not name.startswith(("VARDR", "DOCKER", "COMPOSE")))
    intent.image(worker_image)
    model = json.loads(_compose(client, root, "--profile", "tools", "config", "--format", "json"))
    require(set(model["services"]) == recovery.SERVICES)
    images = {s: model["services"][s]["image"] for s in recovery.SERVICES}
    frozen = json.loads((root / ".active-images.json").read_bytes())
    require(all(images[s] == frozen["services"][s]["image"] for s in images))
    for image in images.values():
        intent.image(image)
    network = model["networks"]["runner"]["name"]
    state = model["volumes"]["runner-state"]["name"]
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", network)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", state))
    core = {}
    for service in ("api", "db", "proxy", "web"):
        ids = _compose(client, root, "ps", "-a", "-q", service).decode().split()
        selected = [json.loads(_docker(client, root, "inspect", identifier))[0] for identifier in ids]
        selected = [row for row in selected if row["Config"]["Labels"].get("com.docker.compose.oneoff") == "False"]
        require(len(selected) == 1 and selected[0]["Image"] == images[service])
        core[service] = images[service]
    _docker(client, root, "image", "inspect", worker_image)
    for file in (root / "trust" / "root.crt", root / "compose.worker.json"):
        require(file.is_file() and file.resolve(strict=True) == file)
    raw_model = (root / "compose.worker.json").read_bytes().replace(b"\r\n", b"\n")
    require(hashlib.sha256(raw_model).hexdigest() == inventory._MODEL_SHA256)
    daemon = json.loads(_docker(client, root, "info", "--format", "{{json .ID}}"))
    port = int(model["services"]["proxy"]["environment"]["HTTPS_PORT"])
    require(1 <= port <= 65535)
    require(type(api_pin) is dict and set(api_pin) == {"base_url", "ca_file", "ca_sha256"})
    require(api_pin["base_url"] == f"https://localhost:{port}/backend"
            and Path(api_pin["ca_file"]).resolve(strict=True) == (root / "trust" / "root.crt").resolve(strict=True)
            and host.HostClient(api_pin["base_url"], api_pin["ca_file"]).pin() == api_pin)
    pins = json.loads((root / "versions.json").read_bytes())["components"]
    git = lambda *a: _run(["git", *a], cwd=root, env=_platform(client)).decode().strip()
    require(not git("status", "--porcelain", "--untracked-files=no"))
    source = {"distribution_commit": git("rev-parse", "HEAD"),
              "distribution_tree": git("rev-parse", "HEAD^{tree}"),
              **{name + "_commit": pins[name]["commit"] for name in ("runner", "map", "gate")},
              "runner_image": worker_image, "compose_version": inventory._VERSION,
              "compose_executable_sha256": client.compose_sha256,
              "unresolved_model_sha256": inventory._MODEL_SHA256}
    operator_id, contract_id = "operator", "contract"
    suffix = uuid.uuid4().hex
    operator_volume = operator_volume or model["name"] + "-operator-" + suffix
    contract_volume = contract_volume or model["name"] + "-contract-" + suffix
    require(operator_volume != contract_volume and operator_volume != state and contract_volume != state)
    existing_volumes = _docker(client, root, "volume", "ls", "--format", "{{.Name}}").decode().splitlines()
    require(all(type(v) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", v)
                and v not in existing_volumes for v in (operator_volume, contract_volume)))
    for name in ("prepare-intent.json", "runner-trust.json", "launch-override.json", "launch-empty.env",
                 "launch-config.json", "api-managed.json", "preparation.json"):
        require(not (private / name).exists() and not (private / name).is_symlink())
    # Persist public intent first; a later invocation refuses this partial state.
    _write(private / "prepare-intent.json", host.canonical({"project": model["name"],
           "owner_id": owner_id, "issuer_id": issuer_id, "operator_volume": operator_volume,
           "contract_volume": contract_volume, "provision_image": images["runner"]}))
    operator_public_key = _provision_key(client, root, image=images["runner"], volume=operator_volume,
        project=model["name"], context={"role": "operator", "issuer_id": issuer_id, "owner_id": owner_id})
    operator_trust = [{"issuer_id": issuer_id, "key_id": operator_id, "approver_id": owner_id,
                       "public_key": operator_public_key, "revoked": False}]
    contract_public_key = _provision_key(client, root, image=images["runner"], volume=contract_volume,
        project=model["name"], context={"role": "contract", "issuer_id": issuer_id,
                                      "owner_id": owner_id, "operator_trust": operator_trust})
    require(operator_public_key != contract_public_key)
    public.mkdir(mode=0o755)
    public_keys = {"operator": operator_public_key, "contract": contract_public_key}
    anchors = [{"issuer_id": issuer_id, "key_id": role, "public_key": public_keys[role],
                "purposes": ["approval" if role == "operator" else "contract"],
                "origins": ["map"], "revoked": False} for role in ("operator", "contract")]
    operator_trust = [{"issuer_id": issuer_id, "key_id": operator_id, "approver_id": owner_id,
                       "public_key": operator_public_key, "revoked": False}]
    _write(private / "runner-trust.json", host.canonical(anchors))
    override = {"networks": {"runner": {"external": True, "name": network}},
                "volumes": {"runner-state": {"external": True, "name": state}}}
    _write(private / "launch-override.json", host.canonical(override))
    _write(private / "launch-empty.env", b"")
    if not credential_file:
        _write(credentials, b"")
    source.update(closed_override_sha256=host.digest(override),
                  environment_contract_sha256=host.digest({"credential_names": sorted(credential_names), "https_port": port}),
                  core_image_set_sha256=host.digest(core))
    config = {"docker": str(client.docker), "docker_sha256": client.docker_sha256,
              "compose": str(client.compose), "compose_sha256": client.compose_sha256,
              "docker_config": str(client.config), "local_endpoint": client.endpoint,
              "daemon_id": daemon, "override": str(private / "launch-override.json"),
              "empty_env": str(private / "launch-empty.env"), "source": source,
              "core_images": core, "credential_file": str(credentials),
              "credential_names": sorted(credential_names), "https_port": port}
    _write(private / "launch-config.json", host.canonical(config))
    api_env = {"VARDRMAP_MANAGED_WORKER": "1", "VARDRMAP_MANAGED_ORIGIN": f"https://vardrsec.localhost:{port}/backend",
               "VARDRMAP_MANAGED_OPERATOR_TRUST_FILE": "/run/vardr-managed/operator-trust.json",
               "VARDRMAP_MANAGED_CONTRACT_KEY_FILE": "/run/vardr-managed/signing.key",
               "VARDRMAP_MANAGED_ISSUER_ID": issuer_id, "VARDRMAP_MANAGED_CONTRACT_KEY_ID": contract_id}
    api = {"services": {"api": {"environment": api_env, "volumes": [
        {"type": "volume", "source": "managed-contract-authority", "target": "/run/vardr-managed",
         "read_only": True, "volume": {"nocopy": True}}]}},
           "volumes": {"managed-contract-authority": {"external": True, "name": contract_volume}}}
    _write(private / "api-managed.json", host.canonical(api))
    receipt = {"installation": str(root), "context": client.context, "api": api_pin,
               "worker_image": worker_image, "operator_key_id": operator_id, "project": model["name"], "private_root": str(private), "admission_root": str(public),
               "runner_network": network, "state_volume": state, "owner_id": owner_id,
               "issuer_id": issuer_id, "operator_volume": operator_volume, "contract_volume": contract_volume,
               "operator_key_path": "/issuer/signing.key", "provision_image": images["runner"], "origin": api_env["VARDRMAP_MANAGED_ORIGIN"],
               "launch_config": str(private / "launch-config.json"), "public_trust": str(private / "runner-trust.json"),
               "api_override": str(private / "api-managed.json"), "source": source,
               "api_configuration_applied": False, "worker_started": False, "job_authorized": False}
    _write(private / "preparation.json", host.canonical(receipt))
    return receipt


def bind_enrollment(installation, *, client, owner_id, api_key_id, runner_id, origin, api_key):
    """Separate explicit one-shot delegation; unknown replies are never retried."""
    root = Path(installation).resolve(strict=True)
    require(type(api_key) is str and re.fullmatch(r"vmap_[A-Za-z0-9_-]{1,256}", api_key))
    require(str(uuid.UUID(runner_id)) == runner_id and read_mode(root) == "full")
    _docker(client, root, "info", "--format", "{{json .ID}}")
    _compose(client, root, "version", "--short")
    # stdin, not argv/environment/logs; the existing component owns DB validation.
    executable = inventory._hash_executable(client.compose, client.compose_sha256)
    flags = [v for path in compose_files(root) for v in ("-f", str(path))]
    command = [str(executable), "--context", client.context, *flags, "exec", "-T", "api",
               "python", "-m", "managed_enrollment", "bind", "--owner", owner_id,
               "--api-key-id", api_key_id, "--runner-id", runner_id, "--origin", origin, "--key-stdin"]
    return json.loads(_run(command, cwd=root, env=_platform(client), data=(api_key + "\n").encode()))



def discover_client(installation, context=None):
    """Select the existing local Docker/Compose clients; never install software."""
    root = Path(installation).resolve(strict=True)
    docker = Path(shutil.which("docker") or "").resolve(strict=True)
    require(docker.is_file())
    env = {k: v for k, v in os.environ.items() if k.upper() in inventory._PLATFORM_ENV}
    config = Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))).resolve(strict=True)
    require(config.is_dir())
    env["DOCKER_CONFIG"] = str(config)
    selected_context = context or _run([str(docker), "--config", str(config), "context", "show"], cwd=root, env=env).decode().strip()
    require(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", selected_context))
    prefix = [str(docker), "--config", str(config), "--context", selected_context]
    endpoint = json.loads(_run(prefix + ["context", "inspect", selected_context, "--format", "{{json .Endpoints.docker.Host}}"], cwd=root, env=env))
    require(endpoint.startswith(("unix:///", "npipe:////./pipe/")))
    plugins = json.loads(_run(prefix + ["info", "--format", "{{json .ClientInfo.Plugins}}"], cwd=root, env=env))
    matches = [row for row in plugins if row.get("Name") == "compose"]
    require(len(matches) == 1)
    compose = Path(matches[0]["Path"]).resolve(strict=True)
    result = inventory.LocalClient(docker, recovery.digest(docker), compose, recovery.digest(compose), config, selected_context, endpoint)
    _compose(result, root, "version", "--short")
    return result


_STATE = r"""
import json,pathlib,sys
from vardrrunner import config,identity
p=json.load(sys.stdin);current=config.load()
if p['action']=='status':
    f=identity.identity_file()
    ident=identity.read_existing(f).runner_id if f.exists() else None
    print(json.dumps({'has_connection':bool(current.get('api_key') or current.get('api_url')),'runner_id':ident}))
elif p['action']=='save':
    assert not current.get('api_key') and not current.get('api_url')
    ident=identity.load_or_create().runner_id
    config.validate_api_url(p['origin'])
    config.save({**current,'api_url':p['origin'],'api_key':p['key']})
    print(json.dumps({'runner_id':ident}))
else:
    assert current.get('api_url')==p['origin'] and current.get('api_key')
    ident=identity.read_existing(identity.identity_file()).runner_id
    print(json.dumps({'runner_id':ident,'api_key':current['api_key']}))
"""


def _state(installation, preparation, client, action, **payload):
    root = Path(installation).resolve(strict=True)
    require(Path(preparation['installation']).resolve(strict=True) == root
            and not (root / updater.STATE).exists())
    volume = preparation['state_volume']
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume))
    raw = _docker(client, root, "run", "--rm", "--pull", "never", "-i", "--network", "none",
                  "--read-only", "--user", "10001:10001", "--cap-drop=ALL",
                  "--security-opt=no-new-privileges:true", "--pids-limit", "32", "--memory", "256m", "--cpus", "1",
                  "--mount", f"type=volume,source={volume},target=/home/runner/.vardrmap,volume-nocopy",
                  "--entrypoint", "python", preparation['provision_image'], "-I", "-c", _STATE,
                  data=host.canonical({'action':action, **payload}))
    return host._json(raw)


def read_runner_key(installation, preparation, *, client):
    """Secret return for the existing launch boundary only; never a public result."""
    value = _state(installation, preparation, client, 'read', origin=preparation['origin'])
    binding = host._json((Path(preparation['private_root']) / 'enrollment.json').read_bytes())
    require(binding['setup_sha256'] == host.digest(preparation)
            and binding['runner_id'] == value['runner_id'])
    key = value['api_key']
    require(type(key) is str and re.fullmatch(r"vmap_[A-Za-z0-9_-]{43}", key))
    return key


def apply_api(installation, preparation, *, client):
    """Explicit API environment/mount apply; no image or storage migration."""
    root = Path(installation).resolve(strict=True)
    require(Path(preparation['installation']).resolve(strict=True) == root
            and not (root / updater.STATE).exists())
    private = Path(preparation['private_root'])
    configured = private / 'api-configured.json'
    if configured.exists():
        require(host._json(configured.read_bytes()) == {'setup_sha256':host.digest(preparation)})
        # Do not claim healthy enabled state merely from a prior local receipt.
        info_ids = _compose(client, root, 'ps', '-q', 'api').decode().split()
        require(len(info_ids) == 1)
        info = json.loads(_docker(client, root, 'inspect', info_ids[0]))[0]
        require(info['State'].get('Health',{}).get('Status') == 'healthy')
        runtime = dict(v.split('=',1) for v in info['Config']['Env'] if '=' in v)
        require(info['Image'] == host._json(Path(preparation['launch_config']).read_bytes())['core_images']['api'])
        if runtime.get('VARDRMAP_MANAGED_WORKER') == '1':
            require(runtime.get('VARDRMAP_MANAGED_ISSUER_ID') == preparation['issuer_id'])
            require(any(m.get('Type')=='volume' and m.get('Name')==preparation['contract_volume']
                        and m.get('Destination')=='/run/vardr-managed' and m.get('RW') is False for m in info['Mounts']))
            return
        require(runtime.get('VARDRMAP_MANAGED_WORKER') in (None,'0'))
        # Explicit configure may reapply the same reviewed custody after an
        # ordinary API recreation; it never creates replacement authority.

    # Environment/mount-only configuration; no image, schema or volume migration.
    # Existing updater pending-state and recovery active-worker gates are retained.
    for service in ('runner','managed-worker'):
        running = _docker(client, root, 'ps', '-q', '--filter', 'label=com.docker.compose.project='+preparation['project'],
                          '--filter', 'label=com.docker.compose.service='+service).decode().strip()
        require(not running)
    _compose(client, root, '-f', preparation['api_override'], 'up', '-d', '--no-build', '--wait',
             '--wait-timeout', '120', 'api', 'web', 'proxy', timeout=135)
    # Map startup's existing configure_managed validates the strict key/trust graph;
    # healthy /ready follows successful startup. No tool/job is started here.
    if not configured.exists():
        _write(configured, host.canonical({'setup_sha256':host.digest(preparation)}))
    apply_api(root, preparation, client=client)


def configure(installation, preparation, *, client, session, allow_plaintext_key=False):
    """Configure the existing connected Runner store, enrollment and API only."""
    root = Path(installation).resolve(strict=True)
    require(allow_plaintext_key is True and not (root / updater.STATE).exists()
            and Path(preparation['installation']).resolve(strict=True) == root
            and session.owner_id() == preparation['owner_id'])
    private = Path(preparation['private_root'])
    binding_path, pending = private / 'enrollment.json', private / 'configure-intent.json'
    if binding_path.exists():
        binding = host._json(binding_path.read_bytes())
        require(binding['setup_sha256']==host.digest(preparation) and binding['owner_id']==preparation['owner_id']
                and binding['origin']==preparation['origin'])
        key = read_runner_key(root, preparation, client=client)
        observed = bind_enrollment(root, client=client, owner_id=binding['owner_id'], api_key_id=binding['api_key_id'],
                                   runner_id=binding['runner_id'], origin=binding['origin'], api_key=key)
        require(observed['enrollment_id']==binding['enrollment_id'] and observed['revoked'] is False)
        apply_api(root, preparation, client=client)
        return binding
    require(not pending.exists())
    state = _state(root, preparation, client, 'status')
    require(not state['has_connection'])
    _write(pending, host.canonical({'setup_sha256':host.digest(preparation), 'phase':'explicit_configure_started'}))
    apply_api(root, preparation, client=client)
    issued = session.create_runner_key('Managed Runner '+preparation['project'])
    key = issued['token']
    stored = _state(root, preparation, client, 'save', origin=preparation['origin'], key=key)
    enrolled = bind_enrollment(root, client=client, owner_id=preparation['owner_id'], api_key_id=issued['id'],
                               runner_id=stored['runner_id'], origin=preparation['origin'], api_key=key)
    require(enrolled['owner']==preparation['owner_id'] and enrolled['runner_id']==stored['runner_id']
            and enrolled['api_key_id']==issued['id'] and enrolled['origin']==preparation['origin'] and enrolled['revoked'] is False)
    binding = {'setup_sha256':host.digest(preparation),'owner_id':preparation['owner_id'],
               'runner_id':stored['runner_id'],'enrollment_id':enrolled['enrollment_id'],
               'api_key_id':issued['id'],'origin':preparation['origin']}
    _write(binding_path, host.canonical(binding))
    return binding

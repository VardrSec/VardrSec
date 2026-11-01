"""Read-only privilege posture of the installed containers (register decision R1).

Run only against the named disposable Compose project after the installed workflow
(`db`, `api`, `web`, `proxy` running). It starts no scan or job, contacts no target and
changes no image, Compose or platform setting. For each service it records Docker's
`HostConfig` privilege fields and the process capability sets from `/proc/1/status`; the
Runner, which is not a running service, is read from a one-off container. Only privilege
fields are read; no environment value is printed or stored.
"""

import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
RECEIPT = ROOT / "artifacts" / "container-capabilities" / "receipt.json"

CAPABILITIES = {
    "DAC_READ_SEARCH": 2,
    "LINUX_IMMUTABLE": 9,
    "NET_BIND_SERVICE": 10,
    "NET_ADMIN": 12,
    "SYS_MODULE": 16,
    "SYS_RAWIO": 17,
    "SYS_PTRACE": 19,
    "SYS_ADMIN": 21,
    "SYS_BOOT": 22,
    "SYS_TIME": 25,
    "MAC_OVERRIDE": 32,
    "MAC_ADMIN": 33,
    "SYSLOG": 34,
    "PERFMON": 38,
    "BPF": 39,
}
# Capabilities no service may hold, in any set: they enable mounting, tracing, module or
# kernel-level control. Docker's default set contains none of them.
FORBIDDEN = tuple(name for name in CAPABILITIES if name != "NET_BIND_SERVICE")
RUNNING = ("api", "web", "proxy", "db")
BIND = 1 << CAPABILITIES["NET_BIND_SERVICE"]
# service -> (expected CapDrop, expected CapAdd, no-new-privileges required, largest allowed
# effective set). The proxy may hold exactly the low-port bind capability; the database keeps
# Docker's default bounding set but runs PostgreSQL unprivileged.
EXPECTED = {
    "api": (["ALL"], [], True, 0),
    "web": (["ALL"], [], True, 0),
    "proxy": (["ALL"], ["NET_BIND_SERVICE"], True, BIND),
    "db": ([], [], False, None),
}


def parse_status(text):
    """Capability masks and flags from the text of /proc/<pid>/status."""
    fields = dict(
        line.split(":", 1) for line in text.splitlines() if ":" in line
    )
    return {
        "uid": int(fields["Uid"].split()[0]),
        "cap_effective": int(fields["CapEff"].strip(), 16),
        "cap_bounding": int(fields["CapBnd"].strip(), 16),
        "no_new_privileges": fields["NoNewPrivs"].strip() == "1",
    }


def held(mask):
    return sorted(name for name, bit in CAPABILITIES.items() if mask >> bit & 1)


def docker(*args, stdin=None):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=120, cwd=ROOT
    )
    if result.returncode:
        sys.exit(f"docker {args[0]} failed: {result.stderr.strip()[-300:]}")
    return result.stdout


def compose(*args):
    return docker("compose", "-p", PROJECT, *args)


def names(values):
    """Capability names without Docker's optional CAP_ prefix."""
    return sorted(v.removeprefix("CAP_") for v in values or [])


def host_config(service):
    container = compose("ps", "-q", service).split()[0]
    info = json.loads(docker("inspect", container))[0]
    config = info["HostConfig"]
    return {
        "privileged": config["Privileged"],
        "cap_add": names(config.get("CapAdd")),
        "cap_drop": names(config.get("CapDrop")),
        "no_new_privileges_configured": any(
            option.startswith("no-new-privileges") and not option.endswith("false")
            for option in config.get("SecurityOpt") or []
        ),
        "pid_mode": config.get("PidMode", ""),
        "docker_socket_mounted": any(
            "docker.sock" in (m.get("Source", "") + m.get("Destination", ""))
            for m in info.get("Mounts", [])
        ),
        "published_ports": sorted(
            (binding["HostIp"] or "0.0.0.0") + ":" + binding["HostPort"]
            for bindings in (config.get("PortBindings") or {}).values()
            for binding in bindings or []
        ),
    }


def observe():
    seen = {}
    for service in RUNNING:
        status = parse_status(compose("exec", "-T", service, "cat", "/proc/1/status"))
        seen[service] = {**host_config(service), **status}
    runner = parse_status(
        compose(
            "--profile", "tools", "run", "--rm", "--no-deps", "-T",
            "--entrypoint", "cat", "runner", "/proc/self/status",
        )
    )
    seen["runner"] = runner
    return seen


def check(seen):
    failures = []
    for service, (drop, add, no_new, effective) in EXPECTED.items():
        item = seen[service]
        if item["privileged"]:
            failures.append(f"{service}: privileged")
        if item["docker_socket_mounted"]:
            failures.append(f"{service}: Docker socket mounted")
        if item["pid_mode"]:
            failures.append(f"{service}: shares a PID namespace ({item['pid_mode']})")
        if item["cap_add"] != add:
            failures.append(f"{service}: CapAdd {item['cap_add']} != {add}")
        if item["cap_drop"] != drop:
            failures.append(f"{service}: CapDrop {item['cap_drop']} != {drop}")
        if no_new and not (item["no_new_privileges_configured"] and item["no_new_privileges"]):
            failures.append(f"{service}: no-new-privileges is not configured and in effect")
        if effective is not None and item["cap_effective"] & ~effective:
            failures.append(f"{service}: CapEff {item['cap_effective']:#x} exceeds {effective:#x}")
        for label in ("cap_effective", "cap_bounding"):
            bad = [c for c in held(item[label]) if c in FORBIDDEN]
            if bad:
                failures.append(f"{service}: {label} holds {bad}")
    proxy_ports = seen["proxy"]["published_ports"]
    if len(proxy_ports) != 1 or not proxy_ports[0].startswith("127.0.0.1:"):
        failures.append(f"proxy: published ports {proxy_ports}")
    for service in ("api", "web", "db"):
        if seen[service]["published_ports"]:
            failures.append(f"{service}: publishes {seen[service]['published_ports']}")
    runner = seen["runner"]
    if runner["cap_effective"] or runner["cap_bounding"] or not runner["no_new_privileges"]:
        failures.append("runner: capabilities or no-new-privileges differ from the baseline")
    return failures


def main():
    running = set(compose("ps", "--services", "--status", "running").split())
    assert set(RUNNING) <= running, f"installed stack is not running: {sorted(running)}"
    seen = observe()
    summary = {
        service: {
            **{k: v for k, v in item.items() if k not in ("cap_effective", "cap_bounding")},
            "cap_effective": hex(item["cap_effective"]),
            "cap_bounding": hex(item["cap_bounding"]),
            "effective_named": held(item["cap_effective"]),
            "bounding_named": held(item["cap_bounding"]),
        }
        for service, item in seen.items()
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    failures = check(seen)
    if failures:
        sys.exit("FAIL:\n" + "\n".join(failures))
    print("PASS: no privileged container, socket mount or forbidden capability; expected sets held")


if __name__ == "__main__":
    main()

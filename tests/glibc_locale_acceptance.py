"""Read-only locale, environment, gettext and database-role probes for CVE-2026-84243.

Run only against the named disposable Compose project after the installed workflow
(`db`, `api`, `web`, `proxy` running). It starts no scan, job or Runner worker, contacts
no target and changes no image, Compose or platform setting. The Runner service is
only used for a one-off container that runs `env`, `locale`, `getconf` and the probe.
Environments are read inside the containers and filtered to locale variable names in
this process: no other name or value is printed or stored. The gettext probe uses a
harmless two-string catalog created in a throwaway directory that is removed afterwards.
"""

import base64
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
RECEIPT = ROOT / "artifacts" / "glibc-locale" / "receipt.json"

SERVICES = ("api", "web", "runner", "db")
RUNNING = frozenset({"api", "web", "db"})
# The database image deliberately ships a non-C locale; the others must not.
C_ONLY = ("api", "web", "runner")
C_LOCALES = frozenset({"c", "c.utf8", "c.utf-8", "posix"})
LOCALE_VARIABLE = re.compile(r"^(LANG|LANGUAGE|LC_[A-Z_]+|LOCPATH)$")
LANG_ALLOWED = {
    "api": {None, "C.UTF-8"},
    "web": {None, "C.UTF-8"},
    "runner": {None, "C.UTF-8"},
    "db": {None, "C.UTF-8", "en_US.utf8"},
}

DOMAIN = "vardrsec_probe"
SOURCE = "vardrsec-probe-source"
ORDINARY = "vardrsec-probe-ordinary"
TRAVERSAL = "vardrsec-probe-traversal"
# `$"..."` makes bash call libc gettext with the process environment. bash returns the
# string untouched when the locale variable is unset, `C` or `POSIX`, so the glibc
# result is only meaningful under an explicit non-empty locale such as C.UTF-8.
GETTEXT_SCRIPT = f"""set -eu
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
mkdir -p "$d/locale/xx/LC_MESSAGES" "$d/xx/LC_MESSAGES"
read -r ordinary
read -r traversal
printf %s "$ordinary" | base64 -d > "$d/locale/xx/LC_MESSAGES/{DOMAIN}.mo"
printf %s "$traversal" | base64 -d > "$d/xx/LC_MESSAGES/{DOMAIN}.mo"
if [ "$1" != - ]; then export LC_ALL="$1"; fi
probe() {{ env LANGUAGE="$1" TEXTDOMAIN={DOMAIN} TEXTDOMAINDIR="$d/locale" bash -c 'echo $"{SOURCE}"'; }}
printf 'ordinary=%s\\n' "$(probe xx)"
printf 'traversal=%s\\n' "$(probe ../xx)"
"""
ROLE_QUERY = (
    "select rolsuper, rolcreaterole, rolcreatedb, rolbypassrls "
    "from pg_roles where rolname = current_user"
)


def build_catalog(translations):
    """A minimal little-endian GNU .mo catalog with a UTF-8 header entry."""
    entries = {"": "Content-Type: text/plain; charset=UTF-8\n", **translations}
    keys = sorted(entries)
    ids, strings, offsets = b"", b"", []
    for key in keys:
        raw_key, raw_value = key.encode(), entries[key].encode()
        offsets.append((len(ids), len(raw_key), len(strings), len(raw_value)))
        ids += raw_key + b"\0"
        strings += raw_value + b"\0"
    key_table = 7 * 4 + 16 * len(keys)
    value_table = key_table + len(ids)
    table = []
    for id_off, id_len, str_off, str_len in offsets:
        table += [id_len, key_table + id_off]
    for id_off, id_len, str_off, str_len in offsets:
        table += [str_len, value_table + str_off]
    header = struct.pack("<7I", 0x950412DE, 0, len(keys), 28, 28 + 8 * len(keys), 0, 0)
    return header + struct.pack(f"<{len(table)}I", *table) + ids + strings


def locale_variables(raw_environment):
    """Only locale-related variables from a NUL-separated environment block."""
    found = {}
    for entry in raw_environment.decode("utf-8", "replace").split("\0"):
        name, separator, value = entry.partition("=")
        if separator and LOCALE_VARIABLE.match(name):
            found[name] = value
    return found


def unexpected_locales(listing):
    """Locale names from `locale -a` that are not C or POSIX."""
    names = {line.strip() for line in listing.splitlines() if line.strip()}
    return sorted(name for name in names if name.lower() not in C_LOCALES)


def parse_gettext(output):
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def parse_role(row):
    flags = row.strip().split("|")
    names = ("superuser", "createrole", "createdb", "bypassrls")
    if len(flags) != len(names) or any(flag not in ("t", "f") for flag in flags):
        raise ValueError("unexpected role row")
    return {name: flag == "t" for name, flag in zip(names, flags)}


def compose(*args, stdin=None):
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *args],
        cwd=ROOT,
        input=stdin,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True,
        timeout=180,
    )


def run_in(service, *argv, stdin=None):
    """Run a command in a service; stdout only. Runner is not a running service."""
    if service == "runner":
        result = compose(
            "--profile", "tools", "run", "--rm", "--no-deps", "-T",
            "--entrypoint", argv[0], service, *argv[1:], stdin=stdin,
        )
    else:
        user = ["-u", "postgres"] if service == "db" else []
        result = compose("exec", "-T", *user, service, *argv, stdin=stdin)
    if result.returncode:
        # stderr can name paths or images; never echo stdout, which may hold secrets.
        sys.exit(
            f"{service}: {argv[0]} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace').strip()[-300:]}"
        )
    return result.stdout


def environment(service):
    if service == "runner":
        return locale_variables(run_in(service, "env", "-0"))
    return locale_variables(run_in(service, "cat", "/proc/1/environ"))


def gettext_probe(service, locale):
    catalogs = (
        base64.b64encode(build_catalog({SOURCE: ORDINARY})),
        base64.b64encode(build_catalog({SOURCE: TRAVERSAL})),
    )
    output = run_in(
        service, "bash", "-c", GETTEXT_SCRIPT, "probe", locale or "-",
        stdin=b"\n".join(catalogs) + b"\n",
    )
    return parse_gettext(output.decode("utf-8", "replace"))


def observe(service):
    locales = run_in(service, "locale", "-a").decode("utf-8", "replace")
    variants = (None, "C.UTF-8") if service in C_ONLY else ("en_US.utf8", "C.UTF-8")
    return {
        "glibc": run_in(service, "getconf", "GNU_LIBC_VERSION").decode().strip(),
        "locales": sorted(line for line in locales.splitlines() if line),
        "locale_environment": environment(service),
        "gettext": {
            (variant or "image default"): gettext_probe(service, variant)
            for variant in variants
        },
    }


def database_role():
    user = run_in(
        "api", "python", "-c",
        "import os, urllib.parse as u; print(u.urlparse(os.environ['DATABASE_URL']).username)",
    ).decode().strip()
    row = run_in(
        "db", "psql", "-w", "-U", user, "-d", "vardrmap", "-At", "-F", "|", "-c", ROLE_QUERY
    ).decode()
    return {"role": user, **parse_role(row)}


def check(observations):
    failures = []
    for service, seen in observations.items():
        env = seen["locale_environment"]
        extra = sorted(set(env) - {"LANG"})
        if extra:
            failures.append(f"{service}: unexpected locale variables {extra}")
        if env.get("LANG") not in LANG_ALLOWED[service]:
            failures.append(f"{service}: unexpected LANG {env.get('LANG')!r}")
        if service in C_ONLY:
            other = unexpected_locales("\n".join(seen["locales"]))
            if other:
                failures.append(f"{service}: non-C locales installed {other}")
            for variant, result in seen["gettext"].items():
                if result != {"ordinary": SOURCE, "traversal": SOURCE}:
                    failures.append(f"{service} [{variant}]: catalog loaded {result}")
        else:
            if "en_us.utf8" not in {name.lower() for name in seen["locales"]}:
                failures.append("db: en_US.utf8 missing; the positive control is invalid")
            control = seen["gettext"]["en_US.utf8"]
            if control.get("ordinary") != ORDINARY:
                failures.append(f"db [en_US.utf8]: fixture catalog not loaded {control}")
            ignored = seen["gettext"]["C.UTF-8"]
            if ignored != {"ordinary": SOURCE, "traversal": SOURCE}:
                failures.append(f"db [C.UTF-8]: catalog loaded {ignored}")
    return failures


def main():
    running = compose("ps", "--services", "--status", "running").stdout.decode().split()
    assert RUNNING <= set(running), f"installed stack is not running: {running}"
    observations = {service: observe(service) for service in SERVICES}
    role = database_role()
    receipt = {"project": PROJECT, "services": observations, "api_database_role": role}
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    if role["superuser"]:
        print(
            "::warning title=API database role is a PostgreSQL superuser::"
            f"role {role['role']} has rolsuper=true; needs a separate security review"
        )
    failures = check(observations)
    if failures:
        sys.exit("FAIL:\n" + "\n".join(failures))
    print(
        "PASS: locale variables and installed locales as expected; gettext ignored "
        "LANGUAGE under C.UTF-8; fixture catalog loaded under en_US.utf8"
    )


if __name__ == "__main__":
    main()

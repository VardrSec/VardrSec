"""Acceptance for the least-privilege PostgreSQL application role (issue #52).

Mutates only disposable Compose projects. Part A checks the freshly installed stack
(`vardrsec-compose-review`). Part B builds a faithful *existing* installation in a
second project (pre-change Compose file and .env, migrations run by the administrator,
seeded account), takes a backup, upgrades it with `database-role`, repeats the upgrade,
proves failure leaves the database untouched, and restores the pre-change backup.
A successful fresh install alone does not prove an existing volume can be upgraded.
Passwords are never printed; only booleans, counts and fingerprints are reported.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import database_roles as roles
import recovery

PROJECT = "vardrsec-compose-review"
DRILL = "vardrsec-role-upgrade"
RESTORED = "vardrsec-restore-roleupgrade"
WORK = ROOT / "artifacts" / "role-upgrade"
RECEIPT = ROOT / "artifacts" / "role-receipt" / "receipt.json"
DRILL_ENVIRONMENT = {
    "COMPOSE_PROJECT_NAME": DRILL,
    "APPLICATION_SUBNET": "172.30.201.0/24",
    "APPLICATION_IP_RANGE": "172.30.201.128/25",
    "PROXY_IP": "172.30.201.2",
}
PLACEHOLDER = "p" * 40  # lets Compose parse files before the real credential exists
# Statements an application login must never be able to run: SQLSTATE 42501.
DENIED = (
    "COPY (SELECT 1) TO PROGRAM 'true'",
    "CREATE ROLE zz_denied_role",
    "CREATE DATABASE zz_denied_database",
    "ALTER SYSTEM SET work_mem = '8MB'",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT rolpassword FROM pg_authid LIMIT 1",
    "ALTER ROLE vardrmap_app SUPERUSER",
    "SET ROLE vardrmap",
    "CREATE SCHEMA zz_denied_schema",
)


def expect_denied(root, project, password, statement):
    try:
        roles.psql(
            root, project, "-v", "VERBOSITY=sqlstate", "-c", statement,
            user=roles.APP, host="db", password=password,
        )
    except ValueError as error:
        assert "42501" in str(error), f"{statement!r} failed for another reason: {error}"
        return
    raise AssertionError(f"Application role was allowed to run: {statement}")


def app_scalar(root, project, password, statement):
    return roles.psql(
        root, project, "-At", "-c", statement,
        user=roles.APP, host="db", password=password,
    ).strip()


def admin_scalar(root, project, statement):
    with roles.credential(roles.read_password(root) or PLACEHOLDER):
        return recovery.sql(root, statement, project)


def verify_privileges(root, project):
    """Role flags, ownership, denied operations, DDL, scram enforcement, API identity."""
    password = roles.read_password(root)
    roles.verify(root, project, password)
    for statement in DENIED:
        expect_denied(root, project, password, statement)
    # Normal application work, including the schema changes migrations perform.
    app_scalar(root, project, password, "CREATE TABLE zz_probe (id integer); DROP TABLE zz_probe")
    try:
        roles.psql(
            root, project, "-c", "SELECT 1",
            user=roles.APP, host="db", password="x" * 40,
        )
    except ValueError as error:
        assert "password authentication failed" in str(error), error
    else:
        raise AssertionError("A wrong password was accepted over the network")
    with roles.credential(password):
        state = roles.state(root, project)
    assert state["objects"] > 0 and state["foreign"] == 0, state
    return {"objects_owned": state["objects"], "denied": len(DENIED)}


def verify_api(root, project):
    """The running API connects as the application role and never holds the administrator."""
    password = roles.read_password(root)
    with roles.credential(password):
        user = recovery.compose(
            root, "exec", "-T", "api", "python", "-c",
            "import os, urllib.parse as u; print(u.urlparse(os.environ['DATABASE_URL']).username)",
            project=project, capture_output=True, text=True,
        ).stdout.strip()
        administrator_absent = recovery.compose(
            root, "exec", "-T", "-e", "ADMIN_SECRET", "api", "python", "-c",
            "import os; secret = os.environ.pop('ADMIN_SECRET'); "
            "print(secret not in ''.join(os.environ.values()))",
            project=project, capture_output=True, text=True,
            env={**os.environ, "ADMIN_SECRET": env_value(root, "POSTGRES_PASSWORD")},
        ).stdout.strip()
    assert user == roles.APP, "The API does not connect as the application role"
    assert administrator_absent == "True", "The API holds the administrator password"
    return {"api_user": user, "administrator_password_in_api": False}


def env_value(root, name):
    for line in (root / ".env").read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == name:
            return value.strip()
    raise ValueError(f"{name} missing from .env")


def legacy_installation():
    """A copy of the repository files as an installation made before this change had them."""
    if WORK.exists():
        shutil.rmtree(WORK)
    root = WORK / "legacy-install"
    (root / "trust").mkdir(parents=True)
    for name in (*recovery.FILES, "database_roles.py"):
        if name != ".env":
            shutil.copy2(ROOT / name, root / name)
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    legacy, count = re.subn(
        r"(?m)^(\s*DATABASE_URL: )postgresql://vardrmap_app:.*$",
        r"\1postgresql://vardrmap:${POSTGRES_PASSWORD:?Run configuration setup first}"
        r"@db/vardrmap?sslmode=disable",
        compose,
    )
    assert count == 1, "Could not derive the pre-change Compose file"
    (root / "current-compose.yaml").write_text(compose, encoding="utf-8")
    (root / "compose.yaml").write_text(legacy, encoding="utf-8")
    kept = [
        line
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines()
        if not line.startswith(roles.PASSWORD_NAME + "=")
    ]
    (root / ".env").write_text("\n".join(kept) + "\n", encoding="utf-8")
    (root / ".env").chmod(0o600)
    return root


def cli(root, *args):
    return subprocess.run(
        [sys.executable, str(root / "vardrsec.py"), *args],
        cwd=root, capture_output=True, text=True, timeout=900,
    )


def owners(root, project):
    return admin_scalar(
        root, project,
        "SELECT string_agg(DISTINCT tableowner, ',' ORDER BY tableowner) "
        "FROM pg_tables WHERE schemaname = 'public'",
    )


def role_count(root, project):
    return admin_scalar(
        root, project, "SELECT count(*) FROM pg_roles WHERE rolname = 'vardrmap_app'"
    )


def unchanged(root, fingerprint, message):
    assert owners(root, DRILL) == "vardrmap", message
    assert role_count(root, DRILL) == "0", message
    assert recovery.database_fingerprint(root, DRILL) == fingerprint, message


def upgrade_drill(receipt):
    root = legacy_installation()
    saved = {name: os.environ.get(name) for name in DRILL_ENVIRONMENT}
    os.environ.update(DRILL_ENVIRONMENT)
    try:
        # 1. A real existing installation: the administrator runs the migrations.
        recovery.compose(
            root, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180",
            "db", "api", project=DRILL,
        )
        recovery.compose(root, "create", "--no-build", "web", "proxy", project=DRILL)
        recovery.compose(
            root, "exec", "-T", "api", "python", "-m", "local_accounts", "init",
            "--username", "legacy", "--generate-password",
            project=DRILL, capture_output=True,
        )
        assert owners(root, DRILL) == "vardrmap" and role_count(root, DRILL) == "0"
        users = admin_scalar(root, DRILL, "SELECT count(*) FROM users")
        assert int(users) >= 1
        before = recovery.database_fingerprint(root, DRILL)
        # 2. The backup is taken by the pre-change installation, as documented.
        backup = WORK / "legacy-backup"
        recovery.backup(root, backup)
        # 3. "git pull": the checkout now carries the new Compose file.
        shutil.copy2(root / "current-compose.yaml", root / "compose.yaml")
        # 4. Fail closed: no backup, then a stale backup, then a failure mid-change.
        refused = cli(root, "database-role")
        assert refused.returncode != 0 and "backup" in refused.stdout + refused.stderr
        admin_scalar(root, DRILL, "CREATE TABLE zz_stale (id integer)")
        stale = cli(root, "database-role", "--backup", str(backup))
        assert stale.returncode != 0 and "does not match" in stale.stdout + stale.stderr
        admin_scalar(root, DRILL, "DROP TABLE zz_stale")
        unchanged(root, before, "A refused upgrade changed the database")
        env_before = (root / ".env").read_bytes()
        try:
            roles.apply(root, DRILL, backup=backup, trailer="SELECT 1/0;\n")
        except ValueError:
            pass
        else:
            raise AssertionError("The injected failure did not abort the upgrade")
        unchanged(root, before, "A failed upgrade was not rolled back")
        stored = roles.read_password(root)
        assert stored is not None, "The generated credential was not kept for the retry"
        # 5. The real upgrade.
        upgraded = cli(root, "database-role", "--backup", str(backup))
        assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr
        assert stored not in upgraded.stdout + upgraded.stderr
        assert roles.read_password(root) == stored, "The credential changed silently"
        assert recovery.database_fingerprint(root, DRILL) == before, "Data changed"
        assert owners(root, DRILL) == "vardrmap_app"
        receipt["upgrade"] = verify_privileges_on_drill(root)
        # 6. Repeating it changes nothing.
        role_oid = admin_scalar(
            root, DRILL, "SELECT oid FROM pg_roles WHERE rolname = 'vardrmap_app'"
        )
        env_after = (root / ".env").read_bytes()
        again = cli(root, "database-role")
        assert again.returncode == 0, again.stdout + again.stderr
        assert (root / ".env").read_bytes() == env_after
        assert role_oid == admin_scalar(
            root, DRILL, "SELECT oid FROM pg_roles WHERE rolname = 'vardrmap_app'"
        )
        assert recovery.database_fingerprint(root, DRILL) == before
        assert env_before != env_after
        # 7. The application runs on the upgraded volume with its startup migrations.
        recovery.compose(
            root, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "api",
            project=DRILL,
        )
        count = recovery.compose(
            root, "exec", "-T", "api", "python", "-c",
            "from db import engine; from sqlalchemy import text; "
            "print(engine.connect().execute(text('SELECT count(*) FROM users')).scalar())",
            project=DRILL, capture_output=True, text=True,
        ).stdout.strip()
        assert count == users, "The upgraded API cannot read existing rows"
        head = recovery.compose(
            root, "exec", "-T", "api", "alembic", "current",
            project=DRILL, capture_output=True, text=True,
        )
        assert "(head)" in head.stdout + head.stderr, "Migrations are not current on the upgraded volume"
        receipt["upgrade"].update(verify_api(root, DRILL))
        receipt["upgrade"]["api_reads_existing_rows"] = True
        # 8. The pre-change backup still restores, as a pre-change installation.
        recovery.compose(root, "stop", "api", project=DRILL)
        # Restore chooses its own project and network; the drill's overrides must not leak in.
        for name in DRILL_ENVIRONMENT:
            os.environ.pop(name, None)
        recovery.restore(root, backup, WORK / "restored", RESTORED)
        restored = WORK / "restored"
        assert roles.read_password(restored) is None
        recovery.compose(
            restored, "up", "-d", "--no-build", "--wait", "--wait-timeout", "180",
            "db", "api", project=RESTORED,
        )
        receipt["pre_change_backup_restores"] = True
    finally:
        for project, directory in ((RESTORED, WORK / "restored"), (DRILL, root)):
            if (directory / "compose.yaml").exists():
                with roles.credential(PLACEHOLDER):
                    recovery.compose(
                        directory, "--profile", "tools", "down", "--volumes",
                        "--remove-orphans", project=project, check=False,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(WORK, ignore_errors=True)


def verify_privileges_on_drill(root):
    return verify_privileges(root, DRILL)


def main():
    receipt = {}
    receipt["fresh_install"] = {
        **verify_privileges(ROOT, PROJECT),
        **verify_api(ROOT, PROJECT),
    }
    print("PASS: fresh install runs migrations and the API as a non-superuser role")
    upgrade_drill(receipt)
    print(
        "PASS: existing volume upgraded; refusals and failure left data untouched; "
        "repeat is a no-op; application, migrations and pre-change backup restore work"
    )
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

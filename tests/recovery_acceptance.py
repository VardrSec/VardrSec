"""Real recovery/migration drill. Mutates only the disposable acceptance projects."""

import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import sys
import ssl
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery
import backup_crypto
from gate_acceptance import verify_retained

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
RESTORE_PROJECT = "vardrsec-restore-acceptance"
ARTIFACTS = ROOT / "artifacts" / "recovery-drill"


def verify_application(restored, original_ca, images):
    recovery.compose(
        restored,
        "up",
        "-d",
        "--no-build",
        "--wait",
        "--wait-timeout",
        "180",
        "db",
        "api",
        "web",
        "proxy",
        project=RESTORE_PROJECT,
    )
    recovery.compose(
        restored,
        "cp",
        "proxy:/data/caddy/pki/authorities/local/root.crt",
        "trust/root.crt",
        project=RESTORE_PROJECT,
    )
    trust = restored / "trust/root.crt"
    trust.chmod(0o644)
    assert hashlib.sha256(trust.read_bytes()).hexdigest() == original_ca
    assert (
        recovery.sql(
            restored, "SELECT version_num FROM alembic_version", RESTORE_PROJECT
        )
        == "0031localauth"
    )
    assert (
        recovery.sql(
            restored,
            "SELECT to_regclass('public.successful_upgrade_fixture') IS NULL",
            RESTORE_PROJECT,
        )
        == "t"
    )
    assert (
        recovery.container(restored, "api", RESTORE_PROJECT)["Image"] == images["api"]
    )
    reset = recovery.compose(
        restored,
        "exec",
        "-T",
        "api",
        "python",
        "-m",
        "local_accounts",
        "reset-password",
        "--username",
        "operator",
        "--generate-password",
        project=RESTORE_PROJECT,
        capture_output=True,
        text=True,
    )
    password = reset.stdout.split(
        "Generated password (store securely; shown once): ", 1
    )[1].strip()
    assert (
        recovery.sql(restored, "SELECT count(*) FROM local_sessions", RESTORE_PROJECT)
        == "0"
    )
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=str(trust))
        ),
    )

    def request(path, data=None, csrf=None):
        headers = {
            "Origin": "https://localhost:8443",
            "Content-Type": "application/json",
        }
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(
            "https://localhost:8443/backend" + path,
            headers=headers,
            data=None if data is None else json.dumps(data).encode(),
        )
        with client.open(req, timeout=20) as response:
            return json.load(response)

    request("/auth/local/login", {"username": "operator", "password": password})
    receipt = json.loads(
        (ROOT / "artifacts/installed-gate/accepted.json").read_text(encoding="utf-8")
    )
    verify_retained(request, receipt)
    print(
        "PASS: restored authenticated account retains write/readback evidence, retest history and delivered report revisions"
    )
    assert any(
        e["name"] == "Compose trusted HTTPS acceptance"
        for e in request("/engagements")["programs"]
    )
    csrf = request("/auth/local/session")["csrfToken"]
    token = request(
        "/auth/apikeys",
        {"label": "Disposable restore acceptance", "scope": "runner"},
        csrf,
    )["token"]
    doctor = recovery.compose(
        restored,
        "run",
        "--rm",
        "--no-deps",
        "runner",
        "doctor",
        "--platform",
        "--offline",
        "--json",
        project=RESTORE_PROJECT,
        env={**os.environ, "VARDRMAP_API_KEY": token},
        capture_output=True,
        text=True,
    )
    assert token not in doctor.stdout + doctor.stderr
    assert json.loads(doctor.stdout)["healthy"] is True
    print(
        "PASS: restored login/access, session revocation and Runner diagnostics over the preserved trusted CA"
    )


def compose(*args, **kwargs):
    return recovery.compose(ROOT, *args, project=PROJECT, **kwargs)


def candidate(tag, parent, revision, fail=False):
    directory = ARTIFACTS / tag
    directory.mkdir(parents=True)
    script = f"""
from alembic import op
import sqlalchemy as sa
revision = {revision!r}
down_revision = {parent!r}
branch_labels = None
depends_on = None
def upgrade():
    op.create_table({("failed_upgrade_fixture" if fail else "successful_upgrade_fixture")!r}, sa.Column('id', sa.Integer(), primary_key=True, autoincrement=False))
    {"raise RuntimeError('intentional recovery acceptance failure')" if fail else "pass"}
def downgrade():
    raise RuntimeError('fixture downgrade is not supported; restore the snapshot')
"""
    (directory / "migration.py").write_text(script, encoding="utf-8")
    base = "vardrsec-api:successful-fixture" if fail else "vardrmap-api:development"
    (directory / "Dockerfile").write_text(
        f"FROM {base}\nCOPY migration.py /app/migrations/versions/{revision}.py\n",
        encoding="utf-8",
    )
    recovery.command(
        "docker",
        "build",
        "-t",
        f"vardrsec-api:{tag}",
        str(directory),
        stdout=subprocess.DEVNULL,
    )
    return recovery.command(
        "docker",
        "image",
        "inspect",
        f"vardrsec-api:{tag}",
        "--format",
        "{{.Id}}",
        capture_output=True,
        text=True,
    ).stdout.strip()


def main():
    ARTIFACTS.mkdir(parents=True)
    if (ROOT / ".active-images.json").exists():
        raise ValueError(
            "Recovery fixture requires the unchanged development installation"
        )
    # Existing Compose acceptance seeded a real engagement, account and API key.
    compose(
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        "runner",
        "-c",
        "from pathlib import Path; p=Path.home()/'.vardrmap'/'recovery-evidence'; p.write_bytes(b'disposable evidence hash fixture')",
    )
    original_ca = hashlib.sha256((ROOT / "trust/root.crt").read_bytes()).hexdigest()
    previous = os.environ.get("COMPOSE_PROJECT_NAME")
    os.environ["COMPOSE_PROJECT_NAME"] = PROJECT
    try:
        recovery.backup(ROOT, ARTIFACTS / "backup")
    finally:
        if previous is None:
            os.environ.pop("COMPOSE_PROJECT_NAME", None)
        else:
            os.environ["COMPOSE_PROJECT_NAME"] = previous
    snapshot = recovery.validate(ARTIFACTS / "backup")
    identity = ARTIFACTS / "private-age-identity.txt"
    subprocess.run(
        ["age-keygen", "--output", str(identity)], check=True, capture_output=True
    )
    recipient = subprocess.check_output(
        ["age-keygen", "-y", str(identity)], text=True
    ).strip()
    backup_crypto.seal(ARTIFACTS / "backup", ARTIFACTS / "snapshot.age", recipient)
    backup_crypto.unseal(ARTIFACTS / "snapshot.age", ARTIFACTS / "unsealed", identity)
    assert recovery.digest(ARTIFACTS / "unsealed/snapshot.json") == recovery.digest(
        ARTIFACTS / "backup/snapshot.json"
    )
    print(
        "PASS: full image/data/CA backup sealed and authenticated with age before recovery"
    )
    current_base = recovery.command(
        "docker",
        "image",
        "inspect",
        "vardrmap-api:development",
        "--format",
        "{{.Id}}",
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert current_base == snapshot["images"]["api"]
    successful = candidate("successful-fixture", "0031localauth", "0032restorefixture")
    recovery.json_write(
        ROOT / ".active-images.json", {"services": {"api": {"image": successful}}}
    )
    compose(
        "up",
        "-d",
        "--no-build",
        "--wait",
        "--wait-timeout",
        "180",
        "api",
        "web",
        "proxy",
    )
    assert (
        recovery.sql(ROOT, "SELECT version_num FROM alembic_version", PROJECT)
        == "0032restorefixture"
    )
    after = recovery.database_fingerprint(ROOT, PROJECT)
    assert all(
        after[table] == value
        for table, value in snapshot["database"].items()
        if table != "alembic_version"
    )
    print(
        "PASS: real additive image migration retains every pre-upgrade database row and sequence"
    )
    compose("stop", "proxy", "web", "api")
    failed = candidate(
        "failed-fixture", "0032restorefixture", "0033failedfixture", fail=True
    )
    (ROOT / ".active-images.json").write_text(
        json.dumps({"services": {"api": {"image": failed}}}), encoding="utf-8"
    )
    try:
        compose(
            "run",
            "--rm",
            "--no-deps",
            "api",
            "bash",
            "start.sh",
            capture_output=True,
            text=True,
            timeout=60,
        )
        raise AssertionError("Intentional migration failure unexpectedly succeeded")
    except subprocess.CalledProcessError as exc:
        assert "intentional recovery acceptance failure" in exc.stdout + exc.stderr
    assert (
        recovery.sql(ROOT, "SELECT version_num FROM alembic_version", PROJECT)
        == "0032restorefixture"
    )
    assert (
        recovery.sql(
            ROOT, "SELECT to_regclass('public.failed_upgrade_fixture') IS NULL", PROJECT
        )
        == "t"
    )
    print(
        "PASS: failing migration aborts application startup and rolls back its partial DDL"
    )
    recovery.restore(
        ROOT, ARTIFACTS / "unsealed", ARTIFACTS / "restored", RESTORE_PROJECT
    )
    verify_application(ARTIFACTS / "restored", original_ca, snapshot["images"])
    print(
        "PASS: fresh-install restore recovers original images, schema/data, evidence contents/ownership and CA; source project is retained"
    )


if __name__ == "__main__":
    main()

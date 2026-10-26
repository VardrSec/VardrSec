"""Controlled-updater drill; only the named disposable source/rehearsal projects."""

import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recovery
import updater

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "vardrsec-compose-review"
ARTIFACTS = ROOT / "artifacts/update-drill"


def compose(*args, **kwargs):
    return recovery.compose(ROOT, *args, project=PROJECT, **kwargs)


def image(name, parent, revision, base, failure=""):
    folder = ARTIFACTS / name
    folder.mkdir()
    code = f"""
from alembic import op
import sqlalchemy as sa
import os
revision = {revision!r}
down_revision = {parent!r}
branch_labels = None
depends_on = None
def upgrade():
    op.create_table({name.replace("-", "_")!r}, sa.Column('id',sa.Integer(),primary_key=True,autoincrement=False))
    {failure or "pass"}
def downgrade():
    raise RuntimeError('restore the verified snapshot')
"""
    (folder / "migration.py").write_text(code, encoding="utf-8")
    (folder / "Dockerfile").write_text(
        f"FROM {base}\nCOPY migration.py /app/migrations/versions/{revision}.py\n",
        encoding="utf-8",
    )
    recovery.command(
        "docker",
        "build",
        "-t",
        f"vardrsec-api:{name}",
        str(folder),
        stdout=subprocess.DEVNULL,
    )
    return recovery.command(
        "docker",
        "image",
        "inspect",
        f"vardrsec-api:{name}",
        "--format",
        "{{.Id}}",
        capture_output=True,
        text=True,
    ).stdout.strip()


def manifest(name, api):
    config, images = updater.image_set(ROOT)
    images["api"] = api
    pins = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    path = ARTIFACTS / (name + ".json")
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_origin": config["services"]["web"]["environment"]["AUTH_URL"],
                "images": images,
                "components": {k: v["commit"] for k, v in pins["components"].items()},
            }
        ),
        encoding="utf-8",
    )
    return path


def run(name, candidate):
    return updater.update(
        ROOT,
        candidate,
        ARTIFACTS / (name + "-backup"),
        ARTIFACTS / name,
        "vardrsec-restore-update-" + name,
    )


def main():
    updater.WAIT_SECONDS = 90
    ARTIFACTS.mkdir(parents=True)
    os.environ["COMPOSE_PROJECT_NAME"] = PROJECT
    action = (
        "init"
        if recovery.sql(ROOT, "SELECT count(*) FROM local_credentials", PROJECT) == "0"
        else "reset-password"
    )
    result = compose(
        "exec",
        "-T",
        "api",
        "python",
        "-m",
        "local_accounts",
        action,
        "--username",
        "operator",
        "--generate-password",
        capture_output=True,
        text=True,
    )
    password = result.stdout.split(
        "Generated password (store securely; shown once): ", 1
    )[1].strip()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=str(ROOT / "trust/root.crt"))
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
    csrf = request("/auth/local/session")["csrfToken"]
    request(
        "/engagements",
        {"name": "Controlled update acceptance", "engagement_type": "internal"},
        csrf,
    )
    token = request(
        "/auth/apikeys",
        {"label": "Disposable update diagnostics", "scope": "runner"},
        csrf,
    )["token"]
    os.environ["VARDRMAP_API_KEY"] = token
    baseline = recovery.database_fingerprint(ROOT, PROJECT)
    bad = image(
        "update-bad",
        "0031localauth",
        "0032updatebad",
        "vardrmap-api:development",
        "raise RuntimeError('intentional rehearsal failure')",
    )
    try:
        run("rejected", manifest("bad", bad))
        raise AssertionError("Bad rehearsal unexpectedly passed")
    except ValueError as exc:
        assert "Pending record retained" in str(exc)
    assert recovery.database_fingerprint(ROOT, PROJECT) == baseline
    assert json.loads((ROOT / updater.STATE).read_text())["phase"] == "rehearsal"
    with updater.operation_guard(ROOT, "stop"):
        pass
    try:
        with updater.operation_guard(ROOT, "start"):
            raise AssertionError("Pending update permitted startup")
    except ValueError:
        pass
    updater.cancel(ROOT)
    assert not (ROOT / updater.STATE).exists()
    print(
        "PASS: failed private rehearsal preserves original data, blocks startup and permits verified baseline cancellation"
    )
    good = image(
        "update-good", "0031localauth", "0032updategood", "vardrmap-api:development"
    )
    run("successful", manifest("good", good))
    assert not (ROOT / updater.STATE).exists()
    assert (
        recovery.sql(ROOT, "SELECT version_num FROM alembic_version", PROJECT)
        == "0032updategood"
    )
    assert any(
        e["name"] == "Controlled update acceptance"
        for e in request("/engagements")["programs"]
    )
    assert json.loads((ROOT / ".last-update.json").read_text())["status"] == "success"
    print(
        "PASS: candidate rehearsed privately, applied privately, diagnosed by Runner and published with existing authenticated access"
    )
    source_ip = next(
        v.split("=", 1)[1]
        for v in recovery.container(ROOT, "api", PROJECT)["Config"]["Env"]
        if v.startswith("FORWARDED_ALLOW_IPS=")
    )
    failed = image(
        "update-apply-failure",
        "0032updategood",
        "0033updatefailed",
        "vardrsec-api:update-good",
        f"\n    if os.environ.get('FORWARDED_ALLOW_IPS') == {source_ip!r}:\n        raise RuntimeError('intentional original apply failure')",
    )
    try:
        run("apply-failed", manifest("apply-failed", failed))
        raise AssertionError("Original-apply failure unexpectedly passed")
    except ValueError:
        pass
    assert json.loads((ROOT / updater.STATE).read_text())["phase"] == "applying"
    assert not recovery.container(ROOT, "proxy", PROJECT)["State"]["Running"]
    try:
        updater.cancel(ROOT)
        raise AssertionError("Unsafe image rollback permitted")
    except ValueError as exc:
        assert "mutation may have occurred" in str(exc)
    print(
        "PASS: original migration failure closes traffic and forbids automatic rollback"
    )
    restored = ARTIFACTS / "recovered"
    recovery.restore(
        ROOT,
        ARTIFACTS / "apply-failed-backup",
        restored,
        "vardrsec-restore-update-recovered",
    )
    updater.verify_private(restored, "vardrsec-restore-update-recovered")
    assert json.loads((restored / ".last-update.json").read_text())["status"] == "success"
    assert (
        recovery.sql(
            restored,
            "SELECT version_num FROM alembic_version",
            "vardrsec-restore-update-recovered",
        )
        == "0032updategood"
    )
    print(
        "PASS: failed update recovered from its portable snapshot with original schema, data, CA and Runner authentication"
    )


if __name__ == "__main__":
    main()

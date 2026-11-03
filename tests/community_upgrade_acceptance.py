"""Explicit local Community 0031->0038 upgrade drill on an owned installation.

The orchestrator supplies a verified old installed stack and separately built,
immutable candidate images. This fixture never builds, retags or changes pins.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acceptance_retention
from acceptance_diagnostics import diagnostics, mark, wrap_shared
import database_roles
import recovery
import updater
from gate_acceptance import verify_retained

ROOT = Path(__file__).resolve().parents[1]
OLD = {
    "map": "41d3ef6475f1b81f973dd4a73944b6e549500fd6",
    "runner": "668dc56f8685dc6a6225438ad443e26901828069",
    "gate": "7f82e499ec407eba072e129e3f3b94f1a4eabe94",
}
CURRENT = {
    "map": "9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045",
    "runner": "602a5423dcede0e37dacad52aab3bdad900c9021",
    "gate": OLD["gate"],
}


def quoted(value):
    return '"' + value.replace('"', '""') + '"'


def columns(root, project):
    value = recovery.sql(root, "SELECT coalesce(json_agg(t ORDER BY table_name,ordinal_position),'[]'::json) FROM (SELECT table_name,column_name,ordinal_position FROM information_schema.columns WHERE table_schema='public') t", project)
    result = {}
    for row in json.loads(value):
        result.setdefault(row["table_name"], []).append(row["column_name"])
    if "alembic_version" not in result:
        raise ValueError("Installed schema has no migration revision")
    return result


def projected_rows(root, project, original_columns, diagnostic_key_id=None):
    result = {}
    for table, names in original_columns.items():
        if table == "alembic_version":
            continue
        projection = ",".join(quoted(name) for name in names)
        if table == "api_keys" and diagnostic_key_id is not None:
            key_id = str(uuid.UUID(diagnostic_key_id))
            if key_id != diagnostic_key_id or "last_used_at" not in names or "id" not in names:
                raise ValueError("Unsupported diagnostic key projection")
            # Mask one telemetry column of one newly issued key, never a whole
            # row/table or any other authority, ownership or credential field.
            projection = ",".join(
                f"CASE WHEN {quoted('id')}='{key_id}' THEN NULL ELSE {quoted(name)} END AS {quoted(name)}"
                if name == "last_used_at" else quoted(name) for name in names
            )
        rows = recovery.sql(root, f"SET timezone='UTC'; SELECT encode(sha256(convert_to(row_to_json(t)::text,'UTF8')),'hex') FROM (SELECT {projection} FROM public.{quoted(table)}) t ORDER BY 1", project)
        values = rows.splitlines() if rows else []
        if values and values[0] == "SET":
            values = values[1:]
        if any(len(row) != 64 or any(c not in "0123456789abcdef" for c in row) for row in values):
            raise ValueError("Invalid projected database fingerprint")
        result[table] = values
    return result


def assert_retained(before, after):
    for table, rows in before.items():
        if Counter(rows) - Counter(after.get(table, [])):
            raise ValueError("Original-column database rows changed during upgrade")


def key_telemetry(root, project, key_id):
    if str(uuid.UUID(key_id)) != key_id:
        raise ValueError("Invalid diagnostic key ID")
    return json.loads(recovery.sql(root,
        "SELECT json_build_object('count',count(*),'last_used_at',max(last_used_at),"
        "'observed_at',timezone('UTC',statement_timestamp())) FROM api_keys "
        f"WHERE id='{key_id}'", project))


def assert_key_telemetry(before, after):
    def instant(value):
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    try:
        start, end = instant(before["observed_at"]), instant(after["observed_at"])
        used = instant(after["last_used_at"])
        previous = instant(before["last_used_at"]) if before["last_used_at"] else None
        valid = (type(before["count"]) is int and before["count"] == 1
                 and type(after["count"]) is int and after["count"] == 1
                 and start <= used <= end
                 and (previous is None or previous <= start and previous <= used))
    except (ValueError, TypeError, KeyError):
        valid = False
    if not valid:
        raise ValueError("Diagnostic key telemetry is missing, invalid or nonmonotonic")


def sequences(root, project):
    metadata = json.loads(recovery.sql(root, "SELECT coalesce(json_agg(t ORDER BY sequencename),'[]'::json) FROM (SELECT sequencename,start_value,min_value,max_value,increment_by,cycle,cache_size,last_value FROM pg_sequences WHERE schemaname='public') t", project))
    return [{"definition": row, "state": recovery.sql(root,
        f"SELECT last_value,is_called FROM public.{quoted(row['sequencename'])}", project)}
        for row in metadata]


def assert_sequences_retained(before, after):
    """Preserve every old definition and state; additive migrations may add sequences."""
    def indexed(snapshot):
        result = {}
        for row in snapshot:
            name = row["definition"]["sequencename"]
            if name in result:
                raise ValueError("Duplicate sequence identity in upgrade snapshot")
            result[name] = row
        return result
    original, current = indexed(before), indexed(after)
    if any(name not in current or current[name] != row for name, row in original.items()):
        raise ValueError("Existing sequence definition or state changed during upgrade")


def state_fingerprints(root, project, images):
    # The profile-only Runner is invoked explicitly via one-shots in the journey.
    # Prepare its stopped service container for mount discovery; never start it.
    recovery.compose(root, "create", "--no-build", "--no-recreate", "--pull", "never",
                     "runner", project=project, capture_output=True, text=True)
    return {
        name: recovery.volume_fingerprint(
            images["runner"],
            recovery.volume_name(recovery.container(root, service, project), mount),
        )
        for name, (service, mount) in recovery.VOLUMES.items()
    }


def operator_client(root, project, origin, ca, diagnostic_prefix="upgrade.operator"):
    mark(diagnostic_prefix + ".reset")
    reset = recovery.compose(
        root, "exec", "-T", "api", "python", "-m", "local_accounts",
        "reset-password", "--username", "operator", "--generate-password",
        project=project, capture_output=True, text=True,
    )
    marker = "Generated password (store securely; shown once): "
    if marker not in reset.stdout:
        raise ValueError("Synthetic operator password reset did not return its private result")
    password = reset.stdout.split(marker, 1)[1].strip()
    client = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
    )

    def request(path, data=None, csrf=None):
        headers = {"Origin": origin, "Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = urllib.request.Request(
            origin + "/backend" + path,
            headers=headers,
            data=None if data is None else json.dumps(data).encode(),
        )
        with client.open(req, timeout=20) as response:
            return json.load(response)

    mark(diagnostic_prefix + ".login")
    request("/auth/local/login", {"username": "operator", "password": password})
    return request


def verify_anonymous_denied(origin, ca):
    client = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
    try:
        with client.open(origin + "/backend/engagements", timeout=20):
            raise ValueError("Protected upgrade readback accepted an anonymous request")
    except urllib.error.HTTPError as error:
        if error.code not in (401, 403):
            raise ValueError("Anonymous upgrade readback did not fail closed") from None


def require_owned_source(root, project):
    runner_temp = os.environ.get("RUNNER_TEMP")
    if (project != "vardrsec-compose-review" or not runner_temp
            or root != Path(runner_temp) / "community-run" or root != ROOT
            or not acceptance_retention.enabled()):
        raise ValueError("Fixture requires the fresh run-owned Community CI copy")


def run(root, candidate_path, output, rehearsal_project):
    mark("upgrade.preflight.paths")
    root, candidate_path, output = root.resolve(), candidate_path.resolve(), output.resolve()
    if output.exists():
        raise ValueError("Upgrade evidence destination must be new")
    mark("upgrade.preflight.pins")
    pins = json.loads((root / "versions.json").read_text())
    if {name: value["commit"] for name, value in pins["components"].items()} != OLD:
        raise ValueError("Fixture requires the exact old Community source pins")
    pin_hash = recovery.digest(root / "versions.json")
    mark("upgrade.preflight.images")
    config, baseline_images = updater.image_set(root)
    project = config["name"]
    mark("upgrade.preflight.ownership")
    require_owned_source(root, project)
    if not rehearsal_project.startswith("vardrsec-restore-nm2-community-") or rehearsal_project == project:
        raise ValueError("Fixture requires a separate owned rehearsal project")
    origin = config["services"]["web"]["environment"]["AUTH_URL"]
    if origin != "https://localhost:8443":
        raise ValueError("Fixture requires the existing trusted loopback HTTPS origin")
    mark("upgrade.preflight.candidate")
    candidate = updater.candidate_set(candidate_path, baseline_images, origin)
    if candidate["components"] != CURRENT:
        raise ValueError("Candidate must record the exact NM-2 component commits")
    mark("upgrade.preflight.schema")
    if recovery.sql(root, "SELECT version_num FROM alembic_version", project) != "0031localauth":
        raise ValueError("Actual installed schema must be 0031localauth")
    mark("upgrade.preflight.receipts")
    old_receipt_path = root / "artifacts/installed-gate/accepted.json"
    gate_receipt = json.loads(old_receipt_path.read_text())
    ca = root / "trust/root.crt"
    ca_hash = recovery.digest(ca)
    output.mkdir(parents=True, mode=0o700)
    report = {
        "status": "started", "old_components": OLD, "candidate_components": CURRENT,
        "baseline_images": baseline_images, "candidate_images": candidate["images"],
        "project": project, "rehearsal_project": rehearsal_project,
        "gate_receipt_sha256": recovery.digest(old_receipt_path),
        "candidate_manifest_sha256": recovery.digest(candidate_path),
        "initial_revision": "0031localauth", "original_pin_sha256": pin_hash,
        "nm2_nonempty_state": "Not seeded: existing managed fixtures require test-only pytest and fixed IDs; this product-runtime upgrade drill does not install test dependencies or invent authority rows. Nonempty NM2 backup/restore remains a separate gate.",
    }
    recovery.json_write(output / "started.json", report)
    try:
        mark("upgrade.operator.reset")
        request = operator_client(root, project, origin, ca)
        mark("upgrade.operator.readback")
        verify_retained(request, gate_receipt)
        mark("upgrade.operator.key")
        csrf = request("/auth/local/session")["csrfToken"]
        key = request("/auth/apikeys", {"label": "Disposable NM2 Community upgrade diagnostics", "scope": "runner"}, csrf)
        token, diagnostic_key_id = key["token"], key["id"]
        mark("upgrade.snapshot.telemetry")
        telemetry_before = key_telemetry(root, project, diagnostic_key_id)
        mark("upgrade.snapshot.columns")
        original_columns = columns(root, project)
        mark("upgrade.snapshot.rows")
        before = projected_rows(root, project, original_columns, diagnostic_key_id)
        mark("upgrade.snapshot.sequences")
        before_sequences = sequences(root, project)
        mark("upgrade.snapshot.state")
        before_state = state_fingerprints(root, project, baseline_images)
        mark("upgrade.snapshot.role")
        password = database_roles.read_password(root)
        if password is None:
            raise ValueError("Fixture requires the normal restricted application role")
        database_roles.verify(root, project, password)
        previous = os.environ.get("VARDRMAP_API_KEY")
        os.environ["VARDRMAP_API_KEY"] = token
        try:
            mark("upgrade.update")
            updater.update(root, candidate_path, output / "backup", output / "rehearsal", rehearsal_project)
        finally:
            if previous is None:
                os.environ.pop("VARDRMAP_API_KEY", None)
            else:
                os.environ["VARDRMAP_API_KEY"] = previous
        mark("upgrade.post.schema")
        if recovery.sql(root, "SELECT version_num FROM alembic_version", project) != "0038managedstops":
            raise ValueError("Actual product upgrade did not reach 0038managedstops")
        mark("upgrade.post.rows")
        assert_retained(before, projected_rows(root, project, original_columns, diagnostic_key_id))
        mark("upgrade.post.telemetry")
        assert_key_telemetry(telemetry_before, key_telemetry(root, project, diagnostic_key_id))
        mark("upgrade.post.sequences")
        assert_sequences_retained(before_sequences, sequences(root, project))
        mark("upgrade.post.role")
        database_roles.verify(root, project, password)
        mark("upgrade.post.ca")
        if recovery.digest(ca) != ca_hash:
            raise ValueError("Trusted CA changed during upgrade")
        mark("upgrade.post.state")
        if state_fingerprints(root, project, candidate["images"]) != before_state:
            raise ValueError("Existing Runner/proxy state changed during upgrade")
        mark("upgrade.post.pins")
        if recovery.digest(root / "versions.json") != pin_hash:
            raise ValueError("Original source pins changed during the upgrade fixture")
        mark("upgrade.post.operator.reset")
        request = operator_client(root, project, origin, ca, diagnostic_prefix="upgrade.post.operator")
        mark("upgrade.post.readback")
        verify_retained(request, gate_receipt)
        mark("upgrade.post.anonymous")
        verify_anonymous_denied(origin, ca)
        mark("upgrade.post.receipt")
        last = json.loads((root / ".last-update.json").read_text())
        if last.get("status") != "success" or last.get("candidate") != candidate:
            raise ValueError("Normal updater did not retain the expected successful receipt")
        mark("upgrade.post.report")
        report.update(status="passed", final_revision="0038managedstops",
                      original_column_rows_preserved=True, sequences_preserved=True,
                      diagnostic_key_telemetry="Only the newly issued diagnostic key last_used_at is normalized; separately verified valid, bounded and nondecreasing. All other original columns/rows are checked.",
                      application_role_verified=True, ca_preserved=True, state_preserved=True,
                      old_gate_journey_readback_verified=True, anonymous_protected_readback_denied=True,
                      baseline_table_count=len(before), baseline_row_count=sum(map(len, before.values())),
                      original_columns_sha256=hashlib.sha256(json.dumps(original_columns, sort_keys=True).encode()).hexdigest(),
                      backup_snapshot_sha256=recovery.digest(output / "backup/snapshot.json"),
                      updater_receipt_sha256=recovery.digest(root / ".last-update.json"),
                      acceptance_claimed=False)
        recovery.json_write(output / "result.json", report)
    except BaseException as error:
        report.update(status="failed", error_type=type(error).__name__, acceptance_claimed=False)
        recovery.json_write(output / "failure.json", report)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rehearsal-project", required=True)
    parser.add_argument("--safe-diagnostics", action="store_true")
    args = parser.parse_args()
    try:
        if args.safe_diagnostics:
            with diagnostics(ROOT, "upgrade"), wrap_shared():
                run(ROOT, args.candidate, args.output, args.rehearsal_project)
        else:
            run(ROOT, args.candidate, args.output, args.rehearsal_project)
    except Exception as error:
        raise SystemExit("Community upgrade verification failed: " + type(error).__name__) from None

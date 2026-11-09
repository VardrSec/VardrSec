"""Human-only managed job review/sign/register using existing component contracts."""

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import stat
import sys
import uuid

import recovery
import worker_compose_inventory as inventory
import worker_host as host
import worker_prepare as preparation


def require(value):
    if not value:
        raise ValueError("worker_job_refused")


def read(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
            and not getattr(info, "st_file_attributes", 0) & 0x400)
    with path.open("rb") as source:
        raw = source.read(1024 * 1024 + 1)
    require(0 < len(raw) <= 1024 * 1024)
    return host._json(raw)


def setup(path, installation):
    value = read(path)
    root = Path(installation).resolve(strict=True)
    frozen = read(root / ".active-images.json")
    require(type(value) is dict and value["provision_image"] == frozen["services"]["runner"]["image"])
    config = read(value["launch_config"])
    require(config["source"] == value["source"])
    selected = inventory.LocalClient(
        docker=Path(config["docker"]), docker_sha256=config["docker_sha256"],
        compose=Path(config["compose"]), compose_sha256=config["compose_sha256"],
        config=Path(config["docker_config"]), context=value["context"],
        endpoint=config["local_endpoint"],
    )
    require(Path(value["installation"]).resolve(strict=True) == root)
    model = host._json(preparation._compose(selected, root, "--profile", "tools", "config", "--format", "json"))
    require(model["name"] == value["project"]
            and model["volumes"]["runner-state"]["name"] == value["state_volume"]
            and model["networks"]["runner"]["name"] == value["runner_network"])
    pin = value["api"]
    require(Path(pin["ca_file"]).resolve(strict=True) == (root / "trust" / "root.crt").resolve(strict=True))
    require(host.HostClient(pin["base_url"], pin["ca_file"]).pin() == pin)
    return value, config, selected


def helper(installation, value, client, script, payload, *, image=None, operator=False):
    selected_image = image or value["provision_image"]
    require(type(selected_image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", selected_image))
    mounts = []
    if operator:
        volume = value["operator_volume"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume))
        mounts = ["--mount", f"type=volume,source={volume},target=/issuer,readonly"]
    raw = preparation._docker(client, Path(installation), "run", "--rm", "--pull", "never", "-i",
                              "--network", "none", "--read-only", "--user", "10001:10001",
                              "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                              "--pids-limit", "32", "--memory", "256m", "--cpus", "1",
                              *mounts, "--entrypoint", "python", selected_image, "-I", "-c", script,
                              data=host.canonical(payload))
    require(len(raw) <= 1024 * 1024)
    return host._json(raw)


_PLAN = """
import hashlib,json,pathlib,sys
from vardrrunner.authorization.plan import compile_gate_plan
data=json.load(sys.stdin)
sha=hashlib.sha256(pathlib.Path('/usr/local/bin/vardrgate').read_bytes()).hexdigest()
print(json.dumps(compile_gate_plan(data['case'],data['execution'],tool_sha256=sha)))
"""

_SIGN = """
import json,pathlib,sys
from vardrrunner.authorization.contracts import approve
data=json.load(sys.stdin)
result=approve(data['context'],data['issuer'],'map',data['approver_id'],
               data['approval_id'],data['approved_at'],pathlib.Path('/issuer/signing.key').read_bytes())
print(json.dumps(result))
"""


def choose(rows, supplied, label):
    require(type(rows) is list and 0 < len(rows) <= 1000)
    if supplied is not None:
        matches = [row for row in rows if row.get("id") == supplied]
        require(len(matches) == 1)
        return matches[0]
    require(sys.stdin.isatty())
    for index, row in enumerate(rows, 1):
        print(json.dumps({"selection": index, "id": row["id"],
                          "label": row.get("name", row.get("reference", "")),
                          "status": row.get("status", "")}, ensure_ascii=True))
    answer = input(f"Choose {label} number: ")
    require(answer.isascii() and answer.isdecimal() and len(answer) <= 4)
    require(1 <= int(answer) <= len(rows))
    return rows[int(answer) - 1]


def stamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_context(context):
    expiry = datetime.strptime(context["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    require(datetime.now(timezone.utc) < expiry)


def review(installation, args, session):
    value, config, client = setup(args.setup, installation)
    require(session.owner_id() == value["owner_id"])
    destination = Path(args.output).absolute()
    require(not destination.exists() and destination.parent.is_dir())
    engagement = choose(session.engagements()["engagements"], args.engagement_id, "engagement")
    jobs = session.jobs(engagement["id"])["jobs"]
    job = choose(jobs, args.job_id, "job")
    require(job["status"] == "pending" and job["tool_type"] == "vardrgate_api_test"
            and job.get("authorization_contract_required") is True)
    case = session.test_case(engagement["id"], job["config"]["test_case_id"])
    authorization = choose(session.authorizations(engagement["id"]), args.authorization_id, "authorization")
    require(type(args.expires_in) is int and 1 <= args.expires_in <= 86400
            and type(args.duration_seconds) is int and 1 <= args.duration_seconds <= 3600
            and type(args.max_artifact_bytes) is int and 1 <= args.max_artifact_bytes <= 64 * 1024 * 1024)
    execution = {"timeout_seconds": min(20, args.duration_seconds), "max_response_bytes": 65536,
                 "allow_private_targets": args.allow_private_targets}
    worker_image = config["source"]["runner_image"]
    plan = helper(installation, value, client, _PLAN, {"case": case["spec"], "execution": execution},
                  image=worker_image)
    missing = sorted({reference["name"] for reference in plan["credential_references"]
                      if reference["source"] == "value_env"}
                     - set(config["credential_names"]))
    if missing:
        # Refuse before requesting approval context or registering authority.
        # Report reference names only; never open the private credential file.
        return {"schema": "vardr.worker-cli/1", "state": "held_missing_credential_references",
                "runtime_id": None, "job_id": job["id"], "credential_names": missing,
                "help": "docs/local-managed-setup.md", "job_authorized": False,
                "worker_started": False}
    enrollment = read(Path(value["private_root"]) / "enrollment.json")
    require(enrollment["setup_sha256"] == host.digest(value)
            and enrollment["owner_id"] == value["owner_id"]
            and enrollment["origin"] == value["origin"]
            and str(uuid.UUID(enrollment["runner_id"])) == enrollment["runner_id"])
    expiry = stamp(datetime.now(timezone.utc) + timedelta(seconds=args.expires_in))
    selection = {"enrollment_id": enrollment["enrollment_id"],
                 "authorization_id": authorization["id"], "plan": plan}
    request = {**selection, "expires_at": expiry, "max_executions": 1,
               "max_duration_seconds": args.duration_seconds, "max_artifact_bytes": args.max_artifact_bytes,
               "credential_grants": [{**reference, "revision": 1, "expires_at": expiry}
                                     for reference in plan["credential_references"]]}
    result = session.review_job(job["id"], request)
    document = {"schema": "vardr.worker-job-review/1", "setup_sha256": host.digest(value),
                "job_id": job["id"], "engagement_id": engagement["id"], "case": case["spec"],
                "execution": execution, "selection": selection, "request": request, "review": result}
    destination.mkdir(mode=0o700)
    recovery.private_write(destination / "review.json", host.canonical(document))
    print(json.dumps(document, indent=2, ensure_ascii=True))
    return {"schema": "vardr.worker-cli/1", "state": "job_reviewed", "runtime_id": None,
            "job_id": job["id"], "engagement_id": engagement["id"], "issuer_id": value["issuer_id"],
            "origin": value["origin"], "review": str(destination / "review.json"), "job_authorized": False}


def approve(installation, args):
    value, _, client = setup(args.setup, installation)
    document = read(args.review)
    require(document["schema"] == "vardr.worker-job-review/1"
            and document["setup_sha256"] == host.digest(value) and sys.stdin.isatty())
    current_context(document["review"]["context"])
    destination = Path(args.output).absolute()
    require(not destination.exists() and destination.parent.is_dir())
    print(json.dumps({"case": document["case"], "execution": document["execution"],
                      "plan": document["selection"]["plan"], "review": document["review"]},
                     indent=2, ensure_ascii=True))
    require(input("Review this exact context and type APPROVE: ") == "APPROVE")
    current_context(document["review"]["context"])
    payload = {"context": document["review"]["context"],
               "issuer": {"id": value["issuer_id"], "key_id": value.get("operator_key_id", "operator")},
               "approver_id": value["owner_id"], "approval_id": str(uuid.uuid4()),
               "approved_at": stamp(datetime.now(timezone.utc))}
    envelope = helper(installation, value, client, _SIGN, payload, operator=True)
    require(set(envelope) == {"format", "purpose", "payload", "signature"}
            and envelope["format"] == "vardr.authorization-envelope/1"
            and envelope["purpose"] == "approval"
            and type(envelope["payload"]) is str and 0 < len(envelope["payload"]) <= 350000
            and re.fullmatch(r"[A-Za-z0-9_-]+", envelope["payload"]))
    signed = host._json(base64.urlsafe_b64decode(envelope["payload"] + "=" * (-len(envelope["payload"]) % 4)))
    require(signed["context"] == payload["context"] and signed["issuer"] == payload["issuer"]
            and signed["approver_id"] == payload["approver_id"]
            and signed["approval_id"] == payload["approval_id"] and signed["origin"] == "map"
            and signed["approved_at"] == payload["approved_at"])
    destination.mkdir(mode=0o700)
    output = {"schema": "vardr.worker-job-approval/1", "review_sha256": host.digest(document),
              "job_id": document["job_id"], "selection": document["selection"], "approval": envelope}
    recovery.private_write(destination / "approval.json", host.canonical(output))
    return {"schema": "vardr.worker-cli/1", "state": "job_signed", "runtime_id": None,
            "job_id": document["job_id"], "approval": str(destination / "approval.json"),
            "job_registered": False}


def register(installation, args, session):
    value, _, _ = setup(args.setup, installation)
    require(session.owner_id() == value["owner_id"])
    document, signed = read(args.review), read(args.approval)
    require(document["schema"] == "vardr.worker-job-review/1"
            and signed["schema"] == "vardr.worker-job-approval/1"
            and document["setup_sha256"] == host.digest(value)
            and signed["review_sha256"] == host.digest(document)
            and signed["job_id"] == document["job_id"] and signed["selection"] == document["selection"])
    # Exactly one POST. An uncertain reply stays held; never retry or launch work.
    receipt = session.register_job(document["job_id"], {**signed["selection"], "approval": signed["approval"]})
    return {"schema": "vardr.worker-cli/1", "state": "job_registered", "runtime_id": None,
            "job_id": document["job_id"], "receipt": receipt, "worker_started": False}

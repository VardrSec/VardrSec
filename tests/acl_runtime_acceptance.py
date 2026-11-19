"""Check the installed ACL payloads on the same images exercised by Full acceptance."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import recovery
import updater

SERVICES = ("db", "api", "web", "runner")
OUTPUT = Path("artifacts/acl-runtime")
JOINT_RECEIPT = Path("artifacts/installed-gate/accepted.json")

RUNTIME_CHECK = (ROOT / "qualification/kerberos-image/acl-runtime-check.sh").read_text(encoding="utf-8")


def installed_selection(root):
    path = root / ".active-images.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16384:
        raise ValueError("Expected a small regular Full image selection file")
    frozen = path.read_bytes()
    services = json.loads(frozen)["services"]
    if set(services) != recovery.SERVICES:
        raise ValueError("Expected the full installed service set")
    selected = {name: definition["image"] for name, definition in services.items()}
    if not all(isinstance(image, str) and recovery.IMAGE_ID.fullmatch(image) for image in selected.values()):
        raise ValueError("Frozen selection requires immutable image IDs")

    # The resolved Compose model can contain credentials. Retain only its project and image IDs.
    model, installed = updater.image_set(root)
    configured = {name: service["image"] for name, service in model["services"].items()}
    if configured != selected or installed != selected:
        raise ValueError("Installed or configured images differ from the frozen selection")
    # Resolve the original build model independently of the installed image overlay.
    base = recovery.command(
        "docker", "compose", "--env-file", str(root / ".env"), "-f", str(root / "compose.yaml"),
        "--profile", "tools", "config", "--format", "json", cwd=root, capture_output=True, text=True,
    )
    build_services = json.loads(base.stdout)["services"]
    aliases = {}
    for name in SERVICES:
        alias = build_services[name]["image"]
        if not build_services[name].get("build") or recovery.IMAGE_ID.fullmatch(alias) or "@" in alias:
            raise ValueError(f"Expected a build alias for {name}")
        image = recovery.command("docker", "image", "inspect", "--format", "{{.Id}}", alias,
                                 capture_output=True, text=True).stdout.strip()
        if image != selected[name]:
            raise ValueError(f"Build alias differs from the frozen selection for {name}")
        aliases[name] = alias
    return {
        "project": model["name"],
        "build_aliases": aliases,
        "images": selected,
        "active_images_sha256": hashlib.sha256(frozen).hexdigest(),
        "manifest_sha256": recovery.digest(root / "versions.json"),
    }


def capture(root):
    if (root / JOINT_RECEIPT).exists():
        raise ValueError("Joint acceptance receipt already exists before smoke")
    selection = installed_selection(root)
    public = root / OUTPUT
    public.mkdir(parents=True, exist_ok=False)
    recovery.json_write(public / "baseline.json", selection)


def verify(root):
    public = root / OUTPUT
    baseline = json.loads((public / "baseline.json").read_bytes())
    if (public / "verdict.json").exists():
        raise ValueError("ACL runtime verdict already finalized")
    receipt = root / JOINT_RECEIPT
    if receipt.is_symlink() or not receipt.is_file():
        raise ValueError("Joint acceptance receipt missing")
    accepted = receipt.read_bytes()
    if not json.loads(accepted).get("jobs"):
        raise ValueError("Joint acceptance receipt contains no jobs")
    if installed_selection(root) != baseline:
        raise ValueError("Installed selection or distribution manifest changed during smoke")

    images = {}
    for name in SERVICES:
        image = baseline["images"][name]
        result = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--entrypoint", "sh", image, "-ec", RUNTIME_CHECK],
            check=False, capture_output=True,
        )
        (public / f"{name}-acl.log").write_bytes(result.stdout)
        (public / f"{name}-acl.stderr.log").write_bytes(result.stderr)
        images[name] = {
            "image_id": image, "returncode": result.returncode,
            "evidence_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        }
        (public / f"{name}-acl.result.json").write_text(json.dumps(images[name], indent=2) + "\n", encoding="utf-8")

    failed = [name for name, evidence in images.items() if evidence["returncode"]]
    recovery.json_write(public / "verdict.json", {
        "status": "FAIL" if failed else "PASS", "images": images,
        "baseline_sha256": recovery.digest(public / "baseline.json"),
        "joint_acceptance_sha256": hashlib.sha256(accepted).hexdigest(),
    })
    if failed:
        raise ValueError("ACL runtime check failed for " + ", ".join(failed))
    print("PASS: joint acceptance and installed ACL payloads verified")


if __name__ == "__main__":
    if sys.argv[1:] not in (["capture"], ["verify"]):
        raise SystemExit("Expected capture or verify")
    {"capture": capture, "verify": verify}[sys.argv[1]](ROOT)

"""Check the database selected by a real Full installation against its receipt."""

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import recovery


def main():
    receipt_path = os.environ.get("VARDRSEC_DATABASE_RECEIPT")
    if receipt_path:
        receipt = json.loads(Path(receipt_path).read_text())
        local_id = receipt["image_id"]
        config_id = receipt.get("origin", {}).get("config_id")
    else:
        pin = json.loads((ROOT / "versions.json").read_text())["images"]["db"]
        config_id = pin["config_id"]
        local_id = subprocess.check_output(
            ["docker", "image", "inspect", "--format", "{{.Id}}", pin["reference"]], text=True
        ).strip()
    frozen = json.loads((ROOT / ".active-images.json").read_text())
    if frozen["services"]["db"]["image"] != local_id:
        raise ValueError("Frozen database differs from the qualified local image")
    container = recovery.compose(ROOT, "ps", "--quiet", "db", project=os.environ["COMPOSE_PROJECT_NAME"],
                                 capture_output=True, text=True).stdout.strip()
    running_id, selected_ref = subprocess.check_output(
        ["docker", "container", "inspect", "--format", "{{.Image}} {{.Config.Image}}", container], text=True
    ).split()
    if running_id != local_id:
        # Some image stores expose the platform config on the running container.
        if selected_ref != local_id or running_id != config_id:
            raise ValueError("Running database differs from the qualified local image and platform config")
    if not receipt_path:
        seconds = float((Path(os.environ["RUNNER_TEMP"]) / "full-install-seconds").read_text())
        fixture = os.environ.get("VARDRSEC_TEST_DB_REGISTRY")
        if fixture:
            staging = Path(fixture)
            layers = json.loads((staging / "manifest.json").read_text())["layers"]
            with (staging / "registry.log").open("rb") as stream:
                stream.seek(int((staging / "before-install-log-offset").read_text()))
                gets = "\n".join(line for line in stream.read().decode().splitlines()
                                 if 'http.request.method=GET' in line or '"GET /v2/' in line)
            if not layers or any("/blobs/" + layer["digest"] not in gets for layer in layers):
                raise ValueError("The install did not fetch every qualified image layer from the registry")
        result = ROOT / "artifacts/installed-gate/database-pull.json"
        result.parent.mkdir(parents=True, exist_ok=True)
        result.write_text(json.dumps({"reference": pin["reference"], "config_id": config_id,
                                      "local_id": local_id, "running_id": running_id,
                                      "registry": "loopback fixture" if fixture else "release",
                                      "full_install_seconds": seconds}, indent=2) + "\n")
        print(f"Fresh Full install including database download and verification took {seconds:.2f} seconds.")
    print(f"Verified frozen and running PostgreSQL image {local_id}")


if __name__ == "__main__":
    main()

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
    receipt = json.loads(Path(os.environ["VARDRSEC_DATABASE_RECEIPT"]).read_text())
    local_id = receipt["image_id"]
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
        if selected_ref != local_id or running_id != receipt.get("origin", {}).get("config_id"):
            raise ValueError("Running database differs from the qualified local image and platform config")
    print(f"Verified frozen and running PostgreSQL image {local_id}")


if __name__ == "__main__":
    main()

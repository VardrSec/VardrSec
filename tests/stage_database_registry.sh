#!/usr/bin/env bash
# Stage the qualified candidate outside Docker's image store on a disposable CI host.
set -euo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
[[ -z "${VARDRSEC_DATABASE_RECEIPT:-}" && ! -e .env && ! -e .sources ]]
work=$(mktemp -d "$RUNNER_TEMP/db-registry.XXXXXXXX")
root=$PWD
repo=127.0.0.1:39563/vardrsec/vardrsec-db

# Use the signed Ubuntu package without installing or starting a system service.
(
    cd "$work"
    apt-get download docker-registry
    dpkg-deb -x docker-registry_*.deb registry-package
)
cat > "$work/registry.yml" <<EOF
version: 0.1
storage:
  filesystem:
    rootdirectory: $work/blobs
http:
  addr: 127.0.0.1:39563
EOF
"$work/registry-package/usr/bin/docker-registry" serve "$work/registry.yml" > "$work/registry.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for _ in {1..20}; do
    kill -0 "$pid"
    if curl -fsS http://127.0.0.1:39563/v2/ >/dev/null 2>&1; then break; fi
    sleep 1
done
curl -fsS http://127.0.0.1:39563/v2/ >/dev/null

bundle="$RUNNER_TEMP/db-pull-test.tar"
python3 scripts/ci/database_bundle.py unpack-receipt "$bundle" "$work/producer.json"
tar -xOf "$bundle" image.tar.zst | zstd -dq -o "$work/image.tar"
rm -- "$bundle"
skopeo copy --dest-tls-verify=false --digestfile "$work/manifest-digest" \
    "docker-archive:$work/image.tar" "docker://$repo:candidate"
digest=$(cat "$work/manifest-digest")
skopeo inspect --tls-verify=false --raw "docker://$repo@$digest" > "$work/manifest.json"
skopeo inspect --tls-verify=false --config "docker://$repo@$digest" > "$work/config.json"
python3 - "$work" "$repo" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

import database_image
from image_evidence import archive_config_id

work, repo = Path(sys.argv[1]), sys.argv[2]
manifest = (work / "manifest.json").read_bytes()
digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
assert digest == (work / "manifest-digest").read_text().strip()
config_id = json.loads(manifest)["config"]["digest"]
config = json.loads((work / "config.json").read_text())
assert (config["os"], config["architecture"]) == ("linux", "amd64")
receipt = json.loads((work / "producer.json").read_text())
details = {"Id": receipt["image_id"], "Os": "linux", "Architecture": "amd64",
           "RootFS": {"Layers": config["rootfs"]["diff_ids"]}}
assert archive_config_id(work / "image.tar", details) == config_id
assert receipt["inputs"] == database_image.build_inputs(Path.cwd())

# Make a test checkout whose only release destination is the loopback registry.
# No receipt, registry override or environment pin is passed to the installer.
source = Path("database_release.py")
entry = 'REPOSITORY = "ghcr.io/vardrsec/vardrsec-db"'
text = source.read_text()
assert text.count(entry) == 1
source.write_text(text.replace(entry, f'REPOSITORY = "{repo}"'))
versions = Path("versions.json")
data = json.loads(versions.read_text())
assert data["images"] == {}, "Use the real published digest once this release has a DB pin"
data["images"]["db"] = {"reference": repo + "@" + digest, "config_id": config_id,
                        "platform": "linux/amd64", "inputs": receipt["inputs"]}
versions.write_text(json.dumps(data, indent=2) + "\n")
PY
rm -- "$work/image.tar"
git -C "$root" add -- database_release.py versions.json
git -C "$root" -c user.name='CI registry fixture' -c user.email='ci@localhost' \
    -c commit.gpgsign=false commit -qm 'Select the isolated registry for this installation test'
config=$(jq -er '.config.digest' "$work/manifest.json")
for image in "$config" "$repo@$digest"; do
    if docker image inspect "$image" >/dev/null 2>&1; then
        echo 'The clean installation already has the database image' >&2
        exit 1
    fi
done
stat -c %s "$work/registry.log" > "$work/before-install-log-offset"
echo "VARDRSEC_TEST_DB_REGISTRY=$work" >> "$GITHUB_ENV"
# The hosted runner reaps the registry process at job cleanup.
trap - EXIT

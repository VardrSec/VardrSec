#!/usr/bin/env bash
# Exercise authenticated transport without a repository key or a database rebuild.
set -euo pipefail
umask 077
RUNNER_TEMP=$(mktemp -d "$RUNNER_TEMP/database-transport-test.XXXXXXXX")
export RUNNER_TEMP GITHUB_ENV="$RUNNER_TEMP/github-env" CACHE_KEY=fixture-cache-key
PASSPHRASE=$(openssl rand -hex 32)
export PASSPHRASE
image_id=''
cleanup() {
    if [[ -n "$image_id" ]]; then docker image rm "$image_id" >/dev/null 2>&1 || true; fi
    rm -rf -- "$RUNNER_TEMP"
}
trap cleanup EXIT

# Import a unique single-file image locally; the fixture never runs or leaves this job.
openssl rand -hex 32 > "$RUNNER_TEMP/fixture"
image_id=$(tar -C "$RUNNER_TEMP" -cf - fixture | docker image import --platform linux/amd64 -)
python3 - "$image_id" "$RUNNER_TEMP/fixture.json" <<'PY'
import json
from pathlib import Path
import sys
import database_image

receipt = {"schema": 1, "platform": database_image.PLATFORM, "image_id": sys.argv[1],
           "inputs": database_image.build_inputs(Path.cwd())}
Path(sys.argv[2]).write_text(json.dumps(receipt), encoding="utf-8")
PY
bash scripts/ci/database_bundle.sh save "$RUNNER_TEMP/fixture.json"
docker image rm "$image_id"

reject_load() {
    if env "$@" bash scripts/ci/database_bundle.sh load; then
        echo 'Invalid database transport was accepted' >&2
        exit 1
    fi
    if docker image inspect "$image_id" >/dev/null 2>&1; then
        echo 'Invalid database transport reached the Docker daemon' >&2
        exit 1
    fi
    test ! -e "$RUNNER_TEMP/qualified-database.json"
    test ! -s "$GITHUB_ENV"
}
reject_load PASSPHRASE=wrong
reject_load CACHE_KEY=another-recipe
ciphertext="$RUNNER_TEMP/vardrsec-database.gpg"
cp "$ciphertext" "$ciphertext.valid"
python3 - "$ciphertext" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
PY
reject_load
mv "$ciphertext.valid" "$ciphertext"
bash scripts/ci/database_bundle.sh load
cmp "$RUNNER_TEMP/fixture.json" "$RUNNER_TEMP/qualified-database.json"
grep -Fx "VARDRSEC_DATABASE_RECEIPT=$RUNNER_TEMP/qualified-database.json" "$GITHUB_ENV"

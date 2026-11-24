#!/usr/bin/env bash
set -euo pipefail
docker run --rm --platform linux/amd64 --network none --read-only --user 65534:65534 \
  --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:mode=1777 \
  --mount "type=bind,src=$RUNNER_TEMP/recipient-lib,dst=/recipient,readonly" \
  --entrypoint /bin/sh "$1" -euc '
    printf "%s  %s\n" 48c720d78ad921e2f6d948ee4bf6d2e4bf5e2249e52a67a07f501c5a8b599815 /usr/bin/sqv | sha256sum -c -
    LD_TRACE_LOADED_OBJECTS=1 /usr/bin/sqv | grep "libnettle.so.8 => /"
    keyring=/usr/share/keyrings/debian-archive-keyring.gpg
    sqv --keyring "$keyring" --cleartext /recipient/InRelease --output /tmp/baseline
    export LD_LIBRARY_PATH=/recipient
    LD_TRACE_LOADED_OBJECTS=1 /usr/bin/sqv | grep -F "libnettle.so.8 => /recipient/libnettle.so.8"
    sqv --keyring "$keyring" --cleartext /recipient/InRelease --output /tmp/rebuilt
    cmp /tmp/baseline /tmp/rebuilt
    if sqv --keyring "$keyring" --cleartext /recipient/changed --output /tmp/reject; then exit 1; fi
    echo "PASS unchanged sqv verified signed metadata and rejected changed bytes with the recipient-built Nettle library."
  '

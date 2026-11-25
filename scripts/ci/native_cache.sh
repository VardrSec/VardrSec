#!/usr/bin/env bash
# Share only the two pinned package builds between trusted retry jobs.
set -euo pipefail
umask 077
password=${PASSPHRASE:?}
unset PASSPHRASE
[[ ${NATIVE_KEY:?} =~ ^full-native-v1-[0-9a-f]{64}$ && ${MAP_PIN:?} =~ ^[0-9a-f]{40}$ ]]
work=$(mktemp -d "${RUNNER_TEMP:?}/native-layers.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
store=$work/$NATIVE_KEY
stages=(openssl-build glibc-build)
limit=$((2 * 1024**3))
available=$(df -B1 --output=avail "$work" | tail -1)

manifest_digest() {
    jq -er --arg tag "$1" \
        '[.manifests[] | select(.annotations["org.opencontainers.image.ref.name"] == $tag) | .digest]
         | select(length == 1) | .[0] | select(test("^sha256:[0-9a-f]{64}$"))' "$store/index.json"
}

case "${1:-}" in
    warm)
        encoded=$(stat -c %s "$RUNNER_TEMP/vardrsec-native.gpg")
        # Room for the authenticated archive, its OCI store and the real build.
        if (( encoded > limit + 4 * 1024**2 || available < 3 * encoded + limit )); then
            echo "Insufficient space for the optional native cache; using the ordinary retry builder."
            exit 1
        fi
        PASSPHRASE="$password" bash scripts/ci/database_bundle.sh authenticate \
            "$RUNNER_TEMP/vardrsec-native.gpg" "$work/bundle.tar"
        python3 scripts/ci/native_cache.py unpack "$work/bundle.tar" "$work" "$NATIVE_KEY"
        rm -- "$work/bundle.tar"
        # Fetch outside the install checkout. The interruption test still starts
        # with no .env, source checkouts or application images.
        map=$work/map
        git init --quiet "$map"
        git -C "$map" fetch --quiet --depth=1 https://github.com/VardrSec/VardrMap.git "$MAP_PIN"
        git -C "$map" checkout --quiet --detach FETCH_HEAD
        ;;
    save)
        if (( available < 2 * limit )); then
            echo "Insufficient space to export an optional native cache."
            exit 0
        fi
        map=.sources/map
        mkdir "$store"
        ;;
    *) exit 2 ;;
esac
[[ $(git -C "$map" rev-parse HEAD) == "$MAP_PIN" ]]
[[ -z $(git -C "$map" status --porcelain --untracked-files=all --ignored -- frontend) ]]

for stage in "${stages[@]}"; do
    if [[ $1 == warm ]]; then
        digest=$(manifest_digest "$stage")
        # A cache-only solve can leave lazily imported layers attached to this
        # client session. Mount the complete stage once on the persistent builder
        # before removing the local OCI store and starting the real installer.
        { cat "$map/frontend/Dockerfile"; printf '\nFROM %s AS native-cache-ready\nRUN --network=none ["/bin/true"]\n' "$stage"; } |
            docker buildx build --builder full-native-ci --platform linux/amd64 --progress plain --file - \
                --target native-cache-ready --cache-from "type=local,src=$store,digest=$digest" \
                --output type=cacheonly "$map/frontend"
    else
        # Sequential named exports share base blobs without racing index.json.
        docker buildx build --builder full-native-ci --platform linux/amd64 --progress plain --target "$stage" \
            --cache-to "type=local,dest=$store,tag=$stage,mode=min,compression=zstd" \
            --output type=cacheonly "$map/frontend"
        if (( $(du -sb "$store" | cut -f1) > limit )); then
            echo "Native layer cache exceeds 2 GiB; keeping normal source builds."
            exit 0
        fi
    fi
done

if [[ $1 == save ]]; then
    for stage in "${stages[@]}"; do manifest_digest "$stage" > /dev/null; done
    tar -C "$work" -cf - "$NATIVE_KEY/oci-layout" "$NATIVE_KEY/index.json" "$NATIVE_KEY/blobs/sha256" |
        PASSPHRASE="$password" bash scripts/ci/database_bundle.sh encrypt-native
    echo 'ready=true' >> "$GITHUB_OUTPUT"
else
    echo "Prepared the pinned OpenSSL and glibc stages for the retry in ${SECONDS}s." >> "$GITHUB_STEP_SUMMARY"
fi

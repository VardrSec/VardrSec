#!/usr/bin/env bash
set -euo pipefail
umask 077
case "${1:-}" in
    save|load) stage=${RUNNER_TEMP:?} ;;
    authenticate|import-verified) stage=$(dirname -- "${3:?private output path required}") ;;
    *) exit 2 ;;
esac
work=$(mktemp -d "$stage/qualified-db.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir "$GNUPGHOME"
passphrase=${PASSPHRASE:-}
unset PASSPHRASE
gpg=(gpg --no-options --batch --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3)

authenticate() {
    : "${passphrase:?missing database cache passphrase}"
    "${gpg[@]}" --status-fd 4 --output "$work/bundle.tar" --decrypt "$1" \
        3<<<"$passphrase" 4>"$work/status"
    grep -q '^\[GNUPG:\] NEED_PASSPHRASE_SYM ' "$work/status"
    grep -qx '\[GNUPG:\] GOODMDC' "$work/status"
    grep -qx '\[GNUPG:\] DECRYPTION_OKAY' "$work/status"
}

import_verified() {
    # Callers must authenticate the entire bundle before Docker sees any archive bytes.
    python3 scripts/ci/database_bundle.py unpack-receipt "$1" "$work/receipt.json"
    tar -xOf "$1" image.tar.zst | zstd -dq | docker image load
    python3 scripts/ci/database_bundle.py verify-local "$work/receipt.json"
    ln -T -- "$work/receipt.json" "$2"
}

case "$1" in
    save)
        : "${passphrase:?missing database cache passphrase}"
        cp -- "${2:?qualification receipt required}" "$work/receipt.json"
        image_id=$(jq -er '.image_id' "$work/receipt.json")
        # An ID-only save carries no installation-specific tag to a different host.
        docker image save "$image_id" | zstd -q -T2 -2 -o "$work/image.tar.zst"
        printf '%s\n' "$CACHE_KEY" > "$work/cache-key"
        tar -C "$work" -cf - cache-key receipt.json image.tar.zst |
            "${gpg[@]}" --rfc4880 --cipher-algo AES256 --force-mdc --compress-algo none \
                --output "$RUNNER_TEMP/vardrsec-database.gpg" --symmetric 3<<<"$passphrase"
        ;;
    load)
        receipt="$RUNNER_TEMP/qualified-database.json"
        authenticate "$RUNNER_TEMP/vardrsec-database.gpg"
        import_verified "$work/bundle.tar" "$receipt"
        echo "VARDRSEC_DATABASE_RECEIPT=$receipt" >> "$GITHUB_ENV"
        ;;
    authenticate)
        authenticate "$2"
        ln -T -- "$work/bundle.tar" "$3"
        ;;
    import-verified) import_verified "$2" "$3" ;;
esac

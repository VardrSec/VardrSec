#!/bin/sh
# Run without a network as the unprivileged Docker build user.
set -eu
inputs=/work/krb5-inputs
trap 'rm -rf /build/source /build/local-ccache /build/home' EXIT
cp "$inputs"/krb5_* /repo/db/* /build/
export HOME=/build/home LANG=C.UTF-8 CCACHE_DIR=/build/local-ccache
mkdir "$HOME" "$inputs/compiler-cache"
export CCACHE_REMOTE_STORAGE="file://$inputs/compiler-cache"
. /repo/qualification/kerberos-vm/compiler-cache.sh
start=$(date +%s)
sh /build/build-krb5.sh --seed-compiler-cache > /tmp/native-krb5.log 2>&1 || {
    tail -n 40 /tmp/native-krb5.log
    exit 1
}
# Publish the manifest only after the file backend has stored a complete result.
ccache --print-stats | awk '$1 == "remote_storage_write" && $2 > 0 { wrote=1 } END { exit !wrote }'
cd "$inputs/compiler-cache"
find . -type f -print0 > /tmp/krb-cache-files
LC_ALL=C sort -z /tmp/krb-cache-files | xargs -0 -r sha256sum > ../compiler-cache.tmp
test -s ../compiler-cache.tmp
mv ../compiler-cache.tmp ../compiler-cache.sha256
printf 'Native Kerberos compilation took %ss\n' "$(($(date +%s) - start))"

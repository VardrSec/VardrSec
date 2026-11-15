#!/usr/bin/env bash
# Archive inert legal texts or module download sources. Requires GNU tar/find/sort.
# Does not modify input files, raw build logs, or module ZIP content.
set -euo pipefail
if [ "$#" -ne 3 ]; then
    echo 'usage: canonical_module_archive.sh notices|sources ROOT OUTPUT.tar[.gz]' >&2
    exit 2
fi
mode=$1
root=$2
output=$3
case "$output" in /*.tar|/*.tar.gz) ;; *) echo 'output must be absolute .tar or .tar.gz path' >&2; exit 2;; esac
case "$mode" in notices|sources) ;; *) echo 'unknown archive mode' >&2; exit 2;; esac
# Refuse overwriting an earlier artifact, including symlinks. The caller must
# choose an output outside ROOT; keeping output separate avoids self-inclusion.
if [ -e "$output" ] || [ -L "$output" ]; then echo 'output exists' >&2; exit 2; fi
root=$(realpath -e "$root")
parent=$(realpath -e "$(dirname "$output")")
case "$parent/" in "$root/"*) echo 'output must be outside input tree' >&2; exit 2;; esac
cd "$root"
files() {
    if [ "$mode" = notices ]; then
        find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0
    else
        find . -type f \( -name '*.zip' -o -name '*.mod' -o -name '*.info' -o -name '*.ziphash' \) -print0
    fi
}
archive() {
    files | LC_ALL=C sort -z | tar --null --verbatim-files-from -T - \
        --format=gnu --hard-dereference --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --mode=0644 -cf -
}
# noclobber also protects against a concurrent ordinary file appearing.
set -C
case "$output" in
    *.tar.gz) archive | gzip -n -9 > "$output" ;;
    *.tar) archive > "$output" ;;
esac

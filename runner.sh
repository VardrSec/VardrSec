#!/usr/bin/env bash
# Without a separator all arguments belong to Runner; wrapper options need --.
if (( $# == 1 )) && [[ "$1" == -h || "$1" == --help ]]; then
    printf '%s\n' 'Usage: ./runner.sh [Runner arguments]' \
        './runner.sh [--authority-volume NAME] [--input-directory DIR] [--output-directory DIR] -- <Runner arguments>'
    exit 0
fi
separator=0
for item in "$@"; do [[ "$item" == -- ]] && separator=1; done
if (( ! separator )); then set -- -- "$@"; fi
python=
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then python=$candidate; break; fi
done
if [[ -z "$python" ]]; then printf '%s\n' 'Python 3.10+ is required; use an existing Python installation.' >&2; exit 2; fi
root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 2
if [[ ! -f "$root/vardrsec.py" ]]; then printf '%s\n' 'Run this launcher from the VardrSec checkout.' >&2; exit 2; fi
exec "$python" "$root/vardrsec.py" runner "$@"

#!/usr/bin/env bash
# Thin installer selector; vardrsec.py owns installation behavior.
usage() {
    printf '%s\n' 'Usage: ./install.sh [--full | --mapless] [Python installer arguments]' \
        'Full: Map interface + Runner/Gate + database/proxy. Mapless: Runner/Gate CLI only.'
}
mode=; help=0; forward=()
for item in "$@"; do
    case "$item" in
        --full) [[ -z "$mode" || "$mode" == full ]] || { usage >&2; exit 2; }; mode=full ;;
        --mapless) [[ -z "$mode" || "$mode" == mapless ]] || { usage >&2; exit 2; }; mode=mapless ;;
        -h|--help) help=1 ;;
        *) forward+=("$item") ;;
    esac
done
if (( help )); then usage; exit 0; fi
if [[ -z "$mode" ]]; then
    if [[ ! -t 0 || ! -t 1 ]]; then usage >&2; exit 2; fi
    usage
    printf '%s' 'Choose full or mapless: '
    IFS= read -r mode || exit 2
    case "$mode" in full|mapless) ;; *) printf '%s\n' 'Choose full or mapless explicitly.' >&2; exit 2 ;; esac
fi
python=
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then python=$candidate; break; fi
done
if [[ -z "$python" ]]; then printf '%s\n' 'Python 3.10+ is required; use an existing Python installation.' >&2; exit 2; fi
root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 2
if [[ ! -f "$root/vardrsec.py" ]]; then printf '%s\n' 'Run this launcher from the VardrSec checkout.' >&2; exit 2; fi
exec "$python" "$root/vardrsec.py" install "--$mode" "${forward[@]}"

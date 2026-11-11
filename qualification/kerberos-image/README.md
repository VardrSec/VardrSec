# Qualified Kerberos candidate database image

This is an isolated acceptance workflow, not a production build path or release.
It consumes artifact 13875193642 from successful VM run 43060945526, at
`ea358d51a89d401125be73112aa381a066a71d8f`. The archive is pinned by SHA256;
its successful offline-build receipt, full source manifest, four package hashes,
and current build inputs are checked before any candidate build. Expired or
changed artifacts fail closed. There is no unqualified-build fallback.

`prepare.py` generates a temporary database recipe, substituting only the
Kerberos source-build stage with the already qualified package/source bytes.
The remaining database recipe is unchanged, including the libxml2 and gosu
builds. `db/Dockerfile` itself is not edited. The generated recipe and custody
receipt are retained with the image identity.

`verify.sh` checks source delivery, all installed package bytes, package versions,
and PostgreSQL initialization/CREATE/INSERT/SELECT/DROP in a disposable,
network-disabled container without published ports or persistent database data.
Debian slim deliberately omits nine specific changelog/README/lintian files.
These omissions are accepted only for the exact paths and verified inherited
dpkg exclusion rules; every present byte, all runtime libraries and all four
copyright files must match. No security setting is relaxed.

Passing this workflow does not qualify the whole distribution or publish an
image. Its review artifacts expire after 14 days. Production integration needs
a durable, reviewed source/package custody mechanism and a fresh explicit
merge/release decision. `reproduce.py` can separately verify two successful,
independently prepared VM package builds; whole-image reproducibility remains
a distinct requirement.

## Verified result, 2026-11-11

- Actual candidate image acceptance: [run 43071041475](https://github.com/VardrSec/VardrSec/actions/runs/43071041475), head `2eeee11`.
- Independent successful package builds: [43060945526](https://github.com/VardrSec/VardrSec/actions/runs/43060945526) and [43068431525](https://github.com/VardrSec/VardrSec/actions/runs/43068431525).
- Artifact IDs: `13875193642` and `13878068362`, respectively.
- All four complete runtime `.deb` files are byte-identical across separately
  prepared VM disks, with identical substantive build inputs and installed
  dependency inventories. Both runs passed full Debian package tests and the
  final stripped-library regression. See `reproduction-evidence.json`.
- Scope is linux-amd64 Kerberos packages only. The complete image has other build
  inputs and is **not** claimed reproducible. No release clearance is implied.

Reproduce the comparison after downloading both exact GitHub artifact ZIPs:

```sh
python qualification/kerberos-image/reproduce.py \
  first.zip 5cb8a64e59f2ff8f945adfa934e4e989d62fec754751f38f70bf3765495fdae9 \
  second.zip 3b04ad8e6b1dd95836b9348d8f18bdba5479eb741d4338adf9312f7c9de996f9 \
  reproduction-evidence.json
```

## Offline custody and normal Compose candidate build

Keep the exact first ZIP (including its complete source and evidence), second ZIP
and comparison receipt in your own durable storage. GitHub retention is not a
permanent distribution mechanism. No release endpoint or new registry is created
by this work. The checks below operate on local ZIP files without accessing
GitHub. Building the remaining database recipe still needs its existing network
sources; this is not an offline full-image build.

Use a **fresh isolated checkout** of this branch, never an existing installation:

```sh
python qualification/kerberos-image/reproduce.py \
  first.zip 5cb8a64e59f2ff8f945adfa934e4e989d62fec754751f38f70bf3765495fdae9 \
  second.zip 3b04ad8e6b1dd95836b9348d8f18bdba5479eb741d4338adf9312f7c9de996f9 \
  reproduction-evidence.json
python qualification/kerberos-image/prepare.py first.zip . db/qualified-krb5
python vardrsec.py configure
docker compose -f compose.yaml -f qualification/kerberos-image/compose.candidate.json build db
bash qualification/kerberos-image/verify.sh vardr-db-qualified-candidate
```

The explicit override changes only the database build recipe and candidate image
alias; all runtime configuration remains inherited and unchanged. `build db`
does not start the stack, create database volumes, or touch running services.
The smoke test separately creates and removes its own temporary, network-disabled
container. Do not use `up`, `install`, `update`, or tag/push a release based on
this candidate evidence. Ordinary default builds are not silently switched to
these packages. Promoting this path remains a separate reviewed decision.

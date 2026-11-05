# New Moon acceptance ledger

Updated: 2026-11-05. Development evidence; no release acceptance is implied.

This ledger tracks changing implementation evidence. The approved New Moon charter
remains the architectural authority: one Runner engine, optional Map, shared
authorization, independent Gate/Lab, and separate distribution lifecycle.
Windows 11 is the primary target, Docker Desktop is preferred, Linux compatibility
and justified native Runner operation remain required.

## Fresh source baseline

Recovery was limited to reachable Git source. The unavailable handoff commits
`f605c1f` and `3cdbaa4` are not assumed to have been recovered or reproduced.
Existing security and NM-3 implementation were retained; new checks establish
their behavior independently of historical test counts.

| Component | Source used for fresh baseline | Evidence boundary |
|---|---|---|
| Runner | `96772dd5403653c7e4786c8906e6ea4d9fc6e396` | Native Windows 11, Python 3.14.3: 2,415 passed, 66 skipped, 95.24% coverage. |
| Distribution | `4998e5dfd1554beec88690880c4ac269d4f12240` | Baseline unit suite: 162 run, one CRLF-fixture error, 12 skipped. |
| Map | `45d4286190039462b942a69615214d6e480fb0ee` | Fifteen owned-execution/claim checks on disposable SQLite. |
| Gate | `2df03368007e7b632f2fbaf2ecdcfb7bb6efe0ec` | Pure-Go suite: 762 test/subtest passes across 21 packages; vet and native build passed. |

The exact Map/Runner/Gate baseline cohort also passed 152 real loopback integration
checks, including strict semantic evidence and platform diagnostics. Request bounds
and loopback-only assertions passed. These results do not establish a PostgreSQL
installation, a managed background worker or Docker Desktop distribution acceptance.

Earlier test attempts exposed environment setup failures: sandboxed loopback access,
snapshot/import mismatch and missing declared shell dependencies. They were corrected
and rerun, without suppressing the affected tests. Keep the failing receipts distinct
from the successful baseline. Skipped checks retain their individual reasons.

## Verified development corrections

Runner commit `440ebda7405d9f19f2e5c6f954996b525f0ac5da` passed the fresh native
Windows 11 suite: **2,474 passed, 66 skipped, 95.32% coverage**. The same source
passed Linux container regression as nonroot with networking disabled: **2,491
passed, 49 skipped, 95.69% coverage**. The real POSIX directory-substitution
regression passed. Lint, formatting, both platform type checks and medium/high
security checks passed. All nine jobs in the existing
[cross-platform CI run](https://github.com/VardrSec/VardrRunner/actions/runs/42097439568)
passed, including Linux Python 3.10–3.14, Windows, macOS and dependency audit.

- Full installation must preserve retained proxy CA/config state even if database
  and Runner volumes are absent. A new regression failed before the correction;
  the distribution suite afterward ran 163 tests with no failures/errors and 12
  skips. Four skips need official `age` tools; eight need native symlink privilege.
- Journal connections use canonical DB/WAL names. Windows retains verified
  database/ancestor handles through connection close and refuses observed identity
  changes. POSIX replacement, sidecar replacement and strict snapshot safety remain
  open; see Runner ADR 0042.
- Automatic age cleanup preserves journal-linked evidence and refuses incomplete
  retention inventory. Destructive cleanup requires supported descriptor-relative
  confinement; unsupported runtimes preserve old data while execution remains usable.
- Separate-process CLI tests verify local workspace persistence without Map
  credentials, a real keychain, network access or tool launches.
- The real native standalone Gate check passed with the built Gate binary: all five
  phases, fourteen bounded requests, preserved case binding, no Map calls and no
  additional replay traffic. Active cancellation has separate acceptance tests.

The installer correction is distribution commit
`9e4b56f2f4b4e99891dbf8d2b7004bfa8a63beb7`. No distribution component pins have
advanced.

## Current compatible source verification

The final PostgreSQL checks use these exact Git-archived sources:

| Component | Commit |
|---|---|
| Map | `aad63c8151789cd9bf56864456b5fdf1fdcfde41` |
| Runner | `440ebda7405d9f19f2e5c6f954996b525f0ac5da` |
| Gate | `2df03368007e7b632f2fbaf2ecdcfb7bb6efe0ec` |

All 103 PostgreSQL migration, restricted-role, ownership, cancellation, grant and
budget/concurrency tests passed without skips. The strict real integration passed
152 checks against a migrated disposable PostgreSQL 18.6 database. TLS 1.3 with
full certificate/hostname validation passed; plaintext, wrong-hostname and
untrusted-CA connections refused. The fixture used isolated tmpfs data and a random
localhost port and was removed after identity checks. Retained installations were
not used as test fixtures.

Gate's complete Linux race suite passed all 21 packages and `go vet` passed with
Go 1.27.3 and a 64-bit compiler, using frozen source and offline module cache.
An extra offline `go mod verify` check lacked historical module metadata; that
limitation is recorded separately from the successful race/vet results. Native
Windows race-detector execution remains unavailable with the installed compiler.

This cohort is verified at source/integration level. It has not passed fresh Full
or Mapless installation/recovery as an installed distribution.
The existing [Gate duplicate-JSON guard correction](https://github.com/VardrSec/VardrGate/pull/29)
at `54536ea` remains unmerged. Review and freshly validate it before selecting the
installed cohort; the older baseline above is not acceptance of that known gap.

## Experimental work, not accepted capabilities

A six-case disposable Docker experiment demonstrated kernel-deadline cleanup of
a stopped owner and escaped descendants using existing Docker init. No product
capability was enabled. Trusted-init/main-child binding, hostile tracing,
suspend-aware expiry, lifecycle, authorization and evidence integration still need
review and negative tests. Managed Docker execution remains gated.

## Accepted direction and remaining work

| Gate | Current disposition | Required completion evidence |
|---|---|---|
| NM-1 | Substantial reusable groundwork; full exit not reaccepted by this ledger. | Shared contract/negative fixtures and deployment-feasibility decision tied to exact source. |
| NM-2 | Bounded Community baseline retained; original exit remains open. | Safe operator-enabled Compose worker, cancellation, disconnect/restart, grants and budgets. |
| NM-3 | Development implementation with fresh native evidence; incomplete. | Full and Mapless installation, authorized recon plus reviewed Gate, evidence/export, independent CLI, no-loss transition/recovery, Windows/Docker and Linux acceptance. |
| NM-4 | Sequenced after usable execution/distribution; still required. | Reviewed authorization coverage, assisted cases, structured provenance and bounded AI capabilities. |
| NM-5 | Final integrated acceptance remains open. | Independent benchmarks, frozen-cohort install/network/recovery matrix, supply-chain review and owner release decision. |

Recon and managed Docker execution remain disabled until their safety gates pass.
They are unfinished accepted requirements, not removed scope. Windows Server CI
does not substitute for fresh Windows 11 Docker Desktop acceptance. A passing
SQLite fixture does not substitute for the PostgreSQL ownership/migration path.

Mapless-to-Full automatic history import/synchronization may be a separate increment;
preservation and export are mandatory. NM-4/NM-5 remain in New Moon. New enrollment
services, replacement scanners and orchestration infrastructure require a demonstrated
gap in the existing components before implementation.

## Next acceptance sequence

1. Close POSIX/container containment and consistent non-mutating snapshot gates.
2. Prepare fresh installed acceptance for the verified source cohort; use an isolated
   host so development image tags cannot affect retained projects.
3. Advance distribution pins only with the reviewed installed-acceptance evidence.
4. Demonstrate Mapless install → authorize → recon → reviewed Gate → export/restart
   with Map inaccessible, and Full installation → approved queue → cancel/recover.
5. Complete Windows 11 Docker Desktop, Linux, recovery and native-exception evidence,
   then continue NM-4 and NM-5 against that same reviewed product.

Current unit/integration evidence is not permission to merge, release, publish
images, alter retained installations or waive a safety gate.

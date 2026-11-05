# Hosted Community Full candidate verification

Status: the installation and authorization boundary below passed on a fresh
GitHub-hosted Ubuntu 24.04/amd64 VM in
[run 42103819846](https://github.com/VardrSec/VardrSec/actions/runs/42103819846)
at workflow commit `2af5fd8300774434363d9701c321d7ba0c04096a`.
This is development evidence for the exact cohort below, not Community release
acceptance. Installed assessment and recovery verification are the next increment.
This reuses the branch-only Full harness from `ae19579f18f22da030a0abaa84938d4d44f1faa6`.
It runs only on a fresh GitHub-hosted Ubuntu 24.04/amd64 VM for a push to
`codex/nm3-community-full-verification`. Never invoke it against an operator daemon.

## Exact source cohort

| Component | Commit | Tree |
| --- | --- | --- |
| Distribution | `befe929870107c5a27d291078088fbceaeb58512` | `108948257cc3325f3c223757cf9abbfc7b11c44b` |
| Map | `aad63c8151789cd9bf56864456b5fdf1fdcfde41` | `3cda816378b8862ece82dc70aa6ad3667be0273c` |
| Runner | `440ebda7405d9f19f2e5c6f954996b525f0ac5da` | `0109814200968bebd055ef2629aa45b3dc6ade15` |
| Gate | `54536ea1d900d0e35adf93b4e026962c4d45d34a` | `211b1eec890ff910ee7f381da435897fe3feb15d` |

Production `versions.json` remains unchanged. The harness verifies its existing
base pins, copies only the exact distribution candidate's tracked files, and
changes component commits only in the private disposable fixture. It records
the fixture manifest hash and checks every acquired component commit and tree.
The candidate must be an ancestor of the workflow head; candidate source changes
are refused. A changed changelog is replaced with the candidate's original text.

Before installation, the selected Gate correction passed 791 native Windows
test/subtest checks across 21 packages, native vet/build, and 791 Linux race
test/subtest checks across the same packages with vet. A fresh standalone check
made fourteen bounded requests, preserved case binding and refused replay.
The exact Map/Runner/corrected-Gate cohort passed all 152 PostgreSQL integration
checks, including TLS negative controls. Native Windows race execution remains
unverified with the installed compiler; the Linux race result is separate evidence.

## Isolation and evidence

Host guards require the expected repository, branch, push event, GitHub-hosted
environment, Ubuntu version, architecture and root-owned local Docker socket.
Alternate source paths, Compose/Docker selection, application subnet settings and
injected Runner credentials are refused.
Before any installation, the local daemon must have no containers or volumes,
only its default networks, the expected root directory and inactive Swarm.

The fixture uses a new private Docker configuration and project name. Builds
therefore cannot overwrite retained local image tags or volumes on the operator's
shared engine. All component repositories are public; source acquisition requires
no new CI secret. Checkout does not persist its credentials.

Only the fixed sanitized `public/receipt.json` is uploaded. Generated passwords,
keys, configuration and raw installation output remain private on the VM.
Failure receipts retain fixed failure codes, the installer exit code when
available, and a bounded list of known installer step names. Raw log lines and
exception messages never enter that receipt.
The harness performs no teardown, pruning or trust-store enrollment; the hosted
platform disposes of the VM. Focused tests exercise refusal and receipt behavior
with synthetic local files and mocked Docker observations, never a real daemon.

## Acceptance boundary

The hosted run checks one-command installation, CA-validated HTTPS/readiness,
local bootstrap/login, CSRF refusal without mutation, scoped Runner key issuance,
database/migration readiness and authenticated Runner diagnostics. Before and
after those checks, only database, API, web and proxy services may be running.
No scan or background Runner is started.

The retained sanitized receipt reports installer exit code zero and all six
standard steps: configure, sources, build, database-role, start and export-ca.
Its fixture manifest SHA-256 is
`ff7e6b6140ad66f472a59a3bb10e8b9000a4d23e38792550f3d7725d7eebd520`.
The receipt confirms every check in this boundary and verifies the expected
service set before and after diagnostics. No raw logs, credentials or private
fixture files were uploaded.

This does not establish an installed authorized assessment, UI workflow, recovery,
upgrade/no-loss transition, Mapless installation, native Windows or Docker Desktop
acceptance. Journal/snapshot safety and controlled Docker execution retain their
separate gates. These requirements remain in the [acceptance ledger](new-moon-acceptance.md).
No merge, release, publication or deployment is authorized by this verification.

## Installed lifecycle extension

The next hosted run uses `--installed-lifecycle` on the same fresh-host guard and
source cohort. The existing browser journey owns first-account bootstrap and key
creation; it is not run after the separate smoke bootstrap, which would change
that first-run condition. The unchanged installed workflow exercises reviewed
Gate cases, bounded write/readback and retest, evidence, reports and stop/start
retention against synthetic targets only.

The extension reuses encrypted backup, authenticated unseal and the bundled
restore command in a separate project. It checks the candidate's actual
`0038managedstops` schema, exact image IDs, original database and volume
fingerprints, retained Runner state, CA identity, restored evidence, session
revocation after password reset and authenticated diagnostics. It does not run
the older migration drill's synthetic revisions against this newer schema.
The original source installation remains stopped and retained after backup.

Browser output, assessment receipts, credentials, the age identity, encrypted
package and restored data remain private on the disposable VM. Only whitelisted
stage names, failure codes and completed-check booleans may enter the public
receipt. This extension is prepared for execution; it has not yet passed.

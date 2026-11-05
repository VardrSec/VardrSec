# Hosted Community Full candidate verification

Status: prepared for independent review; no installed acceptance is claimed.
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

This does not establish an installed authorized assessment, UI workflow, recovery,
upgrade/no-loss transition, Mapless installation, native Windows or Docker Desktop
acceptance. Journal/snapshot safety and controlled Docker execution retain their
separate gates. These requirements remain in the [acceptance ledger](new-moon-acceptance.md).
No merge, release, publication or deployment is authorized by this verification.

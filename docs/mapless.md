# Standalone Community workflow

This is the development Full/Mapless integration. Compatible component pins and
installed acceptance must be completed before describing it as a delivered
Community release. Windows 11 with Docker Desktop Linux containers and Ubuntu
24.04 remain required; no native-only substitute is selected.

## Install and keep state

In a separate clean distribution checkout, with Python 3.10+, Git, Docker and
Compose 2.17+ available:

To coexist with another installation, choose a distinct `COMPOSE_PROJECT_NAME`
before installing (`export COMPOSE_PROJECT_NAME=assessment-local` on Linux,
`$env:COMPOSE_PROJECT_NAME='assessment-local'` in PowerShell). Keep it set until
installation completes. The installed image record then preserves the selected
project across shells; a restored installation preserves its separate project.

```sh
python3 vardrsec.py install --mapless
python3 vardrsec.py doctor
python3 vardrsec.py runner -- workspace create "Local assessment"
```

On Windows use `python` for the same commands. Keep the returned workspace ID.
The mode marker selects the Mapless model on subsequent commands. Installation
builds the pinned Runner/Gate toolkit and creates a stopped Runner container.
Its project-scoped build tag does not replace Full's development tag. Installation
then selects the exact local image ID for subsequent commands and recovery.
It creates no Map account, database, proxy, trusted certificate or background
worker. `start` prepares the stopped CLI; `stop` preserves volumes. Installation
refuses existing Full or Mapless state rather than migrating or resetting it.

## Authorize one assessment

Use an operator-chosen private Docker volume for the signing key. It is separate
from Runner execution state and is mounted only for these two issuer commands:

```sh
python3 vardrsec.py runner --authority-volume assessment-issuer -- \
  workspace authority-init WORKSPACE_ID --output /issuer/assessment
```

Put the reviewed unresolved `case.json` and optional `execution.json` in a flat
private host directory named `assessment-inputs`. Use the existing Gate case
format and credential reference names; keep secret values in the operator's
environment. The authorization command shows the exact plan and requires typing
`APPROVE` in the terminal:

```sh
python3 vardrsec.py runner --authority-volume assessment-issuer \
  --input-directory assessment-inputs --output-directory authorization -- \
  workspace authorize WORKSPACE_ID --authority /issuer/assessment \
  --case /inputs/case.json --execution /inputs/execution.json \
  --output /exports/bundle --expires-in 900
```

Omit `--execution` to use existing bounded defaults. In PowerShell put the command
on one line instead of using the shell continuation above. Output destinations
must be new. The wrapper stages private input copies under a protected host
directory, mounts only those copies read-only, and transfers output from the
stopped container with host-user ownership. Original file permissions stay intact.

The bundle contains exactly six public authorization documents. It contains no
signing key, but unresolved case data remains private engagement data. Keep the
issuer volume; recreating a volume or issuer is not authority recovery.

## Execute, inspect and export

Run one explicitly selected signed job. For example, if the case references
`OWNER_TOKEN`, provide its value privately in the caller's environment, set
`VARDRRUNNER_WORKER_CREDENTIAL_ENV` to `OWNER_TOKEN`, then run:

```sh
python3 vardrsec.py runner --controlled --input-directory authorization/bundle \
  --output-directory assessment-result -- --env OWNER_TOKEN
```

For multiple references the declaration is a comma-separated list, and each
reference needs its own `--env NAME`. No secret value appears in the command.
Private targets additionally require the existing explicit private-target policy;
an approved hostname does not authorize other destinations.

This foreground one-shot mode reuses the native containment owner, existing
signed authorization ledger, credential grants, finite leases and job journal.
Its temporary root bootstrap drops to the established owner/SDK identities;
ordinary Runner remains UID 10001 with no capabilities. The signing volume is
never mounted into execution. There is no queue polling or automatic retry.

Successful execution retains original evidence in Runner state and copies the
existing redacted export to `assessment-result/result/` (`artifact.json`,
`audit.json`, `manifest.json`). Inspection uses the same journal:

```sh
python3 vardrsec.py runner -- audit list --engagement WORKSPACE_ID --json
python3 vardrsec.py runner -- audit show RUN_ID
python3 vardrsec.py runner --output-directory recovered-export -- \
  audit export-run RUN_ID --output /exports/result
```

A failed export does not undo execution or restore a spent permission. The
wrapper uses a fresh export volume and retains it with its named stopped container
if transfer fails; recover its export
or use the journal commands. Never rerun a consumed bundle to recover files.

## Recovery and remaining capabilities

Use [encrypted backup and restore](encrypted-backups.md) for the whole Runner
state and exact toolkit image. The separate issuer volume is deliberately outside
execution backup: retain it and keep a separately protected operator backup before
moving hosts. Restoring execution state does not issue new permission or replay a
job. Controlled Mapless updates and automatic Full/Mapless migration remain
deferred; separate installations and explicit evidence export preserve data.

This path targets the existing fixed HTTP Gate assessment. The dormant
Recon projection still refuses executable use until its exact tool bytes and
destination/count enforcement are connected. C09 sleep acceptance, general Recon,
independent benchmarks and release acceptance remain separate roadmap gates;
these are not silently accepted or removed.

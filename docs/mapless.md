# Mapless installation and first assessment

This is the canonical CLI-only source-built path using the **same Runner and
Gate** as Full, without Map, PostgreSQL, an account or an API key. For the web
workspace, use the separate [Full installation](installation.md). No automatic
history or identity migration connects the modes; keep their checkouts and state
separate. This is development software, not a published Community release.

Follow steps 1–3 for a signed Gate assessment, then keep the state and issuer
backups in step 4. Finite Recon and the local assistant are optional workflows
after that path. Read the [support limits](limitations.md) first.

## 1. Install and create a workspace

Use Windows 11 Docker Desktop with Linux/amd64 containers or Ubuntu 24.04/amd64.
Install Python 3.10+, Git, Docker and Compose 2.17+ first, then check that Docker
is running and accessible. Use a private directory outside synchronized folders.
See [platforms](platforms.md) for experimental and unsupported environments.

Create a separate clean checkout:

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec-mapless
cd vardrsec-mapless
```

To coexist with another installation, choose a distinct `COMPOSE_PROJECT_NAME`
before installing (`export COMPOSE_PROJECT_NAME=assessment-local` on Linux,
`$env:COMPOSE_PROJECT_NAME='assessment-local'` in PowerShell). Keep it set until
installation completes. The installed image record then preserves the selected
project across shells; a restored installation preserves its separate project.

Windows PowerShell:

```powershell
.\install.ps1 --mapless
py -3 vardrsec.py doctor
.\runner.ps1 workspace create "Local assessment"
```

Ubuntu:

```sh
./install.sh --mapless
python3 vardrsec.py doctor
./runner.sh workspace create "Local assessment"
```

Both installers delegate to `vardrsec.py install --mapless`. The remaining
examples use `python3`; on Windows replace it with `py -3` and use one line
instead of Bash's `\` continuations. Keep the returned workspace ID.
The mode marker selects the Mapless model on subsequent commands. Installation
builds the pinned Runner/Gate toolkit and creates a stopped Runner container.
Its project-scoped build tag does not replace Full's development tag. Installation
then selects the exact local image ID for subsequent commands and recovery.
It creates no Map account, database, proxy, trusted certificate or background
worker. `start` prepares the stopped CLI; `stop` preserves volumes. Installation
refuses existing Full or Mapless state rather than migrating or resetting it.

Docker chooses the Runner bridge subnet automatically by default. If its automatic
address pools are exhausted, select an unused IPv4 `/24` with
`python3 vardrsec.py install --mapless --runner-subnet SUBNET_CIDR`. For a prepared
installation whose network creation was interrupted, use
`python3 vardrsec.py start --runner-subnet SUBNET_CIDR`. The explicit selection is
checked for overlap with existing Docker networks and retained with the installed
project/image selection. Existing networks, including retained fixture networks,
are left untouched; this option does not add a service or change Runner privileges.

## 2. Authorize one Gate assessment

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

## 3. Execute, inspect and export

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

## 4. Back up and maintain the installation

Use [encrypted backup and restore](encrypted-backups.md) for the whole Runner
state and exact toolkit image. The separate issuer volume is deliberately outside
execution backup: retain it and keep a separately protected operator backup before
moving hosts. Restoring execution state does not issue new permission or replay a
job. State-compatible Mapless image updates use the existing
[controlled updater](updates.md#mapless-updates), leaving Runner stopped.
Runner storage migrations and automatic Full/Mapless migration remain deferred;
separate installations and explicit evidence export preserve data.

This path supports the fixed HTTP Gate assessment and explicit finite Recon
profile described below. The older Recon projection remains dormant; execution
requires the separately compiled profile and verified managed tool bytes.
Controlled execution across suspend/resume is not qualified. Broader Recon,
independent benchmarks and release review remain outside this workflow’s claims.

## Optional workflows

### Finite Recon

The compatible Runner source also provides explicit `workspace authorize
--profile recon`. Prepare exact DNS seeds, numeric resolvers, destination CIDRs
and original HTTPS/443 GET-root candidates, then use the same private issuer,
six-document bundle, controlled execution and export commands below. The complete
input format and review procedure are in Runner's
[finite Recon walkthrough](https://github.com/VardrSec/VardrRunner/blob/cc15dec86574d595c84f323aec813c241b4e56f8/docs/finite-recon.md).

Recon binds both managed tool hashes and consumes one finite permission across
DNS and HTTP. It preserves the original Host/TLS name while connecting to a
validated numeric address. Discovered URLs require a new review and a separate
Gate authorization. No background execution is enabled.

### Review a local Recon candidate

Derive review-only Gate cases from an existing
successful finite Recon run through the same Docker Runner and export transfer:

```sh
python3 vardrsec.py runner --output-directory gate-drafts -- \
  workspace draft-gate WORKSPACE_ID --run RECON_RUN_ID --output /exports/drafts
```

Inspect `gate-drafts/drafts/artifact.json`. Its `cases` contain only observed
candidates, with empty identities and access decisions. Copy the selected `spec`
into your private `case.json`, review the actual request, supply credential
references and decide expected access yourself. Then issue a new Gate
authorization through the existing issuer workflow. Discovery and a draft grant
no execution permission; neither the previous Recon bundle nor its export can
authorize the new case.

### Optional local assistant metadata

The toolkit includes the optional MCP SDK. Configure an MCP
client to launch the canonical Python entrypoint directly with raw stdio:

```sh
python3 vardrsec.py runner -- mcp --standalone
```

Use `python` on Windows. This explicit session reads only local workspace and
workspace-bound run metadata from the installed Runner volume. It needs no Map
account, endpoint or API token and exposes no execution, approval or export tool.
Keep transfer, issuer and controlled-execution options out of this command.

The existing exclusive installation lock remains held for the session. Close the
MCP client before canonical issuer, execution or maintenance commands. Concurrent
MCP/canonical CLI operation is not claimed by this cohort; no new lock service or
background execution authority is introduced. The ordinary CLI workflow does not
require MCP.

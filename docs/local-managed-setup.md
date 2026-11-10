# Local Full managed setup

Source-built development path, available for owner acceptance. Matched component
pins passed existing installation, recovery and compatibility checks. Windows
Full preparation and restricted enrollment passed at `c8adbfe`; that observation
started no worker or job. The supported review/sign/register, execution and
evidence-export path subsequently passed one explicitly owner-approved synthetic
Windows observation. Human usability and the owner walkthrough remain separate;
this is not release acceptance.
Mapless retains its independent [signed local workflow](mapless.md).

Normal installation and `start` run the Full core services only. The commands
below separately prepare custody, configure an enrolled Runner, approve a finite
job and explicitly start a worker. None is called automatically by installation.
Use a clean source-built Full installation, its trusted local CA and local account.
The selected local Docker context must satisfy the existing managed launch
baseline, including Compose 5.6.1; these commands never install or downgrade Docker.

## Prepare and connect

From the Full checkout, authenticate interactively:

```powershell
python vardrsec.py worker prepare --credential-name OWNER_TOKEN --credential-name PEER_TOKEN
python vardrsec.py worker configure --allow-plaintext-key
```

Preparation builds the existing persistent-worker recipe from the exact pinned
Runner source and frozen toolkit. It discovers the selected Docker client and
records its executable hashes, context, installation, network and state binding.
It creates separate operator and contract signing volumes. The private keys
never enter command arguments, host metadata or worker mounts. An optional
`--worker-image sha256:...` selects an already built image explicitly.

Preparation prints the metadata location in a dedicated sibling operator
directory. Its `worker.env` contains empty placeholders for the named target
credentials. Fill those values privately before starting a worker; do not paste
them into chat or shell history. Omit credential-name options only for cases
that genuinely require no credentials. Credential values and local credential
grants are separate; neither the file nor worker availability authorizes a job.
For the authorized private-network fixture, explicitly add
`VARDRRUNNER_ALLOW_PRIVATE_TARGETS=1` to this private file and pass
`--allow-private-targets` to job-review. Keep that runtime setting aligned with
the signed plan; do not list it as a target credential name.

Configure explicitly enables the existing managed API configuration and enrolls
the original Runner identity. `--allow-plaintext-key` accepts storage of its
restricted Runner API key in the existing protected Docker state. It cannot
approve jobs. An unbound preexisting connection is refused rather than replaced.
Subsequent configuration reuses the exact binding; revoked or uncertain state
is held for inspection rather than silently renewed.

## Review one job and explicitly start

In Map, create the engagement scope, written authorization and reviewed Gate
case. Select the Gate-only managed authorization option when queueing the case;
copy the displayed job ID. Ordinary queueing keeps its existing behavior.

```powershell
python vardrsec.py worker job-review JOB_ID --output review-one
python vardrsec.py worker job-approve --review review-one/review.json --output approval-one
python vardrsec.py worker job-register --review review-one/review.json --approval approval-one/approval.json
```

Review interactively selects the engagement and authorization, compiles the
fixed plan with the actual worker's Gate binary and requests current backend
context. If the case needs environment references absent from the prepared
worker's declared names, review holds before requesting approval context and
lists only those names. Correct the case's references or select a correctly
prepared worker; no credential values or grants are inferred.
Signing displays that context and requires typing `APPROVE` in a
terminal. Registration binds the signed envelope to the exact review. Each
default approval permits one execution, 30 seconds and 1 MiB of artifacts,
expires after five minutes, and remains subject to target, credential,
concurrency, cancellation and evidence checks. Expiration is not a retry grant.

Before starting the worker, establish each required local credential grant.
Use the reviewed engagement ID, the Map API URL as the grant issuer, and the
case's target origin (not the Map URL) as the grant origin. For example:

```powershell
.\runner.ps1 credentials approve --issuer https://vardrsec.localhost:8443/backend --engagement ENGAGEMENT_ID --origin http://gate-fixture.test:8000 --env OWNER_TOKEN --expires-in 600
.\runner.ps1 credentials approve --issuer https://vardrsec.localhost:8443/backend --engagement ENGAGEMENT_ID --origin http://gate-fixture.test:8000 --env PEER_TOKEN --expires-in 600
python vardrsec.py worker start
```

Use the actual target origin from the supplied case; these example URLs grant
nothing to other targets. Replacing a local grant changes its identity, so do not
renew it while a job relies on the original grant. Private-network targets also require both the signed
review opt-in and the existing explicit runtime opt-in; neither is implied by
being local. Use only the supplied authorized synthetic target during acceptance.

Worker start uses the existing persistent-v3 launch and custody gates. It never
downgrades to a finite or legacy protocol. Availability continues until explicit
stop; `--max-attempts` and `--idle-timeout-seconds` are optional finite-session
controls. Subsequent start requires physical predecessor exit, Map retirement
and original Runner reconciliation. A held result preserves state for inspection.
Use the returned runtime ID with the existing [status/stop/report controls](nm2-worker-operator.md).

Inspect the completed job and evidence in Map, confirm findings yourself, then
export the report through the existing research workflow.

## Retain evidence and stop

Use the original Runner journal to identify the completed run for this job.
`ENGAGEMENT_ID` is the engagement selected during job review; select `RUN_ID`
from the returned records by the exact job ID, rather than assuming the latest
run belongs to this job:

```powershell
python vardrsec.py runner -- audit list --engagement ENGAGEMENT_ID --json
python vardrsec.py runner -- audit show RUN_ID
python vardrsec.py runner --output-directory full-export -- audit export-run RUN_ID --output /exports/result
```

Choose a new host output directory. The portable export is in
`full-export/result/`: `artifact.json`, `audit.json` and `manifest.json`.
This journal export is separate from Map's research report. An export failure
does not undo execution or restore a spent approval; recover files from the
original run instead of queueing or executing the job again.

Stop the exact worker using the runtime ID returned by `worker start` and the
`private_root` recorded in the preparation metadata. Keep that metadata and
its custody directory; do not substitute a newly prepared worker:

```powershell
python vardrsec.py worker stop --runtime-id RUNTIME_ID --private-root PRIVATE_ROOT --report
python vardrsec.py worker reconcile --runtime-id RUNTIME_ID --private-root PRIVATE_ROOT
python vardrsec.py runner -- audit reconcile-managed RUN_ID
python vardrsec.py stop
```

Host `reconcile` reads the server receipt; it does not retire the original
Runner's local metadata. `audit reconcile-managed` uses that original Runner
state and still-active enrolled key to reconcile the exact run. Keep Map running
until this step completes; neither command refunds spent authorization.

Confirm physical exit and `terminal_observed`. A held or uncertain result needs
the existing [recovery controls](nm2-worker-operator.md); do not clear its state
or repeat an uncertain report. Platform stop preserves volumes and evidence.
Stopping core services alone is not a substitute for stopping the separately
enabled managed worker.

## Recovery boundary

Held setup commands include a fixed failure category and a link to this guide.
Expected configuration refusals use `validation_refused`; local I/O failures
retain `local_io_failed`, and unexpected failures remain `operation_failed`.
Raw exceptions and credentials are never included. Preserve held state before
inspecting the requirements; a diagnostic is not permission to repeat an
uncertain enrollment or replace existing authority.

The setup pointer and private operator directory are installation-specific.
Platform backups preserve the executable helpers but do not export these external
signing volumes or make their private keys portable. Retain their custody
separately. Restoring a platform backup does not enable managed API operation or
a worker. Ordinary core recreation can remove the explicit managed override;
reapply it only with `worker configure` and the original retained setup. Pending
updates and active execution retain the existing refusal safeguards. Partial
preparation or uncertain enrollment is never adopted automatically.

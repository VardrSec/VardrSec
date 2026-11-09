# Local Full managed setup

Implementation candidate; installed qualification and matching component pins
remain pending. Do not substitute this page for a passed owner walkthrough.
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
python vardrsec.py worker start
```

Review interactively selects the engagement and authorization, compiles the
fixed plan with the actual worker's Gate binary and requests current backend
context. Signing displays that context and requires typing `APPROVE` in a
terminal. Registration binds the signed envelope to the exact review. Each
default approval permits one execution, 30 seconds and 1 MiB of artifacts,
expires after five minutes, and remains subject to target, credential,
concurrency, cancellation and evidence checks. Expiration is not a retry grant.

Establish each required local credential grant through Runner's existing
`credentials approve` command for the selected issuer, engagement and exact
origin before execution. Private-network targets also require both the signed
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

## Recovery boundary

The setup pointer and private operator directory are installation-specific.
Platform backups preserve the executable helpers but do not export these external
signing volumes or make their private keys portable. Retain their custody
separately. Restoring a platform backup does not enable managed API operation or
a worker. Ordinary core recreation can remove the explicit managed override;
reapply it only with `worker configure` and the original retained setup. Pending
updates and active execution retain the existing refusal safeguards. Partial
preparation or uncertain enrollment is never adopted automatically.

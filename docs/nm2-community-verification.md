# NM-2 isolated Community verification candidate

This is local test preparation, not a pin adoption, runnable release or acceptance.
The owner must authorize publication and external execution before the first push
of `codex/nm2-community-verification` to `VardrSec/VardrSec`.

The branch-scoped [workflow](../.github/workflows/nm2-community.yml) starts two
separate fresh GitHub-hosted Ubuntu24.04/amd64 jobs. It does not require Railway,
Vercel, live credentials, live targets, privileged containers or Docker socket
mounts. Repository `versions.json` remains unchanged. Only new run-owned copies
receive explicit verification manifests.

| Component | Supported old combination | Current candidate |
|---|---|---|
| Map | `41d3ef6475f1b81f973dd4a73944b6e549500fd6` | `9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045` |
| Runner | `668dc56f8685dc6a6225438ad443e26901828069` | `602a5423dcede0e37dacad52aab3bdad900c9021` |
| Gate | `7f82e499ec407eba072e129e3f3b94f1a4eabe94` | same |

## Coverage intended by the two jobs

The **clean** job preserves the genuine clean-host preflight and normal install,
then tests native trusted HTTPS, local authentication, the existing explicit
six-scenario installed Map→Runner→Gate journey, restart and security probes.
It also tests restricted database roles, legacy role upgrade and recovery, then
normal whole-install encrypted backup/unseal/fresh restore at schema0038, including
database/table/sequence fingerprints, images, Runner/proxy state, CA, evidence,
access and an intentional migration failure. No automatic worker is enabled.

The **upgrade** job starts the exact old combination at schema0031 and runs its
installed journey. It separately acquires clean exact current sources and builds
candidate images with distinct tags; the existing supported PostgreSQL image is
reused exactly, as required by the normal updater. The
[real upgrade fixture](../tests/community_upgrade_acceptance.py) passes immutable
five-image IDs to the existing controlled updater, including normal backup and
private rehearsal, and requires actual0031→0038. It checks old-column row
multiplicity, sequence definitions/state, role, CA and state preservation, existing
Gate evidence readback, anonymous-access rejection and the normal updater receipt.
Only the newly issued diagnostic key's `last_used_at` is normalized for its expected
authentication telemetry; that exact UUID/column is separately checked against
database time bounds and monotonicity. Other old columns and keys remain checked.

The [orchestrator](../tests/community_ci.py) verifies source HEADs and clean trees,
records candidate images and source identities, and exports only a sanitized
summary with stage outcomes and receipt hashes. A failed, interrupted, skipped or
unobserved check is not acceptance. Actual hosted execution is still unrun.

## Existing data and retention boundary

The workflow refuses existing fixture directories, nonfresh initial Docker state,
wrong host/repository/branch, remote Docker selectors and source/config overrides.
Tests use an explicit fresh-run ownership marker and validate ownership before
stopping retained fixtures. The legacy role drill refuses existing work instead of
removing it. No volume teardown, Docker prune, CA removal or deletion of existing
installations is included. Unrelated PR workflows are not triggered by this
branch-only push; do not open a PR before reviewing their separate cleanup paths.

Normal product semantics remain: Compose may recreate service containers; normal
CLI/recovery/updater transport containers use `--rm`; successful updates remove a
transient pending marker after saving their durable result. This candidate does
not claim to retain every temporary container object or change product lifecycle
code. Test-owned persistent volumes, work directories, backups and private logs
remain through the job; the outer orchestrator stops owned services on exit.

**GitHub discards the entire VM after the job.** Unexported fixture volumes,
plaintext/encrypted snapshots, age identity, generated credentials, CA private keys
and private logs then disappear. Only the allowlisted summary is uploaded, with
seven-day Actions retention; stage it separately before expiry if durable evidence
is required. No private recovery package or raw log is exported. Summary hashes
do not make the underlying private artifacts independently retrievable later.
Any request to preserve raw recovery data needs a separately approved private
destination and decryption-identity custody; never upload those files publicly.

Native CA testing deliberately uses sudo to enroll the new fixture's public CA in
the new disposable VM, proves default native curl rejection before enrollment and
verified HTTPS afterward. It changes that fresh VM's trust store. No Papachin,
cloud/shared host or existing trust store is altered. Explicit CA removal and
rejection-after-removal are **unrun** in this retention-compatible cohort.

## Limits and fail-closed capacity checks

Standard public GitHub Ubuntu runners currently document14GB SSD, not a guaranteed
amount of free space for retained image exports. Conservative capacity checks stop
the cohort rather than prune data. The clean/upgrade jobs are separated; if either
cannot fit, report capacity as a concrete blocker. A larger hosted runner is a
separate availability/authorization decision, not an automatic configuration change.

This candidate does not seed nonempty new managed-worker authority/accounting/
receipt/tombstone tables. Full fingerprints include their schema and current
contents, but an empty table is not proof of nonempty managed-state recovery.
Existing component PostgreSQL tests remain separate evidence. Do not claim that
additional stateful gate passed from these jobs. The historical certificate-renewal,
native trust removal and synthetic controlled-update failure workflows are not
freshly rerun by this branch-only workflow; their current applicability remains
explicit in acceptance review. No existing security assertion is removed or
waived by this test preparation.

Managed Docker execution remains disabled and unsupported; its watchdog-hang gate
remains failed/open under the authorized bounded scope exception. Windows-native
cancellation and current20/20 native Gate evidence remain separately bound. Scoped
review of this preparation is not the designated independent phase acceptance.

## Publication authority and disclosure history

### Focused service-lookup correction

Both diagnostic summaries locate their failure at Runner container discovery:
upgrade during its state snapshot, and clean recovery through backup. The original
hosted count is unknown, so neither migration failure nor completed-restore failure
is established. A small isolated Compose2.40.3 check demonstrated that `ps --all`
includes retained one-shots: one was previously selected as the service; two caused
ambiguity; adding a stopped canonical container still returned all three.

Recovery now selects exactly one container with known canonical identity, excluding
known one-shots and refusing unknown, wrong-service, wrong-explicit-project or
duplicate canonical identities. The upgrade state fixture explicitly uses create
with no-build/no-recreate/pull-never to prepare a stopped Runner container before
mount discovery. It never invokes a Runner command. Labels and flags are supported
in the minimum Compose2.17 source; actual focused runtime verification used2.40.3.

The follow-up validation targets the23 changed recovery/upgrade cases. Unchanged
diagnostic/privacy/component evidence remains available at its exact source hashes.
Full cohorts are appropriate only after both diagnostic failures are understood;
their later paths and acceptance remain unproven until observed. No retained
container, volume, old evidence or existing environment is deleted by this fix.

### Approved diagnostic follow-up

The owner authorized a narrowly bounded diagnostic update and rerun of the two
necessary cohorts after the initial stage failures. Both old capacity guards
passed; neither generic `ValueError` establishes that migration execution itself
failed or that backup caused both failures.

The two fixture CLIs opt in with `--safe-diagnostics`. Test-only wrappers restore
original functions and re-raise the original exception. Only fixed substage IDs,
operation states and allowlisted error codes cross the public boundary. No raw
exception text or class names, command arguments, environment, paths, logs, keys
or recovery packages are exported. The reader rejects unknown/duplicate fields,
unknown values, incomplete terminal records, symlinks/nonregular files and records
over1024 events/128KiB. Invalid or missing diagnostics remain unavailable, never
acceptance. A diagnostic operation state is not a test/phase verdict; expected
negative operations can fail within a passing drill.

Follow-up CI runs the affected diagnostic, cohort-helper and fixture-baseline
regressions. Unchanged component CI and unrelated distribution unit evidence are
reused. Only the clean cohort builds host age tools, because the actual-upgrade
cohort uses normal unencrypted updater backup. Both still perform their unchanged
normal source builds and necessary fresh synthetic installation/journey setup:
the previous VMs and unexported fixture state were discarded as authorized.

No trust, containment, assertion, pin or data-retention boundary is relaxed by this
diagnostic permission. Publication of the reviewed diagnostic commit to the same
branch automatically starts those two jobs under the owner's follow-up authority.

The original request, subsequently authorized by the owner, covered:

1. Publish the named reviewed commit to the new public distribution review branch
   using a normal fast-forward push. This discloses the verification source and
   automatically starts this workflow and the existing manifest-only foundation
   workflow. No draft PR, main merge, release or image publication is included.
2. Execute the two fresh Ubuntu jobs, including their isolated synthetic credential
   generation, explicit fixture Gate execution, ephemeral CA enrollment, ordinary
   product temporary-container lifecycle and eventual GitHub VM disposal.
3. Upload only the sanitized per-job summary to public Actions artifacts for seven
   days; private fixture material is not exported and expires with the VM.

Owner approval of those actions does not declare the four Community paths passed.
Read the terminal exact-SHA outcomes and retained receipts first. Replacement of
the personal Railway comparison remains conditional on demonstrated equivalent
supported Community coverage; no Railway deployment is required for this workflow.

# Proposed Full restored-state installer check

This unpublished branch prepares a distinct regression for installer
`8fcc4aa4b2df55514b464192eb0efc77bb7b62d5` and its unchanged Full pins. No remote
run is authorized by preparing this branch. Publish only after exact behavior
review. It triggers only on `codex/nm3-full-preservation-verification` pushes;
no PR, manual/main trigger, release or production deployment is added.

## Why this check

Fresh installation passed in run 41959113683 at workflow commit `6b53e25`.
The older NM-2 community run 41730266134 passed at `f289a0ce378b9fce382fdaa50a9cc09d4a73f2d4`;
its broader upgrade harness and historical assertions do not test the new installer
project-resolution guard. Neither result establishes this new sequence:

1. Fresh install the exact current Full pinned stack on an empty GitHub-hosted VM daemon.
2. Add two synthetic database rows with a sequence in the fixture only.
3. Use unchanged `recovery.backup` and `recovery.restore` into a new restore project.
4. Run the corrected `install` command in that restored checkout, with the source
   project's process override removed. Recovery's `.env` is the project authority.
5. Require the specific existing-install refusal before source acquisition, and
   compare source/restored database row and sequence fingerprints, named-volume
   content/ownership/mode fingerprints, configuration and public-CA-file digests.
   Revalidate the retained backup and restored image mapping as well.

This targets an erroneous reinitialization after restore. It does not repeat the
older successful/failing migration images, browser journey, encrypted age roundtrip,
account/session tests, upgrade or Mapless-to-Full transition. The underlying backup
and restore assertions remain owned by the existing recovery module.

## Isolation and exact side effects for review

Reuse the already-reviewed hosted guard and source copier from the fresh-install
workflow: fresh GitHub-hosted Ubuntu 24.04, local matching empty non-Swarm daemon,
no preexisting containers/volumes/custom networks, no Docker/config/source overrides,
new private fixture paths, exact unchanged installer files and component pins.
The new callback runs only after that guarded fresh installation completes.

The job would build/start the existing Full stack, add synthetic fixture rows,
quiesce source application services for backup, export private configuration,
PostgreSQL data, named-volume archives and exact image archives, then restore into
new volumes/networks/project. Restored applications remain stopped; only the restored
database runs. Source data remains retained. Existing helpers may read synthetic
credentials internally; all private output is captured on the VM.

**Existing helper behavior requiring explicit review:** `recovery.volume_stream`
and `volume_fingerprint` use `docker run --rm --network none` for temporary offline
maintenance containers. Docker automatically removes those helper containers after
exit. The helpers do not remove their named data volumes. Source applications are explicitly stopped by backup for quiescence. There is no
fixture down/prune/rm teardown, no backup/data/volume/CA deletion, no OS CA enrollment,
no encrypted staging cleanup, and no change to production recovery behavior. If
retention must also forbid automatic helper-container removal, this workflow must
remain blocked; do not silently patch or bypass the recovery implementation.

The conservative existing NM-2 capacity formula requires four times total image
size plus 2 GiB free before data seeding/backup. Insufficient space refuses without
pruning, changing storage or deleting anything. Resource sufficiency remains unmeasured.
Normal hosted VM disposal is external platform behavior, not durable retention.

## Evidence limits

Only the fixed public receipt is uploaded for seven days; repository readers may
see it. Additional preservation fields are five literal boolean verdicts. No raw
logs, exception text, paths, fingerprints, keys, config, database rows, archives or
CA material are exported. No hosted run starts until this exact behavior is reviewed.

A pass would cover the current Full pinned stack's synthetic backup/restore and
restored-install refusal. It would not establish an NM-3 component cohort, Mapless,
Windows, live SQLite snapshot non-mutation, journal replacement-race safety,
unrelated native/external data discovery, broad upgrade or no-loss transition
acceptance. These remain separate gates.

## Existing portable-recovery limitation found during review

`recovery.FILES` does not include `database_roles.py`, although restore imports it.
This driver intentionally calls the unchanged recovery module from the retained
original checkout, where that dependency exists. It does not certify a standalone
restored checkout's ability to perform future role maintenance or another restore.
That existing portability gap remains open; this workflow does not patch the bundle
or add a substitute implementation. The restored installer-refusal path does not
reach role maintenance.

The source-preservation comparison begins after backup has quiesced applications
and created its snapshot. It proves retention through restore/refusal, not that
backup preserved every pre-backup physical byte. The five receipt flags are scoped
accordingly; broader backup/restore and no-loss acceptance remain open.

The verification-only additions are recorded here rather than changing the existing
installer changelog: every tracked installer-candidate file must remain byte-identical
for the source guard to bind this run to the reviewed candidate.

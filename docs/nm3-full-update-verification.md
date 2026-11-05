# Candidate-specific Full same-image update verification

This isolated branch targets recovery/updater source
`07307a2707eefd772f00eeac6d4977680f854c4d` with unchanged Full component pins.
The earlier NM-2 drill already exercised successful/failing migration images,
private rehearsal, cancellation and post-mutation recovery. The completed NM-3
fresh-install and bundled restore runs establish their own journeys. This check
adds actual updater consumption of the version-4 bundle and shared version-aware
source-file checks. It does not repeat schema-migration images or claim an upgrade
to new component versions.

The exact branch push trigger is `codex/nm3-full-update-verification`. Reused
source and hosted guards require the bound candidate files, fresh GitHub-hosted
Ubuntu 24.04, matching empty local non-Swarm Docker daemon, no existing
containers/volumes/custom networks or inherited config/source/secret overrides,
and private new fixture paths. No software install step is added. Standard
component builds retain their existing behavior.

After fresh installation, create only a synthetic initial account/API key through
the established TLS-verified localhost authentication and CSRF flow. Seed two
synthetic rows and a sequence. Reuse the existing manifest builder with exactly
the current immutable image IDs; source pins do not change.

Run the actual updater. Its private rehearsal restores a v4 backup, starts the
rehearsal services without published proxy ports and runs the existing explicit
Runner doctor --platform --offline diagnostics. These still contact the local
synthetic platform; offline disables release discovery, not all networking. The harness injects a
KeyboardInterrupt only after that real verification succeeds and before the
original source is mutated. Require a failed rehearsal-phase record, stopped
source applications and blocked ordinary startup. Run real cancellation, which
revalidates backup/source state and resumes the pinned baseline. Then complete a
second real update using the same image IDs without fault injection.

Verify the seeded row fingerprint, dedicated sequence and public CA bytes across
both operations; inspect the completed/cancelled records and final image IDs;
revalidate the retained interrupted backup and require v4 for both backups.
This retention verdict does not cover all database/auth rows, Runner state or
private CA material. Other authentication/diagnostic records may legitimately change. This is not a
whole-database byte-invariance or general no-loss claim. Interruption injection
exercises the updater's caught preapply path, not hard power loss/SIGKILL.

Remote effects include fresh synthetic install/build, account/key creation,
private diagnostics, service stopping/restarting and forced proxy recreation,
two backup/image exports,
two retained rehearsal projects/volumes and loopback source republishing. No
production service, target scan, recon, unattended worker or Mapless is enabled.
The existing updater clears only its own synthetic pending-operation record on
success/cancellation. Existing temporary maintenance/diagnostic containers
self-remove. No explicit fixture teardown, named-volume/backup/data/CA deletion,
OS trust changes or image pruning. Capacity must exceed eight times total image
size plus four GiB before authentication/seeding; inability to fit fails closed.

Only the existing fixed receipt plus six literal boolean verdicts is uploaded,
visible to repository readers for seven days. Private credentials, logs, paths,
fingerprints and raw errors remain on the ephemeral VM. Normal platform VM
disposal is not durable backup retention.

Local verification is 14 focused harness tests plus static/diff checks. Independent
source review precedes publication. A pass covers this Full pinned stack's
same-image updater/interruption/cancellation journey with v4 snapshots. It does
not establish final NM-3 component-cohort installation, new-version migration,
Mapless-to-Full/no-loss, encrypted recovery, native Windows, SQLite snapshot
non-mutation, journal race resistance or hard-crash recovery acceptance.

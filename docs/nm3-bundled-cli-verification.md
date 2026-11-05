# Generated-bundle restore CLI verification

This verification branch extends the bundled recovery API harness that passed
run 41964729308. Installer source remains bound byte-for-byte to
`07307a2707eefd772f00eeac6d4977680f854c4d`, with unchanged Full component pins.
The new exact push trigger is `codex/nm3-bundled-cli-verification`; no PR/main
or manual trigger is added. Earlier branch-only workflow triggers remain inert
on this branch. No candidate source or production workflow behavior changes.

After generating a synthetic trusted backup on a guarded fresh GitHub-hosted
Ubuntu VM with an empty local daemon, the reviewed checkout validates its
manifest, exact entry list and archives and compares each executable file with
the source-bound checkout. No arbitrary external backup is executed.

The child uses `python -I -B`, adds only the generated bundle to application
imports and checks module origins. It runs the documented command
`python vardrsec.py restore --backup BUNDLE --destination NEW --project vardrsec-restore-NAME`
through `runpy.run_path(..., run_name='__main__')` with equivalent `sys.argv`, so
the real parser, dispatch, lock and exception handling determine its exit status.
There are no original-checkout application imports. Only exit status zero permits
verification to continue. Isolated Python is not a filesystem sandbox.

The CLI creates its own `.update-lock` in the synthetic bundle. It retains that
empty file after closing/releasing the lock; the harness reacquires/releases it
and checks its state. No lock file is deleted. The extra lock file is explicitly
permitted only after execution. Manifest-covered files and snapshot metadata must
remain unchanged. This is not a snapshot-non-mutation claim: a directory entry is
added and access metadata may change.

All previous source/restored synthetic database and named-volume fingerprints,
restored image mapping and installed-state refusal remain checked. Source-state
preservation is measured from after backup quiescence. Source apps stay stopped;
the restored database runs, while restored applications remain stopped.

Remote effects remain fresh synthetic installation/build, backup/image export,
image load, new restore project/volumes and offline helper containers. Only those
helpers auto-remove themselves. No explicit teardown, user state, existing
services, named-volume/backup/data/CA deletion, external scans, OS CA enrollment,
pin changes, Mapless activation, release or production deployment. Standard hosted
VM disposal remains platform behavior. Capacity refusal does not prune anything.

Only the allowlisted fixed public receipt is retained for seven days, visible to
repository readers; the new boolean is `bundled_recovery_cli_verified`. Private
logs, exceptions, secrets, configuration, paths, archive contents and fingerprints
are not uploaded. Child output is captured privately.

Local evidence: 12 focused harness tests, including the actual isolated bootstrap,
CLI parser and lock with restore mocked for success/failure; static/diff checks.
No full candidate suite is claimed rerun. Independent source review precedes push.
A hosted pass verifies this synthetic bundle's documented restore CLI and retained
state checks. It does not certify every portable command, encrypted roundtrip,
final NM-3 cohort, Windows, Mapless-to-Full/no-loss upgrade, SQLite non-mutation,
journal race resistance or untrusted-bundle execution.

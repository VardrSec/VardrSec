# Controlled development updates

Updates are operator-invoked and use a reviewed set of locally loaded image IDs.
There is no periodic updater, registry discovery, implicit pull or image publication.
Use Docker Compose 2.24.4 or later for maintenance port reset support. Keep the
installation in a private directory and finish Runner work before maintenance.

## Candidate manifest

Record a complete compatible set in a JSON file with exactly these fields:

```json
{
  "schema_version": 1,
  "public_origin": "https://localhost:8443",
  "images": {
    "db": "sha256:<64 hex characters>",
    "api": "sha256:<64 hex characters>",
    "web": "sha256:<64 hex characters>",
    "proxy": "sha256:<64 hex characters>",
    "runner": "sha256:<64 hex characters>"
  },
  "components": {
    "map": "<40-character source commit>",
    "runner": "<40-character source commit>",
    "gate": "<40-character source commit>"
  }
}
```

Replace every placeholder. Inspect trusted locally built/loaded images with
`docker image inspect IMAGE --format '{{.Id}}'`. Build candidates under separate
tags; do not overwrite the installed development aliases. The manifest is an
operator compatibility/provenance declaration, not a signature or attestation.
The public origin must match the installed frontend build and authentication
configuration. The database image must remain identical; PostgreSQL image/major
upgrades and Compose configuration changes require separate procedures.

Supply a valid Runner API key in `VARDRMAP_API_KEY`, then run:

```sh
python vardrsec.py update --candidate /private/candidate.json \
  --backup /private/backups/before-update \
  --destination /private/rehearsal --project vardrsec-restore-update-drill
```

Both destinations and the rehearsal project must be new. An exclusive installation
lock prevents competing VardrSec operations. The updater creates the portable
[backup](recovery.md), restores it to fresh volumes, and applies the candidate
there. Its maintenance proxy has no published host port. Runner checks HTTPS,
authentication and platform readiness through the private proxy. No scans run.

Before original mutation, the updater verifies that the source database, state
and installation files still match the snapshot. It then applies the same image
IDs to the original installation, still with the HTTPS port unpublished, and
requires health checks plus Runner diagnostics again. Finally it recreates the
normal loopback proxy and waits for its HTTPS health check. Session/ownership
behavior remains in Map's existing authorization implementation.

The backup and stopped rehearsal installation are retained for inspection.
Protect both as sensitive data; backups are unencrypted. Plan enough disk for
the image archive and restored state. Do not run Docker/Runner operations outside
VardrSec or edit files during maintenance; detected source drift aborts the update.

## Failure and interruption

`.update-state.json` records durable phases before mutation. Failed/interrupted
updates block ordinary `start`, `build` and `bootstrap`. An OS file lock releases
when the process exits, while the pending record remains. Preserve it and the
backup rather than deleting the record to force startup.

If original mutation has not begun (`preparing` or `rehearsal`), explicitly run
`python vardrsec.py cancel-update`. Where a complete snapshot exists, cancellation
revalidates it and verifies source state before resuming the pinned baseline.
After original application/publication begins, cancellation refuses an image
rollback: restore the recorded backup into a fresh installation using the
[credential-review procedure](recovery.md#restore-drill-before-an-upgrade).
No automatic data-deleting restore or migration downgrade occurs.

Successful updates clear the pending record and retain `.last-update.json` with
the exact images, declared component commits and recovery locations. Later
snapshots retain that audit record. `versions.json` remains the distribution's
source-build recipe; `.active-images.json` controls the running installation.
Version-one backups remain readable; new version-two backups include updater code.

The automated drill covers rejected rehearsal, verified cancellation, successful
update, failure during original migration and recovery from the saved snapshot.
Fresh-host Windows/macOS browser trust, long-term certificate renewal, encrypted
backup packaging and published release provenance remain separate release gates.

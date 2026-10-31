# Development backup, restore and upgrade recovery

Recovery is an explicit maintenance operation. Finish any invoked Runner command
first; backup refuses while a Runner container is executing. Keep configuration
secrets and the public URL in the private `.env`, matching the running services.
Shell-only overrides or edits not yet applied to containers are refused.

For encrypted retention, use `backup --recipient age1...` or seal a completed
working bundle; see [encrypted recovery packages](encrypted-backups.md).

```sh
python vardrsec.py backup --destination /private/backups/before-upgrade
```

The destination must be new. Backup stops proxy/web/API, leaves PostgreSQL available
for the logical dump, and never automatically resumes application traffic. The
bundle carries `.env`, distribution scripts/configuration/source pins, the exact
service images, PostgreSQL schema/data, Runner state/evidence and proxy CA/config.
Only `snapshot.json` marks completion; a failed partial directory is not a valid
backup. Keep the source installation and its volumes while validating recovery.

The bundle is **unencrypted** and includes CA private keys, account hashes and
possibly Runner credentials. Store it on protected encrypted storage with access
limited to the operator. POSIX directories/files use 0700/0600; Windows operators
must apply private ACLs to the destination and its parent. Do not place it in a
shared or synchronized directory. Checksums detect corruption; they do not prove
the origin of an untrusted backup. Restore only a trusted backup you created.

The restored `Caddyfile` contains public routing configuration and is readable by
the restricted proxy container. Keep credentials in `.env` or private state,
never in that routing file. The restore directory itself remains private.

## Restore drill before an upgrade

Use a new directory and separate project name; existing directories or Docker
resources cause refusal:

```sh
python vardrsec.py restore --backup /private/backups/before-upgrade \
  --destination /private/restored-platform --project vardrsec-restore-drill
```

Restore validates the entire bundle and safe archive paths before loading images.
It uses the saved images by ID, without a network pull or source rebuild, creates
fresh volumes, restores PostgreSQL and verifies table/sequence fingerprints. It
also verifies Runner/proxy file contents, ownership and modes. Its new application
bridge avoids existing Docker subnets. The source installation is retained.

Successful restoration writes `restore-receipt.json`. Only the restored database
is started: browser/API/proxy remain stopped. This receipt verifies stored state;
it is not release certification or a substitute for application acceptance. The
backup contains Linux images for the original architecture; it is not a cross-CPU
or PostgreSQL-major-version conversion.

Recovered authentication state is from the backup time. Revocations performed
later are absent. Before exposing the restored installation, reset the local
password to invalidate recovered browser sessions:

```sh
cd /private/restored-platform
docker compose -f compose.yaml -f .active-images.json run --rm --no-deps api \
  python -m local_accounts reset-password --username operator
python vardrsec.py start
python vardrsec.py export-ca
```

Review/revoke any API keys that were revoked or compromised after the snapshot,
then supply the intended Runner key and run `python vardrsec.py doctor`. Verify
normal login, organization access and important evidence. The original proxy must
be stopped before this drill because the saved UI uses the original loopback URL.
The restored CA is the original CA; compare its public fingerprint before trust.

## Controlled upgrade boundary

Retain a completed backup and a proven restore before changing component images.
Keep applications quiesced between backup and upgrade; otherwise restoring loses
all later writes. Use only a separately reviewed, compatible image set. Preserve
the backup's image archive and source revisions. Do not prune recovery images or
delete the source volumes during an upgrade.

The API connects as the non-superuser `vardrmap_app`; backups and restores use the
administrator inside the database container, and restore hands restored data to the
application role (see [database-roles.md](database-roles.md)).

Application startup runs Alembic. If migration/startup fails, keep application
traffic stopped and restore the proven bundle into a new project. An image
rollback cannot undo an applied schema change. Never stamp over a failed schema
or downgrade credential tables to make readiness green. There is no automatic
unattended update, in-place restore or automatic data-deleting rollback command.
The [controlled updater](updates.md) automates the explicit backup/rehearsal/apply
sequence for a reviewed local image set and preserves a durable failure record.

`tests/recovery_acceptance.py` builds two disposable fixture images: a successful
additive migration and an intentionally failing migration. It tests migration
transaction rollback, then restores the original schema/data, exact images,
evidence and CA into fresh volumes. Fixture migrations are not product migrations.
The CI drill retains no engagement/credential backup artifact and removes only its
named disposable projects. Fresh-host browser trust and long-term certificate
renewal remain separate platform acceptance requirements.

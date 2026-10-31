# ADR 0003: Least-privilege PostgreSQL role for the API

Status: Accepted for Phase 1, 2026-10-31.

Context: the Compose installation used `POSTGRES_USER` (a superuser) for the API, so a
compromised API or SQL injection had server-level authority (`COPY ... PROGRAM`, file
access, role and database creation) that its queries never need. Map's migrations are plain
DDL and its isolation is application-level; nothing requires superuser. PostgreSQL does not
allow demoting the bootstrap role, and `POSTGRES_USER` is applied only when a volume is
first initialised.

Decision: keep `vardrmap` as the administrator, used only inside the database container and
by backup/restore. Add `vardrmap_app`, a non-superuser login that owns the schema and runs the
unchanged startup migrations. Apply it with one idempotent, transactional command
(`database-role`) used by install, restore and explicit upgrades of existing volumes, instead
of an initdb script, so one code path serves fresh, existing and restored databases and the
database image is unchanged. Existing data is reassigned only after a validated backup that
matches the current database. The password is stored only in `.env` and reaches PostgreSQL as
a SCRAM verifier.

Consequences: existing installations must run an explicit step after updating; backups from
before the change restore as pre-change installations. The application login can still alter
its own tables and would be exempt from row-level security; a separate migration owner with a
data-only application login (Phase 2) remains deferred.

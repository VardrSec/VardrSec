# Full bundled recovery API verification

This branch binds the installer and all its tracked files to
`07307a2707eefd772f00eeac6d4977680f854c4d`. Component pins remain unchanged.
It adapts the preservation harness that passed run 41962343676, replacing only
the recovery invocation and its source binding. Publication triggers the exact
`codex/nm3-bundled-recovery-verification` branch, not a PR or main workflow.

The hosted guard requires GitHub-hosted Ubuntu 24.04, a matching local empty
non-Swarm Docker daemon, no existing containers or volumes/custom networks,
no inherited Docker/Compose/source/secret overrides, and new private fixture
paths. Existing installer source files must equal the bound candidate exactly.

After fresh installation, two synthetic rows are seeded. Backup quiesces the
synthetic source applications and exports the exact images and state. The
reviewed checkout validates the bundle manifest and archives and requires every
bundled Python file to equal the corresponding bound-checkout file. Unexpected
entries and symlinks are refused before bundled code executes. This binding is
for this generated trusted fixture only, not authentication of arbitrary backups.

A separate `python -I -B` process adds only the generated bundle to application
module lookup, checks recovery/role/updater/encryption module origins, invokes
bundled `recovery.restore()`, and rechecks origins. It does not import application
modules from the original checkout or invoke the portable CLI. Isolated Python
is not a filesystem security sandbox. The original checkout remains retained.

Existing post-backup source fingerprints, restored database/volume fingerprints,
retained backup integrity, restored image mapping and install refusal checks
remain required. No new runtime trust mechanism or production behavior is added.

Remote side effects: build/start the current pinned Full stack; stop synthetic
applications for backup; export/load private images; create a separate restore
project and named volumes; run only its database. Existing offline maintenance
containers auto-remove themselves. No fixture teardown, named-volume, backup,
data or CA deletion, OS CA enrollment, external scans or Mapless activation.
Capacity refusal remains fail-closed, without pruning. Hosted VM disposal is
platform behavior, not durable evidence retention.

Only a fixed receipt is uploaded for seven days and is visible to repository
readers. It contains source/pin identifiers, fixed status/stage/scope fields,
and six allowlisted boolean verdicts, including `bundled_recovery_api_verified`.
No raw exceptions, logs, configuration, paths, archive contents, fingerprints or
credentials are uploaded. Child output is captured privately and never emitted.

A pass establishes the synthetic bundled recovery API journey for the current
Full pins. It does not establish complete portable CLI, encrypted v4 roundtrip,
final NM-3 component cohort, Mapless, Windows, installed upgrade/no-loss,
SQLite snapshot non-mutation or journal race acceptance. Older readers reject v4.

Local verification: 11 focused harness tests; AST/YAML/diff checks. Existing
candidate tests remain attributed to 07307a2 (154 passed, 4 age-tool skips), not
claimed as rerun for this verification-only branch. Candidate files including its
changelog remain unchanged; these verification additions are documented here.

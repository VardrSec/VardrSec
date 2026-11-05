# Proposed hosted standard Full fresh-install verification

This unpublished branch prepares an acceptance job for installer source
`8fcc4aa4b2df55514b464192eb0efc77bb7b62d5`. It has not run remotely.
Publishing `codex/nm3-full-hosted-verification` would start external execution;
owner approval is required before pushing. It also triggers the repository's
existing read-only Distribution foundation manifest check.

The new workflow triggers only on pushes to that named branch, never a PR,
manual dispatch or main. It uses a GitHub-hosted Ubuntu 24.04 VM, not a self-hosted
runner. The VM's stock daemon qualifies as dedicated to this job only after the
harness verifies the hosted/repository/event/branch/OS boundary, root-owned local
socket, matching hostname, local default data root, inactive Swarm, no containers,
no volumes and no networks except the default bridge/host/none. Unexpected state
causes refusal; it is never cleared. No separate daemon is started or existing
daemon reconfigured. This relies on GitHub's hosted VM isolation, not merely an
empty project name, and does not support a shared daemon.

The job rejects inherited Docker, Compose and source/config credential overrides.
It creates new private fixture and Docker-client configuration directories under
RUNNER_TEMP. Only tracked regular files from the exact installer candidate are
copied, after checking the candidate's ancestry and that every candidate file is
unchanged in the workflow checkout. Component pins stay exactly:

- Map `41d3ef6475f1b81f973dd4a73944b6e549500fd6`
- Runner `668dc56f8685dc6a6225438ad443e26901828069`
- Gate `7f82e499ec407eba072e129e3f3b94f1a4eabe94`

One `python vardrsec.py install` invocation generates fresh synthetic credentials,
fetches pinned public source, pulls build dependencies/base images, builds local
images, creates the fixture's networks/volumes/database role and starts db/api/web/
proxy. It exports the fixture public CA without enrolling it in OS trust. The
help-only Runner is not started; no assessment, scan, bootstrap account, worker,
backup, restore or upgrade journey runs. The harness checks acquired source heads,
clean source trees, successful install/health completion, public CA presence and
exactly the four expected running services. It does not modify pins to simulate
an NM-3 cohort.

No stop/down/rm/prune or CA/data teardown is included. Failed or completed job state
is left intact for the remainder of the job. GitHub's eventual VM disposal is
external platform behavior, not retained backup or explicit harness teardown.

Only `public/receipt.json` is uploaded for seven days. Hosted artifacts may be
visible to repository readers. Its fixed allowlist contains candidate/workflow
commits, fixed component pins, a stage/status and scope labels. No raw logs,
exception messages, paths, resolved Compose output, credentials, database files,
private CA keys, certificates or source bundles are uploaded. Private install logs
stay on the ephemeral VM; a failure receipt deliberately omits raw diagnostics.

A pass would verify the one-command standard Full installer against the existing
Full pinned stack on this hosted Linux environment. It would not establish NM-3
component-cohort acceptance, Mapless, native Windows, upgrade/no-loss preservation,
SQLite snapshot safety, journal race resistance or supported controlled Docker
execution. Those gates remain open. Local preparation uses only mocked guard tests
and static checks; it does not access the local Docker daemon.

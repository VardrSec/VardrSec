# VardrSec

The local-first distribution for the VardrSec security-testing platform.

**Status: implementation started; a runnable Compose distribution is not released.**
This repository currently records the agreed responsibilities, candidate component
revisions and the implementation sequence. It does not yet provide Compose files,
container images, installation scripts or automatic updates.

| Component | Responsibility |
|---|---|
| VardrSec | Install, start, stop and update the platform through Docker Compose; maintain tested component pins and recovery procedures. |
| VardrRunner | Diagnose installation, connectivity, tools and configuration; retain explicitly invoked local execution, credential resolution, jobs and result transport. |
| VardrMap | Provide the engagement web interface, expose backend readiness and display platform/runner status with freshness. |
| VardrGate | Remain the specialized authorization-testing engine and independently usable CLI. |

Keep the component repositories separate. Reuse Runner's existing diagnostics;
there is no additional VardrSec doctor or scanning engine. Starting services must
not start scans or a detached queue worker. Stop operations must preserve data.

## First implementation slice

- [Map #110](https://github.com/VardrSec/VardrMap/pull/110): value-free database and
  migration-marker readiness through `GET /ready`, preserving `/health` liveness.
- [Runner #82](https://github.com/VardrSec/VardrRunner/pull/82): opt-in
  `doctor --platform` and `doctor --offline`, preserving ordinary diagnostics.
- [versions.json](versions.json): candidate source revisions for those reviews,
  with publication/runnable status kept separate from source compatibility.

These features are in review, not promised in a published Runner installation.
When using the candidate sources, `vardrrunner doctor --platform --offline --json`
checks the configured backend and skips release discovery. It does not install,
repair, migrate or execute jobs. An older Map without `/ready` fails the requested
platform check; ordinary doctor calls remain supported.

## Next implementation slices

1. Decide local authentication, Runner packaging and the local network/trust model.
2. Add component image builds and a minimal Compose installation with health,
   migration, secret and persistent-volume handling.
3. Implement VardrSec install/start/stop/update through Compose and display fresh
   component/runner status in Map.
4. Verify clean installation, upgrades, backup/restore and explicitly approved
   testing before a tagged Community alpha.

See the [architecture decision](docs/adr/0001-component-responsibilities.md) and
[acceptance plan](docs/acceptance.md). Component source access depends on each
repository's permissions. Image publication, licensing decisions and releases
remain separate reviewed steps; this foundation publishes none of those artifacts.

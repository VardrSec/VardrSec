# VardrSec

The local-first distribution for the VardrSec security-testing platform.

**Status: implementation started; a runnable Compose distribution is not released.**
This repository provides a source-built Compose development installation with
Map UI/API, migrated PostgreSQL, an HTTPS proxy and explicitly invoked Runner.
Application images are built locally from exact source pins; release images and
automatic updates are not published. See [installation and explicit CA trust](docs/installation.md).

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
- [versions.json](versions.json): exact development source revisions for the image PRs and Gate,
  with publication/runnable status kept separate from source compatibility.

These readiness features are merged; a published installation is a separate step.
When using the pinned sources, `vardrrunner doctor --platform --offline --json`
checks the configured backend and skips release discovery. It does not install,
repair, migrate or execute jobs. An older Map without `/ready` fails the requested
platform check; ordinary doctor calls remain supported.

## Next implementation slices

1. Review [Map images #113](https://github.com/VardrSec/VardrMap/pull/113) and
   [Runner packaging #83](https://github.com/VardrSec/VardrRunner/pull/83). The
   tool-enabled Runner includes Gate, nmap/libpcap and verified managed binaries.
2. Validate the [Compose installation](docs/installation.md), explicit public-CA
   enrollment, one-time administrator bootstrap and Runner diagnostics. Start/stop
   preserve volumes; platform startup executes no scans.
3. Add fresh component/runner status presentation in Map and complete tooling,
   host/VPN networking and supported-OS acceptance.
4. Review the controlled updater, portable recovery and encrypted backup drafts.
   Review [accelerated leaf renewal](docs/certificate-renewal-acceptance.md) and
   complete remaining certificate lifecycle/fresh-host acceptance before tagging
   a Community alpha.

See the [architecture decision](docs/adr/0001-component-responsibilities.md) and
[acceptance plan](docs/acceptance.md). Component source access depends on each
repository's permissions. Image publication, licensing decisions and releases
remain separate reviewed steps; this foundation publishes none of those artifacts.

## Development entry point

`python vardrsec.py configure`, `sources`, `build`, `start`, `export-ca`,
`bootstrap`, `doctor` and `stop` delegate lifecycle to Compose and diagnostics to
Runner. Follow the [installation guide](docs/installation.md) for prerequisites,
explicit trust enrollment and credentials. `start` alone does not establish browser trust.

`backup` and `restore` provide quiesced portable snapshots, saved service images
and state verification into a fresh installation. See [recovery](docs/recovery.md)
before changing images. [Controlled updates](docs/updates.md) rehearse an explicit
local image set privately, verify the original before mutation and retain a
recovery record on failure. There is no unattended updater or in-place restore.

Add `--recipient age1...` to `backup` for encrypted packaging, or seal an existing
working bundle. [Encrypted recovery](docs/encrypted-backups.md) explains separate
key custody, authenticated unsealing and the plaintext working-data boundary.

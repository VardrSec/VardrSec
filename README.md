# VardrSec

The local-first distribution for the VardrSec security-testing platform: a research
interface (VardrMap), an explicit-execution runner (VardrRunner) and a multi-identity API
authorization tester (VardrGate), run together with Docker Compose on your own machine. Each
component also runs natively; see [platforms](docs/platforms.md).

> **Source-built alpha, not an official release.** You build it locally from pinned sources.
> No images are published and there are no automatic updates.

Full keeps the web research workflow below. Standalone installation uses
`python3 vardrsec.py install --mapless` in a separate clean checkout; see the
[Mapless authorization, execution and export walkthrough](docs/mapless.md).
The reviewed compatible Runner/Gate pins are merged; verified installation
boundaries and remaining requirements are recorded in the
[New Moon ledger](docs/new-moon-acceptance.md#community-delivery-priority).

The opt-in [local managed setup](docs/local-managed-setup.md) connects Full's
signed job workflow to the existing persistent worker. Local setup and enrollment
are verified for owner acceptance; ordinary startup remains inert.

## Install (Docker and Compose, Python 3.10+, Git)

Choose one variant per checkout. Full includes Map's web research interface;
Mapless provides the Runner/Gate CLI without Map or PostgreSQL. The thin
entrypoints prompt when no mode is supplied in a terminal:

```powershell
.\install.ps1 --full       # Windows 11, Docker Desktop with Linux containers
.\install.ps1 --mapless    # choose this instead for standalone use
.\runner.ps1 workspace list
```

```sh
./install.sh --full        # Linux
./install.sh --mapless     # choose this instead for standalone use
./runner.sh workspace list
```

For coexistence, keep Full and Mapless in separate checkouts; the original
Mapless workspace and history stay in place. Installer arguments pass through to
the Python CLI below. Runner launchers add the usual argument separator; retain
an explicit `--` after distribution input/output/issuer options when using those
options. The existing `python vardrsec.py` commands remain available.

Windows installers print the platform-specific trust and account setup steps.
The equivalent Python sequence for an Ubuntu 24.04 Full installation is:

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec
cd vardrsec
python3 vardrsec.py install        # builds everything; takes several minutes
sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
sudo update-ca-certificates        # trust only your own local CA (compare the printed fingerprint)
python3 vardrsec.py bootstrap --username operator
```

If the install is interrupted, follow the [resume and recovery instructions](docs/installation.md)
before retrying. Existing configuration is preserved; retained state can cause a
fresh-install refusal rather than being overwritten. The certificate step is manual
by design; VardrSec never changes your trust store or starts a scan on its own.
Firefox needs the CA imported in its own settings.

## Use it

1. Open **https://localhost:8443** and sign in with the username and passphrase you just created.
2. Create an engagement, then on its Overview add the client, testing window and written
   authorization, and add your target under Scope.
3. Draft test cases from your OpenAPI document under Review, edit each identity's expected
   access yourself, and queue a case. Manual jobs require an explicit Runner invocation;
   managed jobs require the separately enabled worker and valid per-job approval.

The full step-by-step, including running the assessment and exporting a report, is the
[first-assessment walkthrough](docs/installation.md#first-assessment-walkthrough).
Stop core services with `python3 vardrsec.py stop` (your data is kept). Stop and
reconcile any separately enabled worker through its [operator controls](docs/nm2-worker-operator.md)
first; core-service stop is not a substitute for worker termination.
Other platforms, VPN-only targets and recovery are covered in
[installation](docs/installation.md), [networking](docs/networking.md) and
[recovery](docs/recovery.md).

## Project status

New Moon preserves one Runner engine, optional Map, Full/Mapless installation,
Windows 11 with Docker Desktop preferred, Linux compatibility and justified native
operation. The [acceptance ledger](docs/new-moon-acceptance.md) is the current
source/evidence record; dated phase checkpoints are historical, not competing task lists.

**NM-3 and NM-4 are accepted for their recorded source-built Community scope.**
NM-3 covers Full/Mapless installation, authorization, finite Recon, reviewed Gate
execution, export and state-preserving lifecycle. NM-4 adds boundary coverage,
grounded drafts, operator-approved AI queue proposals and structured provenance.
See the [NM-3 closeout](docs/new-moon-acceptance.md#exit-criteria-closeout) and
[NM-4 closeout](docs/new-moon-acceptance.md#current-nm-4-community-delivery-status).

The accepted application-installation targets are Windows 11 Docker Desktop
(Linux/amd64 containers) and Ubuntu 24.04/amd64 within their recorded boundaries.
This does not certify every network/tool mode, a freshly provisioned operating
system, or macOS Docker. The earlier [Community Alpha plan](docs/community-alpha.md)
records the Ubuntu-first baseline; it does not erase later Windows application evidence.

**NM-5 and release approval remain open.** NM-2 C09 is unaccepted and C10's final
disposition remains pending. Source-built acceptance does not waive those limits,
image risks, licensing/source-delivery review, independent human/research evidence,
or final architecture sign-off. See the [six closure gates](docs/new-moon-architecture-review.md#six-remaining-closure-gates).

| Component | Responsibility |
|---|---|
| VardrSec | Install, start, stop and update the platform through Docker Compose; maintain tested component pins and recovery procedures. |
| VardrRunner | One execution engine for connected and standalone work, diagnostics, local credentials, journals and result transport. |
| VardrMap | Engagement web interface/API, reviewed policy, queue proposals, budgets, evidence, findings and reports. |
| VardrGate | Specialized authorization-testing engine and independently usable CLI. |
| VardrLab | Independent synthetic scenarios and tool-neutral benchmark/oracle work; not an execution authority. |

Keep the component repositories separate. Reuse Runner's existing diagnostics;
there is no additional VardrSec doctor or scanning engine. Normal startup must not
start scans or a detached queue worker. Stop operations preserve data.

## Implemented development workflow

The following capabilities are merged and exercised by retained development
acceptance checks. They describe source-built development artifacts, not a
published Community alpha:

- [Pinned source builds and Compose installation](docs/installation.md): Map UI/API,
  PostgreSQL and HTTPS proxy; explicit CA trust enrollment and terminal local-account
  bootstrap. Startup launches no scans and stop preserves data volumes.
- Runner's opt-in platform diagnostics and Map's timestamped platform/Runner status,
  including stale, unknown and unreachable states. With the pinned sources,
  `vardrrunner doctor --platform --offline --json` checks the configured backend
  without release discovery, installation, migration or job execution.
- The [installed authorization workflow](docs/installed-gate-acceptance.md): browser
  engagement setup, reviewed case queueing, explicit Runner/Gate execution, negative
  and inconclusive outcomes, independent readback, evidence review and report exports.
- [Recovery](docs/recovery.md), [encrypted backups](docs/encrypted-backups.md),
  [controlled updates](docs/updates.md), failed-update recovery and
  [accelerated certificate renewal](docs/certificate-renewal-acceptance.md).
- A bounded [tool/network matrix](docs/tool-network-acceptance.md) for selected modes
  on fresh Linux CI hosts, plus retained [image evidence](docs/image-evidence.md).
  Evidence collection succeeds independently of the strict vulnerability gate;
  that gate still reports unresolved blockers.

## Documentation by purpose

| Need | Start here |
|---|---|
| Install and run Full | [Installation](docs/installation.md), [managed setup](docs/local-managed-setup.md) |
| Run without Map | [Mapless walkthrough](docs/mapless.md) |
| Stop, recover or update | [Worker controls](docs/nm2-worker-operator.md), [recovery](docs/recovery.md), [updates](docs/updates.md) |
| Understand platform limits | [Platforms](docs/platforms.md), [networking](docs/networking.md) |
| Check current delivery and release status | [New Moon ledger](docs/new-moon-acceptance.md), [architecture review](docs/new-moon-architecture-review.md), [release checklist](docs/community-alpha-release.md) |
| Review design and historical proof | [ADRs](docs/adr/), dated acceptance reports and their exact-source receipts |

Historical review/acceptance files preserve provenance; they are not installation
instructions, renewed approvals or current completion percentages. Contributor
instructions remain in `AGENTS.md`; personal coordination belongs outside operator guides.

## Remaining release gates

Use the [release checklist](docs/community-alpha-release.md) alongside the
[architecture closure gates](docs/new-moon-architecture-review.md#six-remaining-closure-gates).
They retain final source/image attribution, host/Docker restart persistence,
network/native-fallback qualification, independent research and human acceptance,
vulnerability dispositions, transitive licensing/source delivery, artifact
reproduction and architecture/safety sign-off. No risk exception, license decision,
tag or publication is implied by merged checks.

The bounded tool matrix does not establish genuine VPN support, macOS Docker
acceptance or every tool mode. Follow the [documented support limits](docs/platforms.md).
Component source access depends on each repository's permissions; image publication
and releases remain separately reviewed decisions.

## Development entry point

`python3 vardrsec.py sources --mapless` prepares pinned Runner/Gate caches only;
`install --mapless` additionally builds and selects the separate standalone model.
See [mode selection](docs/installation.md#full-and-mapless-selection) and the
[operator walkthrough](docs/mapless.md). Default Full lifecycle behavior is
preserved. Compatible pins, installed acceptance and a published release remain
distinct from source implementation; automatic mode transition is deferred.

`python vardrsec.py configure`, `sources`, `build`, `database-role`, `start`, `export-ca`,
`bootstrap`, `doctor` and `stop` delegate lifecycle to Compose and diagnostics to
Runner. `python vardrsec.py runner [--env NAME]... -- <command>` runs one Runner
command in the installed image set. Follow the [installation guide](docs/installation.md) for prerequisites,
explicit trust enrollment and credentials. `start` alone does not establish browser trust.

`backup` and `restore` provide quiesced portable snapshots, saved service images
and state verification into a fresh installation. See [recovery](docs/recovery.md)
before changing images. [Controlled updates](docs/updates.md) rehearse an explicit
local image set privately, verify the original before mutation and retain a
recovery record on failure. There is no unattended updater or in-place restore.

Add `--recipient age1...` to `backup` for encrypted packaging, or seal an existing
working bundle. [Encrypted recovery](docs/encrypted-backups.md) explains separate
key custody, authenticated unsealing and the plaintext working-data boundary.

## License

The original code of this distribution repository (Compose configuration, lifecycle, backup
and update scripts, tests and documentation) is licensed under the
[Apache License 2.0](LICENSE); see also [NOTICE](NOTICE). That license applies only to this
repository's own files. It does not relicense, and does not override the terms of, the
independently licensed components that the distribution pins and builds: VardrMap
(AGPL-3.0, including its network-service source obligations), VardrRunner (MIT) and
VardrGate (Apache-2.0), nor any third-party tool, dependency, base image or package. Each
keeps its own license and notices. The [license inventory](docs/release-license-inventory.md)
records what is verified and what remains open before any release or redistribution of
built images.

The offline [component notice collector](docs/source-notices.md) copies top-level
licenses and notices from exact pinned Git objects into a new directory, with
machine-readable source references and hashes. It does not resolve the remaining
third-party licensing or source-delivery review.

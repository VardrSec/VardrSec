# VardrSec

The local-first distribution for the VardrSec security-testing platform: a research
interface (VardrMap), an explicit-execution runner (VardrRunner) and a multi-identity API
authorization tester (VardrGate), run together with Docker Compose on your own machine. Each
component also runs natively; see [platforms](docs/platforms.md).

> **Source-built alpha, not an official release.** You build it locally from pinned sources.
> No images are published and there are no automatic updates.

## Install (Ubuntu 24.04, Docker and Compose, Python 3.10+, Git)

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec
cd vardrsec
python3 vardrsec.py install        # builds everything; takes several minutes
sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
sudo update-ca-certificates        # trust only your own local CA (compare the printed fingerprint)
python3 vardrsec.py bootstrap --username operator
```

If the install is interrupted, run `python3 vardrsec.py install` again: it resumes, keeps your
secrets and deletes nothing. The certificate step is manual by design; VardrSec never changes
your trust store or starts a scan on its own. Firefox needs the CA imported in its own settings.

## Use it

1. Open **https://localhost:8443** and sign in with the username and passphrase you just created.
2. Create an engagement, then on its Overview add the client, testing window and written
   authorization, and add your target under Scope.
3. Draft test cases from your OpenAPI document under Review, edit each identity's expected
   access yourself, and queue a case. Nothing runs until you run the Runner explicitly.

The full step-by-step, including running the assessment and exporting a report, is the
[first-assessment walkthrough](docs/installation.md#first-assessment-walkthrough).
Stop with `python3 vardrsec.py stop` (your data is kept). Other platforms, VPN-only
targets and recovery are covered in [installation](docs/installation.md),
[networking](docs/networking.md) and [recovery](docs/recovery.md).

## Project status

Current work follows the [Community Alpha v0.1.0 stabilization plan](docs/community-alpha.md):
security and clean Ubuntu installation first, then user-workflow validation and
release preparation. The initial packaged distribution is officially supported on Ubuntu
24.04; other platforms are labelled from their own acceptance evidence. See
[platforms and deployment methods](docs/platforms.md) for native component execution and
future cross-platform work.

| Component | Responsibility |
|---|---|
| VardrSec | Install, start, stop and update the platform through Docker Compose; maintain tested component pins and recovery procedures. |
| VardrRunner | Diagnose installation, connectivity, tools and configuration; retain explicitly invoked local execution, credential resolution, jobs and result transport. |
| VardrMap | Provide the engagement web interface, expose backend readiness and display platform/runner status with freshness. |
| VardrGate | Remain the specialized authorization-testing engine and independently usable CLI. |

Keep the component repositories separate. Reuse Runner's existing diagnostics;
there is no additional VardrSec doctor or scanning engine. Starting services must
not start scans or a detached queue worker. Stop operations must preserve data.

## Implemented development workflow

The following capabilities are merged and exercised by the retained development
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

## Remaining release gates

The [Community alpha release checklist](docs/community-alpha-release.md) is the
authoritative current queue. Remaining work includes residual security dispositions,
the distribution/bundled-tool licensing and artifact-delivery review, a timed
unfamiliar-user installation and first assessment, freezing a release candidate,
independent artifact reproduction and recovery/update reruns against that freeze.
No risk exception, license decision, tag or publication is implied by merged checks.

The [alpha scope](docs/community-alpha.md) remains Ubuntu 24.04/amd64 first.
The bounded tool matrix does not establish genuine VPN or fresh Windows/macOS
Desktop acceptance, nor support for every tool mode. Follow its documented limits.

See the [architecture decision](docs/adr/0001-component-responsibilities.md) and
[acceptance plan](docs/acceptance.md). Component source access depends on each
repository's permissions. Image publication, licensing decisions and releases
remain separate reviewed steps; this foundation publishes none of those artifacts.

## Development entry point

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

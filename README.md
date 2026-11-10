# VardrSec

A local-first security-testing platform. VardrMap provides the engagement interface,
VardrRunner executes explicitly authorized work, and VardrGate evaluates API
access-control expectations. This repository installs and maintains the selected
components with Docker Compose.

> **Source-built development software, not an official release.** Build locally
> from the component revisions in `versions.json`. No images are published and
> there are no automatic updates. Review the [support and safety limits](docs/limitations.md)
> before using it.

## Choose an installation

**Full** includes Map, Runner, Gate, PostgreSQL and the HTTPS proxy. **Mapless**
provides the Runner/Gate CLI without a Map account, API key or PostgreSQL service.
Use a separate checkout and installation state for each mode; existing Mapless
history is preserved rather than automatically imported into Full.

Prerequisites: Git, Python 3.10+, Docker with Compose, and the platform-specific
requirements in the [installation guide](docs/installation.md).

```powershell
# Windows 11 with Docker Desktop using Linux containers; choose one mode.
.\install.ps1 --full
.\install.ps1 --mapless
.\runner.ps1 workspace list
```

```sh
# Linux; choose one mode.
./install.sh --full
./install.sh --mapless
./runner.sh workspace list
```

The entrypoints prompt for a mode when invoked interactively without one.
Installation prints the applicable trust and account-setup steps. Trust only your
own local CA after checking its fingerprint. Browser trust is not established by
starting Compose alone; never bypass certificate verification to make setup work.

## Start using the platform

For Full, follow the [first-assessment walkthrough](docs/installation.md#first-assessment-walkthrough).
Create an engagement, record written authorization and scope, review expected
access for each identity, and explicitly execute the approved work. Queueing a
case or starting core services does not grant execution authority.

For standalone work, follow the [Mapless walkthrough](docs/mapless.md).
For separately enabled managed execution, use [local managed setup](docs/local-managed-setup.md).
Manual `jobs run` remains available and retains its existing meaning.

## Preserve results and stop safely

Use the [recovery guide](docs/recovery.md), [encrypted backup instructions](docs/encrypted-backups.md)
and [controlled update procedure](docs/updates.md) before changing installation
state or images. Interrupted operations can refuse unsafe retries; do not remove
retained state to force them through.

```sh
python3 vardrsec.py stop
```

This stops the core services and preserves their data. A separately enabled
managed worker must be stopped and reconciled through its own operator controls
first. An uncertain execution is not permission to replay a job or reuse a spent
approval.

## Documentation

- [Installation and first assessment](docs/installation.md)
- [Standalone Mapless operation](docs/mapless.md)
- [Managed setup](docs/local-managed-setup.md)
- [Recovery](docs/recovery.md), [encrypted backups](docs/encrypted-backups.md) and [updates](docs/updates.md)
- [Platforms](docs/platforms.md), [networking](docs/networking.md) and [support limits](docs/limitations.md)
- [Component notices](docs/source-notices.md) and [license inventory](docs/release-license-inventory.md)
- [Changelog](CHANGELOG.md)

## Component responsibilities

| Component | Role |
|---|---|
| VardrSec | Installation, component pins, Compose lifecycle, trust, backup and recovery |
| VardrMap | Engagements, reviewed cases, queue proposals, evidence, findings and reports |
| VardrRunner | Shared execution engine, local credentials, workspaces, diagnostics and exports |
| VardrGate | Independent multi-identity API authorization testing |
| VardrLab | Isolated synthetic targets and independent research validation |

## License

This repository's original code and documentation use [Apache-2.0](LICENSE);
see [NOTICE](NOTICE). Each independently licensed component, third-party tool and
dependency retains its own terms. This license does not relicense VardrMap,
VardrRunner, VardrGate or bundled software. The [license inventory](docs/release-license-inventory.md)
and [source-notice guide](docs/source-notices.md) explain the separate delivery
boundaries. Source-built compatibility is not a claim of completed release or
license-compliance review.

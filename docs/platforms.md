# Platforms and deployment methods

VardrSec is not an operating-system-specific application. Its components run natively
on their supported operating systems; what is *packaged and officially supported* in
Community Alpha v0.1.0 is one distribution, the source-built Docker Compose install on
Ubuntu. Requirements below are either an application requirement or a Docker requirement;
the two are kept apart on purpose.

## Two deployment methods

| Method | What it is | Status for Community Alpha v0.1.0 |
| --- | --- | --- |
| **A. Native components** | Map (FastAPI backend, Next.js frontend), Runner (Python CLI/worker) and Gate (Go binary) started directly with their own tooling; PostgreSQL installed natively where used. No Docker, WSL2 or Linux virtual machine is required by the applications | Works per each component's own documentation and CI (see below). **An integrated, end-to-end native installation is not an officially supported or verified deployment** |
| **B. Containerized distribution** | This repository: pinned components built from source and run by Docker Compose, with trusted local HTTPS, backup, recovery and controlled updates | **Officially supported: Ubuntu 24.04 Linux/amd64 with Docker Engine and Compose** |

The Docker requirement for *Linux containers* is Docker's, not VardrSec's: the images are
Linux images, so any Docker installation that runs Linux containers can host them in
principle. VardrSec does not require WSL2; Docker Desktop on Windows is evaluated later
with whichever Docker-supported Linux-container backend is available.

| Environment | Position |
| --- | --- |
| Ubuntu 24.04 amd64, source-built Compose | Officially supported; automated clean install, workflow, recovery and update |
| Ubuntu 22.04, other Linux distributions, arm64 | Not established; Ubuntu 22.04 has bounded tool/network evidence only |
| Windows 11 / macOS Docker Desktop (Linux containers) | Experimental; no fresh-host install or recovery acceptance |
| Native Map, Runner, Gate on Windows or Linux | Supported for individual development and execution as documented by each component; not an integrated distribution |

Do not describe Windows, macOS or other Linux distributions as supported until their
installation and recovery workflows have their own acceptance evidence.

## Native component evidence

Run on 2026-10-31 on native Windows 11 (no Docker, no WSL2), Python 3.14, Node 24 and Go 1.26,
without changing any checkout: Map and Runner in fresh virtual environments from an export of
`main`, Gate from its checkout (Go reused cached test results):

| Component | Result | Windows in each repository's CI |
| --- | --- | --- |
| Map backend | 1,229 tests pass, 1 skipped (SQLite) | None: Map CI is Ubuntu only (Python 3.12, Node 20 and 24, PostgreSQL service) |
| Map frontend | `npm ci`, lint (0 errors), typecheck, 253 tests and production build succeed | None |
| Runner | 1,712 tests pass, 10 skipped | Python 3.14 on Windows and macOS, Python 3.10-3.14 on Ubuntu. Windows process-tree termination, Windows environment variables, the Credential Locker keychain and `.zip` tool installs are handled in code |
| Gate | `go build`, `go vet` and `go test ./...` pass | The GitHub Action job runs on Ubuntu, macOS and Windows; releases cross-compile `windows/amd64`. Unit tests run on Ubuntu in CI |
| Distribution scripts | Unit tests on `windows-latest` in CI; native certificate-store enrollment on Windows and macOS | `Compose acceptance` and `Native certificate trust` |
| Map + Runner + Gate loopback acceptance (`scripts/integration/run.py`) | 104 checks pass with the companions Map CI pins (Runner `e8bc306`, Gate `af29a93`) on SQLite | Linux only (CI) |

Known gaps, none a Windows-specific regression:

- The loopback acceptance fails against current Runner 0.54.0 and Gate 0.2.0 on every
  operating system, because its harness does not approve Runner's new credential references
  and Map CI pins older companions. Tracked in
  [VardrMap #140](https://github.com/VardrSec/VardrMap/issues/140); the correction is test
  tooling only.
- Native Gau installation is refused by design on every operating system (Runner #94); the
  container build carries a reviewed patched Gau.
- The native Windows Compose workflow, native PostgreSQL on Windows and native HTTPS for Map
  are not covered by any CI job.

## Future work (planning direction, not commitments)

- **Community Alpha v0.1.0:** Ubuntu source-built Docker Compose distribution.
- **Next:** validate an integrated Windows deployment; evaluate a native installation versus
  Docker Desktop distribution; keep native component execution working. Candidate
  prerequisites: a Windows job in Map CI, an end-to-end native acceptance against the pinned
  Runner and Gate, and fresh-host Docker Desktop installation and recovery acceptance.
- **Later:** evaluate macOS; consider prebuilt container images and simplified installers
  after the licensing and security requirements in the
  [release checklist](community-alpha-release.md) are met.

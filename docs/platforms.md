# Platforms and deployment methods

VardrSec is not an operating-system-specific application. Its components run natively
on their supported operating systems. NM-3 source-built Community acceptance is
closed for Windows 11 Docker Desktop (Linux/amd64 containers) and Ubuntu 24.04/amd64
Compose installations. Windows 11 is the primary Community target; Ubuntu compatibility remains
required. Source acceptance and release approval are separate. Requirements
below distinguish application support from Docker's requirements.

## Two deployment methods

| Method | What it is | Status for Community Alpha v0.1.0 |
| --- | --- | --- |
| **A. Native components** | Map (FastAPI backend, Next.js frontend), Runner (Python CLI/worker) and Gate (Go binary) started directly with their own tooling; PostgreSQL installed natively where used. No Docker, WSL2 or Linux virtual machine is required by the applications | Works per each component's own documentation and CI (see below). **An integrated, end-to-end native installation is not an officially supported or verified deployment** |
| **B. Containerized distribution** | This repository: pinned components built from source and run by Docker Compose, with trusted local HTTPS, backup, recovery and controlled updates | **NM-3 source acceptance: Windows 11 Docker Desktop/Linux-amd64 and Ubuntu 24.04/amd64. Release approval remains separate.** |

The Docker requirement for *Linux containers* is Docker's, not VardrSec's: the images are
Linux images, so any Docker installation that runs Linux containers can host them in
principle. VardrSec does not require WSL2 as an application dependency. Windows
acceptance used Docker Desktop's WSL2 Linux-container backend; other backends are
not independently certified by that observation.

| Environment | Position |
| --- | --- |
| Ubuntu 24.04 amd64, source-built Compose | NM-3 accepted; automated clean install, workflow, recovery and update |
| Ubuntu 22.04, other Linux distributions, arm64 | Not established; Ubuntu 22.04 has bounded tool/network evidence only |
| Windows 11 Docker Desktop (Linux/amd64 containers) | NM-3 accepted from clean application source trees/projects, configured Full/Mapless workflows, finite Recon, portable recovery and state-preserving Mapless update. Windows/Docker prerequisites were installed; clean-OS provisioning and release certification are separate |
| macOS Docker Desktop (Linux containers) | Experimental; no fresh-host install or recovery acceptance |
| Native Map, Runner, Gate on Windows or Linux | Supported for individual development and execution as documented by each component; not an integrated distribution |

Keep source-built compatibility distinct
from a published release and from unverified platforms. macOS Docker, other Linux
distributions and genuine VPN behavior do not inherit Windows/Ubuntu acceptance.

## Native component evidence

New Moon retains Windows 11 with Docker Desktop as a required distribution target.
The Full/Mapless cohort has canonical Windows Docker Desktop installation/recovery,
configured Windows workflow and fresh Ubuntu installation/workflow/recovery evidence; see the
[support limits](limitations.md).
Windows prerequisites were already installed and retained Docker resources were
preserved. Native Windows redacted export keeps its documented Windows 11 24H2+
and fixed-local-NTFS boundary; native Linux controlled execution requires its
existing owner context. These limits do not change the accepted container route.
The historical native results below do not replace container acceptance.

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

Limitations of that 2026-10-31 observation (later container support is summarized above):

- The loopback acceptance failed against then-current Runner 0.54.0 and Gate 0.2.0 on every
  operating system, because its harness does not approve Runner's new credential references
  and Map CI pins older companions. Tracked in
  [VardrMap #140](https://github.com/VardrSec/VardrMap/issues/140); the correction is test
  tooling only.
- Native Gau installation is refused by design on every operating system (Runner #94); the
  container build carries a reviewed patched Gau.
- The native Windows Compose workflow, native PostgreSQL on Windows and native HTTPS for Map
  are not covered by any CI job.

## Future work (planning direction, not commitments)

- **Community Alpha:** Windows 11 Docker Desktop is primary; Ubuntu 24.04/amd64
  source-built Compose remains required. Neither is a published release.
- **New Moon:** NM-3 Windows 11 Docker Desktop and Ubuntu source-built distribution
  acceptance is closed. Keep native component execution for justified host/VPN/keychain needs;
  integrated native deployment, genuine VPN behavior and prerequisite provisioning
  remain unqualified.
- **Later:** evaluate macOS; consider prebuilt container images and simplified installers
  after the [licensing review](release-license-inventory.md) and
  [security and support requirements](limitations.md) are resolved.

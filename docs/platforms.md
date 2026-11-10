# Platforms and deployment methods

Windows 11 with Docker Desktop is the primary Community target. Ubuntu
24.04/amd64 remains supported for the documented source-built Compose path.
These are source-built installations, not a published Community release.

## Containerized distribution

Full and Mapless use Linux/amd64 images and Docker Compose. Windows installation
uses Docker Desktop with Linux containers; VardrSec itself does not install WSL2
or provision operating-system prerequisites. The documented Windows path uses
Docker Desktop's WSL2 backend. Other backends are not independently qualified.

| Environment | Support boundary |
| --- | --- |
| Windows 11 Docker Desktop, Linux/amd64 | Documented Full/Mapless installation, workflow, recovery and update paths |
| Ubuntu 24.04/amd64 Compose | Documented Full/Mapless installation, workflow, recovery and update paths |
| Ubuntu 22.04, other Linux distributions, arm64 | Integrated installation support is not established |
| macOS Docker Desktop | Experimental; fresh-host installation and recovery are not qualified |

## Native components

Map, Runner and Gate can run with their own tooling on the platforms documented
by each component. An integrated native Full installation is not a supported
alternative to this distribution's Compose lifecycle.

Native execution may be appropriate for host-only routes, VPN access or OS
keychain custody, but those capabilities must be verified in the actual environment.
Native Windows redacted export requires its documented Windows 11 24H2+ and fixed
local NTFS boundary. Native Linux controlled execution requires its lifecycle-owner
context; an environment flag cannot replace that boundary.

Native Gau installation is excluded. The container toolkit has a separately
maintained Gau build. Raw-packet modes, genuine VPN/split-DNS/reconnect behavior
and controlled execution across suspend/resume are not universally qualified.

See [installation](installation.md), [networking](networking.md) and
[support and safety limits](limitations.md) before choosing a deployment method.

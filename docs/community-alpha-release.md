# Community Alpha v0.1.0 release preparation (draft, unpublished)

Status: **draft for review.** Nothing here is a release. No images are published,
no tag exists and `versions.json` still declares `distribution_release: null`.
The authoritative scope and task status are in [community-alpha.md](community-alpha.md).

## Intended support boundary

| Environment | Alpha position |
| --- | --- |
| Ubuntu 24.04 Linux/amd64, source-built Compose | Supported target; the only environment with a full automated clean-install, workflow, recovery and update record |
| Ubuntu 22.04 Linux/amd64 | Bounded tool/network checks only; not certified |
| Windows 11 / macOS with Docker Desktop | Experimental, no certification |
| Linux arm64, other hosts | Not established |
| Native Runner on the host | Supported as the fallback for VPN or host-only targets ([networking](networking.md)) |

## Release candidate checklist

Each item needs evidence recorded in the repository, not only a green CI run.

| # | Requirement | State |
| --- | --- | --- |
| 1 | Image security gates reviewed: every critical/high occurrence has a supported affected-status or exposure disposition, a fix, or an explicit owner-approved exception | **Open** (latest recount in [community-alpha.md](community-alpha.md); gates blocked) |
| 2 | Gau provider TLS: container fix pinned; native archive decision (fix, remove or exclude Gau from alpha scope) | **Open** owner decision ([review](gau-tls-review.md)) |
| 3 | Full researcher workflow through the interface with no API seeding | In review (see the installed-acceptance change) |
| 4 | Unfamiliar-user installation and first assessment, timed, with friction recorded | **Not done** (needs a real person) |
| 5 | Exact component commits frozen in `versions.json`, each reachable on its repository's `main` | Re-check at freeze |
| 6 | Independent rebuild reproduces the install artifacts from the frozen pins | Not started |
| 7 | Backup, encrypted restore, successful update and failed-update recovery rerun against the frozen pins | Passing on development pins; rerun at freeze |
| 8 | Redistribution and licensing review of every bundled tool and base image | **Open**, see below |
| 9 | Release notes, limitations, troubleshooting and recovery instructions reviewed | This draft |
| 10 | Owner approval for any image publication, tag or announcement | Not requested |

## Redistribution review items

The toolkit bundles nine managed tools (dalfox, dnsx, ffuf, gau, httpx, katana,
naabu, nuclei, subfinder) plus nmap and libpcap from the base distribution. Most
are believed to be MIT-licensed, but this has not been verified for this release:
confirm each license and its notice requirements against the pinned upstream
versions. Nmap is distributed under its own Nmap Public Source License, which has
specific terms for redistribution and bundling that need an explicit decision
before any published image includes it; a source-built distribution that installs
it on the user's machine is a different situation from shipping an image. Nuclei
templates are not bundled and must not be provisioned automatically without review.
This is an engineering checklist, not legal advice.

## Known limitations to state in the release notes

- Development, source-built distribution; no published images or signed artifacts.
- Genuine VPN routing, split tunnelling and kill-switch behavior are not verified.
- Raw-packet scanning modes, headless browser tooling and operator wordlists are
  not certified in the container; no capability or privileged mode is added.
- Scanner image findings remain open (see the latest recount); they are scanner
  occurrences, not confirmed exploit paths, and none is an accepted risk.
- Local authentication is implemented in Map but unreleased; hosted OAuth is not
  part of the local distribution acceptance.
- Gate results are correlated to reviewed cases, not cryptographically attested.

## Recovery and support pointers

Operators need only these existing guides: [installation](installation.md),
[backup and recovery](recovery.md), [encrypted backups](encrypted-backups.md),
[controlled updates](updates.md) and [networking](networking.md). Stopping the
platform preserves volumes; deleting a volume destroys stored state and evidence.

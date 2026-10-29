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
| 1 | Image security gates reviewed: every critical/high occurrence has a supported affected-status or exposure disposition, a fix, or an explicit owner-approved exception | **Remediation verified, residual disposition pending.** Rebuilt images: 1 critical / 195 high / 15 unknown; both fixable v4 occurrences removed; v3 has a [configuration-specific source/control review](caddy-v3-jwk-exposure.md) with no shipped JWK ingress; the dependency remains affected and unaccepted. See [checkpoint](alpha-review-2026-10-28.md). Nothing accepted; strict gates stay blocked |
| 2 | Gau provider TLS: container fix pinned; native archive decision (fix, remove or exclude Gau from alpha scope) | **Done:** container fixed (Runner #89); native archive excluded and enforced (Runner #94) |
| 3 | Full researcher workflow through the interface with no API seeding | **Done in CI:** client, window, scope and authorization are recorded through the Map UI in the installed workflow (Map #119, VardrSec #26) |
| 4 | Unfamiliar-user installation and first assessment, timed, with friction recorded | **Not done** (needs a real person) |
| 5 | Exact component commits frozen in `versions.json`, each reachable on its repository's `main` | **Exact development pins recorded:** Map #127, Runner #97 and unchanged Gate. Main ancestry for every exact pin is required at integration merge and rechecked at freeze; see #40 checks/merge record. This is not a release freeze |
| 6 | Independent rebuild reproduces the install artifacts from the frozen pins | **Partially reproducible**, see below |
| 7 | Backup, encrypted restore, successful update and failed-update recovery rerun against the frozen pins | Historical development baseline passed; integration results for the new exact pins are recorded in [#40 checks](https://github.com/VardrSec/VardrSec/pull/40/checks). Rerun at freeze |
| 8 | Redistribution and licensing review of every bundled tool and base image | **Open**, see below |
| 9 | Release notes, limitations, troubleshooting and recovery instructions reviewed | This draft |
| 10 | Owner approval for any image publication, tag or announcement | Not requested |

## Reproducibility evidence (2026-10-27)

What was verified, and its limits. This is **partial** reproducibility with pinned
inputs, not a hermetic or byte-identical image build.

| Check | Result | Limit |
| --- | --- | --- |
| Component pins are ancestors of each repository's `main` | Verified after Map #127 / Runner #96 merged. Runner then advanced to #97 for builder HTTP/1.1 transport; the final exact-pin ancestry check is required in #40's merge record. Map includes #120–#127 | Re-run at freeze |
| Base images pinned by digest | Verified in every Dockerfile at the pinned commits | Digest availability is outside our control |
| Gate binary from the pinned commit, two clean builds (separate caches), Go 1.27.3 | Byte-identical SHA-256 | Local linux/amd64 build, not compared to the CI image |
| FFUF source build, two clean builds | Byte-identical SHA-256 | As above |
| Package inventories of all five images from two independent CI builds of identical sources | Identical component sets and versions | About twenty minutes apart; apt and pip resolve at build time, so drift over longer periods is expected |
| Container images | **Not** byte-identical; not tested | Layer timestamps and build metadata differ |

Not hermetic: apt packages and Python dependency ranges resolve when images are built,
and Go modules are downloaded (checksum-verified against `go.sum` and the checksum
database) at build time. Describe the alpha as source-built from pinned sources and
base images, reproducible in its inputs but not offline or bit-for-bit.

## Owner decisions: status

Gau is decided and enforced. The go-jose/v4 fixes are verified in rebuilt images;
the unfixed v3 module advisory and the existing Debian/OpenPGP/Rust findings remain
unaccepted. The human and environment gates still apply. Each decision below states the evidence and a recommendation.

### 1. Native Gau archive (checklist item 2) — decided: excluded

Decision (owner, 2026-10-27): exclude the vulnerable native Gau from the alpha and enforce
the exclusion rather than only documenting it. Implemented in Runner #94: `tools install
gau` is refused, `tools install --all` skips it with the reason, and Runner executes only
the reviewed container source build (no PATH fallback, no opt-in). The container Gau is
the fixed build (Runner #89; fixtures reject untrusted and wrong-host certificates). Native
users who need Gau use the container toolkit. See [review](gau-tls-review.md).

### 2. Nmap redistribution (checklist item 8)

Usage audit (2026-10-27): no repository vendors Nmap code, data or binaries (the only
`nmap` files tracked are Runner's own tests and documentation). Nmap reaches a user only
through `apt-get install nmap` in the Runner toolkit Dockerfile, executed on the user's
machine during a local build. Runner invokes it as a separate process with a fixed safe
argument list (no `-A`, `-O`, `--script`, `-p-` or `-T5`) and reads its XML output; it does
not link, modify or embed it. Publishing a prebuilt image would redistribute the Debian
package, which is the situation that needs the license review.

Evidence: the toolkit installs nmap from the base distribution; Nmap's license (NPSL)
has specific bundling and redistribution terms. The alpha is source-built, so each user
installs it on their own machine and no image containing nmap is published.

Recommendation: **ship the alpha source-built only and do not publish any image that
contains nmap** until the license terms have been reviewed. This is an engineering
reading, not legal advice.

### 3. Residual security findings (checklist item 1)

The per-finding [residual-risk register](residual-risk-register.md) lists every unresolved
item with exposure assumptions, evidence and a proposed disposition; approve rows rather
than an aggregate count.

Nothing here is accepted. The owner chooses, per row, to accept as a documented alpha
limitation, to require a fix before release, or to exclude the component.

| Residual | Evidence | Recommendation |
| --- | --- | --- |
| 194 high Debian findings (util-linux, libxml2, GnuPG, perl, libacl, systemd, ncurses, libpcap) with no fixed version in the pinned suite | Exposure reviews; no fixed version; database network is internal and unpublished | Accept for a source-built alpha, listing them in the release notes; re-scan before any published image |
| 1 critical: CVE-2026-6653, libxml2 in the PostgreSQL image | Needs attacker-controlled XML parsed by SQL/XML functions; Map's source and migrations use none; only the API reaches the database | Accept for the alpha, conditional on Map continuing to avoid XML SQL functions |
| Nuclei: GO-2026-5932 (unmaintained openpgp, no fix) | Reported reachable by `govulncheck`; upstream Nuclei dependency | Accept; track upstream |
| Dalfox: moderate/low Rust advisories (`rustls` and others) | `Cargo.lock` against OSV; no critical/high; scanner cannot see Rust binaries | Accept; re-check on the next Dalfox release |
| Caddy go-jose/v3: CVE-2026-116587, no upstream v3 fix | Raw finding retained; [source/control review](caddy-v3-jwk-exposure.md) identifies the affected optional ACME path and its absence from shipped routes | Conditional non-exposure proposed only for the recorded pins/configuration, with CI regression guards; explicit owner disposition still required |
| Naabu: binary reachability verified | Runner #95 scanned the actual CGO/libpcap binary and reported no vulnerabilities | No exception required for the former evidence gap |

### 4. Items that need a person or an environment (not decisions)

- **Unfamiliar-user test** ([protocol](first-user-test.md)) needs a real participant and a
  fresh Ubuntu 24.04 machine. Recommended before any announcement.
- **Genuine VPN routing** needs a VPN. Recommendation: ship as a documented, unverified
  limitation with the native-Runner fallback ([networking](networking.md)).
- **Publishing, tagging or announcing** needs explicit approval and has not been requested.

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

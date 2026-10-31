# Community Alpha license inventory — 2026-10-28

Status: **direct-component inventory verified; distribution license adopted
(Apache-2.0, 2026-10-31); release licensing review open**.
This records the existing licenses, not a compatibility opinion,
permission to publish, or substitute for the actual license texts. Source-built
packaging is a proposal, not an exemption from license conditions.

## Reviewed inputs

Distribution `bc865d2d448f4d80738738a91c7f332d8aa6bfaa`; exact component pins:
Map `1c560f8b72f93c4396e57216e1ad93cc10785609`, Runner
`65186ddb6c26c9d895f146a74decc52e08d3913e`, Gate
`af29a93140b54cf5b684a06f552a05cd92f6dee6`. The inventory uses the pinned
Runner tool manifest and Dockerfile, distribution Dockerfiles and actual image
SBOMs from [run 40794172256](https://github.com/VardrSec/VardrSec/actions/runs/40794172256).
The CI merge tree equals the reviewed #41 tree. Each SBOM hash matches its receipt.

[Machine-readable evidence](release-license-inventory.json) records the immutable
upstream revisions, license Git blob IDs and text SHA-256 values. All nine license
files were fetched again at their resolved commits and matched the tagged blobs.
These are top-level licenses; dependency licenses require their own review.

## VardrSec components

| Component | Observed root license at the reviewed revision | Release action |
| --- | --- | --- |
| Distribution (this repository) | **Apache-2.0**, root `LICENSE` (official unmodified text, SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`) and `NOTICE`, adopted by the owner on 2026-10-31. At the reviewed revision above no root license existed. Copyright holder Jorge Aquino, supported by the sole-author history of this repository (every commit on `main` as of 2026-10-31 is authored by Jorge Aquino), Runner's `LICENSE` and Map's README; no other holder is evidenced | Original files only; the grant does not extend to, replace or override any component or third-party license |
| [Map](https://github.com/VardrSec/VardrMap/blob/1c560f8b72f93c4396e57216e1ad93cc10785609/LICENSE) | GNU AGPL version 3 text; README identifies AGPL v3.0 | Retain license/notices and review complete corresponding-source delivery and modified network-service obligations; private source pins alone are not a public source offer |
| [Runner](https://github.com/VardrSec/VardrRunner/blob/65186ddb6c26c9d895f146a74decc52e08d3913e/LICENSE) | MIT | Retain copyright and permission notice |
| [Gate](https://github.com/VardrSec/VardrGate/blob/af29a93140b54cf5b684a06f552a05cd92f6dee6/LICENSE) | Apache-2.0 | Retain license/attributions and applicable notices; identify modifications as required |

VardrForge is a separate research project with no license file; it is not part of the
platform release and is unchanged. The repositories remain independent. This inventory makes
no assertion about cross-component license compatibility or alternative commercial terms.
Confirmed 2026-10-31: Map's root `LICENSE` is AGPL-3.0, Runner's is MIT and Gate's is
Apache-2.0 (text identical to the official Apache-2.0 apart from surrounding whitespace);
none was modified.

## License structure and obligations

| Layer | License position | Obligations tracked here |
| --- | --- | --- |
| Original distribution code | Apache-2.0 | Keep `LICENSE` and `NOTICE`; retain notices in redistributed copies |
| Independently licensed components (Map, Runner, Gate) | Their own licenses (AGPL-3.0, MIT, Apache-2.0), unchanged | Preserve each license and its notices; Map's AGPL obligations, including source for a modified network service, apply to Map and are not altered by the distribution's license |
| Third-party tools, dependencies, base images and OS packages | Mixed; see the tables below | Notice and source obligations per package; Nmap excluded from packaging (retained integration code is an open question); transitive review incomplete |
| Source-built distribution (Community Alpha) | This repository distributes its own source, pins and scripts; users fetch the pinned component sources and build the images themselves | Components and their notices come from their own repositories and are not redistributed by this repository, but source-built packaging is not an exemption and the Nmap question stands |
| Future prebuilt-image redistribution | Not authorized | Would make the project a redistributor of every package in each image: a complete notice bundle, corresponding source or written offers for copyleft code, the Nmap determination and the transitive review, verified in the final images |

Adding the root `LICENSE` does not establish that any third-party or component
redistribution requirement is satisfied; the open items remain open.

## Managed tools

All nine pinned top-level license texts are MIT. Preserve their copyright and
permission notices; [the collected notices](managed-tool-notices.md) are review
inputs. Source-build dependency overrides and Gau's local patch remain governed
by their respective licenses and need provenance retained.

| Tool | Pinned version | Immutable license source | Delivery in the toolkit |
| --- | --- | --- | --- |
| dalfox | 3.2.4 | [MIT text](https://github.com/hahwul/dalfox/blob/da19527f9c82d8525e911ca3669fc456daeb50f2/LICENSE.txt) | Checksum-pinned release binary |
| dnsx | 1.3.1 | [MIT text](https://github.com/projectdiscovery/dnsx/blob/01e315f216db7d36198ec326fac13dd7846b1bec/LICENSE.md) | Source build with recorded dependency overrides |
| ffuf | 2.3.0 | [MIT text](https://github.com/ffuf/ffuf/blob/256c1b02499f5f8672af965d4ad7a321d606bc65/LICENSE) | Source build with recorded dependency overrides |
| gau | 2.2.4 | [MIT text](https://github.com/lc/gau/blob/5d4e1270e632732756fe98717520c43c86e8bd18/LICENSE) | Source build with reviewed local patch and dependency overrides; native excluded |
| httpx | 1.12.0 | [MIT text](https://github.com/projectdiscovery/httpx/blob/4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8/LICENSE.md) | Source build with recorded dependency overrides |
| katana | 1.8.0 | [MIT text](https://github.com/projectdiscovery/katana/blob/35267ac5c8ff1db9694a319d0eb466ed97b0969f/LICENSE.md) | Source build with recorded dependency overrides |
| naabu | 2.6.1 | [MIT text](https://github.com/projectdiscovery/naabu/blob/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8/LICENSE.md) | Source build with recorded dependency overrides |
| nuclei | 3.11.1 | [MIT text](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/LICENSE.md) | Source build with recorded dependency overrides |
| subfinder | 2.17.0 | [MIT text](https://github.com/projectdiscovery/subfinder/blob/c97f25802892093060f0fc424bfc3f39e273693a/LICENSE.md) | Source build with recorded dependency overrides |

The current installers stage binaries and provenance, not a complete dependency
notice bundle. Gau explicitly retains `upstream.LICENSE`; the other eight managed
tool notices are not explicitly copied by those build/install paths. The collected
document does not install notices into existing images or native tool directories.
Before distributing binaries, bind and package the required notices and source
materials with those exact artifacts; verify their presence in the final images.
Native Gau remains excluded. Nuclei templates are not included in this inventory
or automatically approved for acquisition/distribution.

## Nmap: excluded from packaging; retained integration code is a separate question

**Decision (owner, 2026-10-31):** Community Alpha uses Naabu for port discovery and does not
package or support Nmap. Verified on the pins of
[distribution #58](https://github.com/VardrSec/VardrSec/pull/58):

- The Runner `toolkit` image no longer installs `nmap` or `nmap-common`
  ([Runner #103](https://github.com/VardrSec/VardrRunner/pull/103)); no installer, manifest or
  `tools install` path ever downloaded Nmap. Runner's container workflow, the tool/network
  fixture (no `nmap` binary, `nmap`/`nmap-common` package or `nmap*` file in the image, and
  not an inventoried tool) and the image evidence check (an SBOM or package inventory
  containing `nmap`/`nmap-common` is rejected for all five images) enforce this.
- No `nmap-service-probes` database or any `nmap*` file is in the image. Naabu is run with
  `-list -top-ports -json -o -silent` only, never its Nmap hooks, which a Runner unit test
  asserts; HTTPx still identifies web services.
- Map no longer offers Nmap in the Composer, and Host Enumeration is `naabu -> httpx`
  ([Map #141](https://github.com/VardrSec/VardrMap/pull/141)). Map's API still accepts the
  `nmap` job type; a Runner that did not opt in fails it as unsupported. Map has no Nmap XML
  file import (its import types are ffuf, httpx, nuclei, katana, gau and dalfox), so none was
  removed; Runner's `parse_nmap_xml` remains for the opt-in path.

**Not resolved by this:** Runner still contains the Nmap execution and XML-parsing code,
off unless an operator sets `VARDRRUNNER_ENABLE_NMAP=1` and supplies their own Nmap. It is
isolated (disabled, never packaged), not removed. NPSL 0.95 section 3 treats software
"designed specifically to execute Covered Software and parse the results" as a derivative
work and says its authors interpret that term broadly; whether keeping that code in the
public Runner repository raises a concern is a legal question this document does not
answer. Removing the code is the alternative. The earlier Debian metadata mismatch
(`nmap-GPL-2` versus NPSL 0.95 for `nmap` 7.95+dfsg-3) concerned the package that is no longer
shipped and is kept only as history.
Removing Nmap from packaging does not resolve any other third-party obligation.

## Other runtime and build materials

| Material | Reviewed version/source | Observed license or review boundary |
| --- | --- | --- |
| [Caddy](https://github.com/caddyserver/caddy/blob/72dd0fb067f6d7826c7f79907670ba4a713bfe37/LICENSE) | 2.11.7, rebuilt with recorded dependency overrides | Apache-2.0; retain license/notices and review statically linked dependencies |
| [gosu](https://github.com/tianon/gosu/blob/6456aaa0f3c854d199d0f037f068eb97515b7513/LICENSE) | 1.19 source revision from db/Dockerfile, rebuilt with moby/sys/user override | Apache-2.0; preserve source/patch provenance and dependency notices |
| [libpcap package](https://metadata.ftp-master.debian.org/changelogs//main/libp/libpcap/libpcap_1.10.5-2_copyright) | libpcap0.8t64 1.10.5-2 in Runner | Debian copyright records BSD-3-Clause; review actual package notices and linked libraries |
| [PostgreSQL](https://www.postgresql.org/about/licence/) | postgres base digest in db/Dockerfile; SBOM PostgreSQL 18.6-1.pgdg13+2 | PostgreSQL license for server; the package and image contain additional separately licensed code |
| [Python](https://docs.python.org/3.12/license.html) / [Node](https://github.com/nodejs/node/blob/v24.x/LICENSE) | Digest-pinned python:3.12-slim-trixie and node:24-trixie-slim | Runtime vendor terms plus bundled dependencies; the Node link is orientation, not exact-image evidence |
| Debian / Alpine packages, including curl and CA data | Actual five-image SBOM package versions | Mixed licenses; retain package copyright/common-license files and collect missing metadata; a base-image label is not one license for the image |
| [age](https://github.com/FiloSottile/age/blob/v1.3.2/LICENSE) | CI host builds age/age-keygen 1.3.2; recovery requires operator-provided age | BSD-3-Clause top-level text; no claim that host tools are included in runtime images |
| Go compiler and build/CI utilities | Go 1.27.3 builders and pinned workflow tools | Separate build inputs; audit notices for code incorporated into shipped binaries; do not count a discarded build stage as a runtime package |

Base image digests are recorded in the JSON alongside the source recipes. They
identify build inputs, not immutable apt/pip package resolutions. Re-run the
inventory at the candidate freeze; no tagged candidate exists yet.

## SBOM license-metadata coverage

| Image | Components | With a nonempty licenses field | Missing that field |
| --- | ---: | ---: | ---: |
| api | 134 | 129 | 5 |
| db | 151 | 140 | 11 |
| proxy | 196 | 32 | 164 |
| runner | 1193 | 115 | 1078 |
| web | 256 | 251 | 5 |
| **Total occurrences** | **1930** | **667** | **1263** |

Counts are per-image occurrences, not deduplicated packages or validated license
determinations. Scanner fields can be stale, incomplete or ambiguous, as Nmap
demonstrates. Go module entries account for many gaps; Dalfox's Rust dependencies
also require its source lockfile review rather than assuming binary SBOM coverage.
Zero security findings would not close these licensing tasks.

## Before release approval

1. **Done (2026-10-31):** the owner selected Apache-2.0 for the distribution; each
   component's existing grant is preserved.
2. **Packaging done (2026-10-31):** Nmap is excluded from every image. Still open: decide whether
   the retained, opt-in Nmap integration code in Runner is acceptable or should be removed.
3. Complete transitive Go/Rust/Python/npm/OS license and notice review, including
   missing/custom metadata, copyleft source obligations and statically linked code.
4. Assemble and verify notices and corresponding source for the actual distributed
   artifacts. This inventory and its links are not that complete delivery bundle.
5. Freeze the candidate, refresh evidence, and approve the packaging/publication
   decision explicitly. Security dispositions and unfamiliar-user testing remain
   separate open gates in the [release checklist](community-alpha-release.md).

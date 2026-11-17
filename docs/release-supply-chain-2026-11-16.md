# Community Edition v0.1.0 Alpha: supply-chain qualification

**HOLD — November 16, 2026.** Engineering checks establish the evidence below;
distribution obligations are not yet closed. No artifacts were published or
central pins changed. This report concerns distribution
`25040b000e3a99c7c0218f58cb08ec73bc189373` and
[qualification run 43863874269](https://github.com/VardrSec/VardrSec/actions/runs/43863874269),
not the older local `480d4e0` candidate. Its manifest remains `development`,
`distribution_release: null`, `runnable: false`, with no release image pins.

## Satisfied checks

- The existing exact-revision image checker validates all five receipt/SBOM/report
  pairs. All 820 retained notice files match their recorded sizes and SHA-256s:
  API 142, web 373, DB 138, Runner 161, proxy 6. Runtime manifests match the
  receipt's image configuration IDs. Image archive hashes are recorded; the
  original image archives were not available for independent rehashing.
- Map's AGPL-3.0, Runner's MIT, Gate's Apache-2.0 and the distribution's
  Apache-2.0 license bytes are retained. Selected actual-image component license
  bytes match the exact source snapshot. These licenses do not license every
  third-party dependency.
- Reused and rehashed the existing 710-file OS/static-source capture, 317-file
  historical native-delivery inventory, and 46 Python sdists with 93 embedded
  notices. No unchanged sources were reacquired. Historical identities were
  preserved; these checks do not promote old image evidence to the new candidate.
- All 18 current native `SHA256SUMS` manifests pass (258 entries). Checked the
  input hashes/sizes in 36 Debian source descriptors. One original Kerberos
  descriptor references an upstream `.asc` absent from its native export; the
  already captured, checksum-matching 833-byte signature is retained separately
  as a supplement. Its cryptographic signature was not reverified.
- The current scanner inventory has 856 Go package occurrences across ten
  binaries. 839 match exact module/version prefixes in actual-image dependency
  notice archives. The other 17 are ten Go standard-library entries and seven
  development/local-replacement entries; retained Go licenses, project licenses,
  patched go-github and go-jose provenance provide their separate review inputs.
  Prefix matching alone does not establish semantic license compliance. The
  historical Nuclei/Censys finding does not apply automatically: this Runner
  inventory has no Nuclei binary entry.

## Bounded corrections

1. Created the missing exact-revision source snapshot using `source_release.py`.
   Two builds match; both pass its existing verifier against the full revision
   and expected SHA-256. This covers the four tracked Git trees and their
   collected notices, excluding transitive/generated external build inputs.
2. Corrected the existing workflow to export and checksum
   `/usr/share/doc/libacl1/vardr-source` from API, web and Runner as well as DB.
   Preserved the existing DB destination and all build inputs. The edited shell
   step passes `bash -n`; `git diff --check` passes. No image rebuild was run.
3. Classified all 14 unresolved runtime entries: API/web have two systemd/udev
   alias paths each; DB has those two, four Kerberos aliases and one libxml2
   alias; Runner has systemd/udev and libpcap aliases. These are non-regular native
   library paths, not missing notices/source archives. Exact link types/targets
   were not retained. Keep the collector's incomplete-coverage flag; do not
   count these entries as 14 legal blockers or as proof of missing libraries.

## Exact remaining requirements and owners

| Requirement | Missing evidence / least disruptive next action | Owner |
|---|---|---|
| ACL delivery in API, web, Runner | Their exact pinned build scripts and two source patches equal the retained DB recipe, and their Dockerfiles copy the source directory. Only DB was actually exported. Obtain that directory and verify `SHA256SUMS` from each exact image; recipe equality is insufficient. The exact API image is unavailable locally. If rebuilt, bind the new export to its new image ID. | Coordinated qualification owner; Codex 2 verifies |
| Recipient source and notices | Supply a recipient-accessible, image-bound index/bundle covering the retained OS/static/custom sources and applicable application dependencies, full notices, patches and build/install inputs. Local captures and expiring CI artifacts are not a completed delivery channel. Current custom source versions outside the historical OS lock are enumerated in the local check evidence; many are already retained in current native exports. Do not recapture those. | Vigil / release owner |
| Final dependency review | Reconcile actual npm/Python/native contents and retained texts; settle applicable per-file terms, alternatives and exceptions. Finish psycopg native mapping/replacement materials and applicable libvips/librsvg linkage review. The historical focused captures and source-lock inventory do not clear all final dependencies. Confirm Alpine package notice delivery: the proxy collector retains only six Caddy/distribution notice files, not proof of complete base-package notices. | Licensing reviewer with Codex 2 evidence |
| Library modification provisions | Complete applicable LGPL replacement/relinking documentation/materials, particularly static sqv and bundled native libraries; confirm terms permit the required modifications/debugging. Preserve GCC exceptions and the existing Berkeley DB caller/source analysis. No blanket demand for object files or byte-identical image rebuilds. | Release owner / licensing reviewer |
| Freeze and integrity handoff | Identify the actual release payloads and trusted checksum channel. Current configuration IDs identify development images, not registry release digests or signatures. If images are shipped, bind the delivered identities to the reviewed source/notice evidence. If the release is source-only, explicitly record that boundary. | Vigil; no independent pin/publication changes |

The source-delivery and modification requirements follow the applicable license
terms, including [AGPL sections 6 and 13](https://www.gnu.org/licenses/agpl-3.0.en.html)
and [LGPL section 4](https://www.gnu.org/licenses/lgpl-3.0.en.html); their application
to particular combined works still requires review. Missing scanner metadata is
not itself a licensing failure. Signatures, a generalized SBOM service and
byte-identical container builds are not added acceptance requirements.

## Checksum and identity anchors

| Evidence | SHA-256 |
|---|---|
| Exact image receipt | `f4ca5baec9326b68859b2ead06a41913f03996d650a4d5579a538d94b4434b0d` |
| `vardrsec-25040b0-source-a.tar.gz` and `-b.tar.gz` | `08ef8e493ca7eb7e8fc1d8d3293914eb1f2c0d76493791c52d21f97984359b3b` |
| Retained OS/static lock | `c5d5da03380e1484ad0c74cd1036cc703f13bbf3534392b5f0ec740d24da33e9` |
| Supplemental Kerberos upstream signature | `85047c935fe949ef2e275885451b168557b923dd13a5aab0ef8fe6acd27b94d7` |

Source snapshot pins: Map `76dcbb9d1b17bb06005da86f3f3194e22521bb32`,
Runner `00812c13b4b2986b594fc91712abe7cc96eafea7`,
Gate `2474296597b6ccd082e2e405662fd1f2cada69f4`.
The snapshot reproducibility receipt applies to these source archives only.
It does not require or establish reproducible containers/executables.

Local `supply-chain-checks.json` and `supply-chain-followup.json` beside the
qualification evidence retain full image IDs, runtime archive hashes, package
version differences, source/license hashes and non-regular-entry classifications.
Codex 1's independent security hold remains in force. No release clearance is
asserted, and optional improvements should stop once the requirements above close.

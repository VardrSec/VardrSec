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
| ACL delivery in API, web, Runner | Both historical run 43863874269 and completed candidate run 43999768066 retain only DB ACL sources. The candidate DB bundle passes all 55 checksums and six source-descriptor checks; it cannot substitute for three actual-image exports. API/web/Runner remain unverified at their respective image IDs. The corrected export step remains queued for the next independently required qualification. No ACL-only rebuild or rerun was triggered. | Coordinated qualification owner; Codex 2 verifies |
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

## ACL export recovery follow-up — November 16

Codex 2 asked Codex 1 to locate existing images, exports or remote retention,
without rebuilding unchanged images. Both local Docker contexts were searched:
207 unique image IDs including intermediate images, and 12 containers per
context; no matching API, web or Runner identity was found. These contexts may
refer to the same underlying engine and are not claimed as independent hosts.
The original job logs identify a GitHub-hosted Ubuntu runner and show only the
DB ACL export before job cleanup. The original artifact listing contains no
complete image archive or build-cache artifact. This establishes that the
checked resources do not supply the missing exports, not that no other copy
could exist. Exact source-bundle checksums for the three images remain
unverified. Local `acl-export-recovery.json`, `acl-export-local-search.json`
and `acl-export-job-excerpts.log` retain the search and DB checksum evidence.
Codex 1's `acl-export-codex1.md` confirms no source exports were recovered on
its active daemon and no retained remote archive is evidenced. The receipt's
registry digest lists are empty. PR #118's separate database remediation does
not establish ACL source delivery for these historical images.
No prior source archives, notices or image scans were regenerated.

### Next required qualification: coordinated, verification pending

Codex 1 identified [RC PR #116](https://github.com/VardrSec/VardrSec/pull/116)
as the next combined database-acceptance and image-evidence qualification. Its
current head is `320b93eb634aa6998fe0f08bf87d24b1093b2f5d`. The RC owner must
integrate the reviewed PR #118 libxml2 fix and correct the Kerberos
installed-version assertion; the workflow-only ACL export patch from `01f557c`
is to be included in that same required qualification update. Codex 1 recorded
this in the [RC owner handoff](https://github.com/VardrSec/VardrSec/pull/116#issuecomment-6949225553)
and the shared acknowledgment. The patch remains queued, not asserted as
integrated. No additional build, rerun or PR push was requested solely to
collect ACL sources. Standalone PR #118 run `43999768066` used the original
workflow and does not close the three missing exports.

The next handoff must retain the corrected workflow revision, qualification run
and attempt, `native-source-delivery` artifact and paired image receipt. For API,
web and Runner, verify every source `SHA256SUMS` entry and each `.dsc` input set;
bind the service export to the same stopped-container/image identity used for
that run's runtime evidence and receipt. Record the new full configuration ID,
artifact and source-manifest hashes with each result. Reject missing exports or
identity mismatches, and preserve historical run `43863874269` as unverified.
The combined revision, next run ID, new image IDs and export verification results are **pending**;
no queued work is reported as acceptance. Local `acl-next-qualification-codex1.md`
retains Codex 1's acknowledgment and `acl-next-qualification.json` records the
handoff state.

### Completed qualification checked November 17 at 7:16 a.m. CST

[Image run 43999768066](https://github.com/VardrSec/VardrSec/actions/runs/43999768066)
completed successfully for PR #118 head
`7a34cb2f1fbef227393dbf46f4ab513fc07d0644`, tested at merge revision
`d66e3517cdabe47c6f3561d768462e1d7eecf45f`. Its seven retained artifacts include
native sources, runtime evidence and the paired image receipt. Reused the
already extracted artifacts; no rebuild, scan or source recapture was performed.
The exact tested workflow still exports ACL sources only from DB. No API, web
or Runner ACL export directory exists in its retained native-source artifact.

| Service | New image configuration ID | ACL source export result |
|---|---|---|
| API | `sha256:32581c3b4167053deb8156435eb39fa03063433b097ba2e88a6bf6792dff4482` | Missing; source checksums cannot be verified |
| Web | `sha256:e4aa72208477a1f5233021759ceac8439e3a01c2265a597d5e04c7f8b74e8a8e` | Missing; source checksums cannot be verified |
| Runner | `sha256:c56f60c143b5e38a5bf58533af69b6aabad611f2572d15afe36afb4ed09789d7` | Missing; source checksums cannot be verified |
| DB | `sha256:24f4538dd19f79213d5ad3835a48b8e960c6535bcbdb0ae35bd3dabf97a5faff` | All 55 manifest entries match; six `.dsc` descriptors and 14 declared input references match sizes/hashes |

All four runtime image IDs and distribution revisions match the paired receipt;
the exact-revision image checker passes its receipt/report integrity checks.
The DB source export and runtime evidence come from the same stopped container
in the successful workflow. DB source-manifest SHA-256:
`07b4787b249af2295b1cf77e0c31daec9cbf7ec64cecb66dcdb6c8363555aece`.
Candidate image-receipt SHA-256:
`47218c416662b70c19e62d1f85de26953cad0674300a570a6a81305d97d36ee0`.
The native-source artifact is `14293334998`; GitHub records ZIP SHA-256
`1478a52cdb68b7b94d6e077f0b0337db1b089ae721025b404611539b6ce1acd1`.
That ZIP digest was recorded, not independently rehashed from a fresh download.

Separate database acceptance run `43999767850` also completed successfully.
Its smoke image `sha256:fd1df4cfd2b30858b0db5da606677d09d7011222a5ffe12cadd903ad0ce7b1c6`
has an ACL installed-custody exit code of zero, including cp/tar/libacl checks.
That separate image is not substituted for the scanned DB image or the three
missing source exports. Local `qualification-43999768066/acl-source-verification.json`
records the bounded verification; its adjacent artifact inventory and job
excerpts retain provenance. The API/web/Runner gap remains open for the next
independently required qualification with the corrected export step. Successful
CI collection is not release or vulnerability clearance.

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

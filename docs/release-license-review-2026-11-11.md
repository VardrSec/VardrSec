# Exact-image license and source review — 2026-11-11

**Status: technical inventory refreshed; transitive review and final delivery are
not complete. No redistribution clearance is asserted.** This supplements, rather
than rewrites, the [historical inventory](release-license-inventory.md).

## Evidence boundary

Reviewed the five-image evidence from [workflow 42988221940](https://github.com/VardrSec/VardrSec/actions/runs/42988221940),
artifact `13840484215`. The image collector's receipt/report hashes, selected image
identities and scanner/database validation were rechecked locally with
`image_evidence.review`. Vulnerability gates remain blocked independently of this
license review. The receipt names CI merge commit
`12c82d11b9145f3dd09ee6f1319bff7688f524c9`, not a published release.

Its source manifest records the pre-remediation component pins:
Map `8bde9ff0c919db83c8995f46eac7bd828163892d`, Runner
`cc15dec86574d595c84f323aec813c241b4e56f8`, Gate
`ecd180627c9e692a8df532122713577d0afcefa1`. Newer component version headings do not
change these historical image inputs. The candidate branch now changes Runner
and Gate pins; this report does not clear the new images. Refresh this review after changing pins or rebuilding
images; build-time dependency resolution can also change their contents.

The [machine-readable review](release-license-review-2026-11-11.json) records the
receipt, SBOM and exact root license hashes. Root licenses are unchanged: Map
AGPL-3.0, Runner MIT, Gate Apache-2.0. This says nothing by itself about the
licenses of code inside their dependencies.

## Recomputed SBOM metadata

| Image | Component occurrences | With license metadata | Without license metadata |
| --- | ---: | ---: | ---: |
| api | 135 | 130 | 5 |
| db | 144 | 133 | 11 |
| proxy | 196 | 32 | 164 |
| runner | 1211 | 134 | 1077 |
| web | 256 | 251 | 5 |
| Total | 1942 | 680 | 1262 |

These are per-image SBOM occurrences, not unique libraries or legal conclusions.
Missing metadata is not proof a package has no license; nonempty metadata is not
proof all applicable terms or notices were delivered. Go binary detection accounts
for many missing fields. Operating-system/application entries also appear in these
counts. Scanner SPDX identifiers, custom names and expressions are preserved
verbatim for review, not converted into an allowlist.

Generate the full per-occurrence review queue from a fresh report directory:

```sh
python license_evidence.py artifacts/image-evidence/run-EXAMPLE/reports --output ../license-review-queue.json
```

The output must not already exist. This offline command validates the evidence
and requires its source manifest to match `versions.json` (or `--manifest PATH`).
It never downloads sources, runs images, accepts a license or marks a gate clear.
Every entry remains `missing_metadata` or `declaration_requires_review`; the
result always has `release_clearance: false`. Retain this queue with the exact
reports for package-by-package notice/source review.

## Source and notice delivery checked

- **Component sources:** the existing `source-notices --include-sources` collector
  can verify every tracked blob in the exact component trees. It explicitly does
  not include transitive or external build inputs. Root license bytes were read
  from each pinned Git commit and hashed again for this review.
- **Dalfox:** the committed `dalfox-3.2.4-notices.tar.gz` at the Runner pin contains
  336 lockfile package records. All 217 `SHA256SUMS` entries matched retained
  bytes. It includes four unmodified MPL-2.0 crate source archives. This verifies
  archive integrity, not final linkage or compatibility. Optional/other-target
  dependencies are included; the unresolved Android-only grant text remains
  explicitly outside claimed supported-target coverage.
- **Source-built Go binaries:** current recipes retain Go license texts and module
  cache legal-text archives for Caddy/gosu and Runner tools. A cache can contain
  unused versions. Final-image extraction and linked-module-to-notice coverage
  must be checked before treating these archives as complete attribution.
- **Modified native libraries:** libxml2 and libpcap recipes retain their source,
  patches, build metadata and checksums. Those deliveries cover these libraries,
  not all Debian/Alpine runtime packages.

## Remaining decisions and evidence

1. Reconcile Map's npm/Python dependencies and standalone web runtime contents
   with delivered notices and required source materials.
2. Match actual linked Go modules, including Gate, against retained legal texts;
   review custom/missing declarations and stale cache versions individually.
3. Match every runtime OS package to exact source and notice delivery. Do not
   substitute a base-image license label for individual package obligations.
4. Resolve the retained opt-in Nmap integration question separately. Nmap is
   excluded from images; this is not a conclusion about the integration's legal
   status or permission to change/remove it.
5. Verify the final distributable files/images contain the reviewed materials.
   A hash-only inventory or a link to a repository is not a universal substitute
   for required source/notice delivery. Publication remains a separate approval.

No existing gate is weakened or waived by this report. Unresolved legal
interpretations require qualified review rather than an automated compatibility
assertion. Reproducibility, vulnerability disposition and operational acceptance
remain independent requirements.

## Subsequent bounded delivery and runtime checks

The historical table above is not a final candidate inventory. Subsequent work
captured 46 exact Python source distributions and 93 legal texts, five focused
npm packages, the psycopg-binary upstream source/wheel mapping, and all 33 direct
sharp-libvips recipe inputs (28 source archives and five patches) with 98 legal
texts. See `map-dependency-source-delivery.md` and the linked hash manifests.
These captures do not include every transitive dependency. In particular,
librsvg's Rust crates remain unvendored and its recipe performs a workspace
update; direct recipe inputs alone cannot prove the original build.

Image-evidence run [42995798879](https://github.com/VardrSec/VardrSec/actions/runs/42995798879)
for distribution head `7b4747048a591dbbbf045f6352e3bd88ca0ccd9d`
(retained receipt commit `48576dc6f00fdf11263365f8db00501e010ca3a2`)
provided 795 allowlisted runtime notice files across five images. Their file
hashes and image identities were checked against the paired image receipts.
Runtime artifact `13844982085` has ZIP SHA-256
`4eaca9dfa07b42fe5590fa73e0a86320f0aa100a78290620f4edc7794cdf3d52`;
paired image artifact `13844233198` has ZIP SHA-256
`9227379a20b0c82770cdf8fba7d40dd56f61128f1787f1a901ddd1c1fecdd0f3`.
All 15 selected psycopg native library files matched the previously verified
wheel; the actual libvips binary matched the verified npm archive with SHA-256
`4aa73553408c3964071728f4a231a8e86918e39bc49f1fbae75355f7ea933ea9`.

This closes the selected native-byte identity check for those exact images,
not source completeness, whole-wheel identity, legal compatibility or release
clearance. That older collector omitted generated Go-license/provenance names;
the current collector includes them, with fresh candidate evidence still needed.
The full OS and linked-module notice/source reconciliation remains open.

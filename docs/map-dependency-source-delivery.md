# Map dependency source-delivery evidence

This supplements the release license review. It is not a legal clearance or a
claim that package metadata proves compliance. The input is the exact API/web
CycloneDX inventory from image-evidence run 42988221940 (2026-11-11), not a new
resolution of the direct dependency files. Map source pin:
`8bde9ff0c919db83c8995f46eac7bd828163892d`.

## Python source collector

```sh
python python_source_delivery.py reports/api.cdx.json --output api-python-sources.tar
```

The collector deduplicates Python package name/version identities from the SBOM,
fetches **only** official PyPI release metadata and source distributions, verifies
each sdist against that release's SHA-256, and retains the complete sdist, registry
metadata, input SBOM and conventional license/notice/copyright files in a tar.
Nothing is installed or executed. Paths are not extracted from untrusted archives.
Existing output is never overwritten. Missing/multiple sdists, metadata identity
mismatches, corrupt hashes and collection failures remain explicit and yield a
nonzero exit. Absence of a conventional legal filename remains explicit even if
the source archive is retained. The tar serializes identical captured inputs
identically; independently fetched registry JSON can change, so a fresh network
collection is **not** asserted byte-reproducible.

`complete_sdist_coverage` means only that each exact Python package has a retained
registry source archive. `release_clearance` is always false. This does not verify
that a wheel was built from that sdist, supply sources of all native libraries
embedded in wheels, establish required relinking/replacement material, cover OS
packages or Node dependencies, or establish license compatibility. Final runtime
notice extraction and source reconciliation are separate release gates.

The pinned backend Dockerfile installs 17 direct requirements, but the examined
API image contains 47 Python package identities. The requirements file has no
transitive/hash lock. A newly resolved backend can therefore differ; always use
the final image's SBOM and bind its source-delivery tar digest to that image's
receipt before publication. In particular psycopg and psycopg-binary 3.3.6 are
reported LGPL-3.0-only, and certifi 2026.10.23 MPL-2.0. These need actual retained
license/source and native-bundle review, not an automatic permissive allowlist.

## Focused npm artifact inspection

The following exact registry artifacts were downloaded and SHA-512 integrity
verified against their registry release metadata. Complete package tarballs were
retained in the review workspace; this table is evidence of inspection, **not**
proof of delivery to users or linkage into browser bundles.

| Package | Version | SHA-256 of registry tarball | Inspection |
|---|---|---|---|
| `@img/sharp-libvips-linux-x64` | 1.3.4 | `e371cb713fc8822c96a0d3fb60a3d092799d0aefab6d7f1fb3b72d8d75f1d109` | Binary native bundle; README license table, no full legal texts or native sources |
| `@vercel/og` | 1.0.1 | `c7f0946ae4b90f4a38615f69ceacfb5990e865c847b96475752b100b93e4e27f` | MPL-2.0 declaration and `package/LICENSE` retained; generated/bundled code source mapping remains |
| `caniuse-lite` | 1.0.30001815 | `13a77d8ee9818bd5cc19aafb1eca23724a3ed1afc41f39095c9f19b485a2e3a4` | CC-BY-4.0 declaration and `package/LICENSE` retained; attribution delivery still requires verification |
| `dompurify` | 3.4.17 | `056cbdae276897208b88c21d1d779adfa09ad7be488a2f510a28e900d3bbffe7` | MPL-2.0 OR Apache-2.0 declaration; LICENSE, LICENSE-MPL and source license header retained; no branch selection claimed |
| `rgbcolor` | 1.0.1 | `51be5b477cbe2b12d89be8d72772c609d005bb4d6b271f6031796ecf18f7ca03` | MIT OR alternate FEEL-FREE declaration; LICENSE.md retained, no interpretation of alternate grant claimed |

### Native web bundle gap is concrete

The exact libvips npm archive contains just six members: the
`libvips-cpp.so.8.18.7` binary, glib config header, JS loader, package metadata,
`versions.json`, and README. The README lists LGPL, MPL and other licensed bundled
libraries, including libvips, glib, fribidi, libexif, libheif, librsvg, pango and
cairo. There are no full LICENSE/COPYING files or corresponding native sources in
that package. The app repository source archive alone cannot fill this gap.

Before claiming this gate closed: retain the exact sharp-libvips build recipe,
patches and library source inputs matching its `versions.json`; retain applicable
full license/notice material; determine and supply required replacement/relinking
material for this binary arrangement; and verify delivery in the final image or
accompanying release bundle. A list of upstream links to moving branches is not
that evidence. This review does not change the image or select a new dependency.

### Pinned native recipe recovered

The npm metadata's `gitHead` matches upstream tag `v1.3.4` commit
`ebb95f8add54eee8bed840e3fb587e4cbec857d7`. The complete recipe Git archive was
retained (SHA-256 `95dffe5f8b8362cc7826b0d8ef95512f789706d16912624d27decbfda28496d6`).
All 28 native version fields match the npm `versions.json`. The machine-readable
review records 28 expanded source archive URLs and five patch URLs from that
pinned recipe, with download verification explicitly false. These are a concrete
acquisition checklist, not downloaded source evidence. The README lists a 29th
library, libnsgif, absent from the recipe version inventory; linkage is unproven.
The recipe also retrieves its notice summary from moving `main` and one patch
from a mutable pull-request URL. Those exact bytes need preservation and review
before a reproducible-source or complete native-delivery claim.

## Collected Python result

Collection retained **46 of 47** exact Python source distributions, with **93**
legal-text files. Every source hash was matched to official release metadata; all
retained source, legal-text and registry-metadata hashes were then independently
rechecked from the completed tar. A second serialization of the captured bytes
produced the same SHA-256:
`ddb93d55614bdbbb2ee5b8277db8cdcee959ae6f86c409ab8671bc07d8e80628`.
The committed `map-python-source-delivery-2026-11-11.json` records each package,
source URL/hash, metadata hash, legal-text paths/hashes and exact input SBOM hash.

The sole missing sdist is **psycopg-binary 3.3.6**: official PyPI metadata contains
zero sdists. `psycopg` 3.3.6 source was retained separately, but it is **not**
automatically substituted as complete source for the binary wheel or its bundled
native libraries. Recover and verify that wheel's exact upstream build inputs,
patches, libpq/OpenSSL and other native source/notice inventory before closing it.
No package download failed or was silently skipped. This is a partial source
bundle, not a completed release gate. Distribution and final wheel/image matching
remain outstanding.

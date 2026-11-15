# Verified source snapshot artifacts

`source_release.py` creates an **unpublished source snapshot**, not runnable
images or an approved product release. It reuses the offline notice collector to
include the distribution's committed HEAD, each exact component pin from that
commit's `versions.json`, top-level notices, complete tracked Git-tree archives,
and a checksum inventory. Modified and untracked working files are excluded.

Prepare the required Git objects using the normal source setup first. Then run
from the distribution checkout (use your Python 3.10+ launcher):

```sh
python source_release.py create --root . --map-repo .sources/map --runner-repo .sources/runner --gate-repo .sources/gate --output ../vardrsec-source-a.tar.gz
python source_release.py create --root . --map-repo .sources/map --runner-repo .sources/runner --gate-repo .sources/gate --output ../vardrsec-source-b.tar.gz
```

Each command prints its artifact SHA-256. Both must match for a two-build
reproducibility check. Output names must be new; existing artifacts are never
overwritten. No network fetch, checkout, image build, test-target execution,
release publication or service startup occurs. A failed operation may leave
incomplete output; retain it and choose a new destination.

Record the printed digest and the full distribution HEAD commit through a trusted
review channel. Verify the delivered file without extracting it:

```sh
python source_release.py verify ../vardrsec-source-a.tar.gz --sha256 EXPECTED_SHA256 --commit EXPECTED_DISTRIBUTION_COMMIT
```

Verification checks the separately supplied artifact hash, exact distribution
commit, component pins, notice/source archive sizes and hashes, and the complete
outer inventory. Unexpected, duplicate and unsafe outer members are rejected.
Creation additionally checks every inner source archive against its Git tree's
blob identities and executable modes. Git LFS pointers, submodules and omitted
export-attributed files refuse creation rather than silently omitting source.

Archive timestamps, owners, modes and gzip headers are normalized. Repeat builds
on the same Python/Git/zlib toolchain are intended to be byte-identical; compare
the actual outputs rather than assuming cross-version compressor identity. The
inventory contains no current time or machine-local path. Source symlinks remain
inside the inert inner tar files; neither command extracts them.

## Limits

- This verifies source artifact integrity and repeatability, **not reproducible
  container images or executables**. Images can still resolve changing package
  repositories and require separate frozen-input/rebuild evidence.
- A checksum or Git ID is not a signature or authenticated provenance. A checksum
  obtained from the same untrusted location as the archive is insufficient to
  establish authenticity.
- These archives do not include transitive dependencies, base-image sources,
  generated build inputs or all corresponding source. The [license/source
  review](release-license-review-2026-11-11.md) remains separate.
- Versions describe source snapshots. Component source pins may precede later
  component versions; the included `versions.json` and manifest are authoritative.
- No approval, release-readiness flag or published-image metadata is changed.

# Ordinary libvips candidate compatibility (non-shipping)

This separate experiment consumes the exact retained artifact from qualification
run **43037077744**, artifact **13865981097**, commit
`373da86b5d560c6d90d0cd0455f5cb54b4e5106a`. It does not rebuild native sources,
change shipping packages, or weaken the existing strict published-byte comparison.
That comparison still fails: the repeatable candidate is not byte-identical to the
published library. A compatibility pass is not a release clearance or risk waiver.

## Provenance and scope

`pins.json` records the artifact SHA256, both shared-library SHA256 values, and
six exact npm package versions/URLs/SHA512 integrities selected from Map commit
`8bde9ff0c919db83c8995f46eac7bd828163892d`'s frontend lock. Preparation verifies
all downloaded bytes, rejects unsafe archive entries, and runs no npm install
scripts. Each invocation needs a new output directory. The upstream package
`lib/index.js` and other package files remain intact; only the isolated candidate
tree receives the verified replacement ELF. Linux process maps and the loaded
library's digest are checked during testing, preventing accidental tests of the
wrong installed library.

The Node24 Trixie image digest matches that Map commit's Dockerfile. CI records
its inspected identity and runs both variants offline with bounded resources and
no capabilities. This is not the complete final application image: subsequent
Map OS upgrades, application build, runtime UID, and full deployment behavior
remain outside this test.

The published-library baseline generates small ordinary PNG, JPEG, WebP, AVIF,
TIFF and GIF images, an alpha fixture, an sRGB-profiled PNG, and a benign SVG with
shapes and a gradient. Both variants decode identical input bytes and perform
resize then rotation. The candidate must match all **16 baseline decoded-pixel
and geometry receipts exactly**, as well as the library-version inventory. Six
additional candidate encode/decode operations check dimensions and retain hashes.
Lossy re-encoding is not asserted to preserve source pixels. No malformed inputs,
exploit regressions, SQLite tests, network scans, or security-setting relaxation
are involved.

## Local commands

```sh
python3 -m unittest discover -s qualification/libvips-compat -p 'test_*.py' -v
node --check qualification/libvips-compat/fixtures.cjs
python3 qualification/libvips-compat/prepare.py /path/to/verified-artifact.zip /new/output
node qualification/libvips-compat/fixtures.cjs /new/output original
node qualification/libvips-compat/fixtures.cjs /new/output candidate
```

Local Node 24.22.1 verification passed 16 baseline and 22 candidate checks. This
local result is explicitly not evidence for the exact target container; that
requires the separate CI job. No Docker engine is required or installed locally.

## Remaining limits

This suite covers one platform, small synthetic ordinary fixtures, and basic
color/profile handling. It does not cover typography/font selection, animation,
full application image processing, broad ABI compatibility, every codec option,
security regressions, independent builder reconstruction, or reproduction of the
historical published binary. The original qualification gate and all other
release gates remain authoritative and unchanged. Input artifacts expire after
14 days: retrieval failure is a blocker, not permission to substitute another
run. Preserve evidence durably before considering release approval.

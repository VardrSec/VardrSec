# Exact OS source capture: dbd51e14

This evidence applies to image reports produced for distribution revision
`dbd51e14a902249f2576fef18da8dd76b58097bc`. It does not automatically cover
subsequent image rebuilds, changed packages, or application dependencies.

## Coverage and limits

The input reports identify 119 OS source/version pairs. The lock captures:

- 97 Debian-family pairs: 316 exact source descriptors, archives and patchsets,
  including GCC, LLVM and both installed tzdata versions.
- 20 Alpine pairs: exact aports recipe-directory files pinned by APKINDEX's
  commit field, plus every declared source input (119 inputs) checked against
  APKBUILD SHA512 checksums.
- Two custom pairs, `libpcap 1.10.7-1+vardr1` and
  `libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3+vardr2`, are intentionally not
  represented by replacement upstream archives. Their exact downstream
  modifications and build materials must be delivered with the separate
  custom-source evidence before claiming complete coverage.

Source capture is **not** legal approval, a complete compatibility analysis,
proof of source-to-binary reproducibility, or clearance of image vulnerabilities.
Review retained copyright/license texts, applicable exceptions, notices,
modifications, build instructions and actual distribution obligations separately.

## Provenance

Debian source hashes come from Sources indexes whose compressed bytes match
signed InRelease SHA256 records. Verification requires an independently trusted
Debian archive keyring. PGDG uses its official HTTPS-distributed repository key,
whose exact bytes are pinned; that is not independent web-of-trust validation.

Historical `tzdata 2026e-0+deb13u1` comes from the official Debian snapshot of
`trixie-proposed-updates` at `20261022T203737Z`. Its signed InRelease and Sources
chain authenticate the descriptor and all source files. A missing developer
signing key is not silently treated as a verified descriptor signature.

Alpine APKINDEX uses its legacy RSA/SHA1 signature, verified with the pinned key
from Alpine's HTTPS key endpoint. The signed index binds source name/version to
the recipe commit. Recipe downloads are pinned to that commit and checked as Git
blobs; source archives match those recipes' SHA512 checksums. The official Alpine
distfiles mirror supplies mailcap and pax-utils where original URLs failed.
No sources are executed and no archive contents are installed by this verifier.

## Reacquire or verify

Use Python 3.9+, `sqv`, OpenSSL, and an existing trusted Debian archive keyring.
The verifier does not install these tools or change trusted keys. Choose a new,
dedicated directory for downloads:

```sh
python3 docs/release/os-source-dbd51e14/verify_sources.py ./os-source-cache \
  --download --provenance \
  --debian-keyring /usr/share/keyrings/debian-archive-keyring.gpg
```

Omit `--download` for offline verification of an existing capture. Mutable
repository index URLs can move on: a changed response fails the pinned hash
rather than silently accepting new contents. Use retained exact index files or
an independently authenticated historical mirror when that happens. Downloads
are bounded by manifest sizes, never overwrite existing files, and must pass
pinned checksums before being saved. No huge source archives are committed here.

The capture was verified with all 514 pinned files and every repository signature,
index binding, recipe revision, Git blob and declared source checksum check enabled.

## License and recipient-delivery review

See [the bounded obligation matrix](license-review/REVIEW.md),
[recipient source/relinking guidance](license-review/SOURCE-AND-RELINKING.md),
and [caller/source provenance](license-review/libdb-caller-evidence.json).
These distinguish source acquisition from recipient delivery and demonstrated
relinking, and do not grant legal clearance. Findings refer to the original
reviewed inventory; subsequent supplementary captures need reconciliation.

The [sqv static-source supplement](sqv-static/README.md) closes the separately identified 65-pair retention gap; final image reconciliation, relinking and recipient delivery remain pending.

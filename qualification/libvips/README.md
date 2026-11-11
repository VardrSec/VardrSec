# Same-version libvips qualification (non-shipping)

This isolated experiment rebuilds sharp-libvips **1.3.4 / libvips 8.18.7 / librsvg 2.63.2** for Linux x64. It never edits the shipping image, npm lock, release manifest, or existing artifact. A mismatch fails the experiment and preserves evidence; no risk waiver or automatic substitution exists.

## What runs

The path-filtered PR workflow uses read-only contents permission and no stored credentials. It verifies 33 native-input SHA256 values, all 357 registry-archive checksums from the source Cargo.lock, and the original npm tarball. Native hashes are captured-input pins, not proof of their historical published-build provenance. Unknown source URLs and changed bytes fail closed.

Crates are unpacked with traversal/link/special-file rejection and Cargo directory-source checksum metadata. Build containers have no network, no Docker socket and no repository credentials; they are bounded to two CPUs, 6 GiB memory and 75 minutes each. Both runs use the **same immutable builder image ID**, independently created source/build directories, and the same read-only verified sources.

The upstream recipe's manifest edits are preserved. Its workspace lock update is performed offline against vendored packages; the before/after/cbuild locks, SHA256, target-filtered metadata, package feature tree and exact Cargo invocations are retained. These are **new candidate receipts**, not the recovered historical published lock. Meson's actual cbuild invocation remains authoritative for package/features; the supplemental tree describes the default librsvg-c target graph.

Candidate pins are nightly-2026-11-10, cargo-c 0.10.10, Meson 1.11.0, Ninja 1.13.0 and rustup-init 1.28.2. Availability/compatibility are not assumed: preflight verifies the official Rust channel manifest and PyPI wheel checksums before execution, rustup-init is SHA256-checked, and Cargo verifies registry checksums while installing locked cargo-c dependencies. Failures stop the experiment.

## Limits and interpretation

This first experiment captures a builder created from the upstream Rocky Linux 8 tag and package repositories. The resulting image ID, RepoDigests/environment inspection, RPM inventory and tool versions are receipts. **It does not yet reproduce the builder across independent workflow runs**: base digest, RPM closure and all builder-tool dependency inputs must be archived/pinned subsequently. Moving third-party notices are replaced with bytes from the pinned recipe commit, explicitly changing that input to a recorded one.

Comparison uses unpacked library bytes and link metadata, not gzip/tar timestamps. Deterministically packed *regular library files* are supplemental artifacts; link metadata is in comparison.json. ELF headers, symbol/version/SONAME/dependency and build-ID evidence is retained. Any nonidentical library payload remains unqualified even if symbols agree. ABI evidence is not a substitute for Sharp integration/image-format/SVG/security-regression testing, which this workflow does not claim to run. No result constitutes overall release clearance.

All output is CI review evidence with 14-day retention, not a published product release. Preserve successful source, toolchain and build receipts in durable release evidence before approving any eventual candidate.

## Local harness checks

```sh
python3 -m unittest discover -s qualification/libvips -p 'test_*.py' -v
bash -n qualification/libvips/run.sh
```

Native compilation requires the isolated CI runner's Docker engine. Do not install a new container engine or alter a user's existing environment to run this experiment.

Meson 1.11.0 is the minimum required by the frozen fontconfig 2.18.3 `meson.build` (line 3). The earlier 1.9.1 candidate stopped at configuration in run 43034290944. `meson-pin-review.json` records the unchanged fontconfig input hash and verified official PyPI wheel identity. This adjusts only the qualification builder tool; it does not replace shipping native libraries or qualify a completed build.

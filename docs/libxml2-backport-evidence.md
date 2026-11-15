# libxml2 backport evidence

The database build applies seven hash-pinned Ubuntu backports to the pinned
Debian source package. Successful packaging alone does not prove every CVE
regression: Debian's package disables some upstream tests, and the retained
CVE-2026-86144 patch explicitly omits upstream test hunks. The Python binding
fix is retained in source, but the binary build uses the `nopython` profile.

## Evidence emitted by the build

`db/build-libxml2.sh` now fails unless all seven local patch names appear in
quilt's **applied** patch ledger before `dpkg-buildpackage`. Before building it
records hashes of affected source files and local patches. It retains:

- `evidence/package-build.log`: complete packaging, clean and source-build log;
- `evidence/build-environment.txt`: installed build packages, compiler/linker
  versions and build profiles;
- `evidence/applied-patches.txt`, `patched-source-SHA256SUMS` and
  `patch-SHA256SUMS`: applied-source identity;
- `evidence/package-SHA256SUMS`: exact delivered binary package hashes;
- `evidence/*.control.txt`: package/source/version/architecture metadata;
- `evidence/*.files-SHA256SUMS` and `*.symlinks.txt`: each package's unpacked
  payload identities, suitable for comparison with an extracted final image.

All evidence is covered by the source delivery's recursive `SHA256SUMS` and
copied into `/usr/share/doc/libxml2/vardr-source/` in the final database image.
The `libxml2-source-delivery` build target exports the same evidence. Obtain it
from the **same build** as the scanned image; do not substitute an independently
rebuilt target and call it evidence for another image digest.

Verify the delivered directory using `sha256sum -c SHA256SUMS`. Compare the
actual installed library bytes in the final image against the corresponding
package payload inventory, and retain that image digest alongside the result.
The `.buildinfo`, `.changes`, modified `.dsc`, original archives and build recipe
remain included as before. Checksums establish integrity only when anchored in
a trusted artifact; they are not signatures.

## Scope and remaining gates

This establishes a reviewable source-to-package evidence chain, not independent
binary reproducibility or complete runtime regression coverage. Fresh apt build
dependencies are inventoried, not snapshot-pinned. Review the complete build log
to distinguish executed tests from disabled tests. The integer-overflow and
XInclude CVEs still require targeted regression evidence before any policy treats
them as independently validated. No vulnerability is suppressed by this change.
Only an actual successful build produces this evidence; a code review of the
recipe is not a substitute for the retained output.

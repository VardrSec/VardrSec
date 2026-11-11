# OS source/license delivery review

Scope: exact distribution `dbd51e14a902249f2576fef18da8dd76b58097bc` inventory, not automatic clearance of later builds. Read-only engineering review, not legal advice or counsel approval. No builds, scans, outreach, or publication performed. All 273 retained legal-text checksums verified successfully. Machine evidence and exact signed-index sqv stanza accompany this report.

The source-completeness finding below applies to the original 119-source inventory. Later supplementary captures must be assessed separately; this document does not assert they are absent.

## Acquisition follow-up

The [verified sqv supplement](../sqv-static/README.md) now captures all 65 exact static source/version pairs (196 files), with authenticated repository bindings and 267 additional notices. The original gap below describes the initial 119-pair capture; source retention is now complete for that identified set. Relinking, semantic license review, recipient delivery and final image reconciliation remain open.

## Material finding

The 119 source/version inventory is not a complete corresponding-source closure. Debian's authenticated Packages entry for the shipped `sqv 1.3.0-3+b2` declares six `Built-Using` and 65 `Static-Built-Using` source versions, none present in that inventory. The six are `rust-buffered-reader 1.3.1-2`, `rust-nettle 7.3.0-1`, `rust-nettle-sys 2.3.1-1`, `rust-sequoia-openpgp 2.0.0-2+deb13u1`, `rust-sequoia-policy-config 0.8.0-1`, and `rustc 1.85.0+dfsg3-1`. These are a subset of the 65, not 71 independent packages. The application source archive does not vendor them; Debian control uses Cargo-generated Built-Using substitutions. Retaining only the sqv application archive misses statically incorporated dependency sources. Obtain exact Debian source descriptors, orig archives and Debian patches for the six, and inventory/review all 65 for static notices and source obligations. Do not substitute newest crates or generic upstream tarballs.

## Component / obligation / remaining-deliverable matrix

| Actual shipped component | Evidence and applicable distinction | Concrete delivery requirement or remaining check |
|---|---|---|
| sqv 1.3.0-3+b2, api/db/runner/web | LGPL-2.0-or-later application; exact signed package declares six Built-Using and 65 Static-Built-Using | Capture exact dependency source/patchsets and notices. Determine LGPL static-combination relinking provision using exact build recipe/source; current app-only archive does not close it. |
| Debian bash 5.2.37-2, coreutils 9.7-3, grep 3.11-4, sed 4.9-2+deb13u1, tar 1.35+dfsg-3.1, dpkg 1.22.22, apt 3.0.4, findutils 4.10.0-3 | GPL-covered executable utilities; exact source archives/packaging captured | Distribute matching complete source with build/install scripts, Debian modifications and license texts through a documented recipient-accessible channel. Do not equate internal archive capture with source delivery. No assertion that adjacent unrelated applications inherit GPL. |
| Alpine proxy busybox 1.37.0-r30, apk-tools 3.0.9-r0, alpine-baselayout 3.7.2-r0, pax-utils 1.3.8-r2 | GPL-covered packages; exact APKBUILD recipes and SHA512-bound source inputs captured | Bind binary versions to recipes and configuration/patch inputs; ship source bundle and notices alongside artifact. Preserve modifications and build configuration, not just upstream archives. |
| glibc 2.41-12+deb13u4: libc6 and associated utilities/locales | LGPL-2.1+ default with per-file exceptions; source package also includes GPL utilities | Preserve full per-file notices; source and patches for shipped libraries/tools. Document actual dynamic replacement/relink path; do not automatically demand object files where a compliant shared-library mechanism suffices. Do not label every glibc-package file LGPL. |
| libcrypt1 from libxcrypt 1:4.4.38-1 | Scanner license array empty; retained COPYING.LIB is LGPL-2.1 text | Correct review inventory from retained sources, preserve per-file copyright notices and source. `debian/copyright.in` is a template, not proof final binary notices complete. Verify installed generated copyright separately. |
| gcc-14-base, libgcc-s1, libstdc++6 from gcc-14 14.2.0-19 | Actual shipped runtime libraries, not whole compiler; retained Debian copyright includes GPLv3+ WITH GCC Runtime Library Exception 3.1 | Preserve runtime exception with notices and exact applicable source. Record exception eligibility rather than falsely require all linked application code GPL. |
| libdb5.3t64 from db5.3 5.3.28+dfsg2-9 | Retained default Sleepycat AND BSD-3-Clause; Sleepycat clause 3 expressly covers source access for DB and accompanying software using it | Map actual linked callers and provide how to obtain their complete applicable source and DB source, subject to license's normal-OS-components exception. DB archive alone is not sufficient evidence. Do not assume all co-resident container programs use DB. |
| libidn2-0 2.3.8-2 and proxy libidn2 2.3.8-r0 | Library files LGPL-3.0-or-later OR GPL-2.0-or-later; source package contains GPL material too | Record chosen library alternative, preserve notices and matching source/relink mechanism. Scanner's source-wide union is not an AND obligation for every binary. |
| libnettle/libhogweed from nettle 3.10.1-1 | Retained text offers LGPLv3+ OR GPLv2+ | Choose and fully satisfy one alternative; deliver exact library source/patches and notices. Include static sqv bindings separately rather than assume dynamic library source closes them. |
| libgcrypt20 1.11.0-7+deb13u1 | Most library LGPL-2.1+; helper/debug programs/docs GPL; additional contribution notices | Retain contribution LICENSES notices as well as top-level copying text; apply obligations by actual shipped files. |
| Other LGPL library groups: acl, attr, audit, libcap-ng, libseccomp, libsemanage, libsepol, systemd, libassuan, libgpg-error, npth, p11-kit, libtasn1, liburing | Source-level license metadata often combines multiple files/options; inventory retains exact versions | Use per-binary/file mapping for final notice index; preserve exact sources and patches. Document replacement/relinking path and no restriction on permitted reverse engineering for modifications. Do not declare relink compliance based on tarball possession alone. |
| krb5 1.21.3-5+deb13u1 | Scanner GPL-only label conflicts with retained MIT Kerberos BSD-style notices and multiple contributed/doc licenses | Correct component-level review; retain complete copyright/disclaimer and contribution notices. Do not falsely label all runtime Kerberos libraries GPL. |
| libxslt 1.1.35-1.2+deb13u3 | Scanner license array empty; retained libxslt/libexslt copyright contains MIT-style permissions and nonendorsement notice | Populate review with evidenced permissive notices and ship them; empty scanner field is not no-license permission. |
| ca-certificates: Debian 20250419+deb13u1 and Alpine 20261020-r0 | Includes MPL-2.0-covered certificate source material | Retain covered-source access/license notices and packaging terms; no blanket whole-application copyleft conclusion. |
| Custom libxml2/libpcap packages | Explicitly excluded from generic 97 Debian-source capture | Attach separately retained exact patched source, patch provenance/build configuration and license evidence to final image identity. Stock source URL alone cannot represent modified binaries. This review does not reassess those components. |

## Deliverable corrections achievable without changing architecture

1. Exact sqv static-dependency source capture is now verified in the supplement. Complete static-license/relinking review and recipient delivery; do not equate acquisition with compliance clearance.
2. Build final per-image notice index from actual runtime notice files plus retained package copyrights, correcting empty/misleading scanner fields. Preserve full texts, copyright holders, license alternatives and GCC exception.
3. Produce one image-bound source delivery index: binary package/version → exact source archives/patches/recipes → hashes → recipient-accessible source bundle location. Include custom packages and static dependencies. Upstream URLs that can disappear are not the only retention strategy.
4. Document actual LGPL replacement/relink provisions and applicable terms. For statically incorporated LGPL pieces, retain precise build inputs and demonstrate the selected compliance mechanism; don't assume dynamic linking to another library resolves this.
5. Map libdb callers from already captured binary/package evidence to accompanying-software source coverage, without a new scan or executing images.
6. Reconcile this dbd-only evidence against the final candidate before calling source delivery complete. Preserve differences explicitly; later image packages are not automatically covered.

## Evidence anchors

All paths are in the retained OS capture. Selected SHA-256s:

- glibc Debian copyright: f5788886720a2605a946e81d571e6c8162b09f58d2e2ceb8d36e5768fccd850d
- gcc-14 Debian copyright/exception: 20390f8a6f3b1e4d7cb45dd8652dabb259bbef688cbad839bcdb0b9ba7252f79
- db5.3 Debian copyright: 8b53da37d73289d9df7317b3a2dbe16491f1fa9fec8b77b86d69704b40ce2c26
- libxcrypt COPYING.LIB: dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551
- libxslt Copyright: 7e48e290b6bfccc2ec1b297023a1d77f2fd87417f71fbb9f50aabef40a851819
- krb5 Debian copyright: 936728f4181718f42951b881c1e8f1386bf6b2723c4fbc533c374d6f42c71816
- libidn2 Debian copyright: 32df8170a3c5e55c553f684576a2911e6a0611320ccd7fd65f7dceae26be61ee
- sqv Debian copyright: b7ae2cde83ad585eae83cded853d125b034fcef480f6c4cee6d9ddd63327181a

`review-evidence.json` records input hashes, all 273 legal hash-check results, exact sqv binary hash and parsed six/65 source-version identities. The original authenticated package-index stanza is retained verbatim separately. This review does not grant legal clearance, attest independent source rebuilds, or declare all corresponding-source obligations satisfied.

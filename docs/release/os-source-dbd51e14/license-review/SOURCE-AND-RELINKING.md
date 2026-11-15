# Source access and library modification: reviewed candidate

This notice describes distribution `dbd51e14a902249f2576fef18da8dd76b58097bc` only. It is not a release announcement or a statement that all license obligations are closed. Later candidates require their own image/package reconciliation.

## Obtaining and checking the reviewed OS sources

The repository's `docs/release/os-source-dbd51e14/sources.lock.json` identifies the exact captured OS source files, recipes, patches and checksums. Its adjacent verifier can reacquire them into a new directory:

```sh
python3 docs/release/os-source-dbd51e14/verify_sources.py ./os-source-cache \
  --download --provenance \
  --debian-keyring /usr/share/keyrings/debian-archive-keyring.gpg
```

This requires Python 3.9+, sqv, OpenSSL and an already trusted Debian archive keyring. It does not install keys or execute downloaded source. Omit `--download` to verify an existing capture. If an upstream index changed, do not replace the pinned checksum or silently select a newer package: use the retained exact capture. **Pending before release:** a stable recipient-facing location for the retained capture, including static dependencies and custom-package source evidence, must be supplied. This draft does not represent a formal written source offer or promise a source-delivery service.

For Debian packages retain together the `.dsc`, matching upstream archive and Debian archive, including their patches and `debian/rules`. A `.dsc` may reference multiple source inputs; use the complete set, not a bare upstream URL. Alpine packages require the pinned APKBUILD and every declared source/configuration/patch input. Read package copyrights and applicable exceptions before selecting license alternatives. Source possession and hash verification do not establish a reproduced binary.

## Berkeley DB and actual accompanying package sources

The reviewed installed-package dependency metadata identifies these direct consumers of `libdb5.3t64 5.3.28+dfsg2-9`:

| Images | Consumer | Exact corresponding source already captured |
|---|---|---|
| api, web, runner, db | libpam-modules 1.7.0-5 | pam 1.7.0-5; upstream `modules/pam_userdb/pam_userdb.c` contains the Berkeley DB include |
| db | libperl5.40 5.40.1-6+deb13u1 | perl 5.40.1-6+deb13u1; upstream `cpan/DB_File/DB_File.xs` implements the Berkeley DB interface |
| db | libsasl2-modules-db 2.1.28+dfsg1-9 | cyrus-sasl2 2.1.28+dfsg1-9; upstream `sasldb/db_berkeley.c` contains DB API calls |

The exact db5.3, PAM, Perl and Cyrus SASL source archives and Debian patches are present in the reviewed source capture. These callers therefore do **not** need newly guessed upstream source versions. `libdb-caller-evidence.json` records the exact package dependency declarations, source archive hashes and relevant source member hashes.

Installed programs depending on libpam0g include login/util-linux (source util-linux 2.41.5-0+deb13u1), passwd (shadow 1:4.17.4-2), PAM tools and postgresql-18 (18.6-1.pgdg13+2). Those exact source packages are also captured. The installed perl program's source is the same captured Perl source. A PAM dependency does not prove that a program invokes pam_userdb, nor does installing DB support prove runtime use. This package-level trace must not be advertised as exhaustive ELF linkage or dynamic-loading analysis. No claim is made that all applications in a container are subject to Berkeley DB terms. Pending: preserve these sources in the recipient-delivered bundle and reconcile any non-package custom consumers against their own exact component archives.

## Modifying or replacing LGPL libraries

Keep the original copyright, LGPL text and applicable additional notices with the library. Consult the package-specific license version and chosen alternative; do not treat source-wide mixed-license scanner output as one license for every file. For modifications, retain the modified source, changes and build/install instructions.

For dynamically linked Debian/Alpine libraries, the proposed recipient route is a separate derivative image containing your ABI-compatible rebuilt shared library/package, built from the pinned source and packaging inputs. Keep SONAME, architecture and required symbol versions compatible, and retain the loader configuration needed by the executable. Do not alter a running deployment or system library merely to follow these instructions. The final release must document exact library installation paths, loader behavior and a working replacement procedure for its actual images. This review has not demonstrated that procedure and does not certify that all binaries use dynamic linkage or that every replacement is ABI-compatible.

For statically linked LGPL components, providing a shared-library replacement instruction is insufficient. The final source package must include the applicable relinking/build materials required by the chosen license route, with exact build inputs and instructions. In this candidate sqv includes statically incorporated Rust dependencies: six Built-Using entries and 65 Static-Built-Using entries were identified; the [verified supplement](../sqv-static/README.md) now captures all 65 exact source pairs. Integration into a recipient-delivered bundle and demonstrated relinking remain separate requirements. Do not claim sqv relinking is complete from its application archive alone. Where user-product installation information is applicable, assess and provide it as required; applicability has not been determined here.

Any product terms must not prohibit modifications or reverse engineering for debugging those modifications where the applicable LGPL mechanism requires allowing them. This draft is not a substitute for checking actual distributed terms. GCC runtime libraries carry the GCC Runtime Library Exception, which must be preserved rather than replaced with an unconditional whole-application GPL assertion.

## Release readiness still pending

- Recipient-accessible image-bound source/notice bundle, including the static and custom source additions, with final artifact hashes.
- Final candidate reconciliation: this is a historical reviewed image set, not an automatic endorsement of later packages.
- Tested and documented library replacement/relinking instructions where relied on, and assessment of any necessary installation information.
- Exact non-package caller and static-combination mapping where current metadata cannot settle it.

No images, archived payloads, builds or scans were executed for this review. This is an engineering evidence statement, not legal counsel approval.

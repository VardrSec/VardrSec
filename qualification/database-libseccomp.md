# Database libseccomp qualification

The original PostgreSQL image contained Debian Trixie's `libseccomp2` 2.6.0-2.
The Debian security tracker lists seven open advisories for that version and
records fixes for all seven in the source version 2.6.2-1. The exact source
and Debian packaging used by this database build are pinned in `db/Dockerfile`.
The build uses Trixie's toolchain and installs just the runtime library.
[Debian package advisory history](https://security-tracker.debian.org/tracker/source-package/libseccomp)

The four source file hashes in the Dockerfile matched Debian's signed source
index with SHA-256
`4e9e27ffda1be2a1f912a82ae9f7bf37f3325d46f9317d52a8377d6521826a42`.
Two archive signatures verified using the Debian archive keyring. The build
keeps the original source descriptor, source tarballs, upstream signature,
build log, package metadata and runtime library checksum in
`/usr/share/doc/libseccomp2/vardr-source/`.

The normal Debian build runs its package regression suite. On a disposable
hosted VM, `qualification/database-libseccomp.sh` also runs both upstream
Debian machine-isolated autopkgtests against the installed Trixie build.
The first hosted run passed 11 C and 11 Python live checks with zero skips.
[Qualification run](https://github.com/VardrSec/VardrSec/actions/runs/45322101258)

Image evidence checks the selected package version and library bytes against
the saved package payload. The existing PostgreSQL, installer, upgrade,
recovery and image scan checks apply to the resulting database.

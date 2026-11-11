# Native component applicability evidence

This is evidence collection, not a scanner exclusion or release clearance.
The stopped-image export collector traverses every archive member and records
known component basenames at any path, including usrmerge and custom paths:

- systemd-homed, systemd-homework, homectl, systemd-homed.service;
- krb5kdc, kadmind, kdb5_util;
- libgssrpc, libkadm5clnt/srv (including _mit), libkdb5 shared libraries;
- libkrb5, libgssapi_krb5, libk5crypto, libkrb5support shared libraries;
- libsystemd and libudev shared libraries.

Regular-file payloads are SHA-256 hashed, never retained or executed. Links are
recorded as present but unresolved, never followed. Empty inventory groups mean
only that no matching non-directory basename was seen in the completed export.
They do not prove absence of renamed or statically linked code, mounted host
files, or future configuration. No symbol/reachability conclusion is automatic.
The manifest remains bound to the exact Docker configuration ID and distribution
revision; compare both against the matching image receipt before review.

## Why the distinction matters

The systemd vendor identifies CVE-2026-16742 in the homed manager's
`home_authenticating_finish` path, not in the public libsystemd/libudev APIs:
https://github.com/systemd/systemd/security/advisories/GHSA-jm29-p7hh-vjhv

The dbd51e14 image SBOM lists only libsystemd0/libudev1 for that source package.
The new inventory must still run on the candidate image before any image-specific
absence disposition. The earlier notice-only inventory cannot prove absence.

Likewise, Kerberos KDC, kadmind, admin RPC and KDB vulnerabilities must be
separated from shared client/GSS libraries. In particular, CVE-2026-119079 is
in `lib/krb5/asn.1/asn1_encode.c`, and CVE-2026-107778 reaches GSS acceptor
services through `gss_accept_sec_context`. A missing KDC process does not by
itself clear those library findings. Debian currently records the former as
unfixed in Trixie, with upstream fix commit
`782e5ac4fb1496a79de0b87e1fc485f897e97d6d`:
https://security-tracker.debian.org/tracker/CVE-2026-119079

Next review must correlate exact package source, affected object/function,
actual linked library identity and supported application configuration. No
package removal, unstable repository mixing or blanket source-package waiver
is authorized by these receipts.

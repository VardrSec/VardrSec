# Debian package exposure review — 2026-10-27

Partial task-1 assessment, not release clearance or a scanner ignore list. The
[five-image assessment](alpha-security-assessment.md) retains all raw findings and
blocked strict gates. Package occurrences are not distinct vulnerabilities: the
same Debian source advisory can be repeated against several split binary packages.
Review the affected functionality and its caller before accepting or dismissing it.

The verified `695ab39` image checkpoint contains 19 distinct critical/high Debian
advisories across API, web, Runner and PostgreSQL. No fixed-version entries appear
for these occurrences in that frozen report. Debian tracks fixes in unstable or
other suites for several of them, which does not make those packages compatible
with the candidate's Trixie base. Do not mix release suites or substitute database
variants merely to reduce a count.

## Reviewed conditions and remaining work

| Finding / affected surface | Vendor condition | Candidate evidence and required disposition |
| --- | --- | --- |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742), systemd-homed | A logged-in homed-managed user can gain groups; Debian marks the stable source affected with a minor/no-DSA note. | Reports name libsystemd/libudev split packages. Local file probes found no systemd-homed at its standard `/usr/lib/systemd/` or `/lib/systemd/` paths in the four Debian images. Compose starts application/database entry points, not homed. This supports a narrow non-exposure review; it is not a waiver for the whole source package. |
| [CVE-2026-24882](https://security-tracker.debian.org/tracker/CVE-2026-24882), GnuPG tpm2daemon | TPM-backed PKDECRYPT handling; Debian Trixie is affected with a minor/no-DSA note. | PostgreSQL reports GnuPG split packages; local probes found no tpm2daemon under `/usr/lib/gnupg/`, `/usr/libexec/` or `/usr/bin/`. The distribution does not configure TPM-backed decryption. Retain the finding and verify the absence against the eventual immutable image before a scoped disposition. |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [78410](https://security-tracker.debian.org/tracker/CVE-2026-78410), util-linux mount helpers | Privileged mount/fstab/post-hook and pathname conditions; stable fixes are not listed. | API/web/Runner use dropped capabilities and no-new-privileges. Compose grants no SYS_ADMIN or host filesystem namespace. Their normal entry points do not perform these mount operations. Keep privileged/manual configurations outside this inference; audit any actual caller before accepting risk. Do not infer these same dropped-capability settings for PostgreSQL's initialization wrapper. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), nsenter | A privileged operator enters an attacker-controlled target with `--join-cgroup`, retaining cgroup migration authority. | The distribution performs no nsenter operation and mounts no host cgroup hierarchy or Docker socket into Runner. The explicit synthetic namespace test uses Docker's network namespace handoff, not nsenter. Review separately if a later deployment adds privileged namespace entry. |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369), libacl | A privileged ACL caller follows an attacker-controlled pathname/symlink. Debian notes that the fix adds ABI and should arrive through a compatible point update. | No direct ACL-operation path was identified in reviewed lifecycle/Runner command construction. This is not proof about every transitive caller or privileged operator tool. Keep unresolved, preserve file/privilege boundaries and prefer a vendor-compatible package update over an individual ABI-changing backport. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538), Perl Archive::Tar | Attacker-controlled tar entry sizes can exhaust memory; stable updates are postponed pending upstream regressions. | Distribution backup/restore/archive inspection uses Python tarfile, not Perl Archive::Tar. No direct Perl archive caller was identified there. That narrows the reviewed recovery path only; retain the source-package report and assess other callers before a broader disposition. |
| [CVE-2026-0799](https://security-tracker.debian.org/tracker/CVE-2026-0799), [6554](https://security-tracker.debian.org/tracker/CVE-2026-6554), libpcap | Malicious BPF programs; the latter also describes protochain handling of crafted packets. Debian Trixie remains affected with minor/no-DSA notes. | Runner contains libpcap for existing tools. The bounded fixture tests TCP-connect/CONNECT modes and rejects raw SYN at the ordinary capability-free boundary. It does not certify every tool/job default, capture/filter or raw-packet mode. Keep unresolved pending actual input/caller review or compatible fixed artifacts. |

## libxml2 and ncurses (recounted 2026-10-27, image-evidence run 40571078894)

These are the last Debian advisories without a reviewed condition. They affect only
the PostgreSQL image (libxml2) or every Debian-based image (ncurses). All are listed
by the scanner as `affected` with no fixed version in the pinned Trixie suite.

| Finding | What it needs | Packaged-configuration evidence | Disposition |
| --- | --- | --- | --- |
| CVE-2026-6653 (critical), 2026-86138/86139/86140/86142/86143/86144 (high): parser, URI, XPointer, XInclude and I/O defects in libxml2 | Attacker-controlled XML parsed by PostgreSQL's compiled-in libxml2, i.e. SQL/XML functions such as `xmlparse`, `xpath`, `xmltable` or `xml` casts applied to untrusted text | The database sits on the `database` Compose network, which is `internal: true`; only the API service joins it, and no port is published. A search of Map's backend source and migrations at the pinned commit finds no use of those SQL/XML functions or XML column types. Reaching the parser would require an attacker who can already run arbitrary SQL, which is a larger compromise than the parser defect | **Open, reachable path not demonstrated.** Not an accepted risk. Re-evaluate whenever Map adds XML handling; a fixed Debian build or a libxml2 rebuild would close it |
| CVE-2026-74860 (high): libxml2 Python bindings | The Python bindings, which the PostgreSQL image does not load | The finding is reported against the `libxml2` package; PostgreSQL does not use Python bindings for libxml2 | **Open, likely not applicable.** Confirm against a fixed advisory or a package-level check before dismissal |
| CVE-2025-69720 (high): `infocmp` stack overflow in ncurses | A person or process invoking `infocmp` on a crafted terminfo argument | None of the five images' entry points or services runs `infocmp`; invocation needs an interactive shell or container exec by an operator who already controls the container | **Open, low exposure.** Not an accepted risk |

None of this changes severity counts or opens an exception mechanism. A
reachable-path claim above rests on configuration and source search, not a runtime
call graph; the owner must accept or reject any residual item explicitly.

## Evidence limits

Local file probes ran only `/usr/bin/test -e` with explicit entry-point overrides,
read-only filesystems, no network, no capabilities and no-new-privileges. They
recorded actual image identities and did not start services, inspect engagement
data, mount platform volumes or alter host privileges. Absence at named paths is
limited evidence, combined here with package inventory and declared entry points;
it is not an exhaustive executable search or a runtime call graph.

These observations do not change severity counts, mark task 1 complete, accept
unresolved Go/Rust findings or certify privileged/native variants. Recheck the
exact release image and record a reviewed per-finding disposition before treating
any of these conditions as a release exception. No exception mechanism is added.

# Community Alpha residual-risk register

Status: **proposed dispositions, nothing accepted.** Each row needs an explicit owner
decision (accept as an alpha limitation, require a fix, or exclude the component).
Pre-remediation baseline: [image-evidence run 40622056177](https://github.com/VardrSec/VardrSec/actions/runs/40622056177),
clean distribution `524585cac788d08c529df58b4dd82a20029e7c1b`, raw reports and all
five input hashes independently verified 2026-10-28: **1 critical / 197 high / 15 unknown**
occurrences. Two high go-jose/v4 occurrences have a published fix; Caddy also links an
unfixed go-jose/v3 occurrence. The 1/194 figures from run 40605692767 are historical.
Verified rebuilt [run 40757052765](https://github.com/VardrSec/VardrSec/actions/runs/40757052765)
removes both v4 occurrences: **1 critical / 195 high / 15 unknown** remain, with no
critical/high fixed-version occurrence. Both SBOMs contain v4.1.6; strict checking
still exits 1. The [checkpoint](alpha-review-2026-10-28.md) records the exact clean
PR merge tree, input/report hashes and reachability limits. Nothing is accepted;
strict image gates remain blocked pending explicit owner decisions.

Latest recount, 2026-10-31, from the raw reports of [run 41175264942](https://github.com/VardrSec/VardrSec/actions/runs/41175264942)
(distribution `2f71c32`, Map #134 / Runner v0.54.0 / Gate v0.2.0 pins; the #47-merge run
41161013898 is identical): **1 critical / 195 high / 25 unknown**. The critical and high
occurrences match run 40757052765. The ten additional unknown occurrences are glibc
CVE-2026-84243, now reviewed in section A with a conditional acceptance proposed. Strict
checking exits 1; nothing is accepted. See also
[alpha-os-exposure.md](alpha-os-exposure.md) and
[alpha-security-assessment.md](alpha-security-assessment.md).

Common exposure facts used below, each verified in this repository:
- The database is on an `internal: true` network reachable only by the API; no database or
  API port is published (`compose.yaml`). The only published port is the loopback HTTPS proxy.
- Containers run without added capabilities and without the Docker socket
  ([tool/network acceptance](tool-network-acceptance.md)).
- Runner executes only on an explicit operator command.

## A. Debian packages (20 distinct advisories, no fix in the pinned Trixie suite)

| ID | Package / images | What exploitation needs | Evidence and assumptions | Proposed disposition |
| --- | --- | --- | --- | --- |
| CVE-2026-76642, 78408, 78409, 78410 (high) | util-linux (`mount`, `nsenter`, libmount, libblkid, ...) / all four Debian images | A privileged user running `mount`/`nsenter` with attacker-controlled mount options, targets or helpers | Containers are unprivileged, run no `mount` or `nsenter` in any entry point, and have no `CAP_SYS_ADMIN` ([exposure review](alpha-os-exposure.md)) | Accept as alpha limitation; re-scan before any published image |
| CVE-2026-16742 (high) | systemd-homed (`libsystemd0`, `libudev1`) / all | A logged-in homed-managed user | No systemd, no homed, no login sessions in containers | Accept (not applicable in a container) |
| CVE-2026-54369 (high) | libacl1 / all | A privileged ACL caller following an attacker-controlled symlink | No component calls ACL functions on attacker-named paths; unprivileged containers | Accept |
| CVE-2026-9538 (high) | Perl `Archive::Tar` / all | A perl process extracting an attacker-crafted tar | Perl is present as a Debian dependency; no component runs perl on untrusted archives | Accept |
| CVE-2025-69720 (high) | ncurses `infocmp` / all | Someone running `infocmp` on a crafted terminfo argument | A source search of all four repositories finds no `infocmp` invocation; needs an operator shell inside the container | Accept |
| CVE-2026-24882 (high) | GnuPG tpm2daemon, dirmngr, gpg* / db | A TPM-backed decrypt request to the GnuPG daemon | GnuPG ships with the PostgreSQL base image; no TPM, no gpg-agent started, database network internal | Accept |
| CVE-2026-0799, 6554 (high) | libpcap / Runner | Malicious BPF programs or crafted packets handed to libpcap | Only TCP-connect modes are certified; raw-packet modes need capabilities the container lacks | Accept; revisit if raw-packet modes are certified |
| CVE-2026-6653 (**critical**), 86138, 86139, 86140, 86142, 86143, 86144 (high) | libxml2 / db | Attacker-controlled XML parsed inside PostgreSQL by SQL/XML functions (`xmlparse`, `xpath`, `xmltable`, `xml` casts) | Map's source and migrations use none; only the API reaches the database; exploitation would need arbitrary SQL, a larger compromise | **Narrow conditional acceptance**: valid only while Map avoids XML SQL functions; a fixed Debian build or libxml2/PostgreSQL rebuild closes it. Requires an explicit owner decision because it is the only critical |
| CVE-2026-74860 (high) | libxml2 Python bindings / db | The Python bindings, which the PostgreSQL image does not load | Reported against the `libxml2` package | Accept as likely not applicable; confirm against a fixed advisory |
| CVE-2026-84243 (unknown severity; CNA CVSS 7.0 High, `AV:L/AC:H/PR:L`; CISA SSVC exploitation none) | glibc `gettext` family (`libc6`, `libc-bin`, `libc-l10n`, `locales`) / api, db, runner, web (10 occurrences) | An attacker who controls the `LANGUAGE` environment of a glibc-gettext program, with a non-`C` locale selected and a crafted `.mo` at a reachable path, loads an arbitrary catalog | Reviewed 2026-10-31 in [glibc-gettext-language-exposure.md](glibc-gettext-language-exposure.md): no untrusted path to any container's environment found (compose, Map and Runner sources); API/web/Runner install no locale beyond `C.UTF-8`; no privilege gained; no Debian fix exists in any suite; behavior not runtime-tested | **Conditional acceptance proposed, owner decision required:** valid only while no untrusted environment control, no extra locales in API/web/Runner, and no environment-forwarding service; re-assess at the first Debian fix

## B. Go and Rust components

| ID | Component | What exploitation needs | Evidence | Proposed disposition |
| --- | --- | --- | --- | --- |
| CVE-2026-116587 (high) | Caddy go-jose/v4 4.1.5 and Nuclei go-jose/v4 4.1.4 | Parsing attacker-controlled RSA JWKs can exhaust CPU | Both rebuilt SBOMs contain 4.1.6 and the two occurrences are absent in run 40757052765; Runner #96 merged | **Remediated in the reviewed source-built images**, no exception needed for these two occurrences |
| CVE-2026-116587 (high, no fixed v3 release) | Caddy go-jose/v3 3.0.5 | An enabled JWK-consuming ingress such as Caddy's optional ACME server, or changed authority configuration | [Source and bounded-control review](caddy-v3-jwk-exposure.md) traces the real pre-auth parsing path; the shipped adapter graph has no such handler, internal issuance has no JWK provisioners, and loopback controls verify opaque forwarding. Linux CI guards these assumptions using the built image binary. The Go database gap is not used as exposure evidence | **Affected dependency; conditional non-exposure proposed for the shipped configuration only. Unaccepted.** Owner review required; any issuer/handler/admin/dependency change invalidates this bounded assessment |
| GO-2026-5932 (unknown severity; unmaintained `x/crypto/openpgp`, no fix) | Nuclei (reported **reachable**); also linked in httpx, Katana, DNSx, Subfinder, Naabu and Caddy (not reachable per `govulncheck`) | Processing untrusted OpenPGP data, which Nuclei uses to verify signed template bundles | `govulncheck` on the patched Nuclei build; templates are not bundled or auto-provisioned; no fix exists upstream | Conditional acceptance: Nuclei runs only against operator-chosen templates; track upstream |
| Naabu binary-level reachability | Naabu | n/a | **Verified:** `govulncheck` on the CI-built Naabu binary (with CGO/libpcap, Runner #95 run 40617830243) reports no vulnerabilities; the module-level OSV check agrees | None remaining |
| `rustls` 0.23.45 (RUSTSEC-2026-0346/0347/0348/0349, moderate/low), `rustls-webpki` 0.103.15 (RUSTSEC-2026-0382), `tokio` 1.53.1 (RUSTSEC-2026-0386), `rsa` 0.9.10 (Marvin, no fix) | Dalfox 3.2.4 (Rust; invisible to the image scanner) | A hostile HTTPS target or on-path attacker influencing a Dalfox connection; Marvin needs RSA decryption timing, which Dalfox does not offer | `Cargo.lock` at the v3.2.4 tag against OSV: no critical/high; Dalfox is the latest release; rebuild would need a Rust build stage | Accept moderate/low residual risk; re-check on the next Dalfox release |
| CVE-2026-39824 (unknown) | gosu `x/sys` v0.1.0 | Windows-only API (`NewNTUnicodeString`) | gosu runs on Linux; not compiled into any Linux code path that is reachable (`govulncheck` reports none) | Accept (not applicable) |
| CVE-2026-82560 (unknown) | Perl `Pod::Text` | A perl process rendering attacker-supplied POD | Same as Perl above; no component renders POD | Accept |

## C. Excluded or limited (not vulnerabilities in the shipped path)

| Item | State |
| --- | --- |
| Native Gau archive disables TLS verification | **Excluded in code** (Runner #94): install refused, `--all` skips it, no PATH fallback. The container Gau is a reviewed patched build |
| Genuine VPN routing | Unverified; stated as a limitation with the native Runner fallback ([networking](networking.md)) |
| Nmap integration/redistribution | Exact-package license terms and Runner execution/XML parsing need compatibility review even for source builds; no licensing clearance or publication approval ([inventory](release-license-inventory.md)) |

## How to use this register

Approve rows (or groups), reject any that must be fixed first, and the release notes
list the approved rows verbatim. Anything unlisted here is not covered by an
acceptance. Re-run the image evidence and `govulncheck` at the release freeze and
compare against this register; a new critical or high with a published fix is a
release blocker, not a register entry.

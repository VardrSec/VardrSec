# Community Alpha residual-risk register

Status: **conditional dispositions are prepared for the owner's approval; nothing is accepted.**
The [owner decision sheet](#owner-decision-sheet) groups every critical, high and unknown
occurrence in the latest raw reports into nine decisions, each with its proposed disposition,
the exact conditions it depends on, the automatic safeguards that exist today and what is
re-verified at the candidate freeze. Anything unlisted here is not covered. Strict image
gates stay blocked (`image_evidence.py check` exits 1) until the owner decides.

**Current recount** (run [41252576786](https://github.com/VardrSec/VardrSec/actions/runs/41252576786),
distribution `1cc92d2`; pins Map `428be22`, Runner `668dc56`, Gate `7f82e49`):
**1 critical / 195 high / 15 unknown**, with no critical or high occurrence that has a fixed
version. By image (critical/high/unknown): API 0/44/1, PostgreSQL 1/61/5, Proxy 0/1/1,
Runner 0/46/7, Web 0/43/1. No image contains Nmap.

## Recount history

Counts are occurrences in the raw Trivy reports (one advisory can repeat across packages and
images). Each row was recounted from the run's reports; the checkpoint documents record hashes.

| Run | Date | Source | Critical | High | Unknown | Note |
| --- | --- | --- | --- | --- | --- | --- |
| [40622056177](https://github.com/VardrSec/VardrSec/actions/runs/40622056177) | 2026-10-28 | `524585c`, clean baseline | 1 | 197 | 15 | Before remediation; the earlier 1/194 figure (run 40605692767) is historical |
| [40757052765](https://github.com/VardrSec/VardrSec/actions/runs/40757052765) | 2026-10-28 | Rebuilt, go-jose/v4 4.1.6 | 1 | 195 | 15 | Both fixable v4 occurrences removed; see the [checkpoint](alpha-review-2026-10-28.md) |
| [41175264942](https://github.com/VardrSec/VardrSec/actions/runs/41175264942) | 2026-10-31 | `2f71c32`, Map #134 / Runner 0.54.0 / Gate 0.2.0 | 1 | 195 | 25 | +10 unknown: glibc CVE-2026-84243, newly in the scanner database |
| [41232304416](https://github.com/VardrSec/VardrSec/actions/runs/41232304416) | 2026-10-31 | `5226299`, same pins | 1 | 195 | 15 | Database of 13:09Z rates CVE-2026-84243 MEDIUM: a reclassification, not a fix |
| [41252576786](https://github.com/VardrSec/VardrSec/actions/runs/41252576786) | 2026-10-31 | `1cc92d2`, Map #141 / Runner #103 / Gate 0.2.0 | 1 | 195 | 15 | **Current.** Nmap removed from the Runner image; critical and high unchanged |

## Owner decision sheet

Approving a decision means the owner accepts that group **as a documented Community Alpha
limitation, only while its conditions hold**, and the release notes list it verbatim. It is not
an exploitability or absence-of-vulnerability claim. Rejecting one means it must be fixed or the
component excluded before release. A new critical or high with a published fix is a release
blocker, not a register entry. Every approval is conditional on the freeze re-verification
column, and any change to the listed conditions invalidates it.

| # | Group and occurrences (latest raw reports) | Proposed conditional disposition | Conditions that must hold | Automatic safeguards today | Re-verified at the candidate freeze |
| --- | --- | --- | --- | --- | --- |
| R1 | util-linux CVE-2026-76642, 78408, 78409, 78410 (high): 36 each, 144 total, API/DB/Runner/Web | Accept as an alpha limitation | Containers unprivileged; no entry point or service runs `mount`/`nsenter`; no `CAP_SYS_ADMIN`; Docker socket not mounted | Compose drops all capabilities with `no-new-privileges` on API, Web, Proxy (plus `NET_BIND_SERVICE`) and Runner; the database keeps Docker's default capabilities, which exclude `SYS_ADMIN`; tool/network baseline asserts UID 10001, zero effective capabilities and no-new-privileges for the Runner image. **No CI assertion covers the effective capabilities of API, Web or database** | `docker inspect` of each running container: not privileged, no `CapAdd` beyond `NET_BIND_SERVICE`, no socket mount; effective capabilities read from `/proc/1/status` |
| R2 | Other Debian packages: systemd-homed CVE-2026-16742 (8); libacl CVE-2026-54369 (4); Perl Archive::Tar CVE-2026-9538 (7 high) and Pod::Text CVE-2026-82560 (7 unknown); ncurses `infocmp` CVE-2025-69720 (15); GnuPG CVE-2026-24882 (7, database only); libpcap CVE-2026-0799 and 6554 (1 each, Runner) | Accept as alpha limitations (rows in section A) | No systemd, login sessions, TPM or `gpg-agent` in containers; no component runs `infocmp`, perl on untrusted archives or POD, or ACL calls on attacker-named paths; raw-packet modes uncertified and the Runner has no capabilities; database network internal | Runner capability baseline and raw-socket denial in the tool/network fixture; `internal: true` database and application networks; no scan or worker starts with the platform | Repeat the source searches recorded in [alpha-os-exposure.md](alpha-os-exposure.md) at the pins; raw-socket denial from the tool/network receipt |
| R3 | libxml2 in the database image: **CVE-2026-6653 (the only critical)** and CVE-2026-86138, 86139, 86140, 86142, 86143, 86144, 74860 (high): 8 occurrences | **Narrow conditional acceptance; the critical needs its own explicit approval** | Attacker-controlled XML must reach PostgreSQL's SQL/XML functions (`xmlparse`, `xpath`, `xmltable`, XML casts); Map's source and migrations use none; only the API reaches the database, over an internal network, and as the non-superuser `vardrmap_app`. Reaching the condition needs a compromised API or SQL injection first | Installed acceptance and the role drill run Map's migrations and workflow as `vardrmap_app` on the internal network. **No CI check forbids XML SQL functions in Map** | **Mandatory:** (1) search Map's backend, migrations and raw SQL at the pinned commit for `xmlparse`, `xpath`, `xmltable`, `xmlelement`, `xmlforest`, `xmlagg` and `::xml`; (2) recount to confirm libxml2 is still unfixed in the pinned Trixie suite; a fixed Debian build or PostgreSQL image digest lapses this exception and requires a rebuild |
| R4 | glibc gettext CVE-2026-84243 (MEDIUM in the current scanner database): 10 occurrences, API/DB/Runner/Web | Conditional alpha limitation, per [the exposure review](glibc-gettext-language-exposure.md) | (1) No untrusted party can set a container's environment; (2) API, Web and Runner contain no locale beyond `C`/`C.UTF-8`/`POSIX`; (3) no SSH or other environment-forwarding service; re-assess at the first Debian glibc fix and before any published image | `tests/glibc_locale_acceptance.py` in every installed acceptance run fails on an added locale, a `LANGUAGE`/`LC_*`/`LOCPATH` variable or a catalog loading under `C.UTF-8` (receipt `glibc-locale-exposure`); Runner passes tools an allowlisted environment (ADR 0022) | Run the probe on the frozen pins; repeat the negative source searches in the review; read the upstream advisory text (sourceware.org was unreachable); state native-Runner host glibc in the release notes |
| R5 | Caddy go-jose/v3 CVE-2026-116587 (high, no v3 fix): 1 occurrence, Proxy | Conditional non-exposure for the shipped configuration only | No JWK-consuming ingress: no ACME server, JWK provisioners or JWK-authenticated handler; no dynamic admin configuration; the recorded Caddy 2.11.7, smallstep/certificates 0.30.2, go.step.sm/crypto 0.91.0 and go-jose/v3 3.0.5 dependency graph; operator-customised Caddyfiles are not covered | `tests/proxy_jwk_boundary.py` and its unit tests, run in the image-evidence workflow against the binary copied from the built proxy image (receipt `proxy-jwk-boundary`), plus `govulncheck` (artifact `proxy-go-reachability`) | Green `proxy-jwk-boundary` and `proxy-go-reachability` on the frozen commit; Caddyfile and dependency recipe unchanged since the review |
| R6 | Nuclei and others: GO-2026-5932, unmaintained `x/crypto/openpgp`, no fix (unknown): 7 occurrences, Runner (Nuclei reported reachable) and Proxy | Conditional acceptance | Nuclei runs only against operator-chosen templates; no template bundle is shipped or auto-provisioned; the openpgp path is reachable only when verifying signed template bundles | Runner's container workflow reports reachable Go advisories for every shipped binary with `govulncheck`; the tool/network fixture runs Nuclei only against one explicit local template | Runner container job green on the pinned commit; confirm no image contains templates or a template-update step |
| R7 | Dalfox 3.2.4 Rust advisories (`rustls`, `rustls-webpki`, `tokio`, `rsa`; moderate/low, invisible to the image scanner) | Accept the moderate/low residual risk | A hostile HTTPS target or on-path attacker is needed; Dalfox is the latest release | `Cargo.lock` reviewed against OSV at the v3.2.4 tag | Re-check for a newer Dalfox release |
| R8 | gosu `golang.org/x/sys` CVE-2026-39824 (unknown): 1 occurrence, database. **A fixed version (0.44.0) exists** | Either accept as not applicable (Windows-only API; `govulncheck` reports it unreachable) or rebuild gosu with the fix | gosu runs on Linux only | `govulncheck` in the review; the gosu rebuild recipe is pinned in `db/Dockerfile` | If the owner chooses the rebuild, it changes the database image, so the controlled updater will refuse it for existing installations (they use the restore path) |
| R9 | Excluded or limited items in section C: native Gau (excluded in code), genuine VPN routing (unverified), Nmap (not packaged; retained opt-in code is an open licensing question) | Document as limitations in the release notes | As stated in section C | Runner #94 enforcement tests; image evidence rejects `nmap`/`nmap-common` in any image | Gau exclusion test and Nmap-absence checks green on the frozen pins |

### Approval record

Nothing below is approved. The owner fills this in; Claude does not.

| Decision | Owner decision (approve / reject / modify) | Date |
| --- | --- | --- |
| R1 | Pending | |
| R2 | Pending | |
| R3 (including the critical, separately) | Pending | |
| R4 | Pending | |
| R5 | Pending | |
| R6 | Pending | |
| R7 | Pending | |
| R8 | Pending | |
| R9 | Pending | |

See also [alpha-os-exposure.md](alpha-os-exposure.md) and
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
| CVE-2026-84243 (unknown severity; CNA CVSS 7.0 High, `AV:L/AC:H/PR:L`; CISA SSVC exploitation none) | glibc `gettext` family (`libc6`, `libc-bin`, `libc-l10n`, `locales`) / api, db, runner, web (10 occurrences) | An attacker who controls the `LANGUAGE` environment of a glibc-gettext program, with a non-`C` locale selected and a crafted `.mo` at a reachable path, loads an arbitrary catalog | Reviewed 2026-10-31 in [glibc-gettext-language-exposure.md](glibc-gettext-language-exposure.md): no untrusted path to any container's environment identified (Compose, Map, Runner and Gate sources); runtime probe (CI run 41221261206) confirms API/web/Runner have no locale beyond `C.UTF-8`, no `LANGUAGE`/`LC_*`/`LOCPATH` is set, and a catalog is ignored under `C.UTF-8` (positive control loads under the database's `en_US.utf8`); code execution as a service account would still reach that service's secrets and data; no Debian fix exists in any suite | **Proposed conditional exception; not formally accepted.** Would hold only while there is no untrusted environment control, no extra locales in API/web/Runner and no environment-forwarding service; re-assess at the first Debian fix. Upstream advisory text and native-Runner host glibc remain unverified (see the review's conditions table). The API's database role, formerly a PostgreSQL superuser, now runs as non-superuser `vardrmap_app` (distribution #53), so the exception no longer depends on it

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
| Nmap integration/redistribution | Nmap is excluded from packaging and every image (CI-enforced); naabu is the port-discovery tool. Runner's retained, opt-in Nmap integration code is an open licensing question; no licensing clearance or publication approval ([inventory](release-license-inventory.md)) |

## How to use this register

Approve rows (or groups), reject any that must be fixed first, and the release notes
list the approved rows verbatim. Anything unlisted here is not covered by an
acceptance. Re-run the image evidence and `govulncheck` at the release freeze and
compare against this register; a new critical or high with a published fix is a
release blocker, not a register entry.

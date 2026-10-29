# Alpha security assessment — in progress

> **Later manual review:** [Caddy v3 JWK exposure](caddy-v3-jwk-exposure.md)
> now traces the affected code and tests the shipped configuration against an ACME
> positive control. Older "reachability unestablished" statements below describe
> the preceding checkpoint. The dependency remains affected and no risk is accepted.

Assessment checkpoint, 2026-10-27. This is not release approval. The strict image
vulnerability gate remains blocked, raw reports are retained, and no exception or
blanket suppression is introduced. Task 1 of the [alpha plan](community-alpha.md)
remains in progress pending residual affected-status/exposure review and fixes.

> **Current review, 2026-10-28:** the verified clean-main image baseline is
> **1 critical / 197 high / 15 unknown**, with two high go-jose/v4 occurrences now
> fixable and one newly reported unfixed go-jose/v3 occurrence in Caddy.
> Verified rebuilt run 40757052765 removes the two v4 occurrences: **1 critical /
> 195 high / 15 unknown** remain, none of the critical/high occurrences with a fixed
> version. Both SBOMs contain v4.1.6. Caddy reports zero reachable findings only
> within Go database coverage; that database lacks the new v3 advisory, whose
> reachability remains unestablished and unaccepted. See [the checkpoint](alpha-review-2026-10-28.md)
> and [risk register](residual-risk-register.md); this is not clearance.
> Container Gau is fixed and native Gau is excluded; the Gau blocker text below is historical.
>
> **Historical update (post-#30):** the latest recounted combined baseline is **1 critical / 194 high**
> (Runner 0/46; no occurrence with a fixed version); see the status table in [community-alpha.md](community-alpha.md). The
> figures below are retained as the dated record and are superseded. Gate status is unchanged:
> all strict image gates remain blocked.

Behavioral review also confirmed [Gau's disabled provider TLS verification](gau-tls-review.md)
in the existing Linux/amd64 binary. A dependency-only rebuild retains the defect
despite a clear standalone scanner result, so it remains unpromoted. This is an
additional release blocker, independent of the raw image severity counts.

## Implemented remediation

- The PostgreSQL image's bundled gosu 1.19.0 was built with Go 1.24.6 and accounted for
  26 high and 1 critical standard-library occurrences, all with published fixed Go
  versions. `db/Dockerfile` rebuilds that same gosu release with Go 1.27.3 over the
  unchanged reviewed PostgreSQL digest. The remaining PostgreSQL findings are Debian
  packages without fixed versions in the base suite and stay open; see the
  [exposure review](alpha-os-exposure.md).
- [Map #117](https://github.com/VardrSec/VardrMap/pull/117) pins Python/Node Debian
  Trixie bases and removes the unused global npm/npx dependency tree from the web
  runtime. npm remains in the build stage; native development is unchanged.
- [Runner #85](https://github.com/VardrSec/VardrRunner/pull/85) pins its Python/Trixie
  base and patched Go 1.27.3 Gate builder, and verifies the five official Subfinder
  2.17.0 archives before updating that existing tool pin.
- [Runner #86](https://github.com/VardrSec/VardrRunner/pull/86) builds the existing
  Katana 1.8.0 command with Go 1.27.3, pgx 5.9.2, x/net 0.60.0 and compress
  1.18.7. Its image receipt records source/module checksums, compiler, binary hash
  and retained build records without claiming an upstream archive checksum.
  Runtime hash verification remains mandatory. All nine tools and native archive
  pins remain; this development remediation does not decide alpha shipping scope.
- [Runner #87](https://github.com/VardrSec/VardrRunner/pull/87) extends that fixed
  source-build contract to DNSx 1.3.1 with Go 1.27.3, x/net 0.60.0 and compress
  1.18.7. A real in-container regression resolves one synthetic .test A name via
  loopback without external DNS or added capabilities. Native archives remain.
- [Runner #88](https://github.com/VardrSec/VardrRunner/pull/88) applies the same
  contract to Naabu 2.6.1 with Go 1.27.3, x/net 0.60.0, x/crypto 0.57.0 and
  compress 1.18.7. CGO/libpcap-dev stays in the builder; existing runtime libpcap,
  unprivileged TCP-connect operation and the capability-free baseline remain.
- The proxy retains Caddy 2.11.7, rebuilt with pinned Go 1.27.3 and x/net 0.60.0;
  its Alpine packages are refreshed. The small standard-module entry point keeps
  Caddy version metadata available. TLS configuration, installed CA storage and
  the existing file-capability boundary are preserved. This follows Caddy's
  [documented source-build approach](https://caddyserver.com/docs/build).

The latest completed combined review below includes Runner #87, before #88's
integration. Its [five-image run](https://github.com/VardrSec/VardrSec/actions/runs/40546749565)
records clean tested merge `d32f32c2ad48e397c01fc43914756a6ffdb22d9c`, whose tree
matches reviewed head `00d740b3e09802e7a2c6580d8ea2d4ae9e6afc71`. Distribution #22
merged after all installed Ubuntu, recovery/update, trust/certificate, native unit
and bounded tool/network checks passed. Independent review verified each input
against its Git blob, every report hash and recomputed severity count. The strict
check exits 1, as expected:

| Image | Critical | High | Unknown | Critical/high with a published fixed version |
| --- | ---: | ---: | ---: | ---: |
| API | 0 | 44 | 1 | 0 |
| PostgreSQL | 2 | 86 | 5 | 26 |
| Proxy | 0 | 0 | 1 | 0 |
| Runner | 2 | 223 | 9 | 179 |
| Web | 0 | 43 | 1 | 0 |

Critical/high package/path occurrences fell from 13/518 to **4/396**. These are
scanner occurrences, not confirmed exploit paths. All image gates remain blocked,
including the proxy because of its
unknown finding. CI artifacts expire after seven days; retain reviewed receipts
privately or recollect, and never use this dated table as current clearance.

Runner #88's separately reviewed local image reports **1 critical / 178 high**
using the same frozen database. Katana, DNSx and Naabu each have one unknown OpenPGP
finding and zero critical/high/medium/low. Its full suite passes 1,598 tests with
96.48% coverage; all seven host/runtime CI jobs and the real container DNS/state
checks and bounded TCP-connect/tool/network fixture pass. These local counts cover that review image only; the updated pin
requires fresh combined distribution receipts. Native upstream archives, other
tools, broader modes and genuine VPN acceptance remain separate unresolved work.

Runtime probes verified API SQLite 3.46.1, non-root Map users and absence of runtime
npm. Frontend lint/typecheck, 212 tests and production build passed; Runner's full
suite/static checks and the real bounded tool/network fixture passed. Proxy leaf
renewal/restart retained CA hashes and key permissions. Combined installation,
recovery/update, tool/network and certificate checks passed before and after
distribution #14 merged. [Setup #15](https://github.com/VardrSec/VardrSec/pull/15)
also passed the clean Ubuntu/native-trust and installed workflow before merging.

## Residual critical findings

| Finding / location | Current assessment and required action |
| --- | --- |
| CVE-2025-68121 in Gau; former DNSx/Naabu archives | **Superseded:** the container Gau is now rebuilt (Runner #89) and the native Gau archive is excluded (Runner #94). Historical assessment follows. Gau's container binary remains old, as do native archives. Binary review found affected TLS symbols; the [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) also requires session resumption and CA-configuration mutation, which symbols alone do not prove. Recorded DNSx/Naabu source builds remove this finding in their raw review scans; #22 verifies DNSx in combined CI and the Naabu integration needs fresh combined evidence. Gau remains unresolved; its dependency-only experiment also retains the independently confirmed TLS verification defect above. |
| CVE-2025-68121 in PostgreSQL's gosu helper | Binary review found the advisory but no affected TLS symbols in the actual helper. Its embedded metadata identifies gosu 1.19 / Go 1.24.6. The small [1.19 source](https://github.com/tianon/gosu/tree/6456aaa0f3c854d199d0f037f068eb97515b7513) switches user and executes a command; it imports no TLS client/server. This supports a scoped non-exposure assessment for this helper, consistent with [upstream's policy](https://github.com/tianon/gosu/blob/1.20/SECURITY.md). It is not a global Go waiver or database clearance; retain the raw finding and review the disposition before release. |
| CVE-2026-33815 / CVE-2026-33816 in the former Katana archive's pgx dependency | The original binary contained affected protocol decoder symbols; no non-exposure waiver was used. The [Go reports](https://pkg.go.dev/vuln/GO-2026-4771) [identify](https://pkg.go.dev/vuln/GO-2026-4772) fixed pgx 5.9.0. Runner #86 selects 5.9.2 in its recorded source build; both findings are absent from that review binary's raw scan. Retain the old evidence and revalidate the pinned combined image; native upstream archive installation remains unchanged. |
| CVE-2026-6653 in PostgreSQL libxml2 | [Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653) retains affected stable packages with vendor priority notes. The pinned PostgreSQL binary is built `--with-libxml`; [SQL XML input](https://www.postgresql.org/docs/18/datatype-xml.html) can invoke that parser. Reviewed Map models/routes contain no XML columns or XML parsing query, and the database has no published port. These narrow ordinary web exposure, but SQL access, injection or future XML features remain relevant. Keep unresolved; no cross-release package mixing or accepted-risk waiver. |

The separate local review used `govulncheck@v1.9.0` in binary/symbol mode, recorded
image identities and binary SHA256 values, and did not execute the analyzed
binaries. JSON mode exits zero even with findings; findings were parsed explicitly.
All eight bundled Go tools and gosu were reviewed. Comparison with this Trivy
checkpoint found no affected-symbol matches for its 26 gosu critical/high
occurrences. Many tool findings did match symbols, while some Trivy advisories
could not be mapped to the separate Go dataset; those cannot be cleared by it.
Symbol presence is not proof of a reachable call path; absent matches also need
source and advisory coverage review. See the tool's [documented limitations](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

It also identified `github.com/moby/sys/user` 0.1.0 parsing symbols in gosu for
[CVE-2026-61801](https://github.com/moby/sys/security/advisories/GHSA-mjcv-p78q-w5fw).
This needs attacker-controlled passwd/group input. The distribution does not
mount those files or accept user-provided images into that helper. Upstream
[gosu 1.20](https://github.com/tianon/gosu/releases/tag/1.20) fixes the dependency,
while deliberately retaining Go 1.24.6; upgrading it alone would not remove the
version-based TLS report. Track a verified vendor image update rather than
changing PostgreSQL variant, ownership or collation just to change a count.

## Remaining high findings and review boundaries

All remaining API/web high occurrences are Debian packages with no fixed-version
entry in this database. The same is true for 62 critical/high PostgreSQL OS
occurrences and 46 Runner OS occurrences. Preserve vendor package status and
investigate plausible input paths; lack of a packaged fix is not a disposition.
The other 26 PostgreSQL critical/high occurrences belong to gosu's embedded Go
runtime. Runner's other 241 belong to the eight bundled Go tools; each has a
fixed-version entry, which does not imply an upstream tool release already
contains it. The tools process target-controlled responses, so default isolation
and explicit invocation do not by themselves clear parser/client findings.
Prioritize verified upstream patches and symbol/exposure assessment. Full SBOMs,
package paths, installed/fixed versions, source URLs and counts remain available
in the unfiltered [image evidence](image-evidence.md) artifacts.

The separate [Debian exposure review](alpha-os-exposure.md) records vendor
conditions, split-package effects, local executable-absence probes and the
remaining caller/privilege questions. It grants no waiver and changes no gate.

The former bookworm zlib MiniZip critical finding illustrates why affected-status
matters: [Debian documents](https://security-tracker.debian.org/tracker/CVE-2023-45853)
that the vulnerable contrib code is not built into those binary packages. The
Trixie refresh removes that old package baseline; no global ignore rule was added.
Binary analysis can narrow symbol presence but cannot prove all runtime paths or
eliminate reflection/unsafe-analysis limitations. Preserve that uncertainty.

## Proxy dependency follow-up and inventory coverage

The proxy build now selects chi 5.4.0 for
[CVE-2026-114437](https://github.com/go-chi/chi/security/advisories/GHSA-j6qf-3m9c-vwj3).
The advisory concerns `ClientIPFromXFF` peer validation; package presence does not
establish that Caddy invokes that middleware. Retain Caddy 2.11.7, its standard
module set and the existing proxy/forwarded-header configuration. Local build
metadata verifies Caddy 2.11.7, Go 1.27.3, x/net 0.60.0 and chi 5.4.0. The standard
module catalog matches the pinned official Caddy image. The five-image rescan
reports zero critical/high/medium proxy findings and one unknown, so its strict
gate remains blocked. Accelerated renewal passed 119 fresh verified handshakes,
three leaf serials, post-expiry browser trust and CA/key permissions after restart.
Installed workflow/recovery/update CI must also pass before merge.
The dated five-image table above remains the earlier checkpoint.

The proxy's remaining unknown `GO-2026-5932` report concerns unmaintained
[`x/crypto/openpgp`](https://pkg.go.dev/vuln/GO-2026-5932), not every x/crypto API.
The local binary review finds the module-level advisory with no affected-symbol
matches. This supports a narrow non-exposure review, not a waiver for every
x/crypto consumer. There is no fixed x/crypto version listed for it; a broad
version upgrade is not clearance. The raw report and blocked gate are retained.

Dalfox 3.2.4 is a [Rust rewrite](https://github.com/hahwul/dalfox/blob/v3.2.4/Cargo.toml).
Its prebuilt binary passes the existing archive/binary integrity checks, but the
current image report has no Rust dependency inventory for it. The eight Go tool
reports do not cover Dalfox. Record its exact source/lockfile and assess Rust
dependencies separately, with an explicit source-to-release-binary provenance
limit. This coverage gap remains open; absence from a scanner report is not a
clean result. No managed integrity check is bypassed and no new tool is bundled.

Supplemental review of source tag `v3.2.4`, commit
`da19527f9c82d8525e911ca3669fc456daeb50f2`, records Cargo.lock SHA256
`72a57d982859e11ba8a2264cc79f132a507f94d5dd84717c6b41d86db6cd902c`.
An offline Trivy source scan inventories 335 packages and reports zero findings.
An independent `cargo-audit` 0.22.2 check against RustSec commit
`99670cfc0bc574433034b75876a4b791ccaa2efb` exits 1 with **seven advisories and one
unsoundness warning**, without exclusions. The tool's official release archive
SHA256 was verified before it ran in a separate capability-free, network-disabled
container; it is not added to Runner or the platform.

| Lockfile package | Advisory / available patch | Required disposition |
| --- | --- | --- |
| rsa 0.9.10 | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html); no patched version | Source invokes RSA-OAEP private-key decryption in the interactsh poll path. Upstream ignores the advisory based on local short-lived use; that is not automatically our disposition. Review timing exposure and allowed OAST modes. |
| rustls 0.23.45 | [0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html); 0.23.46 | Review enabled TLS/debug/ECH/certificate-decompression paths; obtain a verified patched artifact rather than assume unused features. |
| rustls-webpki 0.103.15 | [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html); 0.103.16 in this stable line | Review certificate trust exposure and a verified patched artifact. |
| webpki-root-certs 1.0.9 | [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383.html); 1.0.10 | Review bundled-root usage and a verified patched artifact. |
| tokio 1.53.1 | Unsoundness warning [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html); 1.53.3 in this stable line | Review `AsyncFd` I/O-safety exposure and a verified patched artifact; keep distinct from the seven vulnerability advisories. |

The source release workflow does not build with `--locked`; this lockfile review
cannot establish which dependency versions are embedded in the downloaded
binary. Preserve the source reports, the separate binary integrity receipt and
this provenance gap. Do not add source-only Rust counts to the five-image binary
checkpoint or reinterpret the zero-result Trivy source scan as clearance. The
RustSec warning also requires disposition before certifying this tool.

## Failures and complexity observed

A retained Windows development checkout had an unreadable `.pytest_cache`, which
prevented Docker context transfer even with an ignore entry. A clean tracked-source
snapshot built successfully; the cache was left untouched and no ineffective
ignore change was retained. This is not evidence of a clean-Ubuntu installation
failure. The new clean-install exercise must use a fresh checkout and record its
own failures.

Existing diagnostics, backup/update implementations and workflow fixtures remain
the implementation path. Further installer layers, general exception frameworks
or broad application refactors are unnecessary for this checkpoint. The next
work is residual security review followed by the phase-1 clean Ubuntu/setup
tasks; release publication remains a separate reviewed action.

## Reachability coverage (`govulncheck`), 2026-10-27

The image scanner uses a database frozen at collection time, so newer advisories are
invisible to it. Go's `govulncheck -mode=binary` (live database, symbol-level
reachability) was run against locally built binaries using the exact recipes and the
Go 1.27.3 toolchain:

| Binary | Result before | Action | Result after |
| --- | --- | --- | --- |
| Gate (pinned `af29a93`) | none | none | none; two clean builds are byte-identical |
| Caddy proxy | GO-2026-6860, GO-2026-6866 (x/net 0.60.0) | x/net 0.62.0 | none |
| gosu (PostgreSQL image) | GO-2026-6686 (moby/sys/user 0.1.0) | moby/sys/user 0.4.1 | none |
| FFUF, Gau | GO-2026-6860 (FFUF) | x/net 0.62.0 | none |
| httpx, Subfinder, Katana, DNSx | GO-2026-5320 goldmark (and x/net) | goldmark 1.7.17, x/net 0.62.0 | none |
| Nuclei | GO-2026-6860, GO-2026-5932 | x/net 0.62.0 etc. | GO-2026-5932 only (x/crypto/openpgp unmaintained, no fixed version) |
| Naabu | not scanned (needs CGO/libpcap) | same dependency set patched | module-level OSV check of its 107 resolved Go modules finds only GO-2026-5932 (openpgp, no fix); symbol reachability **not** verified |

## Coverage gap: Dalfox

Dalfox 3.2.4 (the latest release) is a Rust program. The image scanner reports no
target for it because the release binary carries no `cargo-auditable` data, so the
zero Dalfox findings in the image reports mean **not scanned**, not clean. A manual
assessment used the upstream `Cargo.lock` at the v3.2.4 tag (337 packages) against the
OSV database:

- No critical or high advisory. Six packages have advisories: `rustls` 0.23.45 (four,
  moderate/low, fixed in 0.23.46), `rustls-webpki` 0.103.15 (distrusted intermediates,
  fixed in 0.103.16), `tokio` 1.53.1 (I/O safety, fixed in 1.53.3), `rsa` 0.9.10
  (Marvin timing side channel, no fix; Dalfox links it directly), and `block-buffer` and
  `webpki-root-certs`, which are in the lock file but not embedded in the shipped binary.
- Rebuilding Dalfox from source with updated crates would need a Rust build stage, which
  is outside the stabilization scope. The `rustls` advisories matter when Dalfox connects
  to a hostile HTTPS target; the others have little exposure.
- Disposition: **open, moderate/low, not blocking**; record in the release notes and
  re-check on the next Dalfox release.

Other scanner coverage: Debian/Alpine packages, Python and Node packages (176 npm
packages, no advisories) and nine Go binaries are covered. Three UNKNOWN-severity Debian
or Go entries remain unclassified by their vendors (perl `Pod::Text`, x/sys Windows-only
code in gosu, and the unmaintained openpgp package).

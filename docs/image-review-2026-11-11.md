# Image evidence review (11 November 2026)

## Verified evidence, not release clearance

Reviewed pre-remediation image-evidence run: https://github.com/VardrSec/VardrSec/actions/runs/42988221940 . Artifact 13840484215 (development-image-evidence), SHA-256 `ccf2cb223490f5def91aa4dc611ea4fe72df73a5375f3564bfbfc3de9a27eb37`, expires 18 November. Receipt collected 11 November 08:46 UTC against distribution PR merge tree `12c82d11b9145f3dd09ee6f1319bff7688f524c9`. Trivy 0.76.1 database updated 10 November 19:01 UTC. Receipt/hash/image/config/database checks passed, but `image_evidence.py check` exited 1 BLOCKED. Workflow completion is not vulnerability acceptance.

| Image | Critical | High | Medium | Low | Unknown |
|---|---:|---:|---:|---:|---:|
| api | 0 | 47 | 79 | 66 | 15 |
| db | 1 | 113 | 135 | 120 | 16 |
| proxy | 0 | 1 | 2 | 0 | 1 |
| runner | 0 | 49 | 83 | 69 | 21 |
| web | 0 | 46 | 74 | 64 | 10 |

Counts are scanner occurrences, not distinct exploitable defects. Evidence predates the new remediation branches and does not certify their resulting images.

## Findings needing remediation or supported disposition

- **GO-2026-6859:** the separate proxy govulncheck artifact 13841202514 reports vulnerable net/http symbols in Go 1.27.3, fixed in 1.27.4. This was not yet in the Trivy database. Upgrade exact Go builder pins and rebuild affected binaries; rerun both scanners. Advisory: https://pkg.go.dev/vuln/GO-2026-6859 .
- **CVE-2026-116587 / GHSA-mgcc-cww5-fp2q:** proxy contains go-jose/v3 3.0.5 with no fixed v3 version reported; patched v4 also exists in the graph. RSA JWK processing denial-of-service requires an exact upstream/runtime boundary analysis, not an assumption that v4 presence fixes v3. Advisory: https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q .
- **CVE-2026-6653:** db libxml2 `2.12.7+dfsg+really2.9.14-2.1+deb13u3+vardr2` is still reported CRITICAL with no scanner fixed version. Existing build applies checksum-verified Ubuntu backport `db/libxml2-CVE-2026-6653.patch`; `db/build-libxml2.sh` includes six additional patches and retains corresponding source under `/usr/share/doc/libxml2/vardr-source/`. Verify the exact binary/source/backport relationship and regression coverage before disposition. Package version alone does not prove the backport ineffective, but the patch's presence alone is not scanner clearance.
- **CVE-2026-39824 / GO-2026-5024:** db gosu x/sys 0.1.0, fixed 0.44.0, scanner UNKNOWN. Advisory concerns Windows NewNTUnicodeString overflow; shipped gosu is Linux. Track platform applicability separately from dependency upgrade, without suppressing the finding globally.
- **GO-2026-5932:** x/crypto 0.58.0 appears in proxy and six Runner tools; scanner UNKNOWN with fixed pseudo-version `0.58.1-0.20261009181718-2f1f834330b2`. Concerns unsafe/unmaintained OpenPGP. Proxy govulncheck finds the module but no vulnerable imported package. That does not establish the same result for all six tools. Require per-tool symbol evidence or an appropriate upstream upgrade, rather than a blanket exception.

Remaining OS and unknown findings need package/advisory-specific review. No suppression, acceptance, clean-image, reproducible-image or release-ready claim is made here. CI must rebuild pinned sources and collect fresh receipts/SBOMs/vulnerability and reachability reports before judging remediation. Preserve exact artifact digests before Actions retention expires.


## Subsequent bounded remediation

The database gosu build now selects `golang.org/x/sys v0.44.0`. A separate
Linux/amd64 build of the exact gosu commit with Go 1.27.4 succeeded and its
embedded module list confirms x/sys 0.44.0; `gosu --version` reports 1.19.
Two local builds matched SHA-256
`34d7c9c6f0427a70c52aee706e389d92d52daca3491ad99ba32c61bb7dc71d15`;
`go mod verify` passed and govulncheck 1.9.0 reported no vulnerabilities.
This evidence covers this Linux/amd64 binary, not every database image package.
CI additionally checks the actual binary copied out of the resulting database
image, retains its module list and performs binary govulncheck. This is a module
upgrade, not a suppression or a claim that the old Windows-specific path was
exploitable on Linux. [Upstream advisory](https://pkg.go.dev/vuln/GO-2026-5024).

The stable OS package backlog cannot be cleared by an unqualified apt upgrade:
Debian currently lists Trixie util-linux 2.41.5 as vulnerable to
[CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642),
with the fix in unstable, and Trixie SQLite 3.46.1 as vulnerable to
[CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373),
also fixed in unstable. Both have a no-DSA classification for stable. This is
not VardrSec risk acceptance: no mixed-distribution upgrade is selected. A
reviewed backport or application-specific applicability evidence is still needed.

## Additional proxy boundary evidence

The prior boundary artifact `13840948684` contains a receipt for Caddy v2.11.7, binary SHA-256 `2ccf2914cbfe65d113ce4db51dc62bfd774f020b6ef33882d07d2d30442f370b`, and Caddyfile SHA-256 `19f70759f4cb954ab75b47eb9af8829067d4efd2fce3d77e488a85d1bc492fd4`. Bounded fixtures reached both `/acme/local/new-account` and `/backend/acme/local/new-account` and verified unchanged forwarding of body and Authorization bytes. In an explicitly enabled ACME-server control, a malformed private JWK was rejected before nonce validation, while the public-key control reached the nonce check. The fixture did not install host trust.

This matches the configured boundary: admin API disabled; internal TLS issuer; only reverse-proxy, rewrite and subroute HTTP handlers; no ACME-server handler. The upstream Caddy v2.11.7 source registers ACME as the separately configured `http.handlers.acme_server` module and dispatches smallstep ACME API routes from that handler (https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddypki/acmeserver/acmeserver.go).

Conclusion: the evidence supports absence of the reviewed untrusted JWK ingress through the shipped configuration, not removal of vulnerable code or safety of arbitrary Caddy configurations. The old receipt does not cover the newly rebuilt Go 1.27.4 binary. A matching fresh receipt plus a documented configuration-scoped assessment is needed; leave raw findings intact. Enabling an ACME handler, authentication/JWK processing, admin access, other issuers/loaders or other applications invalidates this conclusion. The upstream advisory still lists go-jose/v3 <=3.0.5 as affected with no patched v3 release.

The gosu recipe now uses committed `gosu.go.mod`/`gosu.go.sum`, verifies module
checksums, then builds with network disabled and `-mod=readonly`. It retains
source archives for the three linked modules, module hashes and binary build
metadata in `/usr/share/licenses/gosu/source/`. The same locked local build with
`GOPROXY=off` reproduced the binary hash above. Image delivery remains subject to
the fresh CI image evidence rather than this local result.

## Candidate integration boundary

This branch selects Runner PR #134 commit
`c7ac178223d2e88d0bf6227cbf9e76a18ccf01a9` for integration verification, with
Go 1.27.4, brotli 1.2.7 and compress 1.20.2 source overrides. It also selects
already-merged Gate `7f610397335c75414d9a47ebabf0c4aab380e14b`, including its
Go 1.27.4 fix. These are candidate source pins, not release approval.
The earlier tables and license/source bundles remain bound to their recorded
pre-remediation SBOMs; regenerate inventories from the candidate image evidence.
The source manifest still declares development status and no published images.
Nuclei's deprecated OpenPGP path is replaced through a pinned go-github/v30
source backport to maintained ProtonMail 1.5.2, with complete original/patched
source and license retention. Moving the old package to a separate module alone
is not considered a remediation. The actual candidate Nuclei binary passed 44
main-graph signing tests (including fresh-key signing and expired-key rejection)
and govulncheck reported no reachable or imported-package vulnerabilities. Its
binary SHA-256 was
`13c41a98fd2474115621cdb8b2ab40976b203daf2a116431a14cc116aafec749`.
This local candidate evidence does not replace the pending integrated image scan.
The original old-SDK full-suite failures were reproduced without the backport
and are documented in Runner's backport review; no crypto policy was weakened.

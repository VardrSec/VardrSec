# Community Alpha v0.1.0 stabilization plan

Accepted owner direction, 2026-10-27. Prepare the first public Community Alpha;
publication and deployment require a separate reviewed decision. This plan
prioritizes completion of the existing product and supersedes broader roadmap
expansion during alpha stabilization. There is no published alpha yet. Status: **release candidate preparation**; no
features are being added, and publication is a separate owner decision.

VardrSec keeps Compose lifecycle/recovery, Runner keeps diagnostics and explicit
execution, Map keeps the researcher interface, and Gate keeps authorization
testing. Keep the four repositories independent. Add no tools, engines, agents,
Enterprise features, frameworks or unnecessary architectural layers.

## Execution order and current evidence

| Phase / task | Required outcome | Current status |
| --- | --- | --- |
| 1 / 1. Security review | Five-image inventory; critical/high affected-status and exposure assessment; fixes; justified unresolved risks; transparent reports. | PR #12 merged collection and strict review. Fixable go-jose/v4 remediation and the Caddy configuration/source review are merged. Raw gates remain blocked pending owner disposition; see the [risk register](residual-risk-register.md). |
| 1 / 2. Clean Ubuntu installation | A genuinely fresh environment follows distribution-only acquisition/build/start, migrations, trust enrollment, bootstrap/login and restart persistence without source edits. | #15 merged after fresh Ubuntu 24.04/amd64, native CA enrollment/removal, CLI bootstrap/Doctor, browser login, restart and recovery passed. Prerequisites were preinstalled on the hosted machine; unfamiliar-user completion remains unverified. See the [checkpoint](alpha-checkpoint-2026-10-27.md). |
| 1 / 3. First-time setup | Clear prerequisites/errors, simple bootstrap, certificate instructions, Runner authentication and success confirmation in one authoritative guide. | #15 implements prerequisite/errors, safe initial-fetch retry, generated-password bootstrap and public CA fingerprints. [Installation](installation.md) is authoritative; new-user usability still needs task 9. |
| 2 / 4. Research workflow | Engagement/scope/two identities, review/queue/explicit execution, definite versus inconclusive results, independent write readback, finding/remediation/retest and report export. | Installed UI workflow, six real Gate scenarios, coverage/boundary drafting, finding confirmation and report export passed #40/#41 CI with controlled local targets. Unfamiliar-user completion remains open. |
| 2 / 5. Networking / VPN | Host/private reachability, representative authorized VPN where available, native/container comparison, safe native fallback and explicit limitations. | Synthetic host/private namespace tests passed; genuine VPN remains unverified. [Networking guidance](networking.md) documents the native-Runner fallback and the unverified VPN cases. Do not change host routes, firewall or VPN settings automatically. |
| 2 / 6. Reliability | Existing backup/encrypted restore, integrity, restart, successful update, failed update/recovery and actionable instructions. | Existing acceptance drills pass. Reuse them for the candidate; extend architecture only for a demonstrated release blocker. |
| 2 / 7. Platform matrix | Accurate supported versus experimental environments and known OS failures. | Ubuntu 24.04 Linux/amd64 automated installation/workflow/recovery passes. Ubuntu 22.04 has bounded tool/network evidence only; Windows/macOS remain experimental despite native certificate-store checks. Broader certification is outside this alpha. |
| 3 / 8. Release candidate | Immutable tested pins, independently reproducible install artifact/process, compatibility, licensing/redistribution review, release notes, limitations and minimal troubleshooting/recovery docs. | Preparation is in progress: [release checklist](community-alpha-release.md), exact development pins and [direct license inventory](release-license-inventory.md) are recorded. Candidate freeze, full licensing review and owner decisions remain open; no publication approved. |
| 3 / 9. First-user test | One getting-started path, controlled example target/engagement, measured installation-to-assessment time and recorded friction for an unfamiliar researcher. | Requires an actual unfamiliar-user exercise; developer automation alone does not establish this result. Protocol: [first-user-test.md](first-user-test.md). |

## Priority and status (updated 2026-10-28)

Priorities map onto the table above; they do not add tasks. Operational state
(unmerged branches, working trees, next PR) lives in the owner's handoff plan, not here.

| Priority | Table task | Status |
| --- | --- | --- |
| P0 release-blocking security | 1 | The two fixable go-jose/v4 occurrences are removed in verified rebuilt images (latest recount, 2026-10-31: 1 critical / 195 high / 25 unknown); Caddy v3 now has a [source and bounded-control exposure review](caddy-v3-jwk-exposure.md): no JWK ingress in the shipped configuration; the dependency and proposed conditional disposition remain unaccepted. Owner disposition of the [residual-risk register](residual-risk-register.md) pending. Container Gau TLS is fixed (Runner #89, pinned) and the native archive is excluded and enforced (Runner #94) ([review](gau-tls-review.md)). Image gates stay blocked until the owner decides. |
| P0 complete researcher workflow | 4 | UI path verified in CI: the installed workflow now creates the client, testing window, scope and authorization through the Map interface (Map #119, VardrSec #26), then runs the reviewed Gate cases, confirms a finding and exports reports. Target/identity fixtures and Runner key issuance remain scripted by design; the unfamiliar-user exercise is still open. |
| P1 first-user experience | 2, 3, 9 | Automated clean-Ubuntu install passes; no unfamiliar-user exercise has occurred. |
| P1 networking | 5, 6, 7 | Synthetic host/private tests pass; genuine VPN unverified. Reliability drills pass and are reused for the candidate. |
| P2 release preparation | 8 | In progress: checklist and verified direct license inventory prepared. Distribution license, Nmap integration terms, transitive notices/source delivery and candidate freeze remain open. |

Pre-remediation independently verified baseline: [image run 40622056177](https://github.com/VardrSec/VardrSec/actions/runs/40622056177),
clean distribution commit `524585cac788d08c529df58b4dd82a20029e7c1b`, collected 2026-10-28.
Raw reports total **1 critical / 197 high / 15 unknown** occurrences (API 0/44,
PostgreSQL 1/61, Proxy 0/2, Runner 0/47, Web 0/43). Two high occurrences have a
published fix: go-jose/v4 in Caddy and Nuclei, fixed in 4.1.6. A third new high
occurrence is Caddy's go-jose/v3 3.0.5, for which upstream reports no fixed v3 release.
The previous 1/194 baseline is historical; its blanket "none fixable" statement no
longer describes current evidence. See the [current security checkpoint](alpha-review-2026-10-28.md).

The rebuilt [image run 40757052765](https://github.com/VardrSec/VardrSec/actions/runs/40757052765)
verifies go-jose/v4 4.1.6 in Caddy and Nuclei, with **1 critical / 195 high / 15 unknown**
remaining and **no critical/high fixed-version occurrence**. Caddy's binary scan
reports zero reachable vulnerabilities in its database coverage; the new v3 advisory
was absent from that database at the checkpoint. The later [manual review](caddy-v3-jwk-exposure.md) establishes no affected JWK ingress in the shipped configuration; the dependency remains affected and its proposed disposition unaccepted.
The [checkpoint](alpha-review-2026-10-28.md) records hashes, counts and limitations.

The current development pins are Map #134 (`696a8bf`), Runner v0.54.0 (`854b973`)
and Gate v0.2.0 (`7f82e49`), set by [distribution #46](https://github.com/VardrSec/VardrSec/pull/46)
and [#47](https://github.com/VardrSec/VardrSec/pull/47); all three are ancestors of their
repositories' `main` (verified 2026-10-31). Both PRs passed all 12 checks, and the
workflows on `main` ([#47 merge](https://github.com/VardrSec/VardrSec/actions/runs/41161013898),
[#48 merge](https://github.com/VardrSec/VardrSec/actions/runs/41175264942)) are green. Earlier
integration evidence ([#40](https://github.com/VardrSec/VardrSec/pull/40/checks),
[#41](https://github.com/VardrSec/VardrSec/pull/41/checks)) covered older pins.

The [#48-merge image collection](https://github.com/VardrSec/VardrSec/actions/runs/41175264942)
(distribution `2f71c32`, database updated 2026-10-31) was recounted from its raw reports
with `image_evidence.py check` (exit 1) and independently from the JSON:
**1 critical / 195 high / 25 unknown** (API 0/44/3, PostgreSQL 1/61/9, Proxy 0/1/1,
Runner 0/46/9, Web 0/43/3). The #47-merge collection
([run 41161013898](https://github.com/VardrSec/VardrSec/actions/runs/41161013898))
is identical. Against run 40757052765 the critical and high occurrences are unchanged;
the ten additional unknown occurrences are a single advisory, glibc CVE-2026-84243
(unfixed `libc6`, `libc-bin`, `libc-l10n`, `locales` in the four Debian images), added to
the scanner database after that run. Its [exposure review](glibc-gettext-language-exposure.md) identifies no
untrusted path to the vulnerable condition in the sources and records a proposed
conditional exception in the [register](residual-risk-register.md); it is not accepted,
the runtime probe in installed acceptance confirmed the locale and environment conditions, and no gate changes. These are development sources, not released artifacts. All strict image gates
remain blocked; no residual risk is accepted.

Group tasks only when sharing an acceptance environment helps; keep changes
individually reviewable. Begin tasks 4–7 after tasks 1–3, then tasks 8–9.

## Acceptance discipline

After each task record what completed, what changed, realistic tests/results,
discovered/fixed defects, remaining blockers, unnecessary complexity and the next
task. Unit-test counts alone do not establish readiness. The first alpha needs a
reliable installation → engagement → authorized assessment → findings/report →
retained-data journey, not every possible tool mode or planned feature.

Preserve authentication, ownership/tenant checks, explicit scope and human review,
HTTPS validation, stop-work and operator-controlled execution. Preserve existing
advisory policy semantics. Keep raw vulnerability reports; affected-status or
exposure dispositions need supporting evidence and review. Never add blanket
suppression to obtain a green result.

Use the existing [image evidence](image-evidence.md), [installed workflow](installed-gate-acceptance.md),
[tool/network coverage](tool-network-acceptance.md), [recovery](recovery.md),
[encrypted backup](encrypted-backups.md) and [controlled update](updates.md)
fixtures and guides. Unsupported configurations must remain explicit. Larger
refactors require a demonstrated need and must not displace stabilization work.

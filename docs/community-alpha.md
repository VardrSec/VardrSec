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
| 1 / 1. Security review | Five-image inventory; critical/high affected-status and exposure assessment; fixes; justified unresolved risks; transparent reports. | PR #12 merged collection and strict review. Initial five-image vulnerability gates are blocked. Focused runtime/tool remediation is in progress; this task is not complete. |
| 1 / 2. Clean Ubuntu installation | A genuinely fresh environment follows distribution-only acquisition/build/start, migrations, trust enrollment, bootstrap/login and restart persistence without source edits. | #15 merged after fresh Ubuntu 24.04/amd64, native CA enrollment/removal, CLI bootstrap/Doctor, browser login, restart and recovery passed. Prerequisites were preinstalled on the hosted machine; unfamiliar-user completion remains unverified. See the [checkpoint](alpha-checkpoint-2026-10-27.md). |
| 1 / 3. First-time setup | Clear prerequisites/errors, simple bootstrap, certificate instructions, Runner authentication and success confirmation in one authoritative guide. | #15 implements prerequisite/errors, safe initial-fetch retry, generated-password bootstrap and public CA fingerprints. [Installation](installation.md) is authoritative; new-user usability still needs task 9. |
| 2 / 4. Research workflow | Engagement/scope/two identities, review/queue/explicit execution, definite versus inconclusive results, independent write readback, finding/remediation/retest and report export. | Existing installed workflow covers substantial behavior. Revalidate the complete researcher path without manual database edits, API workarounds or product-source changes. Use controlled local targets. |
| 2 / 5. Networking / VPN | Host/private reachability, representative authorized VPN where available, native/container comparison, safe native fallback and explicit limitations. | Synthetic host/private namespace tests passed; genuine VPN remains unverified. [Networking guidance](networking.md) documents the native-Runner fallback and the unverified VPN cases. Do not change host routes, firewall or VPN settings automatically. |
| 2 / 6. Reliability | Existing backup/encrypted restore, integrity, restart, successful update, failed update/recovery and actionable instructions. | Existing acceptance drills pass. Reuse them for the candidate; extend architecture only for a demonstrated release blocker. |
| 2 / 7. Platform matrix | Accurate supported versus experimental environments and known OS failures. | Ubuntu Linux is the first release target. Ubuntu 24.04 Linux/amd64 is the initial candidate environment to validate. Windows 11/macOS Docker Desktop require explicit evidence; incomplete cross-platform support alone must not delay a Linux-only alpha. |
| 3 / 8. Release candidate | Immutable tested pins, independently reproducible install artifact/process, compatibility, licensing/redistribution review, release notes, limitations and minimal troubleshooting/recovery docs. | Prepare only after security/acceptance review. Distinguish development artifacts from published releases; prepare for review without publication. Draft checklist: [community-alpha-release.md](community-alpha-release.md). |
| 3 / 9. First-user test | One getting-started path, controlled example target/engagement, measured installation-to-assessment time and recorded friction for an unfamiliar researcher. | Requires an actual unfamiliar-user exercise; developer automation alone does not establish this result. Protocol: [first-user-test.md](first-user-test.md). |

## Priority and status (updated 2026-10-27)

Priorities map onto the table above; they do not add tasks. Operational state
(unmerged branches, working trees, next PR) lives in the owner's handoff plan, not here.

| Priority | Table task | Status |
| --- | --- | --- |
| P0 release-blocking security | 1 | Security review reopened against the 2026-10-28 image baseline; fixable go-jose occurrences are being remediated. Owner disposition of the [residual-risk register](residual-risk-register.md) pending. Container Gau TLS is fixed (Runner #89, pinned) and the native archive is excluded and enforced (Runner #94) ([review](gau-tls-review.md)). Image gates stay blocked until the owner decides. |
| P0 complete researcher workflow | 4 | UI path verified in CI: the installed workflow now creates the client, testing window, scope and authorization through the Map interface (Map #119, VardrSec #26), then runs the reviewed Gate cases, confirms a finding and exports reports. Target/identity fixtures and Runner key issuance remain scripted by design; the unfamiliar-user exercise is still open. |
| P1 first-user experience | 2, 3, 9 | Automated clean-Ubuntu install passes; no unfamiliar-user exercise has occurred. |
| P1 networking | 5, 6, 7 | Synthetic host/private tests pass; genuine VPN unverified. Reliability drills pass and are reused for the candidate. |
| P2 release preparation | 8 | Not started; follows security and acceptance review. |

Latest independently verified baseline: [image run 40622056177](https://github.com/VardrSec/VardrSec/actions/runs/40622056177),
clean distribution commit `524585cac788d08c529df58b4dd82a20029e7c1b`, collected 2026-10-28.
Raw reports total **1 critical / 197 high / 15 unknown** occurrences (API 0/44,
PostgreSQL 1/61, Proxy 0/2, Runner 0/47, Web 0/43). Two high occurrences have a
published fix: go-jose/v4 in Caddy and Nuclei, fixed in 4.1.6. A third new high
occurrence is Caddy's go-jose/v3 3.0.5, for which upstream reports no fixed v3 release.
The previous 1/194 baseline is historical; its blanket "none fixable" statement no
longer describes current evidence. See the [current security checkpoint](alpha-review-2026-10-28.md).

The integration candidate pins Map #127 (including coverage and boundary features
through #120–#126) and Runner #96, patches Caddy's go-jose/v4, and extends installed
acceptance. These are development candidates pending CI and PR review, not released
artifacts. All strict image gates remain blocked; no residual risk is accepted.

Group tasks only when sharing an acceptance environment helps; keep changes
individually reviewable. Begin tasks 4â€“7 after tasks 1â€“3, then tasks 8â€“9.

## Acceptance discipline

After each task record what completed, what changed, realistic tests/results,
discovered/fixed defects, remaining blockers, unnecessary complexity and the next
task. Unit-test counts alone do not establish readiness. The first alpha needs a
reliable installation â†’ engagement â†’ authorized assessment â†’ findings/report â†’
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

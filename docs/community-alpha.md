# Community Alpha v0.1.0 stabilization plan

Accepted owner direction, 2026-10-27. Prepare the first public Community Alpha;
publication and deployment require a separate reviewed decision. This plan
prioritizes completion of the existing product and supersedes broader roadmap
expansion during alpha stabilization. There is no published alpha yet.

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
| 2 / 5. Networking / VPN | Host/private reachability, representative authorized VPN where available, native/container comparison, safe native fallback and explicit limitations. | Synthetic host/private namespace tests passed; genuine VPN remains unverified. Do not change host routes, firewall or VPN settings automatically. |
| 2 / 6. Reliability | Existing backup/encrypted restore, integrity, restart, successful update, failed update/recovery and actionable instructions. | Existing acceptance drills pass. Reuse them for the candidate; extend architecture only for a demonstrated release blocker. |
| 2 / 7. Platform matrix | Accurate supported versus experimental environments and known OS failures. | Ubuntu Linux is the first release target. Ubuntu 24.04 Linux/amd64 is the initial candidate environment to validate. Windows 11/macOS Docker Desktop require explicit evidence; incomplete cross-platform support alone must not delay a Linux-only alpha. |
| 3 / 8. Release candidate | Immutable tested pins, independently reproducible install artifact/process, compatibility, licensing/redistribution review, release notes, limitations and minimal troubleshooting/recovery docs. | Prepare only after security/acceptance review. Distinguish development artifacts from published releases; prepare for review without publication. |
| 3 / 9. First-user test | One getting-started path, controlled example target/engagement, measured installation-to-assessment time and recorded friction for an unfamiliar researcher. | Requires an actual unfamiliar-user exercise; developer automation alone does not establish this result. |

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

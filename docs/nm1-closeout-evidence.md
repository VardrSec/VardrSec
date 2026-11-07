# NM-1 closeout evidence

Status: NM-1 closed for the original foundation/prototype and early-feasibility
gate, 2026-11-05. Separate closeout reviews found no remaining NM-1 implementation
gap; exact-source conformance and the actual Desktop manual workflow passed.
This is not NM-2 controlled-worker acceptance or Windows release certification.

## Main integration note — 2026-11-06

The status and receipts below retain the historical 2026-11-05 closeout scope.
The original foundations are already merged: Distribution [PR64](https://github.com/VardrSec/VardrSec/pull/64),
Runner [PR104](https://github.com/VardrSec/VardrRunner/pull/104), Map
[PR145](https://github.com/VardrSec/VardrMap/pull/145), and Gate
[PR28](https://github.com/VardrSec/VardrGate/pull/28). The owner subsequently approved
Gate [PR29](https://github.com/VardrSec/VardrGate/pull/29), whose exact `54536ea` head
was merged as `f50f9a2b725ab8a90339d53cbc72c1444601950a` on 2026-11-07 UTC.

This isolated Distribution candidate starts from main
`523c69657928c83bb203f738343da8d96ddb4402` and retains the archival evidence,
four byte-exact sanitized receipts and maintained normalized-semantics comparison.
Runner's strengthened future-version regression was merged in
[PR112](https://github.com/VardrSec/VardrRunner/pull/112) as merge commit
0ce139a392165b93a9a41cdd7d60b2f309a42bc0; its tree matches the CI-selected Runner
source below.

The CI-only source selections now use Runner
`9a27417c45fd5347c4d1d6de3c23c2904fe079a7`, Map main
`aad63c8151789cd9bf56864456b5fdf1fdcfde41` and merged Gate
`f50f9a2b725ab8a90339d53cbc72c1444601950a`. The existing exact-source workflow
must qualify this isolated cohort; historical receipts retain their original pins
and are not proof of the new sources. Production `versions.json`, installed
component selections and Lab's CI selection are unchanged. No NM-2/NM-3 acceptance,
release or deployment approval follows from this closeout.

The original New Moon charter is unchanged. NM-1 establishes common permission
semantics and an early deployment decision. Complete Full/Mapless installation,
managed-worker execution, fresh-host certification and the final network/recovery
matrix belong to their later gates. They are not removed from New Moon.

## Sources under review

- Runner closeout `2cbf3619c2db3682e5de7aa4ed70c8f1b07335c5` passed all nine
  [existing CI jobs](https://github.com/VardrSec/VardrRunner/actions/runs/42119533435).
  Its NM-1 authorization implementation matches the verified `440ebda` source;
  closeout adds proof and instruction clarification.
- Map `76b8d97b0d6c1e3869f11e1cfe834f894f04aa93` passed all seven
  [existing CI jobs](https://github.com/VardrSec/VardrMap/actions/runs/42121753279),
  including PostgreSQL and browser checks. The NM-1 read-only authority projection
  remains unchanged; the additional managed adapter remains inactive.
- Gate `54536ea1d900d0e35adf93b4e026962c4d45d34a` is the corrected cohort used
  by the existing native guarded-execution and Full evidence.
- Distribution `fb1c612` refreshed the CI-only `.github/nm1-sources.json` and
  workflow references to those exact Runner/Map commits and Gate `54536ea`.
  [The exact conformance workflow](https://github.com/VardrSec/VardrSec/actions/runs/42123667450)
  passed its conformance job; the separate distribution-unit and historical Map
  matrix jobs were explicitly skipped in this conformance-only dispatch, not
  reported as passing. Current component CI is recorded separately. Production
  `versions.json` remains unchanged.
- The separate Desktop runtime used lifecycle/fixture source
  `41bca70ea035d58b364ed153be05c9d4f7c8bd3c`, tree
  `e22bfac164dfb014b7fc35b1573129bb58593df1`, and the existing immutable images
  built from distribution `befe929`, Map `aad63c8`, Runner `440ebda` and Gate
  `54536ea`. It did not rebuild or activate the new managed adapter. Full source
  commits/trees, stock-file hashes and all five immutable image IDs are recorded
  in [the sanitized Desktop evidence](evidence/nm1-desktop-feasibility-2026-11-05.json).

Final proof receipts must identify the actual source revisions and changed test
bytes. A base commit or a test count alone is not phase acceptance.

## Charter exit matrix

| Original exit requirement | Existing implementation/evidence | Closeout disposition |
| --- | --- | --- |
| Contract specification and threat model reviewed | Runner ADR 0025, `docs/contracts` schemas/threat model, and Map ADR 0005 define issuer/purpose/origin trust, reviewed authority snapshots, exact plans, offline limits, replay/fences and compatibility. | Reviewed against the current fixtures and implementation. Trust bootstrap/rotation, purpose separation, protected approval keys, conservative replay/unknown holds and offline limits are explicit. No new policy or signing service is required. |
| Reference validator passes positive and negative fixtures | Runner authorization contract, CLI, document and runtime tests cover forged/tampered permission, binding/scope/time, revoked authority, trust/purpose, plan/auxiliary requests, replay and conservative durable state. | Focused proof passed, including direct signed future-schema and envelope-version denials; each denial leaves the contract unconsumed. |
| Map and standalone prototypes issue semantically equivalent contracts | The read-only Map owner-session projection supplies reviewed facts; both origins use the same Runner approval/issuance/validation implementation. [The cohort harness](../tests/nm1_contract_acceptance.py) exercises bounded reuse, single-use consumption and denied API-key approval. | Explicit normalized approval/contract comparisons passed. Only issuer/origin, their bound approval digest, and the required local-offline versus managed-online control distinction may differ. Managed control is fixture-injected, not a production worker. |
| Legacy paths still pass CI | Current Runner and Map CI passed; exact-cohort Linux Full installation/assessment/recovery and actual Desktop manual-job evidence remain separate. Map denies legacy claim/result/control paths for jobs requiring managed contracts. | The focused compatibility checks and exact conformance CI passed. Full installation success does not establish controlled-worker assurance. |
| Explicit migration/rollback | NM-1 adds opt-in journal tables and an unregistered read-only Map adapter. Existing engagements, case hashes, CLI/queue and evidence semantics are preserved. Runner ADR 0025 and Map ADR 0005 describe rollback. | Keep prototype journals and spent IDs/ordinals for audit; disable/remove the opt-in path without deleting state or treating required contracts as legacy permission. NM-2 migrations are a separate review. |
| Windows Desktop feasibility report and approved deployment path/fallbacks | The new [NM-1 Desktop evidence](evidence/nm1-desktop-feasibility-2026-11-05.json) verifies two ordinary queued Gate jobs, ten independently observed requests, trusted API/CLI access, evidence/CA/artifact persistence, resource samples and bounded public/host routes. The earlier [manual feasibility](https://github.com/VardrSec/VardrSec/blob/41bca70ea035d58b364ed153be05c9d4f7c8bd3c/docs/nm3-windows-desktop-feasibility.md) and native fourteen-dispatch proof remain separate. | GO for Windows-first, Docker-preferred, native-compatible development under the original charter. No essential tested HTTP workflow failed. There is no Docker-only commitment. Native fixed-Gate and same-host health access remain demonstrated alternatives; VPN and wider tool/network certification remain unverified. |

## Focused contract proof

The current working-source proof passed 153 Runner authorization/compatibility
cases, with one expected Windows FIFO skip, and 33 Map projection/legacy-denial
cases without skips. The existing cohort harness passed explicit normalized
approval/contract equality across standalone and Map origins, bounded approval
reuse, single-use consumption and excess-count refusal. Its normalized permission
digest is `20c82ec8b7de765b9cec94d3786ef489d005606d5562765dd72ede28a69fb0ec`.
All traffic and authority were synthetic; the cohort proof made zero network
requests. No runtime or production policy changed.

The successful hosted cohort retains its exact
[sources](evidence/nm1-42123667450-sources.json),
[contract equivalence](evidence/nm1-42123667450-contracts.json) and
[fourteen-dispatch guarded execution](evidence/nm1-42123667450-guarded.json)
receipts. Guarded execution covered setup, preflight, resource, verification and
reset; replay produced zero additional requests and results contained no credential
values. Managed control was not exercised by that execution receipt.

These are focused assertion results, not a new whole-project coverage result.
The Map invocation used a protected temporary working directory; its existing
relative coverage configuration reported no data. Full coverage thresholds remain
unchanged. An initial Map collection attempt refused an absolute test-database
URL; the successful run respected the existing disposable-name guard using a
relative `vardrmap_test*` database in that temporary directory.

## Feasibility boundaries

The clean measured Desktop pair completed two distinct reviewed cases through
ordinary explicitly invoked `jobs run --yes`: vulnerable produced two **new
candidates**, fixed produced none. Each made exactly five independently counted
target requests and produced five hashed/redacted evidence records. Claimed case
hashes, legitimate baselines and identity preflight passed. This is existing
manual-workflow compatibility, not controlled managed execution or a fallback
around NM-2 containment.

Stop/start preserved the same CA, completed jobs/cases/scans/evidence and Runner
artifact hashes. No worker started and no extra target request occurred. The
container reached the owned Windows loopback health listener through
`host.docker.internal`; native Windows reached that same listener. A separate
credential-free, non-assessment GET to the owned GitHub repository API verified
public DNS, TCP and hostname-checked TLS 1.3, returning HTTP 200. Resource evidence
is a single post-restart sample and declared bounds, not peak-use certification.

The trial finished with all five owned containers stopped and state retained.
Existing container full states/attachments, volume metadata/labels, project
network records/IDs and image-tag IDs remained exact. A documented engine rule
admitted only observed EMPTY built-in `bridge` identity transitions whose full
configuration was unchanged except ID/creation time. Every comparison was retained;
only that bridge entry advanced in the checkpoint. The cause is unproven. No
daemon setting or network recreation command was used, and the earlier unknown
NM-3 network refusal was not rewritten or waived.

A preliminary scratch attempt omitted the required Runner CLI separator and
stopped before execution. A later preliminary job completed but its scratch log
write failed under the Windows default encoding; its independent counter was lost
on safe shutdown. That job and its five evidence records remain separate and are
excluded from the clean measured pair. Explicit UTF-8 writes were used before
the final pair, which used new engagement/case/job IDs without replaying the old job.
The retained original receipt has stale top-level preliminary failure fields
alongside its final passed status; the sanitized derivative explicitly separates
those scopes.

The original local receipt is preserved at SHA-256
`631004ae3d008137f28682f3de437c4b8581656c68893b12beb33cd5da33445c`;
its private evidence-manifest hash is
`d4e9db8427a882a10560268d45354e6dadd376c66b4707feef08a85c15382974`.
The [structured derivative](evidence/nm1-desktop-feasibility-2026-11-05.json)
contains exact image/source identities and fixed measured outcomes. Private
credentials, raw inspection data/logs and machine-specific paths are not published.

The early charter scope includes toolkit execution, API communication, trust,
persisted artifacts, stop/restart, resource demand and representative routes.
It permits a report of limitations and approved native fallbacks. It does not
permit silently replacing required Docker behavior with native-only support.

Only controlled synthetic loopback/host targets were assessed. Public/customer
security assessments and real VPN test targets were not authorized. The single
GitHub API GET was an explicitly approved benign connectivity check. An unavailable
route must be labelled unverified, with the required later proof retained. Existing
private-target, TLS and tool-capability controls remain enabled; no Docker socket,
privileged container or host credential-store exposure is introduced.

The current native fixed-Gate proof supports that bounded profile only. It does
not establish general native VPN compatibility, raw-packet support or containment
for arbitrary tools. Linux controlled execution and the approved managed worker
remain NM-2 requirements. Full/Mapless installer and final Windows acceptance
remain NM-3/NM-5 requirements.

## Closeout disposition and retained later gates

The original NM-1 exit is satisfied by the reviewed contract/prototype boundary,
negative/equivalence proofs, current compatibility CI, explicit rollback and measured
early Desktop report. This development review is not independent benchmark or
release attestation. Keep the Windows-first/Docker-preferred direction and native
Runner for documented host-access exceptions. Before calling an unavailable or
failed route supported, demonstrate that exact container mode or its native
fallback; do not infer VPN support from host-health access.

VPN/split-DNS/reconnect, arbitrary private targets, broader toolkit coverage,
fresh Full/Mapless installation and complete Windows recovery remain accepted
NM-3/NM-5 requirements. They are unverified, not accepted as passes or removed.
The managed worker and its complete failure paths remain NM-2 gates. Earlier
passing, refused and preliminary receipts remain separate; the stopped Windows
recovery extension is not NM-1 proof.

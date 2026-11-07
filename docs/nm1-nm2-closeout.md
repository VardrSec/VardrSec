# NM-1/NM-2 closeout control record

Owner instruction, 2026-11-05: close the original NM-1 and NM-2 gaps before
continuing NM-3. This changes implementation priority, not the accepted roadmap
or any safety gate. NM-1's original foundation/prototype and early-feasibility
exit closed on 2026-11-05; [the reviewed evidence](nm1-closeout-evidence.md)
records its exact scope. NM-2 remains open and NM-3 development remains paused.

## Preserved NM-3 baseline

| Repository | Preserved branch | Recorded head |
| --- | --- | --- |
| Runner | `codex/nm3-community-baseline` | `b8ecb5b378365c51099d5f19b809c9cbb908a094` |
| Distribution | `codex/nm3-community-full-verification` | `41bca70ea035d58b364ed153be05c9d4f7c8bd3c` |

The [passing installed Full receipts](nm3-community-full-verification.md),
[Windows feasibility and recovery-refusal boundaries](nm3-windows-desktop-feasibility.md),
workspace/export implementation and retained test fixtures remain available.
The new work uses separate `codex/nm1-nm2-closeout` branches. No NM-3 interface,
installer choice, recon profile or export capability is being expanded.

## Work order and acceptance

1. Close NM-1 using current-source conformance, issuer equivalence,
   compatibility/rollback review and an actual early Docker Desktop
   Runner/Gate feasibility report. Record unsupported routes and the deployment
   decision explicitly. See [the evidence matrix](nm1-closeout-evidence.md).
2. Reuse NM-2's existing grants, budgets, ownership, leases and durable receipts.
   Add bounded authenticated adapters and the explicitly enabled worker only
   after reviewing the missing containment boundary. Keep ordinary startup inert.
3. Exercise the integrated worker's complete original failure-path criteria on
   supported Linux and actual Windows Docker Desktop before closing NM-2.
4. Resume NM-3 implementation only after both phase exits have evidence and a
   recorded closeout disposition.

Research is separate from activation. A proposed lifecycle mechanism, a mock,
a passing happy path or an approval to develop is not acceptance. A necessary
privilege/deployment deviation must have a concrete threat model and explicit
authorization before it is enabled. Previously blocked adversarial experiments
remain stopped; no alternate worker or environment is used to bypass that block.

The [native Windows development baseline](evidence/nm2-native-windows-development-baseline-2026-11-05.json)
records 20 passing real Gate/TLS fallback checks, including 14 detailed timing and
traffic receipts. It used development working trees; final frozen-cohort CI and
platform acceptance remain separate. A [prepared-worker operator command](nm2-worker-operator.md)
and the [coupled test plan](nm2-worker-acceptance-plan.md) are now implemented
candidates, not accepted deployments.

The [frozen two-job Desktop slice](nm2-worker-acceptance-evidence.md) has now
passed through one explicitly admitted worker, including exact completion/release
history and preserved-resource checks. Its Linux counterpart and the integrated
failure matrix remain separate gates. Healthy continuation alone does not close
NM-2 or authorize NM-3 to resume.

The owner subsequently clarified that normal enabled background operation must
remain available until explicitly stopped, with the 60-second idle and 32-job
controls optional. [The persistent implementation contract](nm2-persistent-worker-contract.md)
separates that availability from fresh per-job execution authority. The finite
candidate is retained as regression evidence; it is not an accepted substitute.

The default-disabled v3 candidate has additive Map/Runner/Host protocol code,
original-key recovery tests and [compiler-only evidence](evidence/nm2-persistent-compiler-2026-11-06.json).
The owner approved persistent STOP reporting for isolated testing on 2026-11-06,
retaining its disclosed trusted-host risk. Component CI and selected physical
results are distinct from phase acceptance. The [current platform evidence](acceptance.md#linux-availability-and-later-held-desktop-idle-2026-11-06)
now includes separate verified Linux and Desktop default-unlimited availability
and optional count-one slices. Their exact source cohorts differ; no result is
transferred to another image or platform. Held attempts and stopped resources
remain retained. No component pass closes NM-2 or resumes NM-3.

## Current NM-2 exit disposition, 2026-11-07

| Requirement | Verified scope | Remaining gate |
| --- | --- | --- |
| Explicit enablement and persistent availability | Separate Linux and Desktop slices observed 70 idle seconds without target traffic, then 35 individually authorized jobs and explicit stop/reconciliation. Both optional limits were unset. | These finite observations do not close the complete failure or containment matrix. Default startup stays disabled and each job still requires fresh finite authority. |
| Optional finite controls | Separate Linux/Desktop count-one slices passed without charging the unissued job. Dedicated Linux/Desktop idle slices now passed one reviewed five-GET job, native124 without operator stop, zero local holds and six stopped containers. See the [current ledger](acceptance.md#accepted-optional-idle-and-zero-issued-job-slices-2026-11-06). | These selected finite controls do not define normal persistent availability or close the cancellation/containment matrix. Earlier held idle receipts remain retained with their original scope and unknown causes. |
| First and subsequent worker launch | Windows Docker Desktop and Ubuntu passed explicit ordinal-one startup from a clear journal and ordinal-two startup after exact predecessor exit. The zero-job and one completed-job scenarios reused the original Runner state volume and retained both exited workers. The completed-job scenario verified fixed evidence, Map retirement, and the original Runner's reconciliation and offline audit. See the [installed startup receipts](nm2-worker-acceptance-evidence.md#installed-first-and-subsequent-startup-2026-11-07). | Ambiguous and preclaim recovery, including physical successor validation of those paths, remain open. |
| Per-job cancellation, permissions and budgets | Map stop-work and Runner local emergency stop passed on Windows Docker Desktop and Ubuntu. An approved second job in a stopped engagement stayed unclaimed and uncharged. An approved job with a missing local grant remained unissued, with zero requests, charges, and original Runner claim associations through a subsequent launch. Revoking the active synthetic target grant stopped the original job on both platforms and preserved the peer grant and original Runner API enrollment. Natural expiry before claim kept the approved job unissued and uncharged through the successor on both platforms. Active expiry stopped the original job within the measured grant-bound cutoff and retained its charges before the same-volume successor. Allocated duration exhaustion refused a second approved job on both platforms, preserving one target spent, 30 seconds allocated and zero reserved slots through reconciliation. See the [installed evidence](nm2-worker-acceptance-evidence.md#installed-first-and-subsequent-startup-2026-11-07). | The remaining Strict denials and full retained partial evidence matrix have separate gates. |
| Failure and containment behavior | Preserve existing conservative holds, exact ownership, durable send fences and independent exit checks. | Disconnect, crash/stop, duplicate/lost reply and the full bootstrap/channel/owner-loss/credential-isolation/pressure/clock matrix remain open. Previously blocked adversarial operations remain stopped. |

Gate's guarded cancellation evidence fix is merged on its own. The
merge tree matches the tested Gate development commit used in the installed
cohorts above. Component pins, releases and deployments have separate approval
and evidence. [Gate PR #30](https://github.com/VardrSec/VardrGate/pull/30)

Map's unregistered managed queue adapters also merged through the signed
replacement PR. Vercel and Railway reported the exact Map merge commit
`921a137c566df31a75b44f786a76b9133c0fd777` in production. The frontend
returned HTTP 200, and Railway reported readiness with a healthy database
and current migrations. This hosted check covers the dormant adapters on
main. The coupled development receipts still identify their separate Map
source. [Map PR #150](https://github.com/VardrSec/VardrMap/pull/150)

The Map duration diagnostic has a separate development commit,
`40bf4e37076d6a85648f817dd8b6bc69104bd863`. Its component regression exercises
the exact duration refusal and rollback while preserving the generic
client response. Windows Docker Desktop and Ubuntu verified the installed
duration refusal and original Runner reconciliation. The paired
represented-origin refusal also preserved charges and capacity.
Shared concurrency exhaustion passed on both platforms. The original
reservation stayed held through the refused claim and contender retirement.
Only the original job's finish released it. Target and duration charges
remained intact.
[Installed duration evidence](nm2-worker-acceptance-evidence.md#allocated-duration-exhaustion)
[Development CI](https://github.com/VardrSec/VardrMap/actions/runs/42397162144)
[Installed target allowance evidence](nm2-worker-acceptance-evidence.md#represented-origin-allowance-exhaustion)
[Installed concurrency evidence](nm2-worker-acceptance-evidence.md#shared-engagement-concurrency-exhaustion)

Windows Docker Desktop and Ubuntu refused stale signed Strict registration
after an authority change. Fresh signed registration for the same job passed
with no execution or charges.
[Installed Strict evidence](nm2-worker-acceptance-evidence.md#strict-approval-after-an-authority-change)

Windows Docker Desktop and Ubuntu passed ordinary stopped-predecessor
recovery. A successor was refused before exact exit reporting and launched
on the same state volume after original Runner reconciliation. The first
two held receipts remain in the record.
[Installed recovery evidence](nm2-worker-acceptance-evidence.md#stopped-predecessor-recovery-after-exact-exit-reporting)

The open NM-2 exit requirements stay in NM-2. NM-3's independent
Runner, Full/Mapless, Docker, Windows and cross-platform objectives remain required
and preserved. NM-4 testing intelligence and NM-5 validation/release keep their
original sequence. None of this evidence authorizes release, deployment or a
component-pin change.

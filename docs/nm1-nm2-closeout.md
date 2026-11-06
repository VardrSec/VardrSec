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

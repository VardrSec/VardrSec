# ADR 0004: Observe a Created worker without fabricating runtime identity

Status: Implementation candidate with passing synthetic regressions. Operator
lifecycle support and physical platform acceptance remain open.

`LocalDocker.capture_created` reads one exact full CID from the explicitly
selected local daemon. It returns a frozen, direct-only `ObservedCreated` with
daemon/CID/image/project/layout. It contains no started timestamp, owner nonce,
admission, stop proof or execution authority. Serialized fields cannot be loaded
as an observation. Existing registration/exit methods continue requiring their
original distinct runtime/exit types.

The existing static profile conjunction is shared by two production callers:
the retained `_bound` check and the new `_created` check. Existing mount, tmpfs,
state, volume-source, readiness, incarnation rechecks and deadlines retain their
order and predicates. Running/exit observation and the closed diagnostics format
are unchanged. The new path uses the existing30-second observation bound, two
complete Created snapshots, and the same expected daemon before and after.
It reads no readiness file and invokes no create/start/exec/wait/stop command.

Created state is an observation; it cannot prove that a start was never sent.
An eventual lifecycle caller must independently validate its durable intent,
replica numbers, network/resource inventory, source ownership and all predecessor
retirement/reconciliation evidence before an exact-CID start. Unknown start,
registration or publication remains held; a later404 proves no absence.

This patch adds no operator command, lifecycle state machine, Map API, service,
privilege or automatic action. The proposed next-enable operation and genuine
zero-issued-job acceptance remain separate open NM-2 gates. Runner's new explicit
`worker-state` inspection contract is a prerequisite for the later wrapper; it is
not called or reimplemented here. See [ADR0001](0001-component-responsibilities.md)
and [Runner's inspection amendment](https://github.com/VardrSec/VardrRunner/blob/09008e5d9c3edf619e55eeacdfd9ea1db31aba89/docs/adr/0043-proposed-linux-worker-lifecycle-owner.md#offline-existing-state-inspection-amendment).

The version-pinned Compose source routes no-start through Create, whose
reconciliation can still start exceptional existing states. Therefore flags alone
are insufficient; safe wrapper inventory guards require separate review.
[Compose5.6.1 up](https://github.com/docker/compose/blob/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/cmd/compose/up.go),
[reconciliation](https://github.com/docker/compose/blob/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/pkg/compose/reconcile.go).

Moby's state model separately retains start errors and zero start time. This
supports the conservative no-inference rule; it does not certify the selected
deployment's engine version or substitute for a fresh normal fixture.
[Moby state model](https://github.com/moby/moby/blob/v28.0.0/container/state.go).

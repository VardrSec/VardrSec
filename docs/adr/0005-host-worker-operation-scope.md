# ADR 0005: Keep worker enablement under one live installation operation

Status: Private implementation candidate. Normal full-module validation and
integration remain required. This does not implement next-enable or close NM-2.

The existing host installation lock also serializes ordinary installation/update
operations. Enablement previously released it between initial checks, owner
authentication/capture, registration and public admission publication. Those
gaps prevent a future lifecycle wrapper from owning one complete operation.

`HostRecords.operation()` owns the existing lock and yields one private frozen
capability. It is bound to the exact records instance, installation/private-root
values and owning thread. Borrowing requires that exact currently live object;
copies, foreign instances, changed paths and different threads fail before
custody or secret I/O. The owning scope invalidates it before releasing the lock,
including on failure. There is no serialized token, CLI input, lock-bypass boolean
or new global owner registry. This internal capability is not an OS sandbox.

The scope checks custody at owning and borrowed entry. It translates lock-entry,
entry-custody and owned lock-exit failures only. Its body preserves original
exception objects when lock release succeeds. The token is invalidated before
the single explicit close; a close failure remains fixed `HostRefused`, including
when the body also failed. It never leaves a usable token or retries release.
`locked()` keeps its legacy whole-body error translation and token-free default
call shape. Registration borrows only when an actual operation was supplied;
ordinary direct registration acquires its existing single lock. Default v3
delegation omits the new keyword. Other commands retain their existing spans.

Enable now owns one scope through its existing checks, owner authentication,
capture, one registration attempt, record reread, recapture/custody and exclusive
public file publication. Its original translated precheck/publication spans
borrow that scope; initial capture still preserves `RuntimeRefused` checkpoints
and local-I/O diagnostics. Request order, wire records, permissions and all
independent observation/HTTP deadlines remain unchanged. No worker is started.

Process death releases the OS lock; it does not prove that an external mutation
was never sent. A future lifecycle increment still needs protected monotonic
durable create/start/registration/publication intents, unknown-state recovery,
predecessor physical exit, positive Map retirement and component-owned original
Runner reconciliation. Missing files, an old prepared record or a 404 cannot
substitute for those facts. No automatic replay or re-enable is introduced here.

Pure tests execute AST-extracted actual definitions with fixed fake I/O and
permanent runtime/provider denials. They cover ownership/lifetime/thread checks,
one-lock ordering, exception release and original diagnostic identity. They do
not replace the normal full Distribution suite against actual imported modules,
or physical Windows/Linux lifecycle acceptance. Background startup remains off.

Enable preparation and the already-owned body have separate private entry points.
`_enable_setup(args)` returns only its existing observer, client, public path,
reviewed trust bytes and admission options. `_enable_owned(args, records,
operation, setup)` requires the exact live operation before unpacking that setup
or performing body effects. It reuses the same records and existing borrowed
critical sections; it constructs neither records nor another operation. The
installation-state checks use the installation already bound to that capability.
Public enable retains its original setup, custody, authentication, capture,
registration and publication order, and constructs its reply after lock release.
This factoring does not wire durable intents, registration/publication fences,
create/start or a next-enable command. Those remain independently gated.

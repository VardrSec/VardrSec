# Represented-target budget recovery increment

This extends the legacy ownership harness at `6234b45b25cb0440dfc153f3e84c9a19b77b5c33`
(previous successful run 41976514474). Distribution source remains bound to
`4998e5dfd1554beec88690880c4ac269d4f12240`; production pins are unchanged.
The disposable fixture still uses Map `9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045`,
Runner `602a5423dcede0e37dacad52aab3bdad900c9021`, and unchanged Gate
`7f82e499ec407eba072e129e3f3b94f1a4eabe94`.

The supported test-case, policy, job and controlled-claim APIs create one stored
fixed Gate case describing two represented HTTPS origins: api.example.test and
setup.example.test. It uses an anonymous static-header identity with empty values;
there are no target credentials, trust enrollments or grant records. The case is
never dispatched. Only localhost Map API requests occur. Neither Gate, a scanner,
a queue worker nor managed Docker execution is started.

The target allowance is two and the claim charges two represented-origin attempts.
The concurrency limit is two with one reserved slot, leaving capacity for a second
pending job. Its mismatched case hash must produce the specific target-binding
409, and its matching claim must produce the specific exhausted-target 409. A
generic 409, including concurrency exhaustion, cannot satisfy these assertions.
Both refused transactions must leave execution ownership, duration allocation,
target accounting and pending-job state unchanged before and after restore.

Existing real version-4 bundled CLI backup/restore, fingerprint, principal/token
hash, wrong-principal, expired-lease and source-preservation checks are reused.
Only the synthetic fixture changes; there are no SQL writes, counter resets,
policy resets, deletion, extra tool installs or new trust mechanism. The original
source and restored synthetic volumes, backups and CA remain retained. Normal
helper-container cleanup and the bundle's retained empty lock file are unchanged.

Local verification: 14 focused offline tests passed, including altered accounting,
exact target refusal reasons, endpoint selection and existing isolation guards;
Python compilation and diff checks passed. Installed evidence requires the new
branch-only hosted workflow, not attribution of the earlier run to this increment.
Only a fixed sanitized receipt is uploaded, visible to repository readers for
seven days. Raw API responses and private logs remain in the disposable VM.

Open: managed enrollment/approval/grants, cross-user isolation, actual execution,
final NM-3 cohort, Windows, Mapless-to-Full no-loss, hard-crash recovery, SQLite
snapshot and journal path race. The watchdog-hang gate remains failed and workers
remain disabled. This narrower check is represented-origin attempt accounting,
not measured target requests or execution authorization.

# NM-2 integrated worker evidence

NM-2 remains open. NM-1's foundation exit is closed; NM-3 remains preserved and
paused. These receipts establish specific development slices, not release or
complete worker acceptance. The [acceptance plan](nm2-worker-acceptance-plan.md)
and [closeout control record](nm1-nm2-closeout.md) retain the remaining gates.

## Installed first and subsequent startup (2026-11-07)

The explicit `worker launch` command passed the zero-issued-job sequence
on Docker Desktop for Windows and Ubuntu 24.04 using distribution
`12983d7e793d4d80f96088dab958d6ab708e1724`, Runner
`2176c8e7ff9361fc9cdebdbaa2fc1ac9b56da15d`, and Compose 5.6.1.
Each test admitted ordinal one from a clear initialized journal, retired
that worker, and admitted ordinal two using the exact predecessor. Both
tests retained the original Runner state volume and the stopped containers.

- The Ubuntu sanitized receipt SHA-256 is
  `5ae6e9692bacd43e43438ed916a1c01b5f607600eb981fa14a2ca269c4b7f3a6`.
  [Installed Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42374672703)
- The Windows private receipt SHA-256 is
  `51ba4dc81f0fc8081e431e4d5c1f897768b628a4866352af70a90a1a4c98ddac`.
  The operator profile hashes matched before and after. Two earlier Desktop
  runs held before writing a startup intent. The corrected image inspection
  accepts the omitted Volumes key and still refuses a nonempty declaration.

The completed-job successor sequence passed on the same platforms using
distribution `08c12cf648fdb441ff7097ac9210cd8b243946da` and the same component
sources. One approved synthetic job made five target requests and produced
fixed evidence. The first worker retired, and Runner's original
reconciliation and independent offline audit agreed on Map's retirement
receipt. The next launch used that audit and retained the state volume.

- The Ubuntu sanitized receipt SHA-256 is
  `3d5eb412338ad4b5fdb2c7c27fa03b777b9f3de4d65d5f25c4d4d07c13f0897d`.
  [Installed Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42376295944)

- The Windows private receipt SHA-256 is
  `2479120f61329a1d2bdc185d76f21b2a1a282102ae08ccd147e7045f3b17c56b`.
  Both workers stopped and were retained. The operator profile hashes matched
  before and after.

Active cancellation and containment acceptance have separate requirements.

The first Windows stop-work fixture at `9778e18efe76d624b6395fc1c32b01ee5e97fc10`
reported the exact exited runtime to Map and retained the installation. The test
held because it used the time of the later target observation as the exit time.
Its private receipt SHA-256 is
`2d537bd7e31e03f815dd1d46ecf76a329970b89552ec26400cd07409b3b8d077`.
The corrected fixture measures Docker's exit event against the target's clock,
checks for clock disagreement, and verifies Map's `cancel_requested` state
while the exact contract still holds capacity. This earlier run receives no
active cancellation or successor credit.

## Verified Desktop development slices (2026-11-06)

The [default-unlimited availability slice](evidence/nm2-desktop-persistent-availability-2026-11-06.json)
passed on actual Docker Desktop with Distribution `dc473835`, Map `52e7b5b`,
Runner `e8cdec3` and Gate `d80d473`: 70.0003674 seconds of ready idle with zero
target traffic, 35 separately authorized jobs, 175 target requests and evidence
records, explicit operator stop, host/original-key reconciliation and zero local
holds. All six owned containers stopped and were retained. The strict offline
reader independently checked the original receipt and supplied inventories.

The separate [optional count-one slice](evidence/nm2-desktop-count-control-2026-11-06.json)
passed for the same source cohort: one original job/five requests, native clean
exit without operator stop, and a still-eligible second job left unissued with
zero target/duration charge. It has no unlimited-availability or idle-timeout
credit. Both guards preserved the approved personal Runner files and unrelated
resources; the existing rule admitted only empty built-in bridge identity churn,
whose cause remains unknown. Digests correlate observations, not attestation.

[Linux count run 42284035325](https://github.com/VardrSec/VardrSec/actions/runs/42284035325)
remained [held at local recapture](evidence/nm2-ubuntu-count-local-capture-held-2026-11-06.json),
with no completed count proof. Both compatibility jobs passed. The reviewed
recapture diagnostic correction passed the [complete guarded unit suite](evidence/nm2-distribution-local-capture-units-2026-11-06.json):
502 tests, including 18 skips, zero failures/errors and zero forbidden attempts.
It changes fixed diagnostics only; the actual held cause remains unknown.

Linux availability/count, actual optional native-idle 124, genuine zero-issued-job
stop, same-installation next enablement and the integrated failure/containment
matrix remain open. The current CLI can admit an already prepared worker but
has no complete supported stop/retire/prepare-next/enable flow. This stays an
NM-2 usability gate. No new API, service or infrastructure has been accepted.

## Earlier component and held evidence

The integrated fixture corrections passed the [complete guarded Distribution unit suite](evidence/nm2-distribution-guarded-units-2026-11-06.json): 447 tests run, zero failures/errors and 18 skip entries, with 181 sources, staged index, HEAD and operator files unchanged. All five helper interpreters retained guards and no prohibited operation was attempted. The earlier controller hold remains separate; no physical acceptance is inferred.

The [third Ubuntu availability attempt](evidence/nm2-linux-persistent-stop-held-2026-11-06.json) remained held in [run 42255272157](https://github.com/VardrSec/VardrSec/actions/runs/42255272157), with `persistent_operator_stop / fixture_stage_failed`. That stage also covered the following independent exit observation, so the exact failure is unknown. Both compatibility jobs passed. No completed 35-job proof was exported and no acceptance credit is assigned. Separate fixed stages now distinguish the independent observer and its exit-binding comparison.

A fresh [one-job Docker Desktop diagnostic](evidence/nm2-desktop-one-job-stop-diagnostic-2026-11-06.json) completed ordinary durable release, five target requests, zero local holds, explicit stop/disable acknowledgement and independent exact-incarnation exit observation. All six owned containers stopped and were retained. Operator files stayed unchanged; the resource guard admitted only an equivalent empty built-in bridge identity change. It used three explicitly selected private subnets after default Docker allocation refused, retaining all older fixtures. This diagnostic establishes neither the prior failure cause nor the 70-second/35-job, finite-control or containment gates.

The [optional-idle component correction](evidence/nm2-persistent-idle-component-2026-11-06.json) at Runner `e8cdec333af0ed721504f3857369a76c8a8a4e06` passed 2,928 native tests with 67 unchanged skips and 95.8048% exact coverage. All nine [cross-platform CI jobs](https://github.com/VardrSec/VardrRunner/actions/runs/42270140956) passed. Same-source compiler checks and the frozen image build passed; actual native exit 124 and the finite-control platform gates remain unverified.

The [second Ubuntu attempt](evidence/nm2-linux-persistent-unobserved-2026-11-06.json)
remained held with unavailable/invalid inner evidence in
[run 42189571582](https://github.com/VardrSec/VardrSec/actions/runs/42189571582).
A separately reproduced hosted entry-point import gap prevented the new failure
diagnostic and success projector from loading root helpers when launched from
`tests/`; unit discovery had supplied that path implicitly. The fix selects the
exact reviewed root. Both real projections now pass isolated subprocess tests
from an external directory, with network and subprocess execution denied inside
the projector. The complete check passed 409 tests with 18 explicit skips and
173 unchanged source files. The underlying registration refusal is not proven.

The [second Desktop attempt](evidence/nm2-desktop-persistent-unobserved-2026-11-06.json)
has no final receipt and remains unobserved. Its four core services resumed when
Docker Desktop was restored; a separate exact-ID controller cleanup stopped all
six owned containers and retained their data, with unrelated resources unchanged.
No existing runtime was resumed or replayed. A manual read-only status probe was
recorded separately because it takes the fixture polling lock; no further manual
status probes are used during acceptance. The interruption cause is unknown.

The [first persistent Desktop attempt](evidence/nm2-desktop-persistent-held-2026-11-06.json)
held at `persistent_job_release` with `persistent_status_refused`. Default-disabled
and Strict out-of-scope checks passed, but the 35-job availability slice did not
complete. All six owned containers stopped and were retained; the independently
rechecked inventories show existing resources unchanged with no admitted diffs.
The original failed status payload was not retained, so its exact cause remains
unknown. A separately reproduced read-only status-shape mismatch is not evidence
of that run's cause. No held result is promoted or replayed.

The matching [Ubuntu attempt](evidence/nm2-linux-persistent-held-2026-11-06.json)
also held, separately, at `enable_registration / host_refused` in
[run 42185842051](https://github.com/VardrSec/VardrSec/actions/runs/42185842051).
Its public receipt confirms the four exact sources, matching persistent images
and schema selection, but does not establish registration or availability.
Both compatibility jobs passed. No discarded VM logs are used to infer a cause.

A pure producer-to-reader regression separately reproduced the product's valid
`running / held / availability_unconfirmed` response with all four remote lookup
fields null. The fixture now permits only that exact shape to keep polling within
its existing 45-second deadline. It cannot count as readiness or approve another
job. Partial-null metadata, physical failures and unsafe local control states
remain refusals; fixed refusal checkpoints contain no raw output or exception text.

Map `52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c` passed all seven
[CI jobs](https://github.com/VardrSec/VardrMap/actions/runs/42184978261): its ordinary
backend run passed 1,900 tests with 156 explicit skips; its PostgreSQL backend
passed 2,034 tests with 22 explicit skips after 120 specialized checks passed.
The actual Map/Runner/Gate integration and retained verdict/source artifact also
passed. Earlier failed and cancelled runs remain historical failures; the prior
masked transport failure did not recur and its cause is not established.

Runner `89f92b50145c06411574f7ba2c32002591f6b915` passed its complete native
Windows suite: 2,913 passed, 67 explicit skips, 95.7998% statement coverage,
with the existing 95% gate unchanged and 215 source files unchanged. Ruff, format,
mypy and Bandit passed. All nine [cross-platform CI jobs](https://github.com/VardrSec/VardrRunner/actions/runs/42176914807)
passed, including Windows, macOS and Ubuntu Python 3.10–3.14.

The [control-fix compiler receipt](evidence/nm2-persistent-control-compiler-2026-11-06.json)
records exact finite/v3 compiler builds after review found a refresh precheck
outside the failure latch and an unbounded clean-idle-EOF wait. Thread regressions
failed on the old callback path and passed after its small correction. Native
scalar units passed for an immutable EOF cleanup deadline without changing
healthy persistent idle. This is source/compiler evidence, not physical
disconnect, owner-loss or containment acceptance.

Distribution `3309b57` passed 390 local unit tests with 18 explicit skips and an
unchanged 169-file manifest. Its [Windows/Ubuntu Python 3.10 compatibility run](https://github.com/VardrSec/VardrSec/actions/runs/42183736936)
also passed. Physical and installation jobs were explicitly disabled in that run.
Separate pure projections retain Linux and Windows host identities. The Desktop
entry additionally binds full inventory hashes, canonical unchanged old rows,
six new stopped service/image identities and explicit semantic bridge exceptions.
It never relabels Windows data to pass the Linux-only guard.
The final Desktop projection candidate passed 394 local unit tests with 18
explicit skips; all 169 source files remained unchanged during that check.

The owner requires persistent availability until explicit operator stop, with
finite idle/job limits optional. The [versioned contract](nm2-persistent-worker-contract.md)
retains fresh authorization and finite execution authority for every job. The
candidate is inactive; finite v1/v2 passes do not establish this requirement.

The [frozen compiler receipt](evidence/nm2-persistent-compiler-2026-11-06.json)
records network-disabled finite and persistent compiler-stage builds from Runner
`5737d317f44a35d5f47ce2dfdd6f7cfb817f7a5d`. Both compiled and passed their
native protocol-state units. These exercise modeled idle/job/counter boundaries;
they do not measure real persistent uptime, run PID1 bootstrap or establish
containment. The 96 prior containers, 76 tag references and 72 volumes were
unchanged. Of 41 prior networks, one empty built-in bridge changed identity with
equivalent checked semantic fields and empty membership; its cause is unknown.

Host receipt review reproduced acceptance of boolean/float nested fences under
Python equality. Commit `4c5f65f7d80d5ae77fb081a8790a4e4dd7df0200` switches the
binding comparison to canonical bytes; recomputed v3 history/release/retirement
hashes cannot hide those malformed values. All 67 focused Host tests passed.
The separately committed diagnostic consumers passed 65 focused checks and
export only fixed capture phase/reason values. Raw subprocess output stays private.

Distribution `853df43b5509202fc9bc18b76a6f5901bad261eb` passed the
[Windows/Ubuntu Python 3.10 compatibility run](https://github.com/VardrSec/VardrSec/actions/runs/42172087330):
372 tests per platform, with 6 Windows and 2 Ubuntu explicit skips. This includes
the corrected canonical temporary-directory bootstrap fixture. Installation,
coupled Docker execution, certificate renewal and update jobs were explicitly
skipped by the unit-only dispatch; their acceptance is not inferred.

Runner journal/original-key recovery tests retain exact admission, selected job,
missing ACKs and artifact bytes. A later job's physical retirement cannot replace
an earlier job's completion. These are component checks, separate from the full
coverage gate, PostgreSQL concurrency and actual Linux/Desktop acceptance.

## Actual Docker Desktop: two healthy jobs

The [sanitized evidence](evidence/nm2-desktop-healthy-sequence-2026-11-05.json)
records a fresh Windows Docker Desktop project, Linux containers, normal trusted
HTTPS/local owner/CSRF, least-privilege database startup and schema
`0040runtimesequence`. Execution used this exact frozen cohort:

| Component | Commit |
| --- | --- |
| Distribution | `3fd573cedd540490318b8aaf3c90c11f1357f597` |
| Map | `16c695ad8f28429584ad608a6fce9696eb23ad29` |
| Runner | `ac129530dfd4965a42de04c0ebf0f46c64979734` |
| Gate | `54536ea1d900d0e35adf93b4e026962c4d45d34a` |

Measured results:

- Normal startup started only the four core services. Unauthenticated access,
  missing CSRF and Strict out-of-scope approval were refused before target work.
- Two distinct approved jobs completed through one explicitly enabled physical
  worker with `max_attempts=2`: five observed requests and five redacted evidence
  rows per job. Both assessments were conclusive and matched their reviewed case.
- Both immutable completion and idle-release receipts were validated. Release 1
  preceded binding 2; both attempts retained distinct artifact, result,
  completion, native-DONE and release hashes. Final sequence was 2, idle.
- Both capacity reservations were released. Two spent targets and 60 allocated
  seconds remained charged. Direct Docker observation recorded worker exit 0.
- All six new containers were stopped and retained. The guard preserved the 68
  prior containers, 68 images/tags, 29 networks and 52 volumes. Its only admitted
  difference was an empty built-in bridge's ID change, with equivalent selected
  semantic fields and empty membership before/after. Its cause is unknown.

The retained raw receipt SHA-256 is
`2e7c96fda5d80936b401f4eeb1673ef112235f8b557ce6939bc51c3ced322a88`.
The public derivative omits host paths, credentials and private logs; it retains
exact source/image identities, source inventories, build-receipt hashes and
measured counts/hashes. The frozen shared sequence validator rechecked the
retained receipt, and the original inventory classifier rechecked its guard.
Windows host metadata was preserved as Windows; the Linux-only hosted entry
guard was not substituted for a Desktop result.

The same cohort ran in the separate
[Linux development check](https://github.com/VardrSec/VardrSec/actions/runs/42160265308).
Its coupled verdict is **held**, at worker enablement with the fixed public reason
`fixture_command_failed`. The discarded private VM logs are not recoverable
evidence; no inner cause or Linux acceptance is inferred. Focused safe diagnostics
are required before the next candidate run. This run's Ubuntu Python 3.10 compatibility job
found that the evidence helper rejected nine-digit Docker timestamps; Windows
compatibility was cancelled by that matrix failure. A narrow subsequent fix
validates calendar fields separately while retaining all nanoseconds for ordering;
21 focused helper tests pass locally, and both Windows/Ubuntu Python 3.10 jobs in
the [fix-only CI run](https://github.com/VardrSec/VardrSec/actions/runs/42160711644)
passed. That unit-only run did not repeat physical worker acceptance.
The earlier Linux one-attempt run remains held; neither
its successfully built images nor passing compatibility jobs establish worker
acceptance.

## Component verification

Runner's exact `ac12953` source passed 2,734 tests with 66 explicit skips and
95.5891% measured statement coverage; its existing 95% gate was unchanged.
Ruff, mypy and Bandit passed. The native test guard recorded no change to its
201 selected source/config/test files. All nine
[Runner CI jobs](https://github.com/VardrSec/VardrRunner/actions/runs/42156359113)
passed, including Linux, Windows and macOS.

Map's final persisted-proof strictness cases passed 40 focused checks. Six
persisted JSON type corruptions were reproduced before the three narrow guards
were fixed. Its [full CI](https://github.com/VardrSec/VardrMap/actions/runs/42159647822)
passed all seven jobs on the final source. PostgreSQL ran 106 migration/concurrency
checks and 1,984 backend tests with 22 explicit skips, followed by the actual
Map/Runner/Gate integration. The earlier PostgreSQL run exposed a test oracle
waiting at the wrong lock and a fixture-variable shadow; their test-only fixes
retain exact backend/blocker and budget assertions. A collected or skipped
PostgreSQL test is not recorded as a pass.

## Actual Docker Desktop: bootstrap refusal

The [bootstrap evidence](evidence/nm2-desktop-bootstrap-2026-11-05.json)
records two fresh target-free containers using the same frozen worker image and
owner executable as the healthy sequence. Distribution helper source was frozen
at `5a6ec7ac6d55341b700c1f63d7e73f049170787f`, with 157 files checked against
their Git blobs before execution.

The ordinary initial-user and missing-SETPCAP misconfigurations both exited 125
before readiness. A successful direct archive read observed the empty original
readiness directory, and the copied executable matched the reviewed binary hash.
The profiles had no network, credentials, admission, data mounts, command override
or extra privilege. Both containers remain stopped. All 80 previous containers,
68 images/tags, 35 networks and 62 volumes were guarded; only the explicitly
classified empty built-in bridge ID change was admitted. Descendant absence was
not independently observed and is not inferred from PID 0.

An earlier attempt refused in metadata preflight because Docker omitted unset
image configuration keys. The corrected lookup handles missing optional fields
without weakening their accepted values. That refusal remains retained and is
not rewritten as a bootstrap result.

## Cancellation work in progress

The first local emergency-stop fixture was held before sending its stop command:
its test expected a dashed Run ID rather than Journal's 32 lower-case hexadecimal
identifier. All six fixture containers were stopped and retained, with the same
narrow inventory classification. The corrected fixture has regression coverage;
this attempt establishes no cancellation pass.

Review also identified a product gap: guarded Gate cancellation could exit before
publishing a partial result, and Runner's stopped path did not retain such a result
through its non-success publication lane. Focused Gate and Runner changes are in
development. They must preserve confirmed-stop proof, existing deadlines and
unknown holds; a partial file never authorizes healthy reuse or a new claim.

The distribution's two-job candidate passed 308 unit methods: 290 passed and 18
explicitly skipped. Its real Map/Runner approval preparation regression passed
both cases. No test result here establishes physical failure-path acceptance.

## Open phase gates

The integrated cancellation, emergency stop, partial evidence, grant
expiry/revocation, budgets, disconnect, crash/restart, duplicate/lost-reply and
reconciliation matrix remains incomplete on both required platforms. Actual
native Windows fallback has separate retained evidence; it does not substitute
for Docker Desktop worker containment.

ADR 0043's remaining independent review, bootstrap/channel/owner-loss, pressure
and supported-host clock obligations remain open. Previously stopped adversarial
experiments stay stopped. Missing proof is neither an accepted risk nor an NM-5
deferral. The selected Desktop unlimited-availability slice now has separate
evidence; Linux, optional idle and checked next enablement remain open. No new infrastructure,
automatic restart, component pin or release is accepted by this evidence.

### Later selected-control evidence

The open-gate paragraph above is the earlier evidence snapshot. The
[current ledger](acceptance.md#accepted-optional-idle-and-zero-issued-job-slices-2026-11-06)
records separate accepted Linux/Desktop optional-idle and normal zero-issued-job
stop slices, with the earlier held/unobserved receipts preserved. Cancellation,
native containment, durable recovery, a matching new image and checked
same-installation next enable remain separate open gates. NM-2 stays incomplete
and NM-3 stays paused; none of the historical receipts is rewritten.

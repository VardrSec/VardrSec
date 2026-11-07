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

On Windows, the corrected `887e134caa523bf438bcf0d5f4d71aecbeef165e` fixture
observed physical exit 13.674 seconds after the third target request. Map
retired the exact active attempt and released capacity, Runner's offline audit
cleared the original hold, and the next worker reused the state volume. Both
workers stopped and were retained. The operator profile hashes matched before
and after. The private receipt SHA-256 is
`19159a3adccedcf4a95a763ffb5813bda2c04641ca9067daf179abd2d853abe7`.

Ubuntu held on the same revision during stop-work verification with an
unclassified assertion. Its sanitized receipt SHA-256 is
`a726428e0113b737354cedf3b27fd3272d222c5971d06562c94eefa54066371b`.
[Installed Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42378261446)

The single-job stop-work sequence then passed on Windows Docker Desktop and
Ubuntu 24.04 at distribution `18b4f83b1d63477546318a4ebbc16b373daa4119`.
Map marked the consumed attempt `cancel_requested`, the first worker exited
before the delayed response could return, and Map retired that exact attempt
and released capacity. Runner's original reconciliation and independent
offline audit admitted a successor on the same state volume. Each target
observed three requests in total.

- Ubuntu observed physical exit 10.607 seconds after the third request.
  The sanitized receipt SHA-256 is
  `1f2646c9ed09ecca03c711e818e389a37cf9c76891aaf820088224105d601b72`.
  [Installed Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42379728874)

- Windows observed physical exit 13.359 seconds after the third request.
  The private receipt SHA-256 is
  `055921012d8337f4bb84523fdcb16042a4248700a6d4242ba62bda1ffbe452f5`.
  Both owned worker containers stopped and were retained. The operator
  profile hashes matched before and after.

The queued-job scenario adds a second, separately approved job in the stopped
engagement. On Windows it retained its original approval, zero issued attempts,
and the same target and duration counters across the successor launch. The
first worker exited in 13.038 seconds. The private receipt SHA-256 is
`c86886ef563a24f03f5099acfd93e71711607e2737c964f108dfcc73656b9e85`.
This scenario uses distribution `8e3c0dd6c5db00ec21cfbdb22a8783ab6610805c`
and Map `bdc5d70c58c004bfc9193d0eeb5ef3ed7baea347`. The Map change excludes
stopped engagements and stale approval revisions from discovery. Claims still
recheck authority and budgets. [Matching Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42380671226)

Ubuntu passed the queued-job scenario on the same exact component revisions.
The first worker exited after 10.753 seconds, the approved second job remained
unclaimed, and the successor made no additional target requests. The Ubuntu
sanitized receipt SHA-256 is
`c25e32bd07db39d23cab527974c3208b362abc0d8b1e10bd8e9d109181d48491`.

### Local emergency stop

On the previous Runner revision, Ubuntu completed local emergency stop and
admitted the successor after 2.575 seconds from the third request to the first
worker's physical exit. The sanitized receipt SHA-256 is
`2c09411e4acad86f8912ecc586437ebc95128435665088abdebf1b250e6219bb`.
[Installed Ubuntu baseline](https://github.com/VardrSec/VardrSec/actions/runs/42381620562)

The Windows baseline stopped the same kind of approved job and Map recorded
the native cancellation. Runner held original-key reconciliation. Both the
installation and its stopped worker were retained, and the operator profile
hashes matched. The private receipt SHA-256 is
`5e40244686390408bc3413c6c5b06f052d57fd5bd6568d5717605a285ccfe1c4`.
The focused Runner regression reproduced a terminal stop with a historical
PID and a temporary claim hold. The correction requires the exact native stop
and original physical retirement, and preserves the stopped process's audit
record.

Windows passed on Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` with
distribution `450ea4df6f426597e8a9b8c8ea2e9d440a1927be`. Physical exit took
3.128 seconds after the third request. Map retained the exact native
`local_emergency_stop` cancellation, Runner cleared the temporary claim
hold, and the successor started on the original volume. Both workers
stopped and were retained. The private receipt SHA-256 is
`ec33fdb46342dc43f06675881316474f3639f65e3e44cde4d8c8a4bd19b75a61`.
[Matching Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42384355007)

Ubuntu passed on the same corrected cohort. Physical exit took 1.937 seconds
after the third request. The sanitized receipt SHA-256 is
`0793a01f16e661b67cdcaf1225028eb5ddd835b60673e712207b52d9a2129fdc`.
Runner's [compatibility workflow](https://github.com/VardrSec/VardrRunner/actions/runs/42384354459)
passed all nine jobs on the corrected revision. The Map queue fix's
[PostgreSQL workflow](https://github.com/VardrSec/VardrMap/actions/runs/42380823791)
passed on its second attempt at the same commit. The first attempt timed out
in the synthetic TLS claim before its intentional response-loss step.

### Approved job with a missing local target grant

Windows passed the missing-grant case on distribution
`911cc349dd3f7aa7cf7c04ba165ca2e9d0967f03` with the corrected Runner and Map
sources. The worker discovered the approved job seven times. Both workers
retired at sequence zero. Map retained the original approval with no issued
contract, attempt, reservation, or budget charge. The target recorded zero
requests and the original Runner journal recorded no job association. The
private receipt SHA-256 is
`c36ec3f9227b6b305797ad21ed2b17f6d73a5892081692973e323ed72cc23713`.
[Matching Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42385472389)

Ubuntu passed the same scenario on the exact matching revisions. It observed
one unissued discovery, zero target requests and charges, sequence-zero
retirement, and a successor with the original state volume. The sanitized
receipt SHA-256 is
`c636dc9a1f3c0db3f5ac0299ef4698256546a16c02658ffeffa4e242c37aeb99`.

### Active target grant revocation

The first Windows run at distribution
`c6eaae8f14665156de6c9b20a2df23f1c51adf3b` revoked only the synthetic owner
grant, observed the worker exit before the delayed response, and retired
the original attempt. The fixture held after the original Runner audit
because its expectation was control-lease expiry. The native terminal
receipt recorded `local_emergency_stop`, which Runner also uses when its
local grant recheck denies execution. The Runner journal showed no operator
stop request. The stopped fixture remains retained. The private held receipt
SHA-256 is
`65e0d68a5d791568e5c23e2c33308a22a77796f05948ada9e1282c57eda7d49b`.

The first Ubuntu run held at `launch_stop_work_partial_evidence` with
`launch_stop_work_terminal_not_proven`. The public receipt does not expose the
underlying local cause. The sanitized held receipt SHA-256 is
`a64a3519dab95ed85f74a6f561bf908007e480ce5a1bc1fafe352c46acacfded`.
[Original Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42386625453)

The fixture correction at distribution
`975c158e3aab3204c850b022db1a96ccc257e5f3` requires that native cause
and the separate original journal and grant-catalog evidence. A lease
expiry, remote stop, or generic observed exit does not satisfy the
revocation check.

Windows Docker Desktop passed the corrected fixture with Map
`bdc5d70c58c004bfc9193d0eeb5ef3ed7baea347` and Runner
`5ecc869d80f53ae7fdbca25b971838976a6c41e9`. The worker exited
2.791 seconds after the third request began. The native cancellation, original
Runner audit and exact physical retirement bound a successor on the same
state volume. Both containers stopped and were retained. The operator profile
hashes matched. The Windows private receipt SHA-256 is
`a85803d8d48f7edfb710564fac399f82254449116e27456d53ec22ad30993010`.
[Matching Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42387479347)

Ubuntu 24.04 passed on the same four component revisions. The worker exited
2.179 seconds after the third request began. Its selected acceptance receipt
bound the grant-catalog change, the original audit and the successor
retirement chain. The Ubuntu sanitized receipt SHA-256 is
`a64118b422c408322a8480403f36b63e048de477373ec2b25fb8c6dac4ef3bcf`.

### Natural target grant expiry before claim

The opt-in expiry case uses the normal Runner grant command to set a short
owner-grant lifetime. It observes the same catalog before and after the
expiry, independently verifies that the peer grant still works, and keeps
the original Runner API enrollment. The approved job is discovered with
zero issuance, target requests or charges. The first worker and successor
retire at sequence zero and use the same Runner state volume.

Windows Docker Desktop passed at distribution
`4ed1871d74dce8118c3a98c056217b01afab1e5a` with the same Gate, Map and Runner
revisions as the active revocation case. It observed
7 unissued discoveries. Both worker containers were stopped and retained.
The Windows private receipt SHA-256 is
`88d8e56db1f8e9198023845208694fa47f83c8de1cee6ad07f030dac0753c6b5`.
[Matching Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42388704333)

Ubuntu 24.04 passed on the same exact revisions and observed one unissued
discovery. Both platforms preserved the peer grant and original API enrollment
through the next launch. The Ubuntu sanitized receipt SHA-256 is
`1f6145ff86412a88d7ed5de61e1d091cdaa945da71a8826422f41bae2b3f88e8`.

### Natural target grant expiry during active work

The fixture keeps approval registration pending while the exact worker becomes
idle. It creates one expiring synthetic target grant through Runner's normal
command and registers the reviewed job with 12 to 14 seconds remaining. The
owned target must observe the delayed resource request before grant expiry.
The fixture verifies physical exit before the delayed response, exact original
retirement, retained charges, the still-valid peer grant and the original
Runner API enrollment. It then checks the same-volume successor.

The first Windows run at `7c58b69c709c3ec24636afd651d9cea56fbd939c` held at
the active expiry timing assertion. Map's retained attempt receipt records
`tool_timeout`. The stopped fixture and its original receipt are retained.
The private receipt SHA-256 is
`0af9c5f208416d8e5528a628656bb28cc0f9884eb20f61aa3f6153083d9d77a1`.
The first Ubuntu run held at the same timing assertion. Its sanitized
receipt does not record the native stop cause. The receipt SHA-256 is
`ce74fd9fac334f5053e6ebb6142fc6d2b6a6c297a4b274f166c468dee52dacf1`.
[First Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42395910348)

Runner's existing launcher rounds the grant-bound tool timeout down to
whole seconds. Distribution `954572986943d66c6f0dfc25c54cc15b5d53390c` checks
that a `tool_timeout` exit may precede expiry by up to one second.
Other terminal causes require exit at or after expiry. Every case retains
the existing delayed-response and late-exit checks.
[Corrected Ubuntu run](https://github.com/VardrSec/VardrSec/actions/runs/42396887879)

Windows Docker Desktop passed on the corrected fixture with Map
`bdc5d70c58c004bfc9193d0eeb5ef3ed7baea347` and Runner
`5ecc869d80f53ae7fdbca25b971838976a6c41e9`. The worker exited
10.139 seconds after the third request and 0.522 seconds before the grant deadline,
with the terminal cause `tool_timeout`. The original retirement and
audit bound the successor, and both stopped workers were retained. The
operator profile hashes matched. The Windows private receipt SHA-256 is
`74b7fde72beb932ac36de5762e8957dca230862dad0556ea3edb2fdcfa9736e7`.

Ubuntu 24.04 passed on the same four component revisions. The worker exited
12.069 seconds after the third request and 0.777 seconds before the grant deadline.
Both runs recorded the existing `tool_timeout` cause. The cutoff proof
combines that cause with the measured grant window, the unchanged grant
catalog, the peer policy check and the exact original attempt receipt.
The Ubuntu sanitized receipt SHA-256 is
`86f8df6abdd67007a0ccff3772c3a4b678f255915cfa5c439855e1adba894611`.

### Allocated duration exhaustion

Distribution `176d4d47a8f743c04fabe00d92bfe89e91e57046` uses the exact
Map diagnostic revision `40bf4e37076d6a85648f817dd8b6bc69104bd863`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9`, and Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b`. The fixture completes one
approved synthetic job and waits for its native completion, release, and
local audit. It then submits a second, separately approved job in the same
engagement. The first job has allocated
the full 30-second duration budget. One concurrency slot remains free and
target allowance remains available.

The owned Map API emits one fixed duration-exhaustion marker. The refused job
stays pending and unissued, with zero target requests. Across the denial and
reconciliation, the engagement retains one target spent, 30 seconds
allocated, and zero capacity reservations. The first job's receipts remain
intact. Runner holds the ambiguous claim until exact physical retirement and
original-key reconciliation. The retired runtime records sequence one as
issued, and the original audit shows zero remaining holds.

Windows Docker Desktop passed. The worker exited with code 125 before any
operator stop, and the fixture was stopped and retained. The operator profile
hashes matched. The private Windows receipt SHA-256 is
`675c6d4463da02bff62e20ec3827d8402edbfa0bba9877c2528311e94033a5cb`.
The matching Ubuntu 24.04 run passed with the same charges, capacity,
issuance and target counts. Its worker exited with code 125
before operator stop, and the original Runner had zero holds after
reconciliation. The sanitized Ubuntu receipt SHA-256 is
`94fc329e879b89f33b973eb7b4f139a51721594e9e588ba0cb0351dd3b6b5e93`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42399656129)

### Strict approval after an authority change

Distribution `5983f5c882b469c8947bec10038d3d472ca16326`,
Map `40bf4e37076d6a85648f817dd8b6bc69104bd863`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop and
Ubuntu 24.04. The fixture signed an unregistered Strict approval, verified the original
signature against the configured public key, then revoked and restored the
synthetic engagement authorization. Its authority revision advanced twice.

Map refused the stale signed registration with HTTP 409. The before and
after inventories matched. A fresh review and signed registration for the
same job returned HTTP 200. The new approval stayed unissued. There were
zero requests, target charges, duration allocations, or reservations, and
no managed worker started. The five owned fixture containers stopped.

Windows receipt SHA-256 `eb2cf91847fdcbeb3dea0323727819bccd85fa488435756116b07fbed75660ad`.
Ubuntu sanitized receipt SHA-256 `1490e5ca62d7205f48062266e95f2185c139969accac35a242613b497d82add2`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42401753135)

### Represented-origin allowance exhaustion

Distribution `bf9a6924c059c5d4616b54172d0d906eda5cdfb5`,
Map `41635f9a75598c84192b4b53be95e025bf0b9b9d`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop
and Ubuntu 24.04. Two separately approved jobs used the same synthetic
origin and engagement. The first completed and used the one-target
allowance. At refusal, 90 of the engagement's 120 allocated-duration seconds
and one concurrency slot were available.

Map emitted one fixed target-exhaustion marker. The second job stayed
pending and unissued with no target requests. Charges stayed at one target
and 30 seconds, and capacity reservations stayed at zero through original-key
reconciliation. The worker exited naturally, the first receipt stayed intact,
and the original Runner audit ended with zero local holds.

The first Windows run stopped and was retained after a Runner initialization
command exited with code 1 before managed launch. The same exact source
and images passed on a fresh installation. The held Windows receipt SHA-256 is
`8954639339178f78beeb1e69d42bde0c25607de2255c22a0615051b65b72986b`.
The passing Windows receipt SHA-256 is `49975b7e3ed77ff0ea2fa5b6cb39017cf2e887a8ba04975a426d9943cf1ae1ff`.
The sanitized Ubuntu receipt SHA-256 is `43d0077862fb19ba379902d46c14f4c080ed1645930078ac710c46bd85aab9fd`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42402880527)

### Stopped predecessor recovery held

Distribution `773655424730e55f4da0a88ac8a076472bd07f6e`,
Map `41635f9a75598c84192b4b53be95e025bf0b9b9d`, Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9`
and the same Gate revision reached the successor-refusal check on both
Windows Docker Desktop and Ubuntu 24.04. Neither receipt matched the
required exact successor refusal. The fixture had already observed the
physical exit and one reserved slot on the unreported original attempt.

The stopped Windows fixture retained one worker, one readiness volume,
one launch intent and no exit report. The original checkout captures no
raw child stdout or stderr. The mismatched CLI response category remains
unknown in those two runs. Both initial attempts remain held.

Windows held receipt SHA-256 `59838357b4f27785a0be0186b7b003f02485a2b980a91682b274253cf6f23594`.
Ubuntu sanitized held receipt SHA-256 `f214f0f7b2a671b1736786ae9e1df333c67bf9e453fafc69dcd7387f7bcf8541`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42404296385)

### Stopped predecessor recovery after exact exit reporting

A Windows diagnostic on `155f76b7666ca1853b8576ca757d53a118903c1b` confirmed the response
had the expected exit status, selected runtime, failure phase and code. The
initial fixture had compared JSON bytes. The corrected fixture strictly
decodes the same bounded envelope and verifies its complete contents.
The diagnostic receipt SHA-256 is `40ade827dbbf04b35dd6d468728a5440a0130a79786ee762056955adf1eb4173`.

Distribution `ca93558951ca5ff191f66caf2a8974afa500d322`,
Map `41635f9a75598c84192b4b53be95e025bf0b9b9d`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop
and Ubuntu 24.04. The fixture invoked the normal operator stop and observed
the exact worker exit during a delayed third request. One successor launch was refused while
the original exit was unreported, with the original slot still reserved
and zero new resources or target requests.

Authenticated exit reporting produced a failed observed-exit receipt. The
original Runner reconciled to zero holds. The reserved slot was released,
and the original charge of one target and 30 seconds remained. The same
successor command then started a distinct worker on the original state
volume. Both exited workers and their fixture were retained.

This cohort also satisfies the ordinary exact-container stop portion of the
failure matrix. Unexpected Runner/PID-1 loss, channel faults and competing
managed claims retain their separate acceptance requirements.

Windows receipt SHA-256 `13a6c3c4050b60b7cce893392a6c8f5e512be3e5c165be62d294aa86fcdaf1c8`.
Ubuntu sanitized receipt SHA-256 `60b278e123af9a7a0b60ebfeb897c1689117e6bbad574443c62d8c1dbc084a6f`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42406589467)

### Shared engagement concurrency exhaustion

Distribution `61c335e3c895152acff1495cb6a552c8ad200c2d`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop
and Ubuntu 24.04. One authorized legacy API claim reserved the only slot
in an isolated engagement without dispatching a tool. A separate managed
claim was refused with the exact concurrency exhaustion marker.

One target, 30 seconds and one slot remained charged or reserved before
the refusal, after the refusal, and through the contender's retirement and
reconciliation. The contender issued zero attempts and made zero target
requests. Its original Runner reconciliation left zero holds. Only the
original job's owned finish released the slot, with a failed terminal
state and the same target and duration charges. The fixture retained six
stopped containers on each platform.

Windows receipt SHA-256 `991bd4fa9364d01b3ed0750486434baa90a2dc43a4671c871d31ae3e4eb6cae3`.
Ubuntu sanitized receipt SHA-256 `ed389544450e6128ee24185e6049a47c8f1ece217ac6e41ae8db224030276987`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42409178298)

### Strict review without authority or an open testing window

Distribution `976b2716abce43f33a09a2e7587f354acdf5e9e2`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop
and Ubuntu 24.04. Review of the first job returned HTTP 409 when there was
no authorization record. Adding the record and selecting it made review
return HTTP 200. The second job's exact existing warning identified a
closed testing window. Map refused review with HTTP 409, then accepted the
same request after the owner extended only the window end.

Both jobs remained pending and unissued, with zero target requests,
charges, or reservations. No managed worker started. Each fixture retained
five stopped containers.

Windows receipt SHA-256 `64db894c4c057c61ce645f3bd1dcc6e68bc181d9c88133996844983c7d2d2861`.
Ubuntu sanitized receipt SHA-256 `89373fa252baf61a2a5c1cdedd218dffa927239fab41c8eee715149442279824`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42409914844)

### Ordinary Map API outage, initial cohort

Distribution `f0e3172e6779a65dd112a65ac75e8861498ff3d8`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` verified the ordinary API-outage check on Ubuntu 24.04.
The exact worker exited 8.759 seconds after the API exited and 10.872 seconds
after the third delayed request was recorded. No further request arrived.
Restarting the same API started no worker and preserved the original
reservation. Authenticated exit reporting and original Runner reconciliation
released the slot with zero local holds and the original one-target,
30-second charge. This measures the configured lease ceiling. The exact
last native lease acknowledgement is outside this observation.

The initial Windows Docker Desktop fixture held at the combined exit and
traffic check. The retained inventory shows that the exact worker exited
with code 125, 9.317 seconds after API exit. The fixture stopped and was
retained. The initial receipt does not distinguish target traffic from the
final API-state comparison, so this attempt does not establish Windows
outage acceptance.

Windows held receipt SHA-256 `6e46666dabe6cf926f50d8d03cc2e504ec89d76f56a97feeb52b27570dc82133`.
Ubuntu sanitized receipt SHA-256 `650d3b9ada4d7f7ba4cf0c35fe303609176e55e205e291b1282dc0ee31549100`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42410862666)

### Ordinary Map API outage, initial serial cohort

Distribution `24f64f52c07a52af5e87d6455f523596bf723378`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` verified the ordinary
API-outage check on Ubuntu 24.04. The exact worker exited 8.278477334 seconds
after the API exited and 11.656861407 seconds after the third delayed
request. Exactly three requests were retained. Restarting the same API started
no worker and preserved the original reservation. Authenticated exit reporting
and original Runner reconciliation released capacity from one to zero with
zero local holds, one target spent and 30 seconds allocated. All six owned
containers were stopped and retained.

The matching Windows attempt held at `launch_map_disconnect_stop_api` with
`launch_map_disconnect_sample_stale`, before stopping the API. All six owned
containers were stopped and retained. The controller operator-profile guard
remained unchanged. Its child recorded zero blocked operations. Windows outage
acceptance and the cause of the stale sample remained open for this cohort.

The serial fixture registered the signed approval after readiness and the
API/daemon checks. It retained the positive consumed, confirmed Map binding
and the original controlled executing journal check before its final target
sample. The five-second sample freshness check, 15-second response delay and
10-second configured lease ceiling remained enforced. A later fixture
chronology correction and any later paired result belong in a separate record.
The exact last native lease acknowledgement remains unverified. NM-2 remains
open and all previously blocked probes remain stopped.

Windows held receipt SHA-256
`df52da2c77ab73e303bd1847e428a8b75a1c1da6097995fc3ce20e633cfc5860`.
Ubuntu sanitized receipt SHA-256
`e5490a4809c981931cf1e67d2100efd12e0b55aa681f9bf2d4b573334de0b5f3`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42413451198)

### Strict claim against a stale registered approval

Distribution `59f43c3b37730604788be1c02d3e95578c6eb732`,
Map `ebb1bc8dd6cc0c3215ad468a2dd1c848d812842a`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed on Windows Docker Desktop
and Ubuntu 24.04. The fixture registered a valid Strict approval and
retained its exact signed context. The owner lowered the target allowance
from five to four, which advanced the authority revision by one and still
left enough allowance for the requested claim.

The original enrolled Runner identity sent one claim to the installed
managed API using the retained stale approval. Map returned HTTP 409
with no-store and emitted one stale-authority-revision refusal marker.
The original approval and job ledger matched before and after the claim.
There were zero issued attempts, target requests, charges, reservations,
and managed workers. Each fixture retained five stopped containers.

This verifies the installed API refusal. Persistent worker discovery and
the ordering between polling and claim remain separate.

Windows receipt SHA-256 `71b713eb380579374a6ec2ba8b4927f607271279c2ab7a5155588226851586c2`.
Ubuntu sanitized receipt SHA-256 `2f64e614471913aed7d43d2fedba81d215127a233ca45f2a6a75ab379f145364`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42411672568)

### Ordinary Map API outage, journal observed after exit

Distribution `5366b397af063366d887931702434f994ea70340`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed the selected
ordinary outage check on Windows Docker Desktop. The exact worker exited
9.385096635 seconds after API exit and 13.020017889 seconds after the third
request. The three requests remained unchanged. Restarting the same API
preserved the reserved slot. Authenticated exit reporting and original Runner
reconciliation released capacity from one to zero with zero local holds and
the original one-target, 30-second charge. Six owned containers stopped and
were retained. The operator profile hashes matched before and after.

This fixture moved the existing controlled executing-journal check after the
physical exit and cutoff checks, before API restart or host reporting. Its
Windows private receipt SHA-256 is
`c202b2e58685efc6020083ac3ede69cc59a4d8af1baeaddddf52de424d715809`.

The Ubuntu attempt held at `launch_map_disconnect_journal_after_exit` with
`cancellation_original_run_not_active`. The differing journal field remains
unidentified in the sanitized receipt. Its SHA-256 is
`bcab98649cde23305e6e2cef7c711043725aafe9f1079c03a42e32c1746fae9c`.
Both compatibility jobs passed. The complete Ubuntu outage result for this
cohort remains unverified. The earlier Ubuntu passes retain their separate
source and observation chronology. Same-cohort cross-platform acceptance
remains open, along with the exact last native lease acknowledgement and the
wider failure and containment matrix.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42415067332)

### Ordinary Map API outage with concurrent original audit

Distribution `e0b1b83792f99ac956ff7ae54b77d4c7cd3663d9`,
Map `05dc78cf9a385255de459c8a5b833842d6528a63`,
Runner `5ecc869d80f53ae7fdbca25b971838976a6c41e9` and
Gate `d80d4730b8486b75be72431b5af88e0ddb45020b` passed the selected
ordinary API-outage check on Windows Docker Desktop and Ubuntu 24.04.

Windows measured API exit to worker exit at 8.964758369 seconds and third
dispatch to worker exit at 13.197046409 seconds. Ubuntu measured
9.433186405 and 11.926060453 seconds respectively. Each fixture retained
exactly three target requests and six stopped owned containers. Restarting
the same API preserved the original reserved slot and started no worker.
Authenticated exit reporting and original Runner reconciliation released
capacity from one to zero with zero local holds and the original one-target,
30-second charge. The Windows operator profile hashes matched throughout.

After a matching target prefix, the fixture starts one existing audit helper
alongside the positive Map check and final fresh target sample. It requires
the original strict controlled executing-record result after physical exit
and timing checks, before API restart or host reporting. The thread joins on
every path. The helper retains its existing 60-second subprocess timeout.
The five-second freshness check, 15-second response delay and 10-second
configured lease ceiling remain enforced. Private timestamps bound the
helper-call interval. The exact SQLite snapshot instant remains unmeasured.
The shared reader validates present intervals and supports older receipts.

The earlier freshness holds and Ubuntu journal-after-exit refusal retain
their separate records. This cohort verifies the configured lease ceiling.
The exact last native lease acknowledgement, unexpected process loss, lost
replies, preclaim recovery and the wider containment matrix remain open.
NM-2 remains open and NM-3 remains paused.

Windows private receipt SHA-256
`837705ed82ed351bd0593f22aa3b42a16c42e44a163d11eb93dacaa24c9697d4`.
Ubuntu sanitized receipt SHA-256
`4fb3a9e0b95600cf3d599570377bf7c939f19f0499007d94395b1359c9367e38`.
[Ubuntu workflow](https://github.com/VardrSec/VardrSec/actions/runs/42417276387)

The guarded Distribution suite ran 790 tests with 772 passing and 18 skipped.
All four new methods ran successfully. Source and operator hashes matched,
and the permanent isolation guard recorded zero blocked operations. Its
private receipt SHA-256 is
`cd0e84eb8cb74b5fd19acb75a1d188a85bd5837ba33dae134358f51f0c785336`.

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

## Current Runner Windows bootstrap configuration refusals (2026-11-07)

A fresh target-free Docker Desktop check used Runner
`5ecc869d80f53ae7fdbca25b971838976a6c41e9`, Git tree
`24644cd467d433bba0ddffd1f27aea88f7ca3c1c`. The qualified private build
receipt SHA-256 is
`807be3790392d95c87f607c9b88bdd6e74896e2f3b599634f975075bf12505a2`.
It identifies image
`sha256:8886f14a82d69d27768bbd9d5cb1c61669d16c239e536496a2daca0dbb657cb0`
and measured owner executable SHA-256
`8880528d5043b89b1e164769ec3b49a2cefe81db3545c5ef9093fe28192ad104`.

The private configuration receipt SHA-256 is
`9534b62c9d1446aeeaef89642624f128e9f994d3e09e46af9bc6472c19259133`.
Both ordinary misconfigurations exited 125 before readiness. The tested profiles
were UID 10001 with all capabilities dropped, and UID 0 with SETUID/SETGID but missing
SETPCAP. Successful archive reads verified empty readiness directories with
mode `0700` and UID/GID 10000. The containers used network-none profiles with no
authentication, admission, work or targets. Both stopped containers remain
retained. All three inventory checkpoints reported no admitted metadata changes.

The distribution helper at `3a5a6e28acbb6b3f310fa55dd9d21781f1de5343`
has Git blob `5720b24a428102f71c29c0be6109ba34c8b17a1d`, matching the existing
helper used for this evidence. This records Windows configuration refusals on the
current Runner source. Ubuntu verification remains open. Descendant absence was
not independently observed. The wider bootstrap and containment matrix remains
open, and previously blocked probes remain stopped.

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

## Independent source review for C10, 2026-11-07

A separate reviewer who authored none of the reviewed code inspected Runner
`5ecc869d80f53ae7fdbca25b971838976a6c41e9` and the Distribution boundary
sources at `8c9dd9d9c5b863d93236635588879de05b416ca4`. The reviewed product
boundary files were also unchanged at `377eea6138bcb8b816ceff25175bd590e00634c1`.
The review found no concrete source defect within ADR 0043's trusted-host,
immutable-image, closed-lineage and responsive-OS assumptions.

The review covered UID/GID transitions, the five capability sets and NNP,
kernel sender credentials and inherited descriptors, host STOP custody,
subreaper drain and refresh-thread quiescence, loss handling and finite
BOOTTIME deadlines. Runner and tools share UID 10001 and writable state.
The credential boundary retains that declared shared-principal limitation
and the owner-approved trusted-host false-exit risk.
[Native owner](https://github.com/VardrSec/VardrRunner/blob/5ecc869d80f53ae7fdbca25b971838976a6c41e9/container/worker_owner.c),
[lifecycle adapter](https://github.com/VardrSec/VardrRunner/blob/5ecc869d80f53ae7fdbca25b971838976a6c41e9/vardrrunner/worker_lifecycle.py),
[approved assumptions](https://github.com/VardrSec/VardrRunner/blob/5ecc869d80f53ae7fdbca25b971838976a6c41e9/docs/adr/0043-proposed-linux-worker-lifecycle-owner.md).

This completes C10's independent source-review portion. C07–C09 still need
their platform evidence. Artifact/cohort consistency and the final phase
disposition remain in C10. Previously stopped experiments remain stopped.

## Open phase gates

The installed evidence above covers first and subsequent startup, selected
cancellation paths, active grant revocation, expiry before claim and expiry
during active work, allocated duration and represented-origin exhaustion, and
Strict registration refusal after an authority change. The ordinary
stopped-predecessor recovery check and shared concurrency exhaustion also
passed. Both platforms also passed the Strict review checks for missing
authorization and a closed testing window, and the installed API refusal of a
stale registered approval. The ordinary API-outage check passed on one shared
cohort within its configured lease ceiling. The original Strict and ordinary
disconnect criteria receive that acceptance credit. The
[fixed checklist C01–C10](nm1-nm2-closeout.md#fixed-nm-2-closeout-checklist)
defines the remaining evidence, recovery and security work.

ADR 0043's independent containment review and bootstrap, channel, owner-loss,
credential-isolation, pressure and supported-host clock obligations remain open.
Previously blocked adversarial experiments stay stopped. Native Windows fallback
has its own retained evidence. Both the integrated Docker Desktop gate and NM-2
remain open. NM-3 remains paused.

The [current platform ledger](acceptance.md#accepted-optional-idle-and-zero-issued-job-slices-2026-11-06)
retains separate Linux and Desktop optional-idle and zero-issued-job receipts.
The historical held and unobserved receipts retain their original scopes.

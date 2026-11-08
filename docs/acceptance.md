# Distribution acceptance plan

Compatible development cohort proposed on 2026-11-08: Map
`14a80a8540c6c7053b1f0630f19a512a2351013a` ([PR151](https://github.com/VardrSec/VardrMap/pull/151)),
Runner `ea4265a12a54bc12593aafb4e0855be399e30fd3` ([PR117](https://github.com/VardrSec/VardrRunner/pull/117), including merged Recon PR116)
and Gate `57cfedfaf59b11cf626288c343f34a34c7b1df13` ([PR31](https://github.com/VardrSec/VardrGate/pull/31)).
Fresh Ubuntu 24.04 Full and Mapless qualification for these exact pins is enforced
by the required Compose installation job. Its result is the installed acceptance
record for this source cohort. The Mapless flow is one added step after the Full
workflow; no new dispatch mode is added.

The retained Windows Docker Desktop Mapless observation at Distribution
`4d7164d8fded8d0cc3d87b511cdab4f1e4ad87d7`, using Runner `5feea8d` and Gate
`57cfedf` before the Recon pin, passed five genuine GETs (owner 200, peer 403, anonymous 401),
native DONE acknowledgement and journal DONE, three redacted evidence exports,
secret/canary checks and byte-identical re-export without further target requests.
Its private receipt SHA-256 is
`81f7878cb3d8151c65785bbc5a97e84d876ae3356600b56526b48b05ad51f38e`.
The configured Windows Full installation at the same source cohort also passed
the unchanged six-scenario UI/assessment/evidence/finding/report workflow and
normal stop/start retention. HTTPS verified the exported CA and hostname;
migrations were current at `0041persistentruntime`. Its private result receipt
SHA-256 is `454a8c218f90ec70f4d4fc6aa636aaed44861023e0df96d5232c62977ed2d1c3`.
Both Windows observations used separate configured state and explicit free
subnets on an existing host; neither is a fresh-default Windows installer claim.
They do not pre-credit Ubuntu. Windows 11/Docker Desktop and Linux remain required
targets, and the other original platform gates remain separate.
`versions.json` remains development,
`runnable:false`, with no image or distribution release declaration. Existing
unaccepted clock/suspend, broader Recon and transition limits remain in force.

Current direction: the [Community Alpha plan](community-alpha.md) targets Ubuntu
24.04 Linux/amd64 first. The [2026-10-27 checkpoint](alpha-checkpoint-2026-10-27.md)
records the clean installation and remaining gates. Windows/macOS stay experimental
until their own full acceptance passes; incomplete Desktop support alone does not
block an Ubuntu-first alpha. See [platforms](platforms.md). Older dated observations below remain historical evidence.

The first source-level slice is merged in Map #110 and Runner #82. The refreshed
Map integration includes local authentication; 1,136 backend tests passed locally
and all PR checks passed, including PostgreSQL and the real three-component loop.
Runner #83 adds a CLI-only development container; local and CI smoke checks prove
non-root startup, no-network help/diagnostics and state retention across container
replacement. This is not full tool, HTTPS or distribution installation acceptance.

Earlier source-snapshot verification: Local
verification passed 1,103 Map backend tests (one skip), six PostgreSQL migration
checks, and 1,570 Runner tests (ten opt-in skips) at 96.48% Runner coverage.

The real three-product loopback harness passed 143 checks on each setup:

| Fixture | Map readiness | Requested Runner platform check |
|---|---|---|
| PostgreSQL 18 with real migrations | Ready | Healthy, exit 0 |
| SQLite create-all without Alembic marker | Not ready | Migration readiness fails, exit 1 |

The negative SQLite result is expected and tested; it must not be hidden by
stamping the schema. Diagnostics sent no target requests, skipped release discovery
when requested, and did not print the API key. These are source-snapshot checks,
not a distribution installation or hosted deployment verification.

Before a runnable alpha, require:

- One distribution checkout prepares the pinned components without manual
  component checkouts and starts the local UI/API/database with explicit secret setup.
- Local login works without required VardrSec hosting or an external provider;
  existing hosted login and tenant/authorization controls remain supported.
- Trusted HTTPS works on a fresh supported machine and clean browser profile,
  with an explicit documented trust-enrollment step if a local CA is used. The
  normal installation URL must show no certificate warning; browser/API/Runner
  certificate checks remain enabled. Never advertise Compose startup alone as
  completing trust enrollment or use insecure flags to pass this acceptance.
- Verify certificate persistence/renewal, restart and upgrade, CA-key protection,
  recovery and trust removal. A reverse proxy must accept forwarded scheme/IP
  metadata only from its configured trusted peers; backend/database ports remain
  private or loopback-bound. Missing trust and incomplete backend upgrades must
  produce actionable Runner/login diagnostics.
- Runner diagnoses actual required components and tools; Map shows status with
  observation times and handles stale/unreachable/unknown state honestly.
- Startup and diagnostics execute no scans. The operator reviews a case and
  explicitly invokes Runner; Gate's result/evidence reaches Map without automatic
  promotion into a confirmed finding.
- Stop/start preserves engagement data, Runner state and evidence. Backup restores
  into a fresh installation with evidence hashes and access intact.
- An upgrade and a failed upgrade have tested migration/recovery behavior.
- Test the declared supported Ubuntu environment, resource use, host-local/private
  target reachability and declared outbound traffic. Record genuine VPN and
  Windows/macOS limitations explicitly. Measure time to the first
  correct reviewed authorization test and assistance required.

Map's self-signed HTTPS browser fixture tests authentication and session behavior;
it does not establish trusted first-install acceptance. The distribution remains
unreleased until the above trust checks pass without certificate-error overrides.
Local authentication is defined in Map [#111](https://github.com/VardrSec/VardrMap/pull/111)
and its browser integration in [#112](https://github.com/VardrSec/VardrMap/pull/112).


## NM-2 optional count: held recapture observation (2026-11-06)

[Ubuntu count trial 42284035325](https://github.com/VardrSec/VardrSec/actions/runs/42284035325)
used Distribution `dc473835dc453bb5f0fa4a8560f41711d57e64ba`, Map
`52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c`, Runner
`e8cdec333af0ed721504f3857369a76c8a8a4e06` and Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b`, selecting
`persistent-count-limit` with database revision `0041persistentruntime`.
Compatibility passed on Ubuntu and Windows; the coupled trial remained held at
registration checkpoint `local_capture`. The sanitized receipt hash is
`90e75c361bc692799d76e1418e21ec55fd1a3ec1bb1d9feb8d6783682d6fd1b0`;
[the retained observation](evidence/nm2-ubuntu-count-local-capture-held-2026-11-06.json)
records its exact sources and limitations.

This checkpoint cannot distinguish a refused observer subcheck from a changed
valid identity. No count completion, independent count oracle or 35-job result was
exported. Startup/admission expiry is an unconfirmed hypothesis: the native startup
ceiling of 120 seconds, fixture admission wait of 60 seconds, observer ceiling of
30 seconds and command ceiling of 15 seconds remain unchanged. No new
capture, retry, timeout extension, permission fallback or authority is introduced
by fixed recapture diagnostics. Pure synthetic regressions are separate from
actual Linux/Desktop acceptance; neither optional-count nor unlimited operation
is accepted by this failed trial. The earlier held 35-job observation remains.

## NM-2 persistent availability: held custody observation (2026-11-06)

[Ubuntu trial 42273172251](https://github.com/VardrSec/VardrSec/actions/runs/42273172251)
used Distribution `9bc09e8e96d1697563dce63741973da9a3a3c07c`, Map
`52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c`, Runner
`e8cdec333af0ed721504f3857369a76c8a8a4e06` and Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b`. Both compatibility jobs passed;
the actual coupled trial remained held at `operator_worker_enable`, registration
checkpoint `mount_custody`. The sanitized public receipt hash is
`1b717c59bc90982f79b34d6f24eae98d1e16bdd47fe9a3cf1571ecef41432fd6`;
[the retained observation](evidence/nm2-ubuntu-persistent-mount-custody-held-2026-11-06.json)
records its exact sources and limitations.

The receipt exports no completed-job measurements or 35-job oracle result. It
cannot isolate daemon-volume metadata, bind/managed/private path resolution, or
path separation, and establishes no permission or layout cause. Existing Linux
`PermissionError` fallback is already explicit. Fixed sub-checkpoint diagnostics
and pure failure-injection tests provide observability only; all custody checks,
exception behavior outside registration and remaining platform gates stay intact.
A separately reviewed optional-count trial is the next focused observation; its
result cannot supply 35-job or unlimited-availability acceptance. No additional
35-job run, default enablement, release or deployment is approved by this record.

## Compose development acceptance (2026-10-26)

The source-built stack passed local validation on Docker Desktop with Linux
containers. All four services started; PostgreSQL applied real migrations. The
browser rejected the installation CA before enrollment, then accepted it after an
explicit import into a disposable container's NSS database. Default certificate
verification remained enabled. Real UI login, secure HTTP-only cookies, CSRF
rejection, engagement creation, reload and logout passed. Runner authenticated
through the proxy with only the public CA and reported current database/migrations.
Stop/start retained the engagement, an existing session and the installation CA;
only db/api/web/proxy were running after startup. No target scans were executed.

The Map image build passed 201 frontend tests, lint/typecheck and production build.
Runner passed 1,571 tests, ten opt-in skips, 96.48% coverage, lint/format and types.
The tool image verified all nine managed binaries and contained Gate and nmap (historical: later pins carry no Nmap; see the tool/network acceptance).
These checks prove this development fixture; fresh-host OS/browser enrollment,
certificate renewal over time, raw-packet/headless/template modes and host/VPN
routing remain release gates. See the reproducible
`tests/compose_acceptance.py` fixture and Compose CI. Publication remains separate.

## Recovery and native trust development acceptance (2026-10-26)

[Encrypted backup #5](https://github.com/VardrSec/VardrSec/pull/5) passed real age
round trips on Windows/Linux, wrong-identity/corruption/truncation rejection and a
full Compose restore from an encrypted/unsealed bundle. The installation and
controlled-update workflows also passed successful and failing migration/recovery
drills. These are development fixtures using pinned local images, not released
upgrade compatibility guarantees.

[Native trust #6](https://github.com/VardrSec/VardrSec/pull/6) checks disposable
hosted Windows/macOS certificate stores and fresh Chromium processes. Windows'
administrative LocalMachine lifecycle passed; interactive CurrentUser consent is
separate. macOS enrollment and verified browser HTTPS passed, but its trust-settings
removal commands stalled with both entries still present. The documented
[native trust scope](native-trust-acceptance.md) requires certificate-store absence
and browser rejection after exact-certificate deletion; residual macOS trust
metadata cleanup and fresh-host Docker Desktop acceptance remain release gates.

The [accelerated leaf-renewal fixture](certificate-renewal-acceptance.md) adds
real-time renewal observation, fresh verified TLS handshakes through original leaf
expiry, a fresh browser after expiry, and root/intermediate CA persistence across
proxy restart. The local Docker Desktop/Linux-container run passed 119 fresh
verified handshakes, three leaf serials, post-expiry browser access and CA/key-mode
persistence after restart. Its CI job reports results separately from full Compose
acceptance. Intermediate renewal, root rollover and sustained operation at normal
lifetimes remain release gates.

## Merged foundation and status integration (2026-10-26)

Distribution #1–#7, Map #113, Runner #83 and Runner dependency updates #79/#80
are merged. All three final main branches passed their post-merge workflows.
These are merged development capabilities, not a published Community release.

The Map source pin includes [status presentation #114](https://github.com/VardrSec/VardrMap/pull/114):
API/database readiness, account-owned Runner reports, observation timestamps,
reported versions/tools and stale/unknown/unreachable states. The Compose fixture
now explicitly sends a one-shot Runner heartbeat over CA-validated HTTPS and
requires the trusted browser to show migrated-database readiness and recent Runner
contact in Settings. Its CI result establishes that integrated snapshot separately
from Map's disposable self-signed authentication/browser fixture. No scan or
background Runner worker is started.

The pin also includes [bounded refresh #115](https://github.com/VardrSec/VardrMap/pull/115),
which enforces the deadline across authentication and body reads, enables retry
after timeout and refuses late success. The existing role/authentication and
heartbeat write contracts are unchanged.

## Installed authorization workflow

The [installed Gate acceptance](installed-gate-acceptance.md) extends the trusted
Compose journey with UI-reviewed cases and queued jobs, explicit real toolkit
execution, session preflight and traceable redacted evidence returned to Map.
Its four scenarios cover default private-target rejection, a vulnerable API, a
fixed API and unavailable resource responses. Diagnostics leave pending jobs and
target traffic unchanged. Assessments/evidence must render in the installed UI and
survive stop/start; scanner candidates never become confirmed findings implicitly.
The historical no-scan installation checks above precede this explicit execution
slice. Starting the platform still executes no scans.

The expanded installed fixture adds an independently verified write case, reruns
the identical reviewed case after an explicit repair, and exercises operator UI
actions for finding confirmation, evidence links, remediation/retests, closure and
two immutable client report revisions. Browser Markdown downloads must match
persisted hashes. Stop/start and encrypted restore verify the accepted finding,
history, linked evidence and delivered report versions. This covers synchronous
isolated write readback and local report export/status; it does not establish
arbitrary write strategies or external client receipt. See the
[installed workflow checks](installed-gate-acceptance.md).

## Tool and network matrix

The separate [tool/network fixture](tool-network-acceptance.md) checks nine managed
binary receipts, selected real unprivileged modes against a synthetic target,
raw-SYN rejection, host reachability, default private isolation, explicit network
namespace sharing and configuration persistence across replacement. Its CI matrix
uses fresh Ubuntu 22.04/24.04 runners; local Windows Docker Desktop evidence is
recorded separately. Genuine VPN routing, fresh Desktop hosts, headless browsers
and provider/DNS-dependent modes remain unverified by this fixture. Binary presence
alone is not mode acceptance.

## Image evidence and release review

The [image evidence collector](image-evidence.md) generates SBOMs and unfiltered
vulnerability reports for all five development images, with scanner/database,
image/configuration and report identities recorded. CI validates collection;
`image_evidence.py check` independently rejects blocking findings or invalid/stale
evidence. The initial local scan keeps all five image vulnerability gates blocked.
Unsigned evidence does not establish authenticated provenance, reproducible builds
or release readiness. Publication remains a separate authorized step.

### Optional native idle control (implementation; platform proof open)

The explicitly selected idle-control fixture and independent reader are implemented
for the existing optional60-second limit. One reviewed job must complete, followed
by native124 without operator stop and exact retirement/reconciliation. Actual
Linux/Desktop idle acceptance remains open. See the [bounded acceptance plan](nm2-worker-acceptance-plan.md).

That implementation-stage snapshot is superseded for the selected idle slice by
the [later ledger](#accepted-optional-idle-and-zero-issued-job-slices-2026-11-06).
The wider phase matrix remains open.


### Selected NM-2 platform evidence, 2026-11-06

[Linux count-one run42300367549](https://github.com/VardrSec/VardrSec/actions/runs/42300367549)
passed on Distribution `b516366e574eaeb1057e88301634e861f761fe0f`,
Runner `1e05c5bc12369e6b6b953d80527ac3fcd906f53c`, Map
`52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c` and Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b`. Both Ubuntu and Windows compatibility
jobs passed. The independently checked [sanitized count receipt](evidence/nm2-linux-count-one-verified-2026-11-06.json)
reports one issued attempt, five target requests and evidence records, zero local
holds, zero target/duration charges for the unissued job, and six owned stopped
containers. The explicit limits were count-one with no idle timeout. Its ZIP digest,
receipt digest and all four immutable source commits/trees were checked.

The separate [Desktop idle receipt](evidence/nm2-desktop-idle-limit-held-2026-11-06.json)
remains held at `idle_control_observation` / `idle_status_refused`, with no idle
acceptance credit. Its retained public facts report six stopped retained containers,
checked inventory and one permitted empty built-in bridge identity change; cause
remains unknown. No job or timing result is inferred from this held receipt.

These are separate selected-slice records. The count result does not establish the
cause of earlier Linux refusals. Other availability, idle, zero-issued-job,
stop/re-enable and containment evidence remains subject to its own acceptance
record. NM-2 remains incomplete; NM-3 is not resumed by this evidence update.

### Linux availability and later held Desktop idle, 2026-11-06

[Linux availability run42303336342](https://github.com/VardrSec/VardrSec/actions/runs/42303336342)
passed on Distribution `b516366e574eaeb1057e88301634e861f761fe0f`,
Runner `1e05c5bc12369e6b6b953d80527ac3fcd906f53c`, Map
`52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c` and Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b`, at database revision
`0041persistentruntime`. Both Ubuntu and Windows compatibility jobs passed.
The independently checked [sanitized availability receipt](evidence/nm2-linux-persistent-availability-verified-2026-11-06.json)
records 70.000108429 seconds of idle with zero target requests, 35 individually
authorized jobs, 175 target requests and evidence records, zero local holds,
explicit stop/reconciliation and six owned stopped containers. Both optional
worker limits were unset. The artifact ZIP digest, receipt digest and all four
immutable source commits/trees were checked; the receipt SHA-256 is
`11b0714b129175aeed475d11230ddec049df5ce28665cb61b6b71d2ae2257a90`.

The later [Desktop idle lookup receipt](evidence/nm2-desktop-idle-limit-lookup-held-2026-11-06.json)
belongs to the separate `a55a8a3039e24830` fixture cohort using Distribution
`751be0f33507ac7d4a845cfd9377e7a2d60345a8` and Runner
`09008e5d9c3edf619e55eeacdfd9ea1db31aba89`. It remains held at
`idle_control_observation` / `idle_status_refused`, with fixed status checkpoint
`lookup` and no acceptance credit. Its SHA-256 is
`af1ccf7b278e2691e4f25d9caf62738ffb1c70466c483d94e5bebebb36348e0a`.
Retained cleanup reported six stopped containers, a checked inventory, one
permitted empty built-in bridge identity change, worker exit124 and no fixture
stop request. These are cleanup-only observations: they establish neither the
worker state at the failure instant nor a verified native-idle outcome. Cause
remains unknown. The earlier
[792719349f4c4923 held receipt](evidence/nm2-desktop-idle-limit-held-2026-11-06.json)
is preserved separately.

[Runner facade CI42303800208](https://github.com/VardrSec/VardrRunner/actions/runs/42303800208)
passed all nine jobs on `09008e5d9c3edf619e55eeacdfd9ea1db31aba89`, including
Ubuntu Python3.10–3.14, Windows/macOS Python3.14, lint/types and dependency audit.
This component validation is separate from the earlier Linux availability cohort
and from actual next-enable integration or idle lifecycle acceptance.

These selected records leave optional idle, zero-issued-job, stop/re-enable and
the remaining containment matrix open. The Linux pass does not identify earlier
Linux refusal causes. NM-2 remains incomplete; NM-3 is not resumed, and no release
or deployment is authorized by this evidence update.

### Accepted optional idle and zero-issued-job slices, 2026-11-06

These are selected physical slices on separate exact Linux and Docker Desktop
cohorts. All use Runner `09008e5d9c3edf619e55eeacdfd9ea1db31aba89`, Map
`52e7b5bb30c4f2fca6cef8a9fb0d5c7181a66c7c`, Gate
`d80d4730b8486b75be72431b5af88e0ddb45020b` and Map revision
`0041persistentruntime`. Linux and Desktop images were built and verified
separately; this record grants no capability to a later Runner image.

| Observation | Distribution cohort | Disposition and exact public receipt |
| --- | --- | --- |
| [Linux idle run42312084921](https://github.com/VardrSec/VardrSec/actions/runs/42312084921) | `036a142e938c10d3d4dbc75d5d8434e4079c0f52` | [Selected idle slice passed](evidence/nm2-linux-idle-control-verified-2026-11-06.json), SHA-256 `2793a1362925bac15846f41f96ef3e138bd89c55d3070f913102c289e9f85a0d`. |
| Desktop idle cohort `96160766c3ec4572` | `036a142e938c10d3d4dbc75d5d8434e4079c0f52` | [Selected idle slice passed](evidence/nm2-desktop-idle-control-verified-2026-11-06.json), SHA-256 `6f20a6d78b345c1a782d843ed8a9722fbb2735092b6e86d1c810e591e97b87f1`. |
| [Earlier Linux zero-job run42312463253](https://github.com/VardrSec/VardrSec/actions/runs/42312463253) | `036a142e938c10d3d4dbc75d5d8434e4079c0f52` | [Held/unobserved](evidence/nm2-linux-empty-stop-unobserved-2026-11-06.json): `receipt_unavailable_or_invalid`; no lifecycle measurements or acceptance credit. SHA-256 `f81c2277062896a4c005faa7617e928928d2176c8c9d801c9c04549334b97329`. |
| Earlier Desktop zero-job cohort `09887e7cca964f29` | `036a142e938c10d3d4dbc75d5d8434e4079c0f52` | [Diagnostic retained](evidence/nm2-desktop-empty-stop-controller-held-diagnostic-2026-11-06.json): independent measurements passed but the controller remained held; `acceptance_credit:false`. SHA-256 `e329001e32c2e2e49e3d5f901ee91fe3a4c9c97dbf0791881386a368f4716e42`. |
| [Fresh Linux zero-job run42316282747](https://github.com/VardrSec/VardrSec/actions/runs/42316282747) | `d73c89c37c7e4f852fce56ae099edebb297fa9f5` | [Selected empty-stop slice passed](evidence/nm2-linux-empty-stop-verified-2026-11-06.json), SHA-256 `7fe0e231d53cda6b952b03d39642284c88ce96f9c856a1d3485a44d19fb89845`. |
| Fresh Desktop zero-job cohort `def01c1675534138` | `d73c89c37c7e4f852fce56ae099edebb297fa9f5` | [Selected empty-stop slice passed](evidence/nm2-desktop-empty-stop-verified-2026-11-06.json), SHA-256 `4771a7e08447cc66773c6e814c1b333338a71a6518a58b3f83a29ad755716d4b`. |

Both successful idle receipts require one reviewed job, five GET requests and
evidence records, native exit124 with no operator stop, zero local holds,
unbound last1 retirement/original-run reconciliation and six stopped containers.
Their optional idle limit is60 seconds with no count limit. They do not replace
the separate default-unlimited 70-second/35-job availability evidence.

Both fresh zero-job receipts require zero issued attempts, associated runs and
claims, engagements, target traffic and local holds. They prove explicit operator
stop and positive unbound host/Map retirement at last0, with both finite limits
unset and six stopped containers. The complete local result remains
`not_applicable_empty_unissued`; it adds no physical/server proof and fabricates
no RunRecord or local retirement.

The Linux named artifact ZIP digests and all four immutable source/tree bindings
were independently checked; Ubuntu and Windows compatibility passed for each
recorded run. Desktop projections used the strict independent reader, exact
cohort/image/source pins, unchanged-input/source guards and zero blocked
operations. The six copied JSON files contain only their existing sanitized
public output; raw receipts, inventories, credentials and private provenance
paths remain excluded.

The corrected fixture CLI success footer explains the observed Desktop098
controller hold after its measured slice. It does not establish the cause of the
earlier Linux unobserved receipt. The original [792 idle hold](evidence/nm2-desktop-idle-limit-held-2026-11-06.json),
[a55 lookup hold](evidence/nm2-desktop-idle-limit-lookup-held-2026-11-06.json),
Linux unobserved record and Desktop098 diagnostic remain unchanged.

The host-operation component at commit
`400f3c6d248d150fc470408dd75c6a1535a5f3e4`, tree
`95fe1c18d3f7c87e6e319f9a22d392b3cd62cb4d`, completed the normal569-test
Distribution suite with18 existing skips and no failures or errors, including
the three real-module token/CLI cases. [Compatibility run42318325511](https://github.com/VardrSec/VardrSec/actions/runs/42318325511)
passed its Ubuntu and Windows jobs; coupled/installation/update/certificate jobs
were intentionally skipped. This verifies locking groundwork. Durable intents
and physical same-installation next-enable acceptance remain open.

These passes close only their selected idle and normal zero-issued-job stop
criteria. Integrated cancellation/partial evidence, native containment and the
remaining bootstrap/channel/owner-loss/pressure/clock matrix retain their own
physical gates. [The host operation scope](adr/0005-host-worker-operation-scope.md)
is component groundwork: durable intents, supported next-enable, ambiguous and
preclaim recovery, a matching new reconciliation-capable image and physical
same-installation reuse remain open. NM-2 is incomplete and NM-3 remains paused.
No requirement is deferred to NM-3/NM-5; no component pin, release or deployment
is authorized by this evidence.

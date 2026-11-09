# New Moon acceptance ledger

Updated: 2026-11-08. Development evidence; no release acceptance is implied.

This ledger tracks changing implementation evidence. The approved New Moon charter
remains the architectural authority: one Runner engine, optional Map, shared
authorization, independent Gate/Lab, and separate distribution lifecycle.
Windows 11 is the primary target, Docker Desktop is preferred, Linux compatibility
and justified native Runner operation remain required.

## Community delivery priority

Owner direction on 2026-11-08 resumes production Community delivery: usable Full
and Mapless installation and authorize/execute/evidence/export take priority.
Reuse existing checks; no further manual fault/sleep campaign is authorized.
This changes sequencing, not the C09 acceptance result or release gates.

The merged integration adds explicit mode selection, state-only Mapless recovery,
private issuer custody, one-shot contained execution and host-owned export using
existing component protocols. Compatible pins and Ubuntu Full/Mapless workflows
are verified. Configured Windows Docker Desktop workflows and subsequent canonical
new-installation/recovery operations passed. Bounded standalone Recon now has
installed development evidence below. State-preserving Mapless updates also have
the bounded installed result below. Broader Recon, optional history import/sync,
C09 sleep behavior and NM-5 acceptance retain their separate dispositions.

## Current NM-5 source cohort and owner handoff

Distribution `d94921504b4ad22a94f0406bd35f5f12414cbd4e` integrates supported
[local managed setup](local-managed-setup.md) through
[PR81](https://github.com/VardrSec/VardrSec/pull/81) and the separate qualified
[pin PR82](https://github.com/VardrSec/VardrSec/pull/82). Map `a01a76f` adds the
Gate-only managed queue control; Runner `2bcd0f5` corrects its persistent image
recipe; Gate `57cfedf` is unchanged. Both component PRs passed all ten checks.
Main's tree `ae9153e18ba0cd94fdde235ed67133427e627cf6` exactly matches reviewed
pin head `c8adbfe`. All existing checks passed, including installed Full/Mapless,
encrypted recovery, controlled updates, networking, trust and Windows/Ubuntu
compatibility ([installed run](https://github.com/VardrSec/VardrSec/actions/runs/42561077668)).

A bounded Windows Docker Desktop observation at `c8adbfe` passed normal Full
installation, account creation, persistent-image build, separate signing custody
and restricted Runner enrollment. Offline readback confirmed the original stable
identity and stored connection. No worker or job was started; synthetic services
were stopped and volumes retained. Its earlier failed attempt remains preserved;
the state ownership and encrypted archive allowlist defects were corrected before
qualification. This setup evidence does not establish interactive job approval,
execution or human usability. The owner walkthrough may proceed; independent
unfamiliar-user evidence, NM-2 C09/C10 and release/security gates remain open.

The earlier runtime-security cohort below retains its original attribution.

Earlier distribution `700e003a3f8b96ed4e1e32eec0c5d980bf704db2`
([PR79](https://github.com/VardrSec/VardrSec/pull/79)) is the qualified source-built
runtime-security cohort: Map `55458b7`, Runner `519c047`, Gate `57cfedf` unchanged.
Its tree `a8b0764073a34a893fdeecbbf871802bc7c3897e` equals reviewed head `b3fb937`.
All existing required checks passed, including installed Full/Mapless,
backup/recovery, controlled updates, trust and Windows/Ubuntu compatibility.
See the [matched runtime checkpoint](nm5-runtime-remediation.md#matched-cohort-qualification).
No duplicate qualification run is needed for that unchanged merge tree.

Rebuilt reports verify 16 high and four medium package occurrences removed with
no added findings. Remaining totals are 1 critical / 207 high / 8 unknown;
all image risk gates remain blocked. This qualifies compatibility and the targeted
remediation, not a release or acceptance of remaining risks. Existing Windows
installation receipts keep their original commits; a new Windows end-to-end
run is not inferred from Linux installed CI or native compatibility checks.

Merged source delivery adds offline exact-pin notices and optional source archives
([guide](source-notices.md)), with explicit completeness and licensing limits.
Lab's merged report/retention changes preserve sanitized observations, source/result
hashes and timing. Its [retained current-Gate receipt](https://github.com/VardrSec/VardrLab/actions/runs/42549665462)
records 8 TP, 8 TN and 20 unsupported observations; raw HTTP validation and a
competitor comparison are not established by that fixture result.

The owner will perform guided Full then Mapless acceptance using the
[walkthrough protocol](first-user-test.md#owner-acceptance). Record actual results
and assistance; this does not silently replace independent unfamiliar-user evidence.
The [architecture review](new-moon-architecture-review.md) records component
boundaries and six remaining closure gates. NM-5 stays open: explicit host/Docker
restart persistence, required route/native-fallback scope, independent research and
human evidence, release artifact/risk decisions and architectural/safety signoff
retain their recorded requirements. C09 remains unaccepted; no stopped fault/sleep
campaign resumes. No tag, image publication or release is authorized here.

## Current NM-4 Community delivery status

**NM-4 is closed for the source-built Community scope, accepted 2026-11-08.**

Owner direction keeps Community Edition local-first: Full and Mapless Docker
installation, Windows 11/Docker Desktop and Linux remain required. Vercel and
Railway are the owner's personal hosted test environment, not Community delivery
or installation acceptance gates.

The qualified source-built cohort is merged in distribution `b4133d7`
([PR74](https://github.com/VardrSec/VardrSec/pull/74)): Map `c983a60`
([PR153](https://github.com/VardrSec/VardrMap/pull/153)) and Runner `dec2ac6`
([PR119](https://github.com/VardrSec/VardrRunner/pull/119)), with accepted Gate
`57cfedf` unchanged. These exact reviewed pins are retained in `versions.json`;
component merge commits do not silently advance them. No published image or
release is claimed.

All required component checks passed. Runner's [final compatibility CI](https://github.com/VardrSec/VardrRunner/actions/runs/42538028836)
passed on Windows, Linux and macOS; its [container workflow](https://github.com/VardrSec/VardrRunner/actions/runs/42538028822)
passed with the optional MCP SDK packaged in the toolkit. The distribution's
[installed acceptance](https://github.com/VardrSec/VardrSec/actions/runs/42538113288)
passed Full/Mapless installation, controlled updates, certificate renewal and
Python compatibility on Windows and Ubuntu. [Tool/network checks](https://github.com/VardrSec/VardrSec/actions/runs/42538113249),
[native trust](https://github.com/VardrSec/VardrSec/actions/runs/42538113292),
[image evidence](https://github.com/VardrSec/VardrSec/actions/runs/42538113357) and
[manifest checks](https://github.com/VardrSec/VardrSec/actions/runs/42538113523)
also passed. The separately dispatched NM-2 fault campaign was skipped, not rerun
or represented as new evidence.

The component changes cover operation × identity × boundary gaps, grounded
review-only drafts, pending AI queue proposals requiring operator approval,
explicit stateful prerequisites and redacted portable execution context.
Reported tool identity is not server attestation; a redacted case derivative is
not the original input or replay authority. Required operator inputs and unknown
historical metadata remain visible.

Reuse the accepted PapaChin Windows installation/recovery and prior Linux
evidence where implementation is unchanged. New Docker MCP packaging has one
bounded offline stdio check in the existing Runner container workflow; it starts
no scan and mounts no engagement volume. MCP/canonical CLI concurrency is not
claimed: close the explicit MCP session before other canonical commands. The
existing installation lock, backup/recovery safeguards, privileges and default-off
execution remain unchanged. Dynamic capture/substitution in the controlled fixed
profile, general cleanup and token lifecycle coverage remain explicit unsupported
or unestablished conditions, not inferred successful workflow coverage.

### Original NM-4 exit criteria

| Requirement | Delivered behavior and evidence |
|---|---|
| Observed operation becomes a reviewable case without invented policy | Map boundary drafts and Runner `workspace draft-gate` preserve observed operations, assumptions and missing identity/policy inputs. Drafts grant no authority; existing artifact/hash and grounded-draft checks passed. |
| Approved cases execute through Full and Mapless | The existing installed acceptance above exercises the qualified shared Runner/Gate paths and evidence/export workflow. Recon suggestions require operator review, credential references and a new signed Gate authorization; the discovery authorization cannot be reused. |
| Evidence/provenance inspected locally and in Map | Runner includes tool/version/hash, target, origin, timing, case correlation and terminal context. Map stores bounded reported provenance and exports selected same-engagement context. Redacted derivatives retain original case hashes as correlation, require missing inputs and fresh review, and explicitly do not claim independent reproduction or server attestation. Existing affected artifact/upload/report suites and component CI passed. |
| Truthful unsupported/inconclusive stateful coverage | Coverage distinguishes per-operation, per-identity and boundary gaps. Review summaries expose setup, reset and missing workflow context; unsupported capture/substitution, cleanup and token lifecycle behavior is not counted as successful assessment. Existing classification and workflow review checks passed. |
| Negative AI instruction/permission boundaries | Existing MCP checks retain untrusted-data instructions and prompts, bound workspace reads, no approval tool and proposal-only queueing. Map checks enforce operator membership, Stop Work, revalidation and atomic approval; pending/rejected proposals create no jobs. These establish the implemented API/tool boundaries, not immunity of an external model to arbitrary prompt injection. |
| Representative workflows inside Windows Docker Desktop | Existing PapaChin Gate/Recon installation evidence is reused where runtime is unchanged. Final Windows component CI passed. The existing offline Docker MCP stdio check passed on Linux and on Windows Docker Desktop using the official toolkit built from the exact Runner/Gate pins above. SDK initialization, the exact read-only tool surface and an empty workspace query passed; no assessment ran. |

The Windows Docker Desktop MCP observation used image
`sha256:a6afd89b2804c4e9763e44ea8fec98376f3732de719611abbaabd85f8122797d`,
built locally with the official Dockerfile. Existing scanner/Gate compile stages
were cached. The existing SDK check ran with network disabled, UID 10001, all
capabilities dropped, no-new-privileges and no mounts; it initialized, listed
exactly `list_local_workspaces`/`get_local_run`, read an empty workspace list and
closed normally. This qualifies the optional read-only stdio surface, not
concurrent canonical commands, new assessment authority or arbitrary AI behavior.

The production increment and matched local cohort are merged. NM-5, C09, broader
Recon, optional history import/sync and release/security decisions keep their
recorded separate dispositions; no stopped fault/sleep campaign resumes.

### Production and verification accounting

Using the unchanged tracked-line classifier, cumulative NM-4 additions are 917
production and 494 verification lines: **64.99% production / 35.01% verification**.
Verification includes CI and fixtures. Documentation, configuration, generated
files and locks are separate. Whole-project source across the four repositories
is 83,799 production and 140,064 verification lines: production rises from
37.28% to 37.43%. No suite was deleted to change these percentages.

## Current NM-3 distribution status

**NM-3 is closed for the source-built Community distribution, accepted 2026-11-08.**
The accepted distribution is `3fc286a848352901b786bb9fdb9e969a3e6a9ad8`
([PR72](https://github.com/VardrSec/VardrSec/pull/72)). Its tree
`23562656809c409523f061c19e3166e21504510e` is identical to reviewed head
`55772d3cb0a599fca95c986aafdd6eb891ef5b80`, where all five existing workflows
passed. The exact component pins are Map `14a80a8540c6c7053b1f0630f19a512a2351013a`,
Runner `ea4265a12a54bc12593aafb4e0855be399e30fd3` and Gate
`57cfedfaf59b11cf626288c343f34a34c7b1df13`.

### Exit-criteria closeout

Requirement source: the owner-approved New Moon roadmap, NM-3 scope and exit gate,
document SHA256 `bede351e2199b527a7d1eb9c0026c97f8d6fc36b875e2ade173251b597a112d2`.
The closeout preserves its Windows/Docker, Linux, independent Runner and optional
Map requirements; it does not add OS provisioning or automatic history import.

| Original NM-3 requirement | Accepted evidence |
|---|---|
| Local workspace, authorization, scope, preferences, history and portable evidence without Map/account/API token | Retained Windows Mapless Gate workflow: five bounded GETs, native/journal DONE and identical redacted re-export; current-pin Ubuntu Mapless authorization/execution/export passed in the [installation job](https://github.com/VardrSec/VardrSec/actions/runs/42523444635). Mapless has Runner/Gate only. |
| Recon pipeline and reviewed Gate case | Windows finite DNS-A → HTTPS/443 GET-root Recon receipt below; original Host/SNI, one DNS question, one HTTP 200 and unchanged re-export. Gate retains its separate reviewed authorization and existing installed workflow. Discovery output grants no further execution authority. |
| Shared execution and contract validation | Both paths use the existing Runner ledger, launcher, owner and export. Exact-pin [Runner CI](https://github.com/VardrSec/VardrRunner/actions/runs/42519151653) and [container checks](https://github.com/VardrSec/VardrRunner/actions/runs/42519151637) passed; Gate defaults and dormant Recon v1 remain unchanged. |
| Windows 11/Docker Desktop Full and Mapless installation; interactive/scriptable entrypoints and convenient CLI | Canonical clean application source trees and new projects/volumes on the owner-designated Windows host passed. PowerShell/Bash entrypoints delegate to that same installer and transfer wrapper; parsing, shell syntax and both-platform compatibility checks passed. Preinstalled Windows/Docker prerequisites and unrelated retained resources were preserved. |
| Full connected workflow | Retained Windows six-scenario UI/queue/assessment/evidence/finding/report and restart receipt; current-pin Ubuntu trusted Full/Gate/restart workflow passed in the installation job. |
| Non-destructive Mapless → Full minimum and protected persistence | Separate Full installation leaves the original Mapless history in place and exportable. Windows Full/Mapless recovery verifies state and export equality. This meets the charter's stated preserved/exportable-record minimum; import/sync remains a separately gated increment. |
| Upgrade without evidence loss; backup/recovery and ownership | Windows Mapless image update preserves exact protected state and the original run's three exports. Final [Compose acceptance](https://github.com/VardrSec/VardrSec/actions/runs/42523444635) passed controlled updates, interruption/resume, encrypted portable recovery, migration-failure recovery and least-privilege role verification. Launcher files survive recovery. |
| Existing Linux deployment and justified native CLI choice retained | Ubuntu 24.04 Full/Mapless installation and recovery passed. [Tool/network checks](https://github.com/VardrSec/VardrSec/actions/runs/42523444594) passed on Ubuntu 22.04/24.04 within their recorded scope. Existing native components and platform CI remain; [networking](networking.md) and [platforms](platforms.md) retain native and VPN limitations. |

### Fresh Windows installation and evidence reuse

The owner selected the Windows qualification host and directed reuse of its
retained evidence. Fresh installation is accepted at the application boundary:
clean source trees, distinct installation projects and new state, with Windows 11,
Docker Desktop and other documented prerequisites already installed. The
canonical installer acquired pinned components and built/froze isolated images.
The source trees were Git exports; this does not claim a literal distribution
clone run, a Windows reinstall, prerequisite provisioning, an empty Docker engine,
or a byte audit of every unrelated retained resource. None is an additional
NM-3 exit requirement. Separate-install coexistence and preservation remain required.

Evidence is composed without relabelling older runs as final-head runs. Windows
installation/recovery, Gate/Full workflow, Recon and update receipts below retain
their original commits and hashes. Runner `dfcd8f2` → `ea4265a` changes standalone
diagnostics, CLI, documentation and tests; the qualified Recon runtime, owner and
authorization code are unchanged. Earlier Gate/Full observations are combined with
the final exact-pin installed regression, rather than being claimed as a new
Windows run. Finishing distribution changes add delegating launchers and recovery
manifest handling. The final installed CI exercised the corrected encrypted
archive allowlist as well as the complete pinned workflow.

The five accepted workflow runs are
[foundation 42523444680](https://github.com/VardrSec/VardrSec/actions/runs/42523444680),
[Compose 42523444635](https://github.com/VardrSec/VardrSec/actions/runs/42523444635),
[tool/network 42523444594](https://github.com/VardrSec/VardrSec/actions/runs/42523444594),
[native trust 42523444627](https://github.com/VardrSec/VardrSec/actions/runs/42523444627)
and [image evidence 42523444750](https://github.com/VardrSec/VardrSec/actions/runs/42523444750).
This closeout rechecks retained receipt hashes, source identity and completed CI;
it adds no qualification run or test case.

### Phase boundaries after closeout

Accepted Recon is the explicit finite DNS-A/HTTPS profile above. Broader discovery,
automatic Gate execution, optional history import/sync and storage migrations have
not been accepted. Native Windows redacted export retains its documented 24H2+
and fixed-local-NTFS boundary; native Linux controlled execution still needs the
existing owner context. Genuine VPN behavior, macOS Docker and other unqualified
platforms retain their documented limits. No integrated native Full stack is added.

NM-2 C09 remains unaccepted and its stopped fault/sleep campaign stays stopped.
NM-4 intelligence and NM-5 benchmarks/release validation remain separate work.
Image-risk disposition, release/tag/image publication and deployment are not
authorized or accepted by this phase closeout. `versions.json` remains a development
source compatibility record with `runnable:false` and no published images.

### Retained implementation and qualification records

Earlier distribution [#68](https://github.com/VardrSec/VardrSec/pull/68), Runner
[#114](https://github.com/VardrSec/VardrRunner/pull/114) and compatibility
[#69](https://github.com/VardrSec/VardrSec/pull/69) are merged. The exact cohort
is Map `14a80a8540c6c7053b1f0630f19a512a2351013a`, Runner
`5feea8d6de373b4bbc5a3951310c69a16ae7179b`, Gate
`57cfedfaf59b11cf626288c343f34a34c7b1df13`.

Merged compatibility [PR71](https://github.com/VardrSec/VardrSec/pull/71) selects reviewed Runner PR117 head
`ea4265a12a54bc12593aafb4e0855be399e30fd3`, including merged Recon PR116 and
standalone diagnostics, retaining Map and Gate. The Windows
finite Recon result retains its original source boundary below; the required existing
Ubuntu Full/Mapless workflow enforces installed compatibility before integration.
Earlier Full/Mapless results retain their exact source boundary.

| Requirement | Verified boundary / remaining work |
|---|---|
| Full install and research workflow | Fresh Ubuntu one-command source install, trusted HTTPS, six installed Gate scenarios, evidence/finding/retest/report and restart passed. Configured Windows Docker Desktop Full journey passed. |
| Independent Mapless workflow | Install, separate private issuer, interactive authorization, bounded five-GET native execution, terminal evidence, redacted export and identical re-export without execution replay passed on Ubuntu and configured Windows Docker Desktop. Map is absent. |
| Finite Recon | Runner PR116 provides explicit signed DNS-A to original HTTPS/443 GET-root candidates through the existing controlled Runner. Windows Docker Desktop observed one DNS question, one HTTPS 200 with original Host/SNI, native/journal DONE and identical redacted re-export without further requests. Broader discovery and automatic Gate execution are not accepted. |
| Distribution lifecycle | Full controlled update, interrupted-install resume, backup/recovery, failed migration and certificate renewal passed in the existing Ubuntu jobs. Windows Full and Mapless portable recovery subsequently passed with retained exact images, state and new isolated projects. |
| Cross-platform installation | Windows/Linux script compatibility passed. Windows 11 Docker Desktop canonical Full/Mapless installation passed from new private checkouts, with existing prerequisites and retained Docker resources. This is an existing-host installation result, not OS provisioning. Native components remain available; integrated native installation is unverified. |
| Installation and CLI entrypoints | Thin `install.ps1` / `install.sh` select Full or Mapless interactively or explicitly. `runner.ps1` / `runner.sh` delegate to the same Python transfer/CLI workflow. PowerShell parsing and Bash syntax checks passed; installed Python workflow evidence is reused. Full selection refuses an existing Mapless checkout. |
| State preservation and transition | Separate Full/Mapless installations, original journal/evidence, portable exports and mode-aware backup preserve data. This meets the charter's minimum non-destructive transition: Mapless history stays in its original installation and is exportable. Optional import/sync and automatic mode conversion remain deferred. |
| Mapless controlled update | PR72 uses the existing backup/rehearsal/updater flow and immutable Runner image. A Windows Docker Desktop update preserved exact protected state, the original completed Recon run and all three export hashes; source and rehearsal Runners stayed stopped. Storage migrations require separate review. |

Exact-head [Compose run 42505203697](https://github.com/VardrSec/VardrSec/actions/runs/42505203697)
passed installation, Full and Mapless workflows, portable recovery/migration failure,
controlled updates, Windows/Linux compatibility and renewal. All five PR workflows
passed at `c376699719c0a899da04207dfd4396a21eaf5e8c`; merged main
`e72d7170285b48d866a271dabc8306c1ab7de2bb` has the same tree.
Windows observations used private configured projects and explicit unused networks;
existing data, image aliases and retained networks were preserved.

Windows installation/recovery at `be86d750e84f77219a430d67d56bf1585a769eb9`
used the production CLI without a private Compose adapter: fresh Full install,
CA/hostname-verified readiness, normal stop, fresh Mapless install with an explicit
unused bridge, then backup/restore of the earlier stopped synthetic installations.
Full restored database and all volume fingerprints; Mapless restored Runner state
and exported its original run with the same three hashes. No assessment was run or
replayed, no host trust store changed, and all six scoped projects were stopped
with volumes retained. Private receipt SHA256:
`fdaefdac4679abf9ce5948f86c01fd86ba6d6dc35bff8ce6dc2b768727aa35f9`.
The earlier refused attempt found Docker stopped before configuration or resource
creation; its receipt is retained separately. Docker was resumed before this pass.

Recon's bounded installed observation used distribution `fb610bf`, Runner
`dfcd8f2a48eca451f91e2f5b06a636f5c393100d` and unchanged Gate `57cfedf` in a new
canonical Mapless installation on Windows 11 Docker Desktop. The synthetic target
observed exactly one UDP A question and one HTTPS GET with the approved Host and
TLS SNI; the response was 200. The original journal and native owner acknowledged
DONE. All three redacted export files were byte-identical on re-export, with
unchanged request counters. Both synthetic targets were stopped; state and the
earlier held attempt remain retained. That earlier attempt sent no requests:
DNSx rejected incompatible file/stream flags, corrected before the successful
fresh authorization. Neither consumed authorization was replayed.
Private receipt SHA256:
`05da6c425c1c81abd8d8294eefaf3544647fa245b0af98e91d8dd06a4ffa0de4`.
This establishes the finite profile on Linux containers under Windows Docker
Desktop; it does not claim native Windows DNSx/HTTPx or broader Recon acceptance.

The Mapless update observation used distribution `bd7f1cd` and Runner PR117 head
`ea4265a` against the retained completed Recon workspace. Backup and restored
rehearsal were verified; candidate diagnostics ran on offline disposable copies
after Runner's existing noncreating schema check. Protected source/rehearsal state
fingerprints were unchanged. The original run's three exports remained byte-identical
after application. Both canonical Runners stayed stopped. Two earlier pre-apply
refusals and their verified cancellations remain retained: an unsupported Compose
flag, then SQLite WAL/SHM housekeeping. The correction preserves exact state checks
without adding SQLite machinery. Private receipt SHA256:
`e1706ee84789cf1e45a91fd7a1c83a2432121d15dcdf42d2b4b82dcd7d3b7602`.

The installation/distribution implementation has canonical Windows and Ubuntu
evidence. Justified native Runner operation retains its documented platform and
network limitations; an integrated native Full stack is not required by the charter.
Automatic import/sync is a separately gated increment, and broader Recon remains
unaccepted. C09 sleep remains unaccepted under NM-2;
the owner stopped further manual fault/sleep testing. No release, image publication,
security-risk acceptance or completion of NM-4/NM-5 is implied.

The sections below retain historical evidence and earlier open-gate statements.
This current status takes precedence where later merged work supersedes them.

## Fresh source baseline

Recovery was limited to reachable Git source. The unavailable handoff commits
`f605c1f` and `3cdbaa4` are not assumed to have been recovered or reproduced.
Existing security and NM-3 implementation were retained; new checks establish
their behavior independently of historical test counts.

| Component | Source used for fresh baseline | Evidence boundary |
|---|---|---|
| Runner | `96772dd5403653c7e4786c8906e6ea4d9fc6e396` | Native Windows 11, Python 3.14.3: 2,415 passed, 66 skipped, 95.24% coverage. |
| Distribution | `4998e5dfd1554beec88690880c4ac269d4f12240` | Baseline unit suite: 162 run, one CRLF-fixture error, 12 skipped. |
| Map | `45d4286190039462b942a69615214d6e480fb0ee` | Fifteen owned-execution/claim checks on disposable SQLite. |
| Gate | `2df03368007e7b632f2fbaf2ecdcfb7bb6efe0ec` | Pure-Go suite: 762 test/subtest passes across 21 packages; vet and native build passed. |

The exact Map/Runner/Gate baseline cohort also passed 152 real loopback integration
checks, including strict semantic evidence and platform diagnostics. Request bounds
and loopback-only assertions passed. These results do not establish a PostgreSQL
installation, a managed background worker or Docker Desktop distribution acceptance.

Earlier test attempts exposed environment setup failures: sandboxed loopback access,
snapshot/import mismatch and missing declared shell dependencies. They were corrected
and rerun, without suppressing the affected tests. Keep the failing receipts distinct
from the successful baseline. Skipped checks retain their individual reasons.

## Verified development corrections

Runner commit `440ebda7405d9f19f2e5c6f954996b525f0ac5da` passed the fresh native
Windows 11 suite: **2,474 passed, 66 skipped, 95.32% coverage**. The same source
passed Linux container regression as nonroot with networking disabled: **2,491
passed, 49 skipped, 95.69% coverage**. The real POSIX directory-substitution
regression passed. Lint, formatting, both platform type checks and medium/high
security checks passed. All nine jobs in the existing
[cross-platform CI run](https://github.com/VardrSec/VardrRunner/actions/runs/42097439568)
passed, including Linux Python 3.10–3.14, Windows, macOS and dependency audit.

- Full installation must preserve retained proxy CA/config state even if database
  and Runner volumes are absent. A new regression failed before the correction;
  the distribution suite afterward ran 163 tests with no failures/errors and 12
  skips. Four skips need official `age` tools; eight need native symlink privilege.
- Journal connections use canonical DB/WAL names. Windows retains verified
  database/ancestor handles through connection close and refuses observed identity
  changes. POSIX replacement, sidecar replacement and strict snapshot safety remain
  open; see Runner ADR 0042.
- Automatic age cleanup preserves journal-linked evidence and refuses incomplete
  retention inventory. Destructive cleanup requires supported descriptor-relative
  confinement; unsupported runtimes preserve old data while execution remains usable.
- Separate-process CLI tests verify local workspace persistence without Map
  credentials, a real keychain, network access or tool launches.
- The real native standalone Gate check passed with the built Gate binary: all five
  phases, fourteen bounded requests, preserved case binding, no Map calls and no
  additional replay traffic. Active cancellation has separate acceptance tests.

The installer correction is distribution commit
`9e4b56f2f4b4e99891dbf8d2b7004bfa8a63beb7`. No distribution component pins have
advanced.

## Current compatible source verification

The initial PostgreSQL cohort used these exact Git-archived sources:

| Component | Commit |
|---|---|
| Map | `aad63c8151789cd9bf56864456b5fdf1fdcfde41` |
| Runner | `440ebda7405d9f19f2e5c6f954996b525f0ac5da` |
| Gate | `2df03368007e7b632f2fbaf2ecdcfb7bb6efe0ec` |

All 103 PostgreSQL migration, restricted-role, ownership, cancellation, grant and
budget/concurrency tests passed without skips. The strict real integration passed
152 checks against a migrated disposable PostgreSQL 18.6 database. TLS 1.3 with
full certificate/hostname validation passed; plaintext, wrong-hostname and
untrusted-CA connections refused. The fixture used isolated tmpfs data and a random
localhost port and was removed after identity checks. Retained installations were
not used as test fixtures.

Gate's complete Linux race suite passed all 21 packages and `go vet` passed with
Go 1.27.3 and a 64-bit compiler, using frozen source and offline module cache.
An extra offline `go mod verify` check lacked historical module metadata; that
limitation is recorded separately from the successful race/vet results. Native
Windows race-detector execution remains unavailable with the installed compiler.

That older Gate cohort is verified at source/integration level. It has no fresh
Full or Mapless installation/recovery acceptance as an installed distribution.
The existing [Gate duplicate-JSON guard correction](https://github.com/VardrSec/VardrGate/pull/29)
at `54536ea1d900d0e35adf93b4e026962c4d45d34a` remains unmerged. Fresh verification
now passes 791 native Windows test/subtest checks across 21 packages, native vet
and build, 791 Linux race checks with vet, the fourteen-request standalone fixture
and all 152 PostgreSQL integration checks with the exact Map/Runner sources above.
The older baseline is not acceptance of the duplicate-key gap.

## Fresh Full installation evidence

The distribution at `befe929870107c5a27d291078088fbceaeb58512`, with Map `aad63c8`,
Runner `440ebda` and corrected Gate `54536ea`, passed one-command Full installation
on a fresh GitHub-hosted Ubuntu 24.04/amd64 VM in
[run 42103819846](https://github.com/VardrSec/VardrSec/actions/runs/42103819846).
The sanitized receipt verifies source commits/trees, successful standard install
steps, CA-validated HTTPS, local login, CSRF rejection without mutation, scoped
Runner key issuance, database/migration readiness and authenticated diagnostics.
Only database, API, web and proxy services ran before and after those checks.

The extended [run 42107206619](https://github.com/VardrSec/VardrSec/actions/runs/42107206619)
also passed all 179 host-side tests without skips, the real browser login/scoped-key
journey, six installed reviewed Gate cases, hashed evidence, write/readback and
retest/report history, stop/start retention, encrypted backup, authenticated unseal
and bundled restore into a separate project. Exact image IDs, schema
`0038managedstops`, original database and three volume fingerprints, original CA,
restored Runner state/evidence, password-reset session revocation and authenticated
restored diagnostics passed. No background Runner service started.

This establishes those Full installation/assessment/recovery boundaries for the
exact development cohort on the tested hosted Linux platform. Mapless, complete
Windows Docker Desktop, managed-worker, upgrade/no-loss transition and active
authority-restoration acceptance remain open;
see [the exact sources and acceptance boundary](nm3-community-full-verification.md).
Production component pins remain unchanged.

The same source cohort also passed a separately scoped actual Windows 11 Docker
Desktop feasibility trial: all five toolkit-cohort images built under unique
tags, trusted HTTPS/login/scoped-key diagnostics passed, and offline workspace
metadata persisted across separate containers. Services stopped with state
retained; original containers and image tags remained unchanged. This used a
private image/resource override, not canonical `install`. Windows installer,
Gate/recon, Mapless and recovery acceptance remain open; see
[the measured boundary](nm3-windows-desktop-feasibility.md).
Four real native Windows `age` file-crypto cases subsequently passed without
skips. Installed Windows backup/recovery did not start: a retained-network
invariant refused an unexplained engine inventory change. Its refusal receipt
is separate from the earlier passing lifecycle result; no guard was waived.

Standalone authoring still lacks an operator-facing context preparation step and
fresh key/trust provisioning. The existing file CLI already signs approvals and
issues contracts; the next usability increment should reuse those paths rather
than add another signer or enrollment service. The execution consumer must stay
separate from private issuance.

## Experimental work, not accepted capabilities

The initial disposable Docker deadline experiment was insufficient. Follow-up
tests found owner/init binding and scheduling interference that could let fixture
writes continue beyond the armed deadline. A scratch additive restriction narrowed
the observed scheduling gap, but complete resource-control, real-tool, lifecycle,
suspend/resume, authorization and evidence acceptance did not run. Further
adversarial testing encountered a tool safety block. No product containment code
or recon capability was enabled; managed Docker execution remains gated.

Separate Windows and Linux scratch probes can copy closed, checkpointed SQLite
journals while excluding new connections and refusing retained sidecars. They do
not establish active-WAL capture, export freshness or private temporary-storage
safety across supported platforms. No snapshot flag or product API was added.

## Accepted direction and remaining work (historical checkpoint)

The table and sequence below retain the earlier checkpoint. The current NM-3
closeout and NM-4 candidate sections above supersede their phase-status wording;
they do not erase earlier limits or unresolved evidence.

| Gate | Current disposition | Required completion evidence |
|---|---|---|
| NM-1 | Substantial reusable groundwork; full exit not reaccepted by this ledger. | Shared contract/negative fixtures and deployment-feasibility decision tied to exact source. |
| NM-2 | Bounded Community baseline retained; original exit remains open. | Safe operator-enabled Compose worker, cancellation, disconnect/restart, grants and budgets. |
| NM-3 | Fresh Linux Full installed assessment/recovery and native/Windows feasibility evidence; incomplete. | Complete Full/Mapless installation, authorized recon plus reviewed Gate, independent operator CLI, no-loss transition, Windows/Docker and cross-platform acceptance. |
| NM-4 | Sequenced after usable execution/distribution; still required. | Reviewed authorization coverage, assisted cases, structured provenance and bounded AI capabilities. |
| NM-5 | Final integrated acceptance remains open. | Independent benchmarks, frozen-cohort install/network/recovery matrix, supply-chain review and owner release decision. |

Recon and managed Docker execution remain disabled until their safety gates pass.
They are unfinished accepted requirements, not removed scope. Windows Server CI
does not substitute for fresh Windows 11 Docker Desktop acceptance. A passing
SQLite fixture does not substitute for the PostgreSQL ownership/migration path.

Mapless-to-Full automatic history import/synchronization may be a separate increment;
preservation and export are mandatory. NM-4/NM-5 remain in New Moon. New enrollment
services, replacement scanners and orchestration infrastructure require a demonstrated
gap in the existing components before implementation.

## Next acceptance sequence

1. Close POSIX/container containment and consistent non-mutating snapshot gates.
2. Build on the passing Linux Full installed assessment/recovery and actual Windows
   Docker Desktop feasibility. Complete Windows recovery and canonical installation,
   preserving retained images/state and the remaining controlled-execution gates.
3. Advance distribution pins only with the reviewed installed-acceptance evidence.
4. Demonstrate Mapless install → authorize → recon → reviewed Gate → export/restart
   with Map inaccessible, and Full installation → approved queue → cancel/recover.
5. Complete Windows 11 Docker Desktop, Linux, recovery and native-exception evidence,
   then continue NM-4 and NM-5 against that same reviewed product.

Current unit/integration evidence is not permission to merge, release, publish
images, alter retained installations or waive a safety gate.

# Distribution acceptance plan

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

- One distribution download installs the pinned components without three source
  checkouts and starts the local UI/API/database with explicit secret setup.
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
- Test supported Linux/macOS/Windows environments, resource use, host-local/VPN
  target reachability and declared outbound traffic. Measure time to the first
  correct reviewed authorization test and assistance required.

Map's self-signed HTTPS browser fixture tests authentication and session behavior;
it does not establish trusted first-install acceptance. The distribution remains
unreleased until the above trust checks pass without certificate-error overrides.
Local authentication is defined in Map [#111](https://github.com/VardrSec/VardrMap/pull/111)
and its browser integration in [#112](https://github.com/VardrSec/VardrMap/pull/112).


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
The tool image verified all nine managed binaries and contained Gate and nmap.
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

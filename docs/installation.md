# Full installation and first assessment

This is the canonical **Full** source-built installation path: Map, Runner, Gate,
PostgreSQL and a local HTTPS proxy. For the CLI-only alternative, follow the
[Mapless walkthrough](mapless.md) instead. Do not run both installers in the same
checkout. Neither mode is a published Community release.

The database source build uses a disposable QEMU/TCG guest inside the Docker
build stage to run the unchanged Debian Kerberos tests under ordinary guest
kernel policy. No host VM configuration, devices or security-policy changes are
needed. Allocate at least 4 GiB guest memory plus Docker/build overhead; the
first uncached database build can take tens of minutes. The Full CLI builds
the database first, then builds application images using its normal cached layer. See the
[build evidence and boundaries](../qualification/kerberos-image/README.md).

## 1. Check prerequisites and clone

Windows 11 Docker Desktop with Linux/amd64 containers is the primary Community
target; Ubuntu 24.04/amd64 is also documented. macOS Docker Desktop remains
experimental. See [platforms](platforms.md) and [support limits](limitations.md).

Install Git, Python 3.10+ and Docker with Compose 2.17+ first. Docker must be
running and accessible to your account. Use a private local directory outside
shared/synchronized folders. The installer does not install system packages,
change Docker access, host routes or firewall/VPN settings. Docker administrators
can read container environments and persistent volumes.

Check your Python version (`py -3 --version` on Windows or `python3 --version`
on Ubuntu), `git --version`, `docker info` and `docker compose version`.
The separately enabled [managed-worker path](local-managed-setup.md) has additional
Docker/Compose requirements; the ordinary installation floor does not qualify it.

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec-full
cd vardrsec-full
```

For coexisting installations choose a distinct `COMPOSE_PROJECT_NAME` before
installation, plus non-overlapping ports/networks as described under
[configuration reference](#configuration-reference). Do not reuse retained state
with fresh credentials.

## 2. Install Full

Windows PowerShell:

```powershell
.\install.ps1 --full
```

Ubuntu:

```sh
./install.sh --full
```

Both launchers call the same Python installer. The direct equivalents are
`py -3 vardrsec.py install --full` and `python3 vardrsec.py install --full`.
Installation configures fresh secrets, prepares exact component sources, builds
and freezes images, prepares the database role, starts core services and exports
the public CA. It never starts a scan or managed worker. A plain
`docker compose up -d --build` is not a fresh-install substitute.

If interrupted before installation state exists, fix the cause and retry the
same installer. It preserves existing configuration and source checkouts. Once
state volumes exist, installation refuses: use the failed step or `start` rather
than deleting state. If services started before CA export failed, run
`python3 vardrsec.py export-ca` (Windows: `py -3`) and continue below.
See [installation safeguards](#installation-safeguards) for the exact boundaries.

## 3. Trust the local CA and create an account

Compare the fingerprint printed by `export-ca` against your local certificate
before explicitly enrolling **your own** CA using the
[platform-specific trust instructions](#explicit-certificate-trust) below.
Trust enrollment is deliberately manual. Never bypass a certificate warning.

Then create the first account:

```powershell
# Windows
py -3 vardrsec.py bootstrap --username operator
```

```sh
# Ubuntu
python3 vardrsec.py bootstrap --username operator
```

Enter a passphrase privately, restart your browser and sign in at
`https://localhost:8443`. Firefox or another browser with a separate trust store
may need the same public CA imported explicitly.

## 4. Connect Runner and perform the first assessment

Follow [bootstrap and diagnostics](#bootstrap-and-diagnostics) to generate a
Runner-only key and check contact. Then follow the
[first-assessment walkthrough](#first-assessment-walkthrough) for the explicit
manual Gate workflow. Queueing alone does not execute work.

For controlled managed execution, finish Full setup first, then follow
[local managed setup](local-managed-setup.md). It is a separate opt-in Gate-only
workflow with signed job approvals and local credential grants, not a prerequisite
for the manual walkthrough or permission to run arbitrary queued scanners.

For day-to-day use, `start` reuses core state and `stop` retains volumes. Stop and
reconcile a separately enabled worker **before** stopping core services. Use
[recovery](recovery.md) and [controlled updates](updates.md) for retained installs,
not a fresh installer or `down --volumes`.

## Configuration reference

The rest of this guide documents configuration, trust, diagnostics and safety
boundaries for that same installation. Commands use Ubuntu's `python3`; replace
it with `py -3` on Windows (or a verified Python 3.10+ `python` command).

Configuration creates random database/signing secrets and refuses to overwrite
`.env`. Protect it with user-only permissions/ACLs. Never commit it or print
`docker compose config` output in shared logs. Source acquisition uses exact
manifest pins and refuses dirty/different checkouts; advanced source overrides
are not the standard fresh-install path.

For separate Full installations, choose a distinct `COMPOSE_PROJECT_NAME` before
`install` or `configure` (`export COMPOSE_PROJECT_NAME=assessment-local` on Linux,
`$env:COMPOSE_PROJECT_NAME='assessment-local'` in PowerShell). New configuration
retains this explicit name across shells and assigns installation-specific build
tags for all five images. Existing configuration keeps its previous tags. Keep
the checkout and `.env` together; changing the project name selects different
volumes rather than moving data. Separate Full installations also need distinct
HTTPS ports and non-overlapping application networks as described below.

The one-command Full installer freezes all five built image IDs before starting
the database. It retains the project and selects distinct unused database/Runner
bridges. It keeps the shipped application subnet when free; if that default
overlaps retained Docker networks, it selects an unused subnet from the existing
recovery range. Explicit application subnet/range/proxy settings are preserved
and must be non-overlapping. Existing Docker resources are never deleted to make
room. These checks concern Docker subnets, not host/VPN route qualification.
An interruption before the first state volume can reuse the validated frozen
selection without rebuilding. Once state exists, use the failed step or `start`
as described above. A frozen installation's `build` refuses; use a separate build
workspace and the controlled updater for image changes.

For an existing installation, skip `configure`; it preserves and refuses to
replace `.env`. An installation made before the least-privilege database role needs the
one-time upgrade in [database-roles.md](database-roles.md) (back up first, then
`database-role --backup DIR`) before `start`. Lost credentials require the documented recovery process, not
fresh signing/database secrets. If the first source download is interrupted,
rerun `sources`: an empty initial Git repository can resume. A checked-out revision
or user files are never reset to force a retry. Preserve differing checkouts.
Build replacement images in a separate source workspace, then use the
[controlled updater](updates.md) from the retained installation. Do not start a
newly configured workspace against retained volumes with different credentials.

The only published port is `127.0.0.1:8443`. UI: `https://localhost:8443`; API:
`https://localhost:8443/backend`. Backend/database ports are not published. The
isolated database bridge explicitly uses plaintext PostgreSQL; browser and Runner
traffic validates HTTPS. This is a single-host deployment boundary, not encrypted
cross-host database transport. Application-network subnet 172.30.248.0/24 reserves
172.30.248.2 for the proxy; if this overlaps a host/VPN network, change
APPLICATION_SUBNET, APPLICATION_IP_RANGE and PROXY_IP in `.env` before first startup. If HTTPS_PORT changes,
rebuild the frontend. Bindings remain loopback-only.

## Explicit certificate trust

Caddy generates an installation-specific CA in its persistent proxy-data volume
and renews leaf certificates. Compose cannot enroll the host browser's trust store.
The documented checks do not qualify every certificate lifecycle scenario; see
[support limits](limitations.md).
Only `trust/root.crt`, the public root, is exported; its private key stays in the
proxy volume, which must never be mounted in Runner. Verify the certificate and its
fingerprint against the local proxy before trusting it. Enroll only your own CA.
`export-ca` prints the public certificate's SHA256 fingerprint for comparison
with your certificate viewer or `openssl x509 -in trust/root.crt -noout -fingerprint -sha256`.

Windows (PowerShell, current user only):

```powershell
$cert = Import-Certificate -FilePath .\trust\root.crt -CertStoreLocation Cert:\CurrentUser\Root
$cert.Thumbprint  # record this for removal
```

Complete the Windows consent prompt. For unattended administrative provisioning,
an explicitly elevated PowerShell can use `Cert:\LocalMachine\Root` instead;
that trusts the CA machine-wide and requires removal from the same store. The
native CI test exercises this administrative alternative, not the interactive
CurrentUser consent UI.

macOS (explicit privileged trust enrollment):

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain trust/root.crt
```

Debian/Ubuntu:

```sh
sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
sudo update-ca-certificates
```

Restart the browser. Browser-specific stores (including some Firefox/Linux setups)
may require importing that same public CA through their certificate settings. Stop
if the ordinary URL shows a certificate warning; do not bypass it. Verify the API with a client that accepts an explicit CA bundle:
`curl --cacert trust/root.crt https://localhost:8443/backend/ready`. Windows curl
using Schannel may additionally reject a local CA without revocation metadata;
use the CA-validating Runner check after enrollment rather than disabling checks.
The installer does not execute trust enrollment automatically.

If Firefox keeps a separate store, use Settings → Privacy & Security →
Certificates → View Certificates → Authorities → Import, select `trust/root.crt`
and trust this CA to identify websites after verifying its fingerprint. Other
browser profiles must enroll that same public certificate through their own CA
settings. A new browser process must open the ordinary URL without a warning.

The disposable Ubuntu installation check records a clean host before configuration,
source acquisition and builds, then verifies native curl rejection, explicit OS
trust enrollment, ordinary HTTPS and rejection after exact certificate removal.
The installed browser fixture independently uses a fresh, explicitly enrolled NSS
profile. These checks do not replace the unfamiliar-user usability exercise.

The native trust workflow exercises enrollment and
removal on disposable hosted Windows/macOS machines. Full Docker Desktop/fresh-host
application acceptance remains separate from those certificate-store checks.

Remove trust when retiring the installation: Windows `Remove-Item` on the exact
recorded `Cert:\CurrentUser\Root\THUMBPRINT` (or `LocalMachine` when enrolled there);
macOS `sudo security delete-certificate -Z THUMBPRINT /Library/Keychains/System.keychain`
with the exact recorded fingerprint. This removes the certificate. The `-t` option
also requests trust-settings removal, but can hang in non-interactive hosted macOS
sessions; complete and verify that cleanup interactively with Keychain Access.
The native CI check requires browser rejection after certificate deletion and
reports residual trust metadata separately. Linux: remove only
`/usr/local/share/ca-certificates/vardrsec-local.crt` then run
`sudo update-ca-certificates --fresh`. Remove browser-specific imports separately.
Do not delete a CA still used by another retained installation.

## Bootstrap and diagnostics

After trust enrollment, run `python3 vardrsec.py bootstrap --username operator`.
Enter a passphrase in the terminal; bootstrap is one-time. Log in through the UI,
then open Settings → Connect Runner → Generate Runner Key. This creates a dedicated
Runner-only key and displays it once; copy it into your private terminal when
prompted below. Supply VARDRMAP_API_KEY through
your shell environment when invoking `python3 vardrsec.py doctor`; do not put the key
in shell command arguments or an image. Runner mounts only the public CA read-only.
The initial local user retains the normal organization/ownership permission rules.

Alternatively, in a private terminal, generate a secure password instead of typing
one: `python3 vardrsec.py bootstrap --username operator --generate-password`.
Store the displayed password securely; it is shown once. Do not record terminal
output containing it in shared logs. The default bootstrap remains interactive.

In Windows PowerShell, read the Runner key privately and send a one-shot report:

```powershell
$key = Read-Host 'Runner API key' -AsSecureString
$env:VARDRMAP_API_KEY = [System.Net.NetworkCredential]::new('', $key).Password
py -3 vardrsec.py doctor
.\runner.ps1 heartbeat
```

This keeps the key out of command history, but it is still present in the process
environment while needed. Clear it with `Remove-Item Env:VARDRMAP_API_KEY` when
finished. Target credential references for the manual assessment can be supplied
using the same private prompt pattern; never put their values in command arguments.

On Ubuntu/Bash, provide the Runner key without putting it in shell history or
command arguments, then invoke the existing diagnostics and one-shot report:

```bash
read -rsp 'Runner API key: ' VARDRMAP_API_KEY
export VARDRMAP_API_KEY
echo
python3 vardrsec.py doctor
python3 vardrsec.py runner -- heartbeat
```

The doctor command delegates to Runner, retains JSON on stdout and confirms
success on stderr. A failing check remains nonzero; follow its remediation before
testing. Sign in at `https://localhost:8443` and confirm Settings shows API/database
readiness and recent Runner contact. Neither command claims image-security
clearance or starts scans. `unset VARDRMAP_API_KEY` when the shell no longer needs
the key.

Settings displays API/database readiness and Runner reports with observation times.
Use an explicit Runner heartbeat to report contact/tool versions; the status view
does not run a worker or invoke diagnostics. Reports expire after five minutes,
fetched observations after one minute, and failed/unsupported checks remain
unreachable or unknown. A recent heartbeat is not complete tool/network acceptance.

Runner is excluded from ordinary startup. The tool-enabled image includes Gate,
libpcap (for naabu, the port-discovery tool; Nmap is not packaged) and Runner's checksum-verified managed tools. Managed tools live in
read-only image storage, separate from persistent Runner state. Native/keychain
operation remains available. Raw-packet scans, headless-browser tooling, operator
wordlists and nuclei template provisioning are not certified by this baseline.
No capability or privileged mode is enabled automatically. Diagnose the intended
tools and host/VPN target reachability before explicitly invoking `jobs run`.
The tool/network fixture documents selected modes,
synthetic private-namespace/host checks and the remaining real-VPN/Desktop gates.
See [networking and VPN guidance](networking.md) for choosing native or container Runner.

`python3 vardrsec.py stop` stops services and retains all volumes. `start` reuses
them. Never use `down --volumes` on a retained installation. Core start/stop commands do not start scans; explicit execution commands do.

## First assessment walkthrough

Use only a target you own or are explicitly authorized to test. Everything below
except the last step happens in the browser at `https://localhost:8443`.

1. **Engagement.** Create an engagement. For a pentest or internal assessment,
   choose a client when creating it, or add one later in step 2.
2. **Client, window and authorization.** On the engagement's Overview, use
   *Client & testing window* to create or link the client and set the window, and
   *Written authorization* to record who authorized the work and what it permits.
   This manual workflow records scope and authorization; its scope/window checks are advisory (stop-work refuses execution). Controlled managed execution has separate enforced authorization checks; see [managed setup](local-managed-setup.md).
3. **Scope.** Open Scope and add the target as an in-scope asset.
4. **Identities and cases.** Open Review → API Surface and generate draft cases from
   your OpenAPI document. Drafts are review-only: edit each access decision for
   every identity yourself and tick the review confirmation before saving. Identities
   reference credentials by environment variable name (for example
   `"value_env": "OWNER_TOKEN"`); never paste a token into a case.
5. **Queue.** On the Dashboard choose the `vardrgate` tool, select your saved case and
   queue the job. Queuing runs nothing.
6. **Run it explicitly.** In a private terminal, supply the Runner key and the
   identity tokens, then claim and execute the queued job once:

```bash
export VARDRMAP_API_KEY OWNER_TOKEN PEER_TOKEN   # set beforehand without echoing them
python3 vardrsec.py runner --env OWNER_TOKEN --env PEER_TOKEN -- jobs run
```

   `--env NAME` passes one variable from your shell by name; its value never appears
   on a command line. A target on a private or loopback address also needs
   `VARDRRUNNER_ALLOW_PRIVATE_TARGETS=1` passed the same way
   (`--env VARDRRUNNER_ALLOW_PRIVATE_TARGETS`), which is a deliberate opt-in. The
   container cannot reach a host-only or VPN target; see [networking](networking.md).

   `python3 vardrsec.py runner -- <command>` runs any Runner command once in the
   installed Runner image, the one recorded after a controlled update or restore.
   Use it rather than a plain `docker compose run`, which builds or reuses the
   development-tagged image instead. Everything after `--` goes to Runner.
7. **Review.** Back in the browser, the job shows its assessment status and evidence.
   Results are candidates: confirm or reject each finding yourself, link the
   supporting evidence, then draft and export a report.

`inconclusive` is not a pass. It means an expectation could not be judged, for
example a rejected credential or an unavailable resource.

## Updates and recovery boundary

Use the [controlled updater](updates.md) for an explicitly reviewed local image
set. Application startup applies migrations, so replacing an image is an upgrade
operation. Before any upgrade,
stop API/web/Runner activity, make a PostgreSQL logical backup plus a protected
backup of `.env`, Runner state and proxy-data/config, and prove restoration into
a separate installation. Protect CA private keys and credential hashes in backups.
Keep old image IDs/source pins and matching backups together. A failed migration
requires a compatible restore; image rollback alone is not a database rollback.

Use the [backup and restore commands](recovery.md) to create a portable snapshot
and verify it in a separate installation before any controlled upgrade. Restored
applications remain stopped until credential review and explicit startup.

Windows 11 with Docker Desktop is the primary Community
target; Linux compatibility remains required. Older Ubuntu-first checkpoints
are historical. Certificate lifetime coverage, broader tool/network modes and
real VPN retain their documented [support limits](limitations.md).
No image or release is published here.

## Installation safeguards

The fresh-install guard asks the existing Compose frontend to resolve the selected
Full model with all profiles and normal interpolation, as used by installation.
Compose determines the project
identity, including `.env` and process overrides; the guard does not parse `.env`
or provide placeholder secrets. Trusted Compose reads/interpolates configuration and service
environment files internally. Its output and errors are captured, never printed or
saved by the guard. Missing configuration, resolver failure, malformed output and
unsupported mappings refuse before installation steps or volume inventory.

Only the shipped Full service/state layout is recognized: default project-scoped
volume names, the database and Runner state mounts, proxy state and the existing
read-only trust/Caddyfile binds. Custom volume names, external/driver mappings,
additional mounts/services and unresolved paths refuse. Existing `.env` files are preserved and an interrupted installation
can still resume when the selected supported model resolves and none of its four
state volumes is observed. Retained proxy state also prevents fresh installation:
its CA identity and configuration belong to the existing installation, even when
the database and Runner-state volumes are absent. Preserve it and use recovery.

For a fresh checkout without `.env`, one-command Full installation is restricted to
this revision's exact shipped `compose.yaml` (LF or CRLF) without an active-image
override. Alternate `COMPOSE_*` settings are refused except `COMPOSE_PROJECT_NAME`.
Custom layouts receive a refusal with recovery/clean-checkout instructions; do not
remove configuration or volumes to bypass it. Configured recovery and update paths
are unchanged.

The installer generates the normal configuration once in memory. Preflight supplies
these prospective defaults to trusted Compose while preserving process-variable
precedence. It resolves and checks the standard state mappings and inventories the
expected volumes before creating `.env` or `trust`. Only after a successful check
does the existing exclusive writer persist those same generated values. The process
environment is not changed. Observed layout/configuration changes refuse; exclusive
creation never overwrites a newly appeared `.env`. This does not prevent arbitrary
concurrent writers or prove absence of other/native/external state.

The standard-layout fingerprint is a compatibility boundary, not a signature or
hostile-file sandbox. Changes to the shipped model require coordinated review.
Interrupted installs with complete existing configuration retain the normal resume
path; incomplete required configuration still refuses rather than regenerating keys.
The separate Mapless installer recognizes its exact shipped one-service model
and refuses existing state from either mode. Its controlled one-job adapter is
an explicit selection; ordinary startup never enables it.

The subsequent bounded Docker inventory checks all four resolved state-volume
names without reading contents. Inventory failures refuse. Absence of those
names does not establish absence of native state, operator-selected evidence,
other projects or external writers. Configuration and inventory are point-in-time
observations, not protection from concurrent changes. Synthetic resolver tests do
not establish installed acceptance across Compose versions. This is not a migration,
backup/revocation reconciliation or no-loss upgrade check; preserve existing state
and use a reviewed transition procedure.


### Source cache safeguards

Source preparation also checks Git's read-only resolved worktree, absolute
metadata directory and common metadata directory against each managed component
directory and its `.git`. Shared `commondir` indirection outside it is refused.
This refuses a plain `.git/config` with redirected `core.worktree`, not just
filesystem links. Existing selected repositories are checked before preparation;
newly initialized repositories are checked before fetch/checkout. Unavailable,
malformed or mismatched binding observations refuse without rewriting config or
touching outside files. Git/user configuration remains trusted operator input:
this is not a sandbox for arbitrary hostile Git settings or concurrent mutation.
The directory-query semantics are documented in
[Git rev-parse](https://git-scm.com/docs/git-rev-parse).

Managed source preparation refuses observed symlinks/reparse points at `.sources`,
selected component directories and `.git`, and refuses `.git` files (including
worktree metadata references). All selected paths are checked before the first Git call.
Links and outside files are retained; use a fresh private cache rather than
deleting or rewriting them. These are point-in-time checks, not a guarantee
against concurrent ancestor/cache replacement. Keep the checkout exclusively
under trusted operator control during preparation; native Windows junction and
concurrent-race acceptance are not established by synthetic marker tests.


## Full and Mapless selection

`python3 vardrsec.py sources --mapless` prepares only the existing exact Runner
and Gate source pins. It needs Git and component-source access, but does not fetch
Map, create `.env`, configure PostgreSQL, build/start containers or run tools.
Existing different/dirty source caches are preserved and refused as before; an
existing Map cache is not inspected or changed by this selection. Bare `sources`
continues preparing Map, Runner and Gate for Full.

`install --mapless` now selects the standalone model in a clean checkout and
persists the selection for build/start/stop/Runner/backup. Unmarked installations
retain Full behavior. See the [standalone walkthrough](mapless.md) for private
issuer custody, signed one-job execution and export. Compatible pins and actual
Windows/Linux installed acceptance are tracked separately. Arguments after the
`runner --` separator still belong to Runner. No automatic Full/Mapless state or
authority migration is implied.

# Development Compose installation

## Quick start (source-built, not an official release)

Tested on Ubuntu 24.04 amd64 with Docker, Compose, Python 3.10+ and Git already installed
(`docker compose version` must work for your user). CI runs these steps on a clean hosted
Ubuntu 24.04 machine; the unfamiliar-user, zero-prerequisite run has not been done.

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec
cd vardrsec
python3 vardrsec.py install            # configure, sources, build, start, export-ca (several minutes)
sudo install -m 0644 trust/root.crt /usr/local/share/ca-certificates/vardrsec-local.crt
sudo update-ca-certificates            # trust only your own CA; compare the printed fingerprint first
python3 vardrsec.py bootstrap --username operator
```

If `install` is interrupted (network drop, full disk, Docker error), fix the cause and run
`python3 vardrsec.py install` again. It resumes: your `.env` secrets are kept, source checkouts
are continued and never reset, and image builds reuse their cache. Nothing is deleted. Once
the platform has been started, `install` refuses to run again (use `start`, `stop` and the
controlled updater); if it stopped after the services started, run `python3 vardrsec.py
export-ca` and continue with the steps above.

Then open `https://localhost:8443` (restart the browser; Firefox needs the CA imported in its
own settings) and sign in. The CA step is manual on purpose: it changes your machine's trust
and VardrSec never does that for you. A plain `docker compose up -d --build` does not work on
a fresh clone because the secrets file and the pinned component sources do not exist yet;
`install` creates them (and refuses to run over an existing installation). Platform startup
never runs a scan; the first-assessment walkthrough below shows how to run one explicitly.


This is a source-built development installation, not a released Community package.
The first alpha candidate targets Ubuntu 24.04 Linux/amd64. Windows/macOS Docker
Desktop instructions remain experimental until their own full installation
acceptance passes; they do not automatically block a Linux-only alpha.

Prerequisites: Docker with Linux containers and Compose 2.17+ for additional build
contexts, Python 3.10+, Git and access to the pinned component sources. Start
from a private local directory, outside shared/synchronized folders. Docker
administrators can read container environment variables and persistent volumes.

Check `python3 --version`, `git --version`, `docker info` and
`docker compose version`. Docker must be running and accessible to your account.
`build` checks Compose's feature floor and Linux container mode before starting.
Use Docker's [Ubuntu installation instructions](https://docs.docker.com/engine/install/ubuntu/)
if prerequisites are missing. No command changes Docker access, host routes or
firewall/VPN settings automatically.

Commands below use Ubuntu's `python3`; no optional `python` alias is required.
On Windows, use the installed Python 3 launcher (`py -3` or `python`) instead.
Install missing Python/Git prerequisites before cloning; the distribution does
not provision operating-system packages.

Get only the distribution checkout; source acquisition below prepares its pinned
components for you:

```sh
git clone https://github.com/VardrSec/VardrSec.git vardrsec
cd vardrsec
```

For a new installation:

```sh
python3 vardrsec.py configure
python3 vardrsec.py sources
python3 vardrsec.py build
python3 vardrsec.py start
python3 vardrsec.py export-ca
```

Configuration creates fresh random database and signing secrets without displaying
them, and refuses to overwrite an existing `.env`. Protect that file with user-only
permissions/ACLs. Never commit it or run `docker compose config` without `--quiet`
in shared logs. Source preparation checks out exact manifest pins and refuses to
overwrite dirty or different checkouts. Advanced development may supply MAP_SOURCE,
RUNNER_SOURCE and GATE_SOURCE paths to Compose explicitly.

For an existing installation, skip `configure`; it preserves and refuses to
replace `.env`. Lost credentials require the documented recovery process, not
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
See [accelerated leaf-renewal acceptance](certificate-renewal-acceptance.md) for the
renewal/restart fixture and the remaining certificate lifecycle release gates.
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

The [native trust workflow](native-trust-acceptance.md) exercises enrollment and
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

On Ubuntu/Bash, provide the Runner key without putting it in shell history or
command arguments, then invoke the existing diagnostics and one-shot report:

```bash
read -rsp 'Runner API key: ' VARDRMAP_API_KEY
export VARDRMAP_API_KEY
echo
python3 vardrsec.py doctor
docker compose run --rm --no-deps runner heartbeat
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
nmap/libpcap and Runner's checksum-verified managed tools. Managed tools live in
read-only image storage, separate from persistent Runner state. Native/keychain
operation remains available. Raw-packet scans, headless-browser tooling, operator
wordlists and nuclei template provisioning are not certified by this baseline.
No capability or privileged mode is enabled automatically. Diagnose the intended
tools and host/VPN target reachability before explicitly invoking `jobs run`.
The [tool/network fixture](tool-network-acceptance.md) documents selected modes,
synthetic private-namespace/host checks and the remaining real-VPN/Desktop gates.
See [networking and VPN guidance](networking.md) for choosing native or container Runner.

`python3 vardrsec.py stop` stops services and retains all volumes. `start` reuses
them. Never use `down --volumes` on a retained installation. No command starts scans.

## First assessment walkthrough

Use only a target you own or are explicitly authorized to test. Everything below
except the last step happens in the browser at `https://localhost:8443`.

1. **Engagement.** Create an engagement. For a pentest or internal assessment,
   choose a client when creating it, or add one later in step 2.
2. **Client, window and authorization.** On the engagement's Overview, use
   *Client & testing window* to create or link the client and set the window, and
   *Written authorization* to record who authorized the work and what it permits.
   Scope and authorization are advisory records, not enforcement.
3. **Scope.** Open Scope and add the target as an in-scope asset.
4. **Identities and cases.** Open Review → API Surface and generate draft cases from
   your OpenAPI document. Drafts are review-only: edit each access decision for
   every identity yourself and tick the review confirmation before saving. Identities
   reference credentials by environment variable name (for example `${OWNER_TOKEN}`);
   never paste a token into a case.
5. **Queue.** On the Dashboard choose the `vardrgate` tool, select your saved case and
   queue the job. Queuing runs nothing.
6. **Run it explicitly.** In a private terminal, supply the Runner key and the
   identity tokens, then claim and execute the queued job once:

```bash
export VARDRMAP_API_KEY OWNER_TOKEN PEER_TOKEN   # set beforehand without echoing them
docker compose run --rm --no-deps -e OWNER_TOKEN -e PEER_TOKEN runner jobs run
```

   A target on a private or loopback address also needs
   `-e VARDRRUNNER_ALLOW_PRIVATE_TARGETS=1`, which is a deliberate opt-in. The
   container cannot reach a host-only or VPN target; see [networking](networking.md).
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

The [current checkpoint](alpha-checkpoint-2026-10-27.md) separates passed clean
Ubuntu installation/recovery checks from security and unfamiliar-user work still
open. Windows/macOS remain experimental; their fresh Desktop acceptance does not
block a Linux-only alpha. Certificate lifetime coverage, broader tool/network
modes and real VPN remain explicit limitations in [acceptance](acceptance.md).
No image or release is published here.

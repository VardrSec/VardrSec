# Development Compose installation

This is a source-built development installation, not a released Community package.
Prerequisites: Docker with Linux containers and Compose supporting additional build
contexts, Python 3.10+, Git and access to the three component repositories. Start
from a private local directory, outside shared/synchronized folders. Docker
administrators can read container environment variables and persistent volumes.

```sh
python vardrsec.py configure
python vardrsec.py sources
python vardrsec.py build
python vardrsec.py start
python vardrsec.py export-ca
```

Configuration creates fresh random database and signing secrets without displaying
them, and refuses to overwrite an existing `.env`. Protect that file with user-only
permissions/ACLs. Never commit it or run `docker compose config` without `--quiet`
in shared logs. Source preparation checks out exact manifest pins and refuses to
overwrite dirty or different checkouts. Advanced development may supply MAP_SOURCE,
RUNNER_SOURCE and GATE_SOURCE paths to Compose explicitly.

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

After trust enrollment, run `python vardrsec.py bootstrap --username operator`.
Enter a passphrase in the terminal; bootstrap is one-time. Log in through the UI,
then create a dedicated Runner API key in Settings. Supply VARDRMAP_API_KEY through
your shell environment when invoking `python vardrsec.py doctor`; do not put the key
in shell command arguments or an image. Runner mounts only the public CA read-only.
The initial local user retains the normal organization/ownership permission rules.

Runner is excluded from ordinary startup. The tool-enabled image includes Gate,
nmap/libpcap and Runner's checksum-verified managed tools. Managed tools live in
read-only image storage, separate from persistent Runner state. Native/keychain
operation remains available. Raw-packet scans, headless-browser tooling, operator
wordlists and nuclei template provisioning are not certified by this baseline.
No capability or privileged mode is enabled automatically. Diagnose the intended
tools and host/VPN target reachability before explicitly invoking `jobs run`.

`python vardrsec.py stop` stops services and retains all volumes. `start` reuses
them. Never use `down --volumes` on a retained installation. No command starts scans.

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

Fresh-host Windows/macOS/Linux browser trust, certificate renewal over time,
tool/network capability coverage and upgrade/restore acceptance remain release
gates. See [acceptance](acceptance.md). No image or release is published here.

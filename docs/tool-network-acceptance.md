# Tool and network acceptance

This development fixture builds the declared toolkit source pins and exercises
only synthetic local targets. Run it explicitly after building the tools profile:

```sh
python vardrsec.py configure
python vardrsec.py sources
docker compose --profile tools build runner
python tests/tool_network_acceptance.py
```

The dedicated workflow repeats it on fresh Ubuntu 22.04 and 24.04 hosted runners.
Local Windows Docker Desktop runs cover an existing installation, not a fresh
Desktop install. Receipts under `artifacts/tool-network/run-*/` record host/Docker
versions, the actual image ID, declared source pins and per-check results. Build
from those pins before running; the receipt does not infer image source history.

## Bounded coverage

| Check | Required evidence |
| --- | --- |
| Immutable inventory | All nine managed binaries pass Runner integrity verification; Gate/nmap resolve; libpcap is present. |
| Runtime baseline | UID 10001, zero effective capabilities, no-new-privileges, managed tool directory not writable. |
| HTTP tools | httpx sees HTTP 200; Nuclei matches one explicit local template; FFUF finds one path from a two-entry local wordlist. |
| Port tools | Nmap TCP connect and Naabu CONNECT find only the selected fixture port. |
| Crawler | Non-headless Katana emits the fixture's linked `/probe` endpoint. |
| Privilege boundary | Nmap raw SYN mode is rejected without root privileges. No capabilities are added. |
| Private target | A separate internal network cannot reach it; explicitly sharing a private namespace can. |
| Host service | A container reaches a temporary synthetic host HTTP service through `host.docker.internal`. |
| Replacement | A state marker, generated Nuclei/Katana configuration and identical tool inventory survive container replacement. |

Nuclei configuration honors XDG; Katana also requires the legacy `~/.config`
path. The pinned Runner image routes both into its existing backed-up state
volume and discards root-owned build-probe defaults. Tools remain immutable.
The fixture caps request rate, concurrency, tool duration and target requests.
It starts no platform services or jobs and contacts no customer target or public
provider. Its labelled containers, networks and state volume are disposable; it
refuses an existing fixture and removes only objects it created with its label.

## Network interpretation

The namespace holder is an unprivileged sleeping container on a private Docker
network. Sharing it proves explicit namespace handoff and reachability. It does
**not** establish a VPN tunnel, encryption, customer routing, DNS policy, split
tunneling, reconnect behavior or kill-switch enforcement. Real VPN acceptance
still requires an authorized representative environment and target.

Docker Desktop supplies `host.docker.internal`; the local host fixture binds only
to loopback. Native Linux Engine uses an explicit `host-gateway` mapping and binds
only to the default Docker bridge gateway address. Docker's
[Desktop networking guide](https://docs.docker.com/desktop/features/networking/networking-how-tos/)
and [networking reference](https://docs.docker.com/compose/how-tos/networking/)
describe these platform differences. VPN behavior depends on the actual host and
VPN settings; this fixture changes neither host routes nor Docker settings.

## Remaining acceptance gates

| Environment or mode | Status established by this fixture |
| --- | --- |
| Fresh Ubuntu 22.04/24.04 Linux Engine | Automated synthetic tool/network checks in CI; full installed workflow remains a separate job. |
| Existing Windows Docker Desktop, Linux containers | Local synthetic tool/network check; no fresh-host claim. |
| Fresh Windows/macOS Docker Desktop | Not established; retain as a release gate. |
| Genuine host or container VPN | Not tested. |
| Headless browser tools | Browser not provisioned by this toolkit; never inferred healthy from binary presence. |
| subfinder, gau, dnsx, dalfox and provider/DNS-dependent modes | Inventory only; no execution or provider credential claim. |
| Arbitrary Nuclei templates/wordlists | Only the explicit local fixture inputs are exercised. |
| Raw-packet modes | Rejection verified at the ordinary baseline; privileged operation is not certified. |

Nmap documents the distinction between
[TCP connect and privileged raw scans](https://nmap.org/book/scan-methods).
These checks do not grant permissions, install browsers or provider data, publish
images, start scans implicitly, or establish a released compatibility guarantee.

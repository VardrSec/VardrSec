# Networking and VPN guidance (development distribution)

Which Runner to use depends on where your authorized target is reachable from.
VardrSec never changes host routes, firewall rules, VPN settings or Docker network
configuration for you. Start with the question: *can the machine running the
platform reach the target without the platform's help?*

## What is verified, and what is not

| Situation | Status |
| --- | --- |
| Container Runner reaches a synthetic service on the Compose network, a shared private namespace, or the host through `host.docker.internal` | Verified by the [tool and network acceptance](tool-network-acceptance.md) on Ubuntu 22.04/24.04 |
| Native Runner on the host talking to the Compose-hosted Map over trusted HTTPS | Covered by the [installation](installation.md) and trust acceptance |
| Container Runner reaching a target **through a host VPN** | **Not verified.** Behavior depends on the VPN client, its routing mode and any kill-switch or firewall rules |
| Split tunnelling, DNS policy, reconnect and kill-switch behavior | **Not verified** |
| Raw-packet scan modes in the container | Unsupported: the container runs with no added capabilities and VardrSec will not add them |

## Choosing a Runner

- **Target is a public address or on the same local network as the host:** the
  container Runner started by the Compose distribution is fine.
- **Target is only reachable through a VPN, a host-only network or an
  OS-keychain-protected credential:** prefer the **native Runner** installed on the
  host. It uses the host's network stack (and therefore the VPN) directly and the
  OS keychain. Point it at the Compose Map over HTTPS after
  [enrolling the platform CA](installation.md#explicit-certificate-trust).
- **Unsure:** test reachability before queueing any job. From the same environment
  that will run the tool, make a single request to an in-scope, authorized address
  you are permitted to contact. If it fails from the container but works on the
  host, use the native Runner.

## Container limits to expect

- `localhost` inside the container is the container. Use the Compose service names
  or `host.docker.internal` for host services.
- The container does not inherit the host keychain or VPN client state.
- If the Compose subnets (see [installation](installation.md)) overlap a VPN or
  corporate network, change the subnet in the configuration rather than the VPN.
- Starting the platform never starts a scan. Jobs run only when you explicitly
  invoke `jobs run` after reviewing the queue and the engagement's scope and
  authorization.

## Reporting a networking problem

Include the Runner mode (native or container), host OS, whether a VPN was active
and its type, and the output of `vardrrunner doctor --platform --offline`. Do not
include credentials, tokens or target data you are not authorized to share.

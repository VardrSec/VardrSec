# ADR 0002: Container Runner for the first distribution

Status: Accepted, 2026-10-26.

The first Compose distribution packages Runner as a Linux container. The operator
approved this direction after local authentication merged. Native Runner remains
supported for host keychains, VPN routing and tool requirements that are awkward
inside containers.

Runner is an explicitly invoked CLI service, excluded from ordinary platform
startup by a Compose profile. Its default image command prints help and exits;
neither startup nor diagnostics claims jobs. Persist its state and evidence in a
dedicated volume. Use non-root execution without the Docker socket, host home
directory, published ports or baseline added capabilities.

The source image belongs in VardrRunner; VardrSec will pin a tested image digest
and supply network, public CA trust and state configuration. Never put API keys or
private CA keys in an image. Diagnostics must expose missing tools honestly.

The first CLI-only development image is not a tool-complete distribution. Gate and
tool packaging, immutable release pins, fresh-install trusted HTTPS, host/VPN
reachability and backup/restore acceptance remain required before release. Image
publication and a tagged release remain separate authorization steps.

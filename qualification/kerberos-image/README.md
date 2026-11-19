# Source-built Kerberos database integration

The normal `db/Dockerfile` now builds the four Kerberos client-library packages
from exact source inside the previously qualified disposable Debian TCG guest.
No prebuilt binary endpoint, GitHub token or expiring Actions artifact is needed.
The approved PostgreSQL package/ABI and runtime configuration are unchanged.
Both PostgreSQL 18.6 and libpq5 directly require libgssapi-krb5-2; removing it is
not a compatible fix.

Docker installs build tools only inside its disposable stage. QEMU runs as UID
65534, with no host mounts/devices, KVM, published ports or security relaxation.
The preparation boot acquires normal signed Debian dependencies; the package
build boot has no virtual NIC. Full ordinary Debian tests, symbol checks and the
bounded stripped-library regression must pass. Newly built package bytes must
also match all four independently reproduced package hashes before installation.
Any mismatch fails closed; there is no stale-artifact fallback.

The image retains corresponding source plus the VM builder scripts, input pins,
prepared dependency inventory, keyring prerequisite and source-only build
receipt. Source-only receipts contain an input hash, not a fabricated Git commit.
The Docker-context and standalone harness copies are checked byte-for-byte.

The normal Full installation/build commands use this Dockerfile automatically.
Mapless does not build a database. A cold database build needs around 4 GiB guest
memory plus build overhead and additional disposable disk space; the first build
can take tens of minutes under TCG. The guest preparation/build budgets remain
30/120 minutes. Docker may reuse an unchanged successful build layer. Windows
Docker Desktop end-to-end qualification remains an independent platform check.

The candidate acceptance workflow now tests the ordinary Compose recipe. Its
explicit override changes only the image alias, never the recipe or runtime
policy. It verifies source/runtime custody and PostgreSQL smoke, then exports
the stopped image for retained legal notices and bounded component inventory.
CI time budgets are expanded to accommodate the unchanged upstream tests, not
to skip or suppress them. Whole-image reproducibility and unrelated CVEs/legal
reviews remain open; this change does not authorize release or deployment.

## Archived offline candidate

The November 2026 candidate used a pinned VM artifact to build a temporary
database image. Its preparer, exact ZIP hashes, command sequence and evidence
are preserved in the [original runbook at beba220](https://github.com/VardrSec/VardrSec/blob/beba220fbb67b7aba57f59c964cea2a5f67dcf50/qualification/kerberos-image/README.md).

The [candidate acceptance run](https://github.com/VardrSec/VardrSec/actions/runs/43071041475)
exercised that image. Two independent VM builds produced identical bytes for
the four linux-amd64 Kerberos packages. The comparison covered those packages
only. See the [first build](https://github.com/VardrSec/VardrSec/actions/runs/43060945526),
[second build](https://github.com/VardrSec/VardrSec/actions/runs/43068431525) and
[archived comparison receipt](https://github.com/VardrSec/VardrSec/blob/beba220fbb67b7aba57f59c964cea2a5f67dcf50/qualification/kerberos-image/reproduction-evidence.json).

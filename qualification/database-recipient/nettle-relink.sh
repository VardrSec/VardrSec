#!/usr/bin/env bash
# Build the recipient's replacement shared library in a disposable Trixie host.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive DEB_BUILD_OPTIONS=parallel=2
cat > /tmp/relink.list <<'EOF'
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20260913T000000Z trixie main
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20260913T000000Z trixie main
EOF
printf '%s\n' 'Dir::Etc::sourcelist "/tmp/relink.list";' 'Dir::Etc::sourceparts "-";' 'Acquire::Retries "3";' 'Acquire::https::CaInfo "/host-ca.crt";' > /etc/apt/apt.conf.d/95-relink
apt-get update --error-on=any
apt-get install -y --no-install-recommends dpkg-dev python3
apt-get build-dep -y --no-install-recommends nettle=3.10.1-1
work=$(mktemp -d)
chmod 0755 "$work"
cd "$work"
apt-get source --download-only nettle=3.10.1-1
python3 - <<'PY'
import hashlib, json
from pathlib import Path
lock = json.loads(Path("/review/docs/release/os-source-dbd51e14/sources.lock.json").read_bytes())
files = [f for f in lock["files"] if (f.get("source"), f.get("version")) == ("nettle", "3.10.1-1")]
if not files:
    raise ValueError("Expected source descriptor and payloads")
for f in files:
    data = Path(Path(f["file"]).name).read_bytes()
    if len(data) != f["bytes"] or hashlib.sha256(data).hexdigest() != f["sha256"]:
        raise ValueError(f["file"])
PY
dpkg-source -x nettle_3.10.1-1.dsc source
# Add an inert, retained data marker, preserving existing API and crypto behavior.
cat >> source/version.c <<'EOF'
static const char recipient_marker[] __attribute__((used)) = "vardr-recipient-nettle-rebuild";
EOF
(cd source && dpkg-buildpackage -us -uc -b)
deb=$(find . -maxdepth 1 -type f -name 'libnettle8t64_*_amd64.deb' -print)
dpkg-deb -x "$deb" extracted
library=$(find extracted/usr/lib -type f -name 'libnettle.so.8.*' -print)
grep -aqF 'vardr-recipient-nettle-rebuild' "$library"
install -m 0755 "$library" /recipient/libnettle.so.8
release=$(find /var/lib/apt/lists -name '*_dists_trixie_InRelease' -print)
install -m 0644 "$release" /recipient/InRelease
sed 's/^Origin: Debian$/Origin: Recipient qualification/' "$release" > /recipient/changed
if cmp -s /recipient/InRelease /recipient/changed; then exit 1; fi
sha256sum "$library" "$deb"

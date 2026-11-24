#!/usr/bin/env bash
# Run only in the disposable Trixie container from the qualification workflow.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_OPTIONS=parallel=2
export CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true
install -D -m 0644 /host-ca.crt /etc/ssl/certs/ca-certificates.crt
cat > /tmp/relink.sources.list <<'EOF'
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20260913T000000Z trixie main
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20260913T000000Z trixie main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261111T100000Z trixie-security main
deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261111T100000Z trixie-security main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg check-valid-until=no] https://snapshot.debian.org/archive/debian/20250427T000000Z sid main
EOF
printf '%s\n' 'Dir::Etc::sourcelist "/tmp/relink.sources.list";' 'Dir::Etc::sourceparts "-";' 'Acquire::Retries "3";' 'Acquire::https::CaInfo "/host-ca.crt";' > /etc/apt/apt.conf.d/95-relink
# The stock binary embeds Debian's 1.85.0 compiler. Later Trixie updates
# carry 1.85.1. Select only the original compiler set from this signed archive.
cat > /etc/apt/preferences.d/relink-rust <<'EOF'
Package: cargo rustc libstd-rust-dev libstd-rust-1.85
Pin: version 1.85.0+dfsg3-1
Pin-Priority: 1001

Package: *
Pin: release a=unstable
Pin-Priority: 1
EOF
apt-get update --error-on=any
apt-get install -y --no-install-recommends dpkg-dev python3 sqv=1.3.0-3+b2
apt-get build-dep -y --no-install-recommends rust-sequoia-sqv=1.3.0-3
work=$(mktemp -d)
chmod 0755 "$work"
cd "$work"
apt-get source --download-only rust-sequoia-sqv=1.3.0-3 rust-sequoia-openpgp=2.0.0-2+deb13u1
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
root = Path("/review/docs/release/os-source-dbd51e14")
files = json.loads((root / "sources.lock.json").read_bytes())["files"]
files += json.loads((root / "sqv-static/capture.json").read_bytes())
pairs = {("rust-sequoia-sqv", "1.3.0-3"), ("rust-sequoia-openpgp", "2.0.0-2+deb13u1")}
matched = set()
for f in files:
    key = (f.get("source"), f.get("version"))
    if key not in pairs:
        continue
    path = Path(f["file"]).name
    data = Path(path).read_bytes()
    if len(data) != f["bytes"] or hashlib.sha256(data).hexdigest() != f["sha256"]:
        raise ValueError(f"Source bytes differ from the reviewed manifest: {path}")
    matched.add(key)
if matched != pairs:
    raise ValueError("Incomplete source inputs")
PY
dpkg-source -x rust-sequoia-sqv_1.3.0-3.dsc sqv-source
dpkg-source -x rust-sequoia-openpgp_2.0.0-2+deb13u1.dsc openpgp-source
crate=/usr/share/cargo/registry/sequoia-openpgp-2.0.0/src/lib.rs
cmp openpgp-source/src/lib.rs "$crate"
# This change makes an independently observed marker visible through sqv --version.
# The signature checks and library verification semantics are identical.
python3 - "$crate" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
src = p.read_bytes()
old = b'pub const VERSION: &str = env!("CARGO_PKG_VERSION");'
new = b'pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-recipient-relink");'
if src.count(old) != 1:
    raise ValueError("Unexpected Sequoia version declaration")
p.write_bytes(src.replace(old, new))
PY
# Use Debian's source packaging and its normal build and test targets.
(cd sqv-source && dpkg-buildpackage -us -uc -b)
package=$(find . -maxdepth 1 -type f -name 'sqv_*_amd64.deb' -print)
test "$(printf '%s\n' "$package" | wc -l)" -eq 1
dpkg-deb -x "$package" replacement
new="$work/replacement/usr/bin/sqv"
stock=$(command -v sqv)
printf '%s  %s\n' 48c720d78ad921e2f6d948ee4bf6d2e4bf5e2249e52a67a07f501c5a8b599815 "$stock" | sha256sum -c -
"$stock" --version | tee stock-version.txt
"$new" --version | tee rebuilt-version.txt
grep -Fq -- '-recipient-relink' rebuilt-version.txt
if grep -Fq -- '-recipient-relink' stock-version.txt; then exit 1; fi
python3 - "$package" <<'PY'
import re
import subprocess
import sys
from pathlib import Path
original = Path("/review/docs/release/os-source-dbd51e14/sqv-static/sqv-signed-index-stanza.txt").read_text()
for field in ("Built-Using", "Static-Built-Using"):
    expected = re.search(r"^" + field + r": (.+)$", original, re.M).group(1)
    observed = subprocess.check_output(["dpkg-deb", "-f", sys.argv[1], field], text=True)
    entries = lambda s: {v.strip() for v in s.split(",") if v.strip()}
    if entries(expected) != entries(observed):
        raise ValueError(f"Rebuilt {field} added {entries(observed)-entries(expected)} and lost {entries(expected)-entries(observed)}")
    print(f"PASS {field}: {len(entries(expected))} matching exact source/version entries")
PY
release=$(find /var/lib/apt/lists -name '*_dists_trixie_InRelease' -print)
test -f "$release"
keyring=/usr/share/keyrings/debian-archive-keyring.gpg
"$stock" --keyring "$keyring" --cleartext "$release" --output stock-release
"$new" --keyring "$keyring" --cleartext "$release" --output rebuilt-release
cmp stock-release rebuilt-release
sed 's/^Origin: Debian$/Origin: Recipient qualification/' "$release" > altered-release
if cmp -s "$release" altered-release; then exit 1; fi
if "$new" --keyring "$keyring" --cleartext altered-release --output rejected-release; then exit 1; fi
printf 'PASS recipient-relinked sqv accepted signed Debian metadata and rejected changed metadata.\n'
sha256sum "$stock" "$new" "$package" "$crate" openpgp-source/src/lib.rs

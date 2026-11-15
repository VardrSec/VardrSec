#!/bin/sh
# Exact Debian stable source, narrow upstream ASN.1 backport, ordinary packaging.
set -eu
cd /build
printf '%s\n' \
 'd17d2840bc97fea2c2375245569ca67838a2b557ee083c6cbe42b129a317212c  krb5_1.21.3-5+deb13u1.dsc' \
 'b7a4cd5ead67fb08b980b21abd150ff7217e85ea320c9ed0c6dadd304840ad35  krb5_1.21.3.orig.tar.gz' \
 '02b873b239fbe7ddf016dfe44deba4130673f4606c18c93da0622e2bc8500fb4  krb5_1.21.3-5+deb13u1.debian.tar.xz' \
 '1c9f5facbcb81930d9c7dac552750273045e35e85dbfbc873b2ce140acf96705  krb5-CVE-2026-119079.patch' \
 '357afeceee72f52a2d5297e5bb086f0fc8a67a22dac8a2aac9d2a369ac35bc24  krb5-keyring-test-diagnostic.patch' | sha256sum -c -
dpkg-source --no-check -x krb5_1.21.3-5+deb13u1.dsc source
cd source
cp ../krb5-CVE-2026-119079.patch debian/patches/vardr-CVE-2026-119079.patch
printf '\nvardr-CVE-2026-119079.patch\n' >> debian/patches/series
cp ../krb5-keyring-test-diagnostic.patch debian/patches/vardr-keyring-test-diagnostic.patch
printf 'vardr-keyring-test-diagnostic.patch\n' >> debian/patches/series
{ printf 'krb5 (1.21.3-5+deb13u1+vardr1) trixie; urgency=high\n\n  * Backport upstream ASN.1 allocation fix 782e5ac (CVE-2026-119079).\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/krb-changelog
mv /tmp/krb-changelog debian/changelog
export DEB_BUILD_OPTIONS=parallel=2
mkdir -p /out/packages /out/source/evidence
{ dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\n'; cc --version; ld --version; } > /out/source/evidence/build-environment.txt
dpkg-source --before-build . > /tmp/krb-build.log 2>&1
grep -Fx vardr-CVE-2026-119079.patch .pc/applied-patches
cp .pc/applied-patches /out/source/evidence/applied-patches.txt
sha256sum src/lib/krb5/asn.1/asn1_encode.c > /out/source/evidence/patched-source-SHA256SUMS
# Read-only keyring probe: preserve its status as diagnostics, not a test waiver.
probe_rc=0
keyctl show > /out/source/evidence/keyring-probe.txt 2>&1 || probe_rc=$?
printf 'keyctl_show_exit=%s\n' "$probe_rc" >> /out/source/evidence/keyring-probe.txt
cat /out/source/evidence/keyring-probe.txt
# Keep upstream tests and Debian exported-symbol checks enabled.
dpkg-buildpackage -us -uc -B >> /tmp/krb-build.log 2>&1 || { tail -n 100 /tmp/krb-build.log; exit 1; }
for name in libkrb5-3 libk5crypto3 libkrb5support0 libgssapi-krb5-2; do
    set -- ../"$name"_*_*.deb
    test "$#" -eq 1
    cp "$1" /out/packages/
done
payload=$(mktemp -d)
for package in /out/packages/*.deb; do dpkg-deb -x "$package" "$payload"; done
library=$(find "$payload/usr/lib" -type f -name 'libkrb5.so.3.*')
test -n "$library"; test "$(printf '%s\n' "$library" | wc -l)" -eq 1
libdir=$(dirname "$library")
# Debian moves installed headers to the multi-dev include prefix. Use the
# exact development package produced above, never ambient system/build headers.
headers=$(mktemp -d)
set -- ../krb5-multidev_*_*.deb
test "$#" -eq 1
dpkg-deb -x "$1" "$headers"
sha256sum "$1" > /out/source/evidence/header-package-SHA256SUMS
test -f "$headers/usr/include/mit-krb5/krb5.h"
cc -O2 -Wall -Wextra -Werror -Wl,--export-dynamic -I"$headers/usr/include/mit-krb5" \
 /build/krb5-sequence-regression.c "$library" -Wl,-rpath-link,"$libdir" -ldl -o /tmp/krb-sequence-regression
(ulimit -c 0; ulimit -v 262144; ulimit -t 10
 LD_LIBRARY_PATH="$libdir" timeout 15 /tmp/krb-sequence-regression patched) > /out/source/evidence/sequence-regression.txt
(cd "$payload" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > /out/source/evidence/package-files-SHA256SUMS
(cd /out/packages && sha256sum ./*.deb) > /out/source/evidence/packages-SHA256SUMS
for package in /out/packages/*.deb; do dpkg-deb -f "$package" Package Version Architecture Source; done > /out/source/evidence/packages.txt
debian/rules clean >> /tmp/krb-build.log 2>&1
dpkg-source --build . >> /tmp/krb-build.log 2>&1
cp ../krb5_*+vardr1.dsc ../krb5_*+vardr1.debian.tar.xz ../krb5_*.buildinfo ../krb5_*.changes /out/source/
cp ../krb5_1.21.3.orig.tar.gz ../krb5_1.21.3-5+deb13u1.dsc ../krb5_1.21.3-5+deb13u1.debian.tar.xz /out/source/
cp /build/krb5-CVE-2026-119079.patch /build/krb5-keyring-test-diagnostic.patch /build/krb5-sequence-regression.c /build/build-krb5.sh /build/Dockerfile /out/source/
cp /tmp/krb-build.log /out/source/evidence/package-build.log
printf '%s\n' 'DB qualification only. Exact source/patch trust hashes, ordinary Debian build/tests, stripped package regression. Build dependencies recorded but not snapshot-pinned. Not bit-reproducibility, not a signature, not other-CVE clearance.' > /out/source/evidence/SCOPE.txt
(cd /out/source && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)

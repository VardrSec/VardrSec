#!/bin/sh
# Build the existing Trixie library with the two applicable upstream fixes.
set -eu
cd /work
version=3.8.9-3+deb13u4
dpkg-source --no-check -x "gnutls28_${version}.dsc" source
cd source
for id in 127039 127040; do
    patch=CVE-2026-$id.patch
    cp "/work/gnutls/$patch" "debian/patches/vardr-$patch"
    printf '\n%s\n' "vardr-$patch" >> debian/patches/series
done
{
    printf 'gnutls28 (%s+vardr1) trixie; urgency=high\n\n' "$version"
    printf '  * Backport upstream certificate allocation and RSA-PSK error cleanup fixes.\n\n'
    printf ' -- VardrSec local build <qualification@localhost>  Tue, 24 Nov 2026 00:00:00 +0000\n\n'
    cat debian/changelog
} > debian/changelog.vardr
mv debian/changelog.vardr debian/changelog
dpkg-source --before-build .
cp .pc/applied-patches /out/source/applied-patches.txt
for id in 127039 127040; do grep -Fx "vardr-CVE-2026-$id.patch" .pc/applied-patches; done
# The Trixie name-constraints implementation already clears the owning and
# borrowed arrays, pointers and sizes after free. Bind the reviewed source to
# this build alongside the exact resulting bytes of the two patched files.
cat > /out/source/reviewed-source.sha256 <<'EOF'
9e5516ab7a6eb4c8e2909e1c03841b197e02cc1841777357a35973e374e5a531  lib/auth/cert.c
4970970f9ce2286c237e7ef84379ca0bb1d213c380869540099851d0f0345b74  lib/auth/rsa_psk.c
3c2fe6d4fdff6e3026269bffdabf09d51c3c1c796177671173b48d9f6a407d3f  lib/x509/name_constraints.c
EOF
sha256sum -c /out/source/reviewed-source.sha256
dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\n' > /out/source/build-environment.txt
dpkg-buildpackage -us -uc -B -j4 > /out/source/package-build.log 2>&1 || {
    build_status=$?
    tail -n 120 /out/source/package-build.log || :
    # Automake writes each test's verdict to .trs and its output to the sibling .log.
    grep -rEl --include='*.trs' '^:(global-test-result|test-result):[[:space:]]+(FAIL|ERROR|XPASS)([[:space:]]|$)' . |
        while IFS= read -r result; do
            test_path=${result%.trs}
            printf '\nFailed GnuTLS test: %s\n' "$test_path"
            tail -n 120 "$test_path.log" || cat "$result"
        done || :
    exit "$build_status"
}
debian/rules clean >> /out/source/package-build.log 2>&1
dpkg-source --build . >> /out/source/package-build.log 2>&1
cd /work
cp "libgnutls30t64_${version}+vardr1_amd64.deb" /out/packages/
cp *.dsc *.tar.xz *.tar.xz.asc *.buildinfo *.changes /out/source/
cp /work/gnutls/* Dockerfile /out/source/
dpkg-deb -x /out/packages/*.deb payload
(cd payload && sha256sum usr/lib/x86_64-linux-gnu/libgnutls.so.30.*) > /out/source/runtime-library.sha256
(cd /out/packages && sha256sum *.deb) > /out/source/package.sha256
chmod 0644 /out/source/*
(cd /out/source && sha256sum ./* > SHA256SUMS)

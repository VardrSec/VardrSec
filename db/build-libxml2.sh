#!/bin/sh
# Rebuild the pinned Debian source with Canonical's maintained 2.9.14 backport.
set -eu
cd /build
printf '%b' '04b1da890535b11e3db231f39114ee09e643badceff79441d749d0ca78efaaa5  libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.dsc\n4fe913dec8b1ab89d13b489b419a8203176ea39e931eaa0d25b17eafb9c279e9  libxml2_2.12.7+dfsg+really2.9.14.orig.tar.xz\n3b6d265f482d6a8fbe3c056d2006fb3b563b4a838f7258b388ac5f0b29206921  libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.debian.tar.xz\n6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54  CVE-2026-6653.patch\n6f3e6bd911a1b0d58ebad1ff752e2302f9e8b92ec32c7461774aa998c1a2b3c0  libxml2-CVE-2026-86140.patch\n546cc59a213567f925437c46ba85e60cb5fc92fd6337c83ccd074e91cc64cc1e  libxml2-CVE-2026-74860.patch\n05e5da494f3e7b5ea9500ffe6c0ef0ebac762aae956c9b8808826dc24871f003  libxml2-CVE-2026-86138.patch\nee0b790809fb0fa3b0af19ef8dd61c10707c9e2f9bbfae52b63d735a15bfafd8  libxml2-CVE-2026-86142.patch\ne809e00ceeb0c4b12997bf46cc411970f4a269ef7e3548acba9973bb5535cea8  libxml2-CVE-2026-86143.patch\n85809cce7c841d76de73d133fc681614850123dcf27f93b179e2e9ac5426c8f7  libxml2-CVE-2026-86144.patch\n' | sha256sum -c -
# Exact descriptor and archive hashes above are the trust pins; no keyserver lookup.
dpkg-source --no-check -x libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.dsc source
cd source
cp ../CVE-2026-6653.patch debian/patches/vardr-CVE-2026-6653.patch
printf '\nvardr-CVE-2026-6653.patch\n' >> debian/patches/series
for patch in CVE-2026-86140.patch CVE-2026-74860.patch CVE-2026-86138.patch CVE-2026-86142.patch CVE-2026-86143.patch CVE-2026-86144.patch; do
    cp "../libxml2-$patch" "debian/patches/vardr-$patch"
    printf 'vardr-%s\n' "$patch" >> debian/patches/series
done
{ printf 'libxml2 (2.12.7+dfsg+really2.9.14-2.1+deb13u3+vardr2) trixie; urgency=high\n\n  * Apply the maintained Ubuntu entity, dictionary, validation, XPointer, I/O and XInclude fixes.\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog
mv /tmp/changelog debian/changelog
export DEB_BUILD_PROFILES=nopython DEB_BUILD_OPTIONS=parallel=2
mkdir -p /out/packages /out/source
# Retain the ordinary Debian packaging and exported-symbol checks.
dpkg-buildpackage -us -uc -B --build-profiles=nopython > /tmp/package-build.log 2>&1 || { tail -n 70 /tmp/package-build.log; exit 1; }
debian/rules clean >> /tmp/package-build.log 2>&1
dpkg-source --build . >> /tmp/package-build.log 2>&1
cp ../libxml2_*_*.deb /out/packages/
cp ../libxml2_*+vardr2.dsc ../libxml2_*+vardr2.debian.tar.xz ../libxml2_*.buildinfo ../libxml2_*.changes /out/source/
cp ../libxml2_2.12.7+dfsg+really2.9.14.orig.tar.xz ../libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.dsc ../libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.debian.tar.xz /out/source/
cp ../CVE-2026-6653.patch ../libxml2-CVE-*.patch /build/build-libxml2.sh /build/Dockerfile /build/libxml2-source.txt /out/source/
cd /out/source
sha256sum ./* > SHA256SUMS

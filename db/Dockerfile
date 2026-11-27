# Coordinated ACL/caller build; no runtime suite or glibc migration.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS acl-callers-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper dh-exec gettext libattr1-dev libacl1-dev libselinux1-dev libgmp3-dev libssl-dev libsystemd-dev gperf bison autoconf automake autopoint texinfo fakeroot acl attr python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build/inputs
ADD --checksum=sha256:b987ebbeb3d498794bad29cd65301b77384978493d8765c94dba8bad8fa325b6 https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0-1.dsc acl_2.4.0-1.dsc
ADD --checksum=sha256:e661131456d2708a01c614a0f400e11d7d1bfaeb6f3e74b75bb980b72f0161a3 https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0.orig.tar.xz acl_2.4.0.orig.tar.xz
ADD --checksum=sha256:65931c2fb3e821bda67f8d8d72d77e99ac61502748dcdf38b6805fe89339085e https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0-1.debian.tar.xz acl_2.4.0-1.debian.tar.xz
ADD --checksum=sha256:c3a207e3aaad165765c7a6fab89045f5fd20035fea6830b9f9ebbb92ebfbff89 https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7-3.dsc coreutils_9.7-3.dsc
ADD --checksum=sha256:e8bb26ad0293f9b5a1fc43fb42ba970e312c66ce92c1b0b16713d7500db251bf https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7.orig.tar.xz coreutils_9.7.orig.tar.xz
ADD --checksum=sha256:483f77876a080577f63da1d004cc1cf17d16df65d6925aefdd3294c6101eccfb https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7-3.debian.tar.xz coreutils_9.7-3.debian.tar.xz
ADD --checksum=sha256:5bb58d4966d94c99a9f1b182676089ecc05058d62fdb927f5c07539d9cda4077 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg-3.1.dsc tar_1.35+dfsg-3.1.dsc
ADD --checksum=sha256:9ae57e981c1e73c0eebc2b26c9b0c4497fe310ef1d516ea430efb5470b71f7a8 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg.orig.tar.xz tar_1.35+dfsg.orig.tar.xz
ADD --checksum=sha256:0d0278034b82ed84dce04a461879b6e1871e4cb416a0ff04d3d35ff05fc30a53 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg-3.1.debian.tar.xz tar_1.35+dfsg-3.1.debian.tar.xz
ADD --checksum=sha256:5f4f0b9b78821764fe6b88e32aef6ec519628522c211c36706bcb78d6f3f036b https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0.orig.tar.xz.asc acl_2.4.0.orig.tar.xz.asc
ADD --checksum=sha256:5070e9428bd372a7fa1f66b395b81092bb40c98f9f56a2e2bc55c47fd387e901 https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7.orig.tar.xz.asc coreutils_9.7.orig.tar.xz.asc
COPY acl/ /recipe/
RUN mkdir -p /out && chown -R 65534:65534 /build /out
USER 65534:65534
RUN --network=none sh /recipe/build.sh acl
USER root
RUN --network=none dpkg --install /out/packages/libacl1_*.deb /out/packages/libacl1-dev_*.deb /out/packages/acl_*.deb && apt-get check
USER 65534:65534
RUN --network=none sh /recipe/build.sh callers

# Ordinary source build, with unchanged upstream tests in a disposable TCG guest.
# Docker's default seccomp policy remains intact; the guest build has no NIC.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS krb5-backport
RUN apt-get -o Acquire::Retries=2 -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends ca-certificates python3 qemu-system-x86 qemu-utils cloud-image-utils xorriso e2fsprogs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /work /out /build && chown 65534:65534 /work /out /build
WORKDIR /repo
COPY kerberos-vm/ /repo/qualification/kerberos-vm/
COPY build-krb5.sh krb5-CVE-2026-119079.patch krb5-CVE-2026-71199.patch krb5-keyring-test-diagnostic.patch krb5-sequence-regression.c Dockerfile /repo/db/
# The two-vCPU source build can use native compiler objects from this machine.
RUN if [ "$(cd qualification/kerberos-vm && python3 -c 'from run import source_build_cpus; print(source_build_cpus())')" = 2 ]; then \
        if sh qualification/kerberos-vm/build-deps.sh ccache; then touch /work/native-compiler-ready; \
        else echo 'Native compiler unavailable; compiling inside the VM.'; fi; \
    fi && rm -rf /var/lib/apt/lists/*
# No host mounts, devices, KVM, published ports, added capabilities or policy changes.
USER 65534:65534
RUN python3 qualification/kerberos-vm/run.py --fetch-sources /work/krb5-inputs
RUN --network=none if test -f /work/native-compiler-ready; then \
        sh qualification/kerberos-vm/seed.sh || echo 'Native seed unavailable; compiling inside the VM.'; \
    fi
RUN python3 qualification/kerberos-vm/run.py --source-only --work /work/qualification --native-inputs /work/krb5-inputs \
    && python3 qualification/kerberos-vm/finalize.py /work/qualification /out

FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS openssl-package-build
WORKDIR /work
ADD --checksum=sha256:a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 https://deb.debian.org/debian-security/pool/updates/main/o/openssl/openssl_3.5.7.orig.tar.gz ./
ADD --checksum=sha256:d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2 https://deb.debian.org/debian-security/pool/updates/main/o/openssl/openssl_3.5.7.orig.tar.gz.asc ./
COPY openssl/ ./
RUN echo '4f069d916c8d0ba5ad594880b52edbf082332b9c93326bbbf12949bee5893010  openssl_3.5.7-1~deb13u3+vardr2.dsc' | sha256sum -c - \
    && apt-get update && apt-get install -y --no-install-recommends build-essential dpkg-dev fakeroot debhelper libzstd-dev zlib1g-dev ca-certificates \
    && dpkg-source -x openssl_3.5.7-1~deb13u3+vardr2.dsc src \
    && useradd -m builduser && chown -R builduser:builduser /work
WORKDIR /work/src
RUN --network=none echo 'c1726a50d589b2dc289727865c184382c2bd846733ddb139427062713ebeb5bd  /work/CVE-2026-107494.upstream.patch' | sha256sum -c - \
    && cp /work/CVE-2026-107494.upstream.patch debian/patches/ \
    && echo 'CVE-2026-107494.upstream.patch' >> debian/patches/series \
    && runuser -u builduser -- dpkg-source --before-build . \
    && { printf 'openssl (3.5.7-1~deb13u3+vardr3) trixie; urgency=high\n\n  * Apply the OpenSSL 3.5 maintenance fix for CVE-2026-107494.\n\n -- VardrSec Qualification <local@invalid>  Tue, 24 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/openssl-changelog \
    && cat /tmp/openssl-changelog > debian/changelog && runuser -u builduser -- dpkg-source -b .
RUN --network=none { runuser -u builduser -- dpkg-buildpackage -us -uc -B -j4 > /tmp/openssl-build.log 2>&1 || { tail -100 /tmp/openssl-build.log; exit 1; }; } \
    && mkdir -p /out/packages /out/source \
    && cp ../libssl3t64_*.deb ../openssl-provider-legacy_*.deb ../openssl_*.deb /out/packages/ \
    && cp /work/openssl_*.dsc /work/openssl_*.tar.* /work/openssl_*.buildinfo /work/openssl_*.changes /tmp/openssl-build.log /out/source/
FROM openssl-package-build AS openssl-build
RUN --network=none cd /out/packages && sha256sum -c /work/qualified-packages.sha256 \
    && dpkg -i ./*.deb && apt-get check \
    && cd / && sha256sum -c /work/qualified-libraries.sha256 \
    && cd /work/src && { debian/tests/run-25-test-verify > /out/source/installed-verify.log 2>&1 || { tail -60 /out/source/installed-verify.log; exit 1; }; } \
    && cp /work/qualified-packages.sha256 /work/qualified-libraries.sha256 /out/source/ && chmod 0644 /out/source/* \
    && cd /out/source && sha256sum ./* > SHA256SUMS

FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS glibc-build
WORKDIR /work
ADD --checksum=sha256:f24aa441021121a79266f0d75242706cab8843a47901fefe74527491807f1998 https://deb.debian.org/debian/pool/main/g/glibc/glibc_2.41.orig.tar.xz ./
COPY glibc/ ./
RUN echo '09999489e728062c43f24b2c45f04ee66a148ca138216c609372e16bfa07c21f  glibc_2.41-12+deb13u4+vardr3.dsc' | sha256sum -c - \
    && apt-get update && apt-get install -y --no-install-recommends build-essential dpkg-dev fakeroot \
    && dpkg-source -x glibc_2.41-12+deb13u4+vardr3.dsc src \
    && apt-get build-dep -y --no-install-recommends ./src \
    && useradd -m builduser && chown -R builduser:builduser /work
WORKDIR /work/src
# Reproduce the previously tested amd64 packages; reject any byte difference.
RUN --network=none { runuser -u builduser -- env DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -us -uc -b -Pnobiarch -j4 > /tmp/glibc-build.log 2>&1 || { tail -100 /tmp/glibc-build.log; exit 1; }; } \
    && mkdir -p /out/packages /out/source \
    && cp ../libc6_*_amd64.deb ../libc-bin_*_amd64.deb ../libc-l10n_*_all.deb ../locales_*_all.deb /out/packages/ \
    && cp ../glibc_*.dsc ../glibc_*.tar.xz ../glibc_*.buildinfo ../glibc_*.changes /out/source/ \
    && cd /out/packages && sha256sum -c /work/qualified-packages.sha256 \
    && cd /out/source && sha256sum glibc_* > SHA256SUMS \
    && rm -rf /work/src /work/*.deb

FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS util-linux-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper dh-exec dh-package-notes dh-sequence-installsysusers dh-debputy asciidoctor bc bison flex gettext libaudit-dev libcap-ng-dev libcrypt-dev libcryptsetup-dev libncurses-dev libpam0g-dev libreadline-dev libselinux1-dev libsqlite3-dev libsystemd-dev libtool libudev-dev netbase pkgconf po-debconf po4a socat systemd systemd-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ADD --checksum=sha256:5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.debian.tar.xz util-linux_2.41.5-0+deb13u1.debian.tar.xz
ADD --checksum=sha256:43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.dsc util-linux_2.41.5-0+deb13u1.dsc
ADD --checksum=sha256:f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5.orig.tar.xz util-linux_2.41.5.orig.tar.xz
RUN --network=none dpkg-source --no-check -x util-linux_2.41.5-0+deb13u1.dsc source
COPY util-linux/*.patch /work/source/debian/patches/
WORKDIR /work/source
RUN for p in debian/patches/vardr-*.patch; do basename "$p" >> debian/patches/series; done && dpkg-source --before-build . && { printf 'util-linux (2.41.5-0+deb13u1+vardr2) trixie; urgency=high\n\n  * Backport upstream stable 485dbb67f1b6 for CVE-2026-78408.\n\n -- VardrSec Qualification <local@invalid>  Tue, 17 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog && mv /tmp/changelog debian/changelog
RUN --network=none dpkg-source --build .
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none dpkg-buildpackage -us -uc -B > /work/package-build.log 2>&1 || (grep -n -i -B 4 -A 5 -E "error:|fatal|undefined|not found|No such" /work/package-build.log | head -n 100; tail -n 15 /work/package-build.log; exit 1)
RUN mkdir -p /out/packages /out/source && cp ../libmount1_*.deb ../libblkid1_*.deb ../libsmartcols1_*.deb ../libuuid1_*.deb ../liblastlog2-2_*.deb ../mount_*.deb ../util-linux_*.deb /out/packages/ && cp ../util-linux_*.dsc ../util-linux_*.tar.* ../util-linux_*.buildinfo ../util-linux_*.changes /out/source/ || (tail -n 50 /work/package-build.log; ls -l /work; exit 1)
COPY Dockerfile /out/source/Dockerfile
COPY util-linux/source.txt /out/source/util-linux-source.txt
COPY util-linux/qualified-packages.sha256 /out/source/qualified-packages.sha256
RUN cd /out/packages && sha256sum -c /out/source/qualified-packages.sha256
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS util-linux-source-delivery
COPY --from=util-linux-build /out/source/ /

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS ncurses-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper libgpm-dev pkgconf autoconf-dickey && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:546930a8992ae3325d8c38378f290265d969cf6333cfae9648ac6d69e1e8a8a6 https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216-2.debian.tar.xz ncurses_6.5+20250216-2.debian.tar.xz
ADD --checksum=sha256:00539cc2bc6bb84be1b8a8a5decf606682e14b6f39b76b9aa090e65d2c2d4580 https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216-2.dsc ncurses_6.5+20250216-2.dsc
ADD --checksum=sha256:b37baafa436e7133bb12a185cb8f60e1599b1947e9f0181c76f3190acf28b6eb https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216.orig.tar.gz ncurses_6.5+20250216.orig.tar.gz
ADD --checksum=sha256:64f4d17923322176c44079f18f170e2164a59d551d7e4e9c1a6e4eebedc5dd6f https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216.orig.tar.gz.asc ncurses_6.5+20250216.orig.tar.gz.asc
RUN --network=none dpkg-source --no-check -x ncurses_6.5+20250216-2.dsc source
COPY infocmp-bound.patch /build/source/debian/patches/vardr-infocmp-bound.patch
WORKDIR /build/source
RUN printf '\nvardr-infocmp-bound.patch\n' >> debian/patches/series && dpkg-source --before-build . && { printf 'ncurses (6.5+20250216-2+vardr1) trixie; urgency=high\n\n  * Bound infocmp analysis copy (CVE-2025-69720).\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog && mv /tmp/changelog debian/changelog
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
ENV DEB_BUILD_PROFILES='nobiarch'
RUN --network=none dpkg-buildpackage -us -uc -B > /build/package-build.log 2>&1 || (tail -n 70 /build/package-build.log; exit 1)
RUN mkdir -p /out/packages /out/source && cp ../ncurses-bin_*.deb /out/packages/ && debian/rules clean >> /build/package-build.log 2>&1 && dpkg-source --build . >> /build/package-build.log 2>&1 && cp ../ncurses_*.dsc ../ncurses_*.tar.* ../ncurses_*.buildinfo ../ncurses_*.changes /out/source/
COPY Dockerfile /out/source/Dockerfile
COPY ncurses-source.txt /out/source/ncurses-source.txt
RUN dpkg-deb -x /out/packages/ncurses-bin_*.deb /tmp/ncurses-payload \
    && cd /tmp/ncurses-payload && sha256sum usr/bin/infocmp > /out/source/infocmp.sha256
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS ncurses-source-delivery
COPY --from=ncurses-build /out/source/ /

# Rebuild the fixed SQLite source on Trixie; build tools are discarded.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS sqlite-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential debhelper autoconf libtool automake pkgconf chrpath lynx \
    libreadline-dev tcl8.6-dev tcl9.0-dev libtommath-dev libicu-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:d3b2efbeb509dfac38a0653112a400d48eaa86f14432c255a6fea8569df407f1 https://snapshot.debian.org/file/adad8188a1de9f6403ff70b3e41ea62465d3ae22 sqlite3_3.54.1-1.dsc
ADD --checksum=sha256:67906ee141109bebe43cdcf197892806397dabc79f5cd7f05f1278f47b0c5e25 https://snapshot.debian.org/file/8bc602b0433a4cc92fe095627afe1c89e1335cb5 sqlite3_3.54.1.orig-www.tar.xz
ADD --checksum=sha256:faeff7682200b3dd58c8f0f229892a7271c73c1fdabc86e7315eb31eb7cb6e83 https://snapshot.debian.org/file/c49acf244fe87e12aa11698a792dd6090c1b4eb9 sqlite3_3.54.1.orig.tar.xz
ADD --checksum=sha256:3f05602b0f4e1441b88f92e9afb2980e148659842565b1f1e27012988433a1d9 https://snapshot.debian.org/file/a8d6dc71abece0bd8f04fc52c793728ef7340a4d sqlite3_3.54.1-1.debian.tar.xz
RUN --network=none dpkg-source --no-check -x sqlite3_3.54.1-1.dsc source
WORKDIR /build/source
RUN sed -i 's/tcl9.1-dev/tcl9.0-dev/' debian/control \
    && sed -i 's/TCLV_SECONDARY = 9.1/TCLV_SECONDARY = 9.0/' debian/rules \
    && { printf 'sqlite3 (3.54.1-1+vardr1) trixie; urgency=high\n\n  * Rebuild the upstream security release with Trixie Tcl 9.0.\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog \
    && mv /tmp/changelog debian/changelog
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none mkdir -p /out/packages /out/source \
    && (dpkg-buildpackage -us -uc -B > /tmp/package-build.log 2>&1 || (tail -n 75 /tmp/package-build.log; exit 1)) \
    && cp ../libsqlite3-0_*.deb /out/packages/ \
    && debian/rules clean >> /tmp/package-build.log 2>&1 \
    && dpkg-source --build . >> /tmp/package-build.log 2>&1 \
    && cp ../sqlite3_*.dsc ../sqlite3_*.tar.xz ../sqlite3_*.buildinfo ../sqlite3_*.changes /out/source/
COPY Dockerfile /out/source/Dockerfile
COPY sqlite-source.txt /out/source/sqlite-source.txt
RUN dpkg-deb -x /out/packages/libsqlite3-0_*.deb /tmp/sqlite-payload \
    && cd /tmp/sqlite-payload && sha256sum usr/lib/x86_64-linux-gnu/libsqlite3.so.3.54.1 > /out/source/library.sha256
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS sqlite-source-delivery
COPY --from=sqlite-build /out/source/ /

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6 AS libxml2-backport
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential debhelper liblzma-dev zlib1g-dev pkg-config rename ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN set -eu; for file in \
    libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.dsc \
    libxml2_2.12.7+dfsg+really2.9.14.orig.tar.xz \
    libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.debian.tar.xz; do \
      curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        "https://deb.debian.org/debian/pool/main/libx/libxml2/$file" --output "$file"; \
    done
COPY libxml2-CVE-2026-6653.patch /build/CVE-2026-6653.patch
COPY libxml2-CVE-2026-861*.patch libxml2-CVE-2026-74860.patch /build/
COPY build-libxml2.sh libxml2-entity-regression.c libxml2-xinclude-options.c libxml2-source.txt Dockerfile /build/
RUN --network=none sh /build/build-libxml2.sh
COPY archive-tar.patch archive-tar-source.txt /build/archive-tar/
RUN --network=none mkdir -p /out/archive-tar-source \
    && echo 'b46ebbba5898fa4d050d610aaf79e6a90e90b4f8d44689c3d9e361145d14a704  /usr/share/perl/5.40/Archive/Tar.pm' | sha256sum -c - \
    && cp /usr/share/perl/5.40/Archive/Tar.pm /out/archive-tar-source/Tar.pm.original \
    && cp /usr/share/perl/5.40/Archive/Tar.pm /out/archive-tar-source/Tar.pm \
    && patch --fuzz=0 /out/archive-tar-source/Tar.pm /build/archive-tar/archive-tar.patch \
    && echo 'e741b0a26fdd5ed3e0515b421cc6f6790f1352833f6765a198e33fd4da954d81  /out/archive-tar-source/Tar.pm' | sha256sum -c - \
    && cp /build/archive-tar/* /out/archive-tar-source/ \
    && cp /usr/share/doc/perl-base/copyright /out/archive-tar-source/perl-copyright \
    && cp /usr/share/common-licenses/Artistic /usr/share/common-licenses/GPL-1 /out/archive-tar-source/ \
    && cd /out/archive-tar-source && sha256sum ./* > SHA256SUMS

FROM scratch AS libxml2-source-delivery
COPY --from=libxml2-backport /out/source/ /

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS gosu
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GODEBUG=http2client=0
WORKDIR /src
# The reviewed PostgreSQL image bundles gosu 1.19.0 built with Go 1.24.6. Keep that
# release (tag 1.19, commit below; gosu tags are not Go semver) and rebuild it from its
# module (checksum database verified) with the patched toolchain used elsewhere.
# x/sys 0.44.0 removes GO-2026-5024 from the module graph (Windows-only path).
# moby/sys/user is raised to 0.4.1 for GO-2026-6686 (unbounded user/group file parsing).
COPY gosu.go.mod /src/go.mod
COPY gosu.go.sum /src/go.sum
COPY canonical_module_archive.sh /usr/local/bin/canonical_module_archive.sh
RUN go mod download && go mod verify
RUN --network=none go build -mod=readonly -trimpath -ldflags '-d -w' -o /go/bin/gosu github.com/tianon/gosu
RUN gosu_notice_source="$(go list -m -f '{{.Dir}}' github.com/tianon/gosu)" \
    && mkdir -p /out/gosu-notices \
    && cp "$gosu_notice_source/LICENSE" /out/gosu-notices/LICENSE \
    && if [ -f "$gosu_notice_source/NOTICE" ]; then cp "$gosu_notice_source/NOTICE" /out/gosu-notices/NOTICE; fi

# Keep legal texts from the exact downloaded module cache as inert notice data.
RUN bash /usr/local/bin/canonical_module_archive.sh notices /go/pkg/mod /out/gosu-notices/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/gosu-notices/GO-LICENSE
# Retain exact checksum-verified source archives for all three linked modules.
RUN mkdir -p /out/gosu-notices/source \
    && cp /src/go.mod /src/go.sum /out/gosu-notices/source/ \
    && go list -m all > /out/gosu-notices/source/modules.txt \
    && go version -m /go/bin/gosu > /out/gosu-notices/source/binary-build-info.txt \
    && bash /usr/local/bin/canonical_module_archive.sh sources /go/pkg/mod/cache/download /out/gosu-notices/source/module-sources.tar \
    && cd /out/gosu-notices/source && sha256sum ./* > SHA256SUMS

# Rebuild the existing Trixie TLS ABI with two upstream maintenance fixes.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS gnutls-build
RUN apt-get -o Acquire::Retries=2 -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends build-essential fakeroot debhelper bison ca-certificates chrpath gperf libcmocka-dev libidn2-dev libp11-kit-dev libssl-dev libtasn1-6-dev libunbound-dev libunistring-dev net-tools nettle-dev openssl pkgconf python3 softhsm2 \
    && rm -rf /var/lib/apt/lists/* && useradd -m builduser
WORKDIR /work
ADD --checksum=sha256:f1153e91212bdf60acf66cb62713ad4ed577f2e85f578a04df31a5619624c1e1 https://deb.debian.org/debian/pool/main/g/gnutls28/gnutls28_3.8.9-3+deb13u4.dsc ./
ADD --checksum=sha256:69e113d802d1670c4d5ac1b99040b1f2d5c7c05daec5003813c049b5184820ed https://deb.debian.org/debian/pool/main/g/gnutls28/gnutls28_3.8.9.orig.tar.xz ./
ADD --checksum=sha256:7631d47762865d4ef494492cca794cf0fe6a8be892a4aa02f362ae29006d3054 https://deb.debian.org/debian/pool/main/g/gnutls28/gnutls28_3.8.9.orig.tar.xz.asc ./
ADD --checksum=sha256:f0b9c7d182072f0bbdb281304686aa6e2bfd343dadefa432ec4dab4893e9841f https://deb.debian.org/debian/pool/main/g/gnutls28/gnutls28_3.8.9-3+deb13u4.debian.tar.xz ./
COPY gnutls/ /work/gnutls/
COPY Dockerfile /work/Dockerfile
RUN mkdir -p /out/source /out/packages && chown -R builduser:builduser /work /out
USER builduser
RUN --network=none sh /work/gnutls/build.sh

# Rebuild Debian's fixed libseccomp source on the same stable system as PostgreSQL.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS libseccomp-build
RUN apt-get -o Acquire::Retries=2 -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends build-essential fakeroot debhelper linux-libc-dev dh-python python3-all-dev libpython3-all-dev cython3 python3-setuptools gperf \
    && rm -rf /var/lib/apt/lists/* && useradd -m builduser
WORKDIR /work
ADD --checksum=sha256:4778ad60e2265dfccd6860e96ce1b8a65327cdee4c075f880aa1aab63ec67d55 https://deb.debian.org/debian/pool/main/libs/libseccomp/libseccomp_2.6.2-1.dsc ./
ADD --checksum=sha256:6b845d352c6d7887d8d134c43d86850d40f5dcee11ad1675c18197ae4d869d42 https://deb.debian.org/debian/pool/main/libs/libseccomp/libseccomp_2.6.2.orig.tar.gz ./
ADD --checksum=sha256:178e8177ce5ac4131473d8f329098e4eb212fa4bbee0bacd50e21fedf2df3c22 https://deb.debian.org/debian/pool/main/libs/libseccomp/libseccomp_2.6.2.orig.tar.gz.asc ./
ADD --checksum=sha256:e571b7a8042620e805274320ccabf54828f21f84e23b35f8532f7123eead5857 https://deb.debian.org/debian/pool/main/libs/libseccomp/libseccomp_2.6.2-1.debian.tar.xz ./
RUN mkdir -p /out/source /out/packages && chown -R builduser:builduser /work /out
USER builduser
RUN --network=none dpkg-source --no-check -x libseccomp_2.6.2-1.dsc source \
    && cd source && { dpkg-buildpackage -us -uc -b -j4 > /out/source/package-build.log 2>&1 || { tail -100 /out/source/package-build.log; exit 1; }; } \
    && cd /work && cp libseccomp2_2.6.2-1_amd64.deb /out/packages/ \
    && cp *.dsc *.tar.* *.buildinfo *.changes /out/source/ \
    && dpkg-deb -x /out/packages/libseccomp2_2.6.2-1_amd64.deb payload \
    && cd payload && sha256sum usr/lib/x86_64-linux-gnu/libseccomp.so.2.* > /out/source/runtime-library.sha256 \
    && chmod 0644 /out/source/*
COPY Dockerfile /out/source/Dockerfile
RUN cd /out/source && sha256sum ./* > SHA256SUMS

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libapt-pkg7.0)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
COPY --from=libseccomp-build /out/source/ /usr/share/doc/libseccomp2/vardr-source/
RUN --network=none --mount=type=bind,from=libseccomp-build,source=/out/packages,target=/candidate \
    dpkg -i /candidate/libseccomp2_2.6.2-1_amd64.deb && apt-get check \
    && cd / && sha256sum -c /usr/share/doc/libseccomp2/vardr-source/runtime-library.sha256
COPY --from=acl-callers-build /out/runtime/ /tmp/acl-security/
COPY --from=gnutls-build /out/source/ /usr/share/doc/libgnutls30t64/vardr-source/
RUN --network=none --mount=type=bind,from=gnutls-build,source=/out/packages,target=/candidate \
    dpkg -i /candidate/libgnutls30t64_3.8.9-3+deb13u4+vardr1_amd64.deb && apt-get check \
    && cd / && sha256sum -c /usr/share/doc/libgnutls30t64/vardr-source/runtime-library.sha256
RUN --network=none dpkg --install /tmp/acl-security/libacl1_*.deb \
    && dpkg --install /tmp/acl-security/coreutils_*.deb /tmp/acl-security/tar_*.deb \
    && apt-get check && rm -rf /tmp/acl-security
COPY --from=acl-callers-build /out/source/ /usr/share/doc/libacl1/vardr-source/
# Retained public sources must remain readable without DAC-bypass capabilities.
RUN find /usr/share/doc/libacl1/vardr-source -type d -exec chmod 0755 {} + \
    && find /usr/share/doc/libacl1/vardr-source -type f -exec chmod 0644 {} +
COPY --from=sqlite-build /out/packages/ /tmp/sqlite-security/
RUN --network=none dpkg --install /tmp/sqlite-security/*.deb \
    && apt-get check && rm -rf /tmp/sqlite-security
COPY --from=sqlite-build /out/source/ /usr/share/doc/libsqlite3-0/vardr-source/
COPY --from=ncurses-build /out/packages/ /tmp/ncurses-security/
RUN --network=none dpkg --install /tmp/ncurses-security/*.deb \
    && apt-get check && rm -rf /tmp/ncurses-security
COPY --from=ncurses-build /out/source/ /usr/share/doc/ncurses-bin/vardr-source/
COPY --from=glibc-build /out/packages/libc6_*_amd64.deb /out/packages/libc-bin_*_amd64.deb /out/packages/libc-l10n_*_all.deb /out/packages/locales_*_all.deb /tmp/glibc-security/
RUN --network=none dpkg -i /tmp/glibc-security/*.deb && apt-get check && rm -rf /tmp/glibc-security
COPY --from=glibc-build /out/source/ /usr/share/doc/libc6/vardr-source/
COPY --from=util-linux-build /out/packages/ /tmp/util-linux-security/
RUN --network=none dpkg --install /tmp/util-linux-security/lib*.deb \
    && dpkg --install /tmp/util-linux-security/mount_*.deb /tmp/util-linux-security/util-linux_*.deb \
    && apt-get check && rm -rf /tmp/util-linux-security
COPY --from=util-linux-build /out/source/ /usr/share/doc/util-linux/vardr-source/
COPY --from=openssl-build /out/packages/ /tmp/openssl-security/
RUN --network=none dpkg --install /tmp/openssl-security/*.deb && apt-get check && rm -rf /tmp/openssl-security
COPY --from=openssl-build /out/source/ /usr/share/doc/libssl3t64/vardr-source/
RUN echo 'b46ebbba5898fa4d050d610aaf79e6a90e90b4f8d44689c3d9e361145d14a704  /usr/share/perl/5.40/Archive/Tar.pm' | sha256sum -c -
COPY --from=libxml2-backport /out/archive-tar-source/Tar.pm /usr/share/perl/5.40/Archive/Tar.pm
COPY --from=libxml2-backport /out/archive-tar-source/ /usr/share/doc/perl-modules-5.40/vardr-source/
# These base-image package acquisition tools are not needed by the database
# entrypoint or server. Keep apt's signature verifier; do not autoremove.
RUN apt-get purge -y --no-auto-remove \
    dirmngr gnupg gnupg-l10n gpg gpg-agent gpgconf gpgsm
COPY --from=gosu /go/bin/gosu /usr/local/bin/gosu
RUN gosu --version && gosu nobody true
COPY --from=gosu /out/gosu-notices/ /usr/share/licenses/gosu/

# Keep PostgreSQL and its ABI generation; replace only the qualified library.
COPY --from=libxml2-backport /out/packages/ /tmp/libxml2-backport/
RUN dpkg --install /tmp/libxml2-backport/*.deb \
    && rm -rf /tmp/libxml2-backport
COPY --from=libxml2-backport /out/source/ /usr/share/doc/libxml2/vardr-source/

# Stable Debian ABI retained; qualify only the database image in this patch.
COPY --from=krb5-backport /out/packages/ /tmp/krb5-backport/
RUN dpkg --install /tmp/krb5-backport/*.deb && rm -rf /tmp/krb5-backport
COPY --from=krb5-backport /out/source/ /usr/share/doc/libkrb5-3/vardr-source/

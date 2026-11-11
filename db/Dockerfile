# Ordinary source build, with unchanged upstream tests in a disposable TCG guest.
# Docker's default seccomp policy remains intact; the guest build has no NIC.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS krb5-backport
RUN apt-get -o Acquire::Retries=2 -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends ca-certificates python3 qemu-system-x86 qemu-utils cloud-image-utils xorriso e2fsprogs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /work /out && chown 65534:65534 /work /out
WORKDIR /repo
COPY kerberos-vm/ /repo/qualification/kerberos-vm/
COPY build-krb5.sh krb5-CVE-2026-119079.patch krb5-keyring-test-diagnostic.patch krb5-sequence-regression.c Dockerfile /repo/db/
# No host mounts, devices, KVM, published ports, added capabilities or policy changes.
USER 65534:65534
RUN python3 qualification/kerberos-vm/run.py --source-only --work /work/qualification \
    && python3 qualification/kerberos-vm/finalize.py /work/qualification /out

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS util-linux-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper dh-exec dh-package-notes dh-sequence-installsysusers dh-debputy asciidoctor bc bison flex gettext libaudit-dev libcap-ng-dev libcrypt-dev libcryptsetup-dev libncurses-dev libpam0g-dev libreadline-dev libselinux1-dev libsqlite3-dev libsystemd-dev libtool libudev-dev netbase pkgconf po-debconf po4a socat systemd systemd-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.debian.tar.xz util-linux_2.41.5-0+deb13u1.debian.tar.xz
ADD --checksum=sha256:43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.dsc util-linux_2.41.5-0+deb13u1.dsc
ADD --checksum=sha256:f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5.orig.tar.xz util-linux_2.41.5.orig.tar.xz
RUN --network=none dpkg-source --no-check -x util-linux_2.41.5-0+deb13u1.dsc source
COPY util-linux/*.patch /build/source/debian/patches/
WORKDIR /build/source
RUN for p in debian/patches/vardr-*.patch; do basename "$p" >> debian/patches/series; done && dpkg-source --before-build . && { printf 'util-linux (2.41.5-0+deb13u1+vardr1) trixie; urgency=high\n\n  * Apply remaining upstream 2.41.6 mount and descriptor security fixes.\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog && mv /tmp/changelog debian/changelog
RUN --network=none dpkg-source --build .
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none dpkg-buildpackage -us -uc -B > /build/package-build.log 2>&1 || (grep -n -i -B 4 -A 5 -E "error:|fatal|undefined|not found|No such" /build/package-build.log | head -n 100; tail -n 15 /build/package-build.log; exit 1)
RUN mkdir -p /out/packages /out/source && cp ../libmount1_*.deb ../libblkid1_*.deb ../libsmartcols1_*.deb ../libuuid1_*.deb ../liblastlog2-2_*.deb ../mount_*.deb ../util-linux_*.deb /out/packages/ && cp ../util-linux_*.dsc ../util-linux_*.tar.* ../util-linux_*.buildinfo ../util-linux_*.changes /out/source/ || (tail -n 50 /build/package-build.log; ls -l /build; exit 1)
COPY Dockerfile /out/source/Dockerfile
COPY util-linux/source.txt /out/source/util-linux-source.txt
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
COPY build-libxml2.sh libxml2-entity-regression.c libxml2-source.txt Dockerfile /build/
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

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libapt-pkg7.0)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
COPY --from=sqlite-build /out/packages/ /tmp/sqlite-security/
RUN --network=none dpkg --install /tmp/sqlite-security/*.deb \
    && apt-get check && rm -rf /tmp/sqlite-security
COPY --from=sqlite-build /out/source/ /usr/share/doc/libsqlite3-0/vardr-source/
COPY --from=ncurses-build /out/packages/ /tmp/ncurses-security/
RUN --network=none dpkg --install /tmp/ncurses-security/*.deb \
    && apt-get check && rm -rf /tmp/ncurses-security
COPY --from=ncurses-build /out/source/ /usr/share/doc/ncurses-bin/vardr-source/
COPY --from=util-linux-build /out/packages/ /tmp/util-linux-security/
RUN --network=none dpkg --install /tmp/util-linux-security/lib*.deb \
    && dpkg --install /tmp/util-linux-security/mount_*.deb /tmp/util-linux-security/util-linux_*.deb \
    && apt-get check && rm -rf /tmp/util-linux-security
COPY --from=util-linux-build /out/source/ /usr/share/doc/util-linux/vardr-source/
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

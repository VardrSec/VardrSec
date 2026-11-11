FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS ncurses-build
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
FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS sqlite-build
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
COPY build-libxml2.sh libxml2-source.txt Dockerfile /build/
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

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gosu
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GODEBUG=http2client=0
WORKDIR /src
# The reviewed PostgreSQL image bundles gosu 1.19.0 built with Go 1.24.6. Keep that
# release (tag 1.19, commit below; gosu tags are not Go semver) and rebuild it from its
# module (checksum database verified) with the patched toolchain used elsewhere.
# moby/sys/user is raised to 0.4.1 for GO-2026-6686 (unbounded user/group file parsing).
RUN go mod init vardrsec-gosu-build \
    && go get github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513 github.com/moby/sys/user@v0.4.1 \
    && go build -trimpath -ldflags '-d -w' -o /go/bin/gosu github.com/tianon/gosu
RUN gosu_notice_source="$(go list -m -f '{{.Dir}}' github.com/tianon/gosu)" \
    && mkdir -p /out/gosu-notices \
    && cp "$gosu_notice_source/LICENSE" /out/gosu-notices/LICENSE \
    && if [ -f "$gosu_notice_source/NOTICE" ]; then cp "$gosu_notice_source/NOTICE" /out/gosu-notices/NOTICE; fi

# Keep legal texts from the exact downloaded module cache as inert notice data.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/gosu-notices/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/gosu-notices/GO-LICENSE

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

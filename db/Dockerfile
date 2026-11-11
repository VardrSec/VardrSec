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
RUN go mod download && go mod verify
RUN --network=none go build -mod=readonly -trimpath -ldflags '-d -w' -o /go/bin/gosu github.com/tianon/gosu
RUN gosu_notice_source="$(go list -m -f '{{.Dir}}' github.com/tianon/gosu)" \
    && mkdir -p /out/gosu-notices \
    && cp "$gosu_notice_source/LICENSE" /out/gosu-notices/LICENSE \
    && if [ -f "$gosu_notice_source/NOTICE" ]; then cp "$gosu_notice_source/NOTICE" /out/gosu-notices/NOTICE; fi

# Keep legal texts from the exact downloaded module cache as inert notice data.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/gosu-notices/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/gosu-notices/GO-LICENSE
# Retain exact checksum-verified source archives for all three linked modules.
RUN mkdir -p /out/gosu-notices/source \
    && cp /src/go.mod /src/go.sum /out/gosu-notices/source/ \
    && go list -m all > /out/gosu-notices/source/modules.txt \
    && go version -m /go/bin/gosu > /out/gosu-notices/source/binary-build-info.txt \
    && cd /go/pkg/mod/cache/download \
    && find . -type f \( -name '*.zip' -o -name '*.mod' -o -name '*.info' -o -name '*.ziphash' \) -print0 | LC_ALL=C sort -z > /tmp/gosu-source-files \
    && tar --null -T /tmp/gosu-source-files --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf /out/gosu-notices/source/module-sources.tar \
    && cd /out/gosu-notices/source && sha256sum ./* > SHA256SUMS

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libapt-pkg7.0)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
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

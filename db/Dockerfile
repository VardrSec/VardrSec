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
# These base-image package acquisition tools are not needed by the database
# entrypoint or server. Keep apt's signature verifier; do not autoremove.
RUN apt-get purge -y --no-auto-remove \
    dirmngr gnupg gnupg-l10n gpg gpg-agent gpgconf gpgsm
COPY --from=gosu /go/bin/gosu /usr/local/bin/gosu
RUN gosu --version && gosu nobody true
COPY --from=gosu /out/gosu-notices/ /usr/share/licenses/gosu/

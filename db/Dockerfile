FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gosu
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
# The reviewed PostgreSQL image bundles gosu 1.19.0 built with Go 1.24.6. Keep that
# release (tag 1.19, commit below; gosu tags are not Go semver) and rebuild it from its
# module (checksum database verified) with the patched toolchain used elsewhere.
# moby/sys/user is raised to 0.4.1 for GO-2026-6686 (unbounded user/group file parsing).
RUN go mod init vardrsec-gosu-build \
    && go get github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513 github.com/moby/sys/user@v0.4.1 \
    && go build -trimpath -ldflags '-d -w' -o /go/bin/gosu github.com/tianon/gosu

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
COPY --from=gosu /go/bin/gosu /usr/local/bin/gosu
RUN gosu --version && gosu nobody true

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gosu
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
# The reviewed PostgreSQL image bundles gosu 1.19.0 built with Go 1.24.6. Keep that
# release and rebuild it from its module (checksum database verified) with the
# patched toolchain used elsewhere in the distribution.
RUN go install -trimpath -ldflags '-d -w' github.com/tianon/gosu@v1.19.0

FROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
COPY --from=gosu /go/bin/gosu /usr/local/bin/gosu
RUN gosu --version && gosu nobody true

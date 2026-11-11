FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS build
WORKDIR /src
ENV CGO_ENABLED=0 GODEBUG=http2client=0
COPY main.go go.mod go.sum ./
COPY sourceprep/ /sourceprep/
COPY canonical_module_archive.sh /usr/local/bin/canonical_module_archive.sh
# The graph is frozen. Retain the actual upstream version and apply a verified
# source backport; do not invent an upstream version to hide scanner findings.
RUN --network=none cd /sourceprep && GOPROXY=off go test ./... \
    && GOPROXY=off go build -trimpath -buildvcs=false -o /tmp/sourceprep .
RUN mkdir -p /out/caddy-notices \
    && go mod download github.com/go-jose/go-jose/v3@v3.0.5 \
    && /tmp/sourceprep /go/pkg/mod/cache/download/github.com/go-jose/go-jose/v3/@v/v3.0.5.zip \
        /sourceprep/backport.json /src/go-jose-v3 /out/caddy-notices/go-jose-v3 \
    && go mod download && go mod verify
# Compilation is offline and cannot mutate the frozen module graph.
RUN --network=none GOPROXY=off go build -mod=readonly -trimpath -buildvcs=false -o /out/caddy .
RUN caddy_notice_source="$(go list -m -f '{{.Dir}}' github.com/caddyserver/caddy/v2)" \
    && mkdir -p /out/caddy-notices \
    && cp "$caddy_notice_source/LICENSE" /out/caddy-notices/LICENSE \
    && if [ -f "$caddy_notice_source/NOTICE" ]; then cp "$caddy_notice_source/NOTICE" /out/caddy-notices/NOTICE; fi

# Keep legal texts from the exact downloaded module cache as inert notice data.
RUN bash /usr/local/bin/canonical_module_archive.sh notices /go/pkg/mod /out/caddy-notices/dependency-notices.tar.gz \
    && bash /usr/local/bin/canonical_module_archive.sh sources /go/pkg/mod/cache/download /out/caddy-notices/module-sources.tar \
    && cp /usr/local/go/LICENSE /out/caddy-notices/GO-LICENSE

FROM caddy@sha256:504a44d7d74bd2bc28a66afc4774912fc21223ca8a67734af1c54ab2f999b489
COPY --from=build /out/caddy /usr/bin/caddy
RUN apk upgrade --no-cache && apk add --no-cache curl \
    && setcap cap_net_bind_service=+ep /usr/bin/caddy
COPY --from=build /out/caddy-notices/ /usr/share/licenses/caddy/

COPY LICENSE NOTICE /usr/share/licenses/vardrsec/

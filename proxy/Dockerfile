FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS build
WORKDIR /src
ENV CGO_ENABLED=0 GODEBUG=http2client=0
COPY main.go .
# Keep the existing Caddy release; rebuild its affected runtime/dependency.
RUN go mod init vardrsec-proxy-build \
    && go get github.com/caddyserver/caddy/v2/cmd/caddy@v2.11.7 \
        golang.org/x/net@v0.62.0 github.com/go-chi/chi/v5@v5.4.0 \
        github.com/go-jose/go-jose/v4@v4.1.6 \
        github.com/klauspost/compress@v1.20.2 \
    && go build -trimpath -o /out/caddy .
RUN caddy_notice_source="$(go list -m -f '{{.Dir}}' github.com/caddyserver/caddy/v2)" \
    && mkdir -p /out/caddy-notices \
    && cp "$caddy_notice_source/LICENSE" /out/caddy-notices/LICENSE \
    && if [ -f "$caddy_notice_source/NOTICE" ]; then cp "$caddy_notice_source/NOTICE" /out/caddy-notices/NOTICE; fi

# Keep legal texts from the exact downloaded module cache as inert notice data.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/caddy-notices/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/caddy-notices/GO-LICENSE

FROM caddy@sha256:504a44d7d74bd2bc28a66afc4774912fc21223ca8a67734af1c54ab2f999b489
COPY --from=build /out/caddy /usr/bin/caddy
RUN apk upgrade --no-cache && apk add --no-cache curl \
    && setcap cap_net_bind_service=+ep /usr/bin/caddy
COPY --from=build /out/caddy-notices/ /usr/share/licenses/caddy/

COPY LICENSE NOTICE /usr/share/licenses/vardrsec/

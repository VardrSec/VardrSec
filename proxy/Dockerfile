FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY main.go .
# Keep the existing Caddy release; rebuild its affected runtime/dependency.
RUN go mod init vardrsec-proxy-build \
    && go get github.com/caddyserver/caddy/v2/cmd/caddy@v2.11.7 \
        golang.org/x/net@v0.60.0 github.com/go-chi/chi/v5@v5.4.0 \
    && go build -trimpath -o /out/caddy .

FROM caddy@sha256:504a44d7d74bd2bc28a66afc4774912fc21223ca8a67734af1c54ab2f999b489
COPY --from=build /out/caddy /usr/bin/caddy
RUN apk upgrade --no-cache && apk add --no-cache curl \
    && setcap cap_net_bind_service=+ep /usr/bin/caddy

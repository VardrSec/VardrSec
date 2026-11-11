#!/bin/sh
set -eu
module=github.com/go-jose/go-jose/v3
test "$(go list -m -f '{{.Version}}' "$module")" = v3.0.5
go mod download "$module@v3.0.5"
go mod verify
source_dir="$(go list -m -f '{{.Dir}}' "$module")"
source_zip="$(go env GOMODCACHE)/cache/download/$module/@v/v3.0.5.zip"
printf '%s  %s\n' 4e7e6b60541ab03bd402e573fc2c1264297e661726c5f53529ca14ae58625a27 "$source_zip" | sha256sum -c -
printf '%s  %s\n' a16f75451c324ada231d814e33bf2cf73281740342c7b8aa2cb286f5cb80c689 /src/go-jose-v3-rsa.patch | sha256sum -c -
mkdir -p /patched /out/caddy-notices/go-jose-v3
cp -R "$source_dir" /patched/go-jose-v3
chmod -R u+w /patched/go-jose-v3
(cd /patched/go-jose-v3 && git apply --check /src/go-jose-v3-rsa.patch && git apply /src/go-jose-v3-rsa.patch)
go list -m -f '{{.Path}} {{.Version}} {{.Sum}}' "$module" > /out/caddy-notices/go-jose-v3/upstream-module.txt
go mod edit -replace "$module=/patched/go-jose-v3"
go build -trimpath -o /out/caddy .
go version -m /out/caddy > /out/caddy-notices/go-jose-v3/build-info.txt
cp go.mod go.sum /out/caddy-notices/go-jose-v3/
cp "$source_zip" /out/caddy-notices/go-jose-v3/upstream-v3.0.5.zip
cp /patched/go-jose-v3/LICENSE /src/go-jose-v3-rsa.patch /src/go-jose-v3-source.txt /src/patch-go-jose-v3.sh /out/caddy-notices/go-jose-v3/
tar -C /patched -czf /out/caddy-notices/go-jose-v3/patched-source.tar.gz go-jose-v3
cd /out/caddy-notices/go-jose-v3
sha256sum ./* > SHA256SUMS

#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
mkdir -p artifacts/kerberos-image
id=$(docker image inspect --format '{{.Id}}' "$image")
printf '%s\n' "$id" > artifacts/kerberos-image/image-id.txt
docker image inspect "$id" > artifacts/kerberos-image/image-inspect.json
docker run --rm --network none --entrypoint sh "$id" -eu -c '
  cd /usr/share/doc/libkrb5-3/vardr-source
  sha256sum -c SHA256SUMS
  cd /
  sha256sum -c /usr/share/doc/libkrb5-3/vardr-source/evidence/package-files-SHA256SUMS
  for package in libgssapi-krb5-2 libk5crypto3 libkrb5-3 libkrb5support0; do
    test "$(dpkg-query -W -f="\${Version}" "$package")" = "1.21.3-5+deb13u1+vardr1"
  done
' > artifacts/kerberos-image/installed-custody.txt
# Local-only disposable database, no ports or network, no persistent data.
# Never print the generated password or save the container configuration.
export POSTGRES_PASSWORD=$(python -c 'import secrets;print(secrets.token_hex(32))')
container=$(docker run -d --network none --tmpfs /var/lib/postgresql/qualification:rw \
  -e POSTGRES_PASSWORD -e PGDATA=/var/lib/postgresql/qualification/data "$id")
trap 'docker logs "$container" > artifacts/kerberos-image/postgres.log 2>&1; docker rm -f "$container" >/dev/null; unset POSTGRES_PASSWORD' EXIT
ready=false
for attempt in $(seq 1 60); do
  if docker exec -u postgres "$container" pg_isready -U postgres >/dev/null; then ready=true; break; fi
  sleep 2
done
test "$ready" = true
docker exec -u postgres "$container" psql -U postgres -v ON_ERROR_STOP=1 -Atc \
  'CREATE TABLE qualification (id integer PRIMARY KEY); INSERT INTO qualification VALUES (1); SELECT count(*) FROM qualification; DROP TABLE qualification;' \
  > artifacts/kerberos-image/postgres-smoke.txt
grep -qx '1' artifacts/kerberos-image/postgres-smoke.txt
printf '%s\n' 'PASS: qualified package payloads, corresponding source and PostgreSQL CRUD smoke; not release clearance' > artifacts/kerberos-image/result.txt

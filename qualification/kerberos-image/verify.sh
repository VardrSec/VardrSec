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
  # Debian slim deliberately omits non-runtime docs and lintian hints.
  # Keep every present byte checked, and allow only these exact omissions
  # when the inherited dpkg exclusion rules are themselves present.
  cat /etc/dpkg/dpkg.cfg.d/*
  while read -r expected path; do
    if [ -f "$path" ]; then
      printf "%s  %s\n" "$expected" "$path" | sha256sum -c -
    else
      case "$path" in
        ./usr/share/doc/libgssapi-krb5-2/changelog.Debian.gz|./usr/share/doc/libk5crypto3/changelog.Debian.gz|./usr/share/doc/libkrb5-3/README.Debian|./usr/share/doc/libkrb5-3/README.gz|./usr/share/doc/libkrb5-3/changelog.Debian.gz|./usr/share/doc/libkrb5support0/changelog.Debian.gz)
          grep -Fxq "path-exclude /usr/share/doc/*" /etc/dpkg/dpkg.cfg.d/* ;;
        ./usr/share/lintian/overrides/libgssapi-krb5-2|./usr/share/lintian/overrides/libkrb5-3|./usr/share/lintian/overrides/libkrb5support0)
          grep -Fxq "path-exclude /usr/share/lintian/overrides/*" /etc/dpkg/dpkg.cfg.d/* ;;
        *) echo "FAIL: unexpected missing package payload: $path" >&2; exit 1 ;;
      esac
      printf "BASE-POLICY NON-RUNTIME OMISSION: %s\n" "$path"
    fi
  done < /usr/share/doc/libkrb5-3/vardr-source/evidence/package-files-SHA256SUMS
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

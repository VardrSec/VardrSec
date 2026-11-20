set -eu
source=/usr/share/doc/libacl1/vardr-source
(cd "$source" && sha256sum -c SHA256SUMS)
grep -Fx "cp-path-substitution: EXPECTED_VULNERABLE" "$source/evidence/negative-controls.log"
grep -Fx "tar-path-substitution: EXPECTED_VULNERABLE" "$source/evidence/negative-controls.log"
grep -Fx "cp-path-substitution: PASS" "$source/evidence/stripped-payload-regressions.log"
grep -Fx "tar-path-substitution: PASS" "$source/evidence/stripped-payload-regressions.log"
cd /
for payload in 'bin/cp' 'bin/tar' 'lib/[^/]+/libacl[.]so[.][0-9.]+'; do
    if ! grep -hE "  [.]/usr/$payload$" "$source"/*.files-SHA256SUMS > /tmp/acl-runtime-hashes ||
        [ "$(wc -l < /tmp/acl-runtime-hashes)" -ne 1 ]; then
        echo "Expected exactly one installed checksum for $payload" >&2
        exit 1
    fi
    sha256sum -c /tmp/acl-runtime-hashes
done

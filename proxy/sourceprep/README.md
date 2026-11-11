# Verified go-jose v3 source preparation

This stdlib-only helper applies a narrow backport from upstream go-jose v4.1.6
(`a0111f82742fa92bceec9ede40845e73319e6230`) to v3.0.5
(`be2f6548701d4ba561cd61c7d4a2f1289b66c273`). Caddy remains 2.11.7.

`backport.json` specifies the exact upstream module ZIP SHA-256, original and
result file hashes, and byte edits. It includes no new private-key fixtures.
The helper verifies all inputs and edited outputs before creating fresh output
directories; it refuses existing destinations, traversal and oversized archives.
It retains the upstream ZIP, complete patched source tar, license, byte-edit
plan, and a hash receipt. The archive has canonical ordering, permissions and
zero timestamps. No module version is fabricated.

The backport covers the upstream RSA modulus and prime-product checks, early
private-parameter rejection for internal JWS `jwk` and JWE `epk` parsing, and
associated header-order fixes. The default RSA modulus limit is 4096 bits and
can be changed before parsing, as upstream permits. Direct `JSONWebKey.UnmarshalJSON`
still supports private keys and is not generally safe for untrusted input.
This is not the separate v4 CEK-size change or an algorithm-allowlist API migration.

Qualification before integration: all five v3 package suites pass; upstream
regressions pass with race detection; unpatched negative controls fail; all
five suites also pass using the frozen Caddy dependency graph. The rebuilt
Caddy passes the shipped loopback JWK ingress fixture. These results do not
assert universal vulnerability clearance or final OCI image identity.

The Docker build verifies dependencies online, then compiles with `GOPROXY=off`,
`-mod=readonly`, `-trimpath` and `-buildvcs=false`. The original version remains
visible to scanners; source patch evidence must be reviewed separately.

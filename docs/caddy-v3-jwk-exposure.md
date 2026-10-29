# Caddy v3 JWK exposure review — 2026-10-28

**Finding: the affected v3 library is present, but its JWK parsing input path is not
exposed by the shipped proxy configuration.** This is a configuration-specific
exposure assessment, not a claim that v3 is patched, a scanner suppression, or an
accepted exception. The raw high occurrence remains and strict review stays blocked.

## Scope and provenance

The review uses distribution main `f31d9e9`, Caddy 2.11.7 built with Go 1.27.3 and
the existing x/net 0.62.0, chi 5.4.0 and go-jose/v4 4.1.6 overrides. Exact source
modules were downloaded with `GOSUMDB=sum.golang.org`; the resolved import graph
and binary build information were checked.

| Module | Version | Verified upstream revision |
| --- | --- | --- |
| caddyserver/caddy/v2 | 2.11.7 | `72dd0fb067f6d7826c7f79907670ba4a713bfe37` |
| smallstep/certificates | 0.30.2 | `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31` |
| go.step.sm/crypto | 0.91.0 | `622be32d9288f7491092aacf19f7bbc035684fc0` |
| go-jose/go-jose/v3 | 3.0.5 | `be2f6548701d4ba561cd61c7d4a2f1289b66c273` |

The [upstream advisory](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q)
covers CVE-2026-116587 and has no v3 fix. Go's vulnerability database did not cover
this advisory at the earlier checkpoint. Its zero-reachable result does not provide
this assessment; the source trace and controls below do.

## Actual input path when the optional ACME server is enabled

1. Caddy's [standard imports](https://github.com/caddyserver/caddy/blob/72dd0fb067f6d7826c7f79907670ba4a713bfe37/modules/standard/imports.go)
   register `http.handlers.acme_server`; registration alone does not install a route.
2. The [ACME handler](https://github.com/caddyserver/caddy/blob/72dd0fb067f6d7826c7f79907670ba4a713bfe37/modules/caddypki/acmeserver/acmeserver.go)
   provisions a Smallstep ACME authority and dispatches its configured path prefix
   through `acmeEndpoints.ServeHTTP`.
3. Smallstep's [route middleware](https://github.com/smallstep/certificates/blob/6e8ec61405239cf3f37b2bbf260a587b7d2e4e31/acme/api/handler.go)
   runs `parseJWS` before `validateJWS`. The [parser](https://github.com/smallstep/certificates/blob/6e8ec61405239cf3f37b2bbf260a587b7d2e4e31/acme/api/middleware.go)
   passes the untrusted request body to `go.step.sm/crypto/jose.ParseJWS`, which
   [delegates](https://github.com/smallstep/crypto/blob/622be32d9288f7491092aacf19f7bbc035684fc0/jose/types.go)
   to v3 `ParseSigned`.
4. v3's [header sanitization](https://github.com/go-jose/go-jose/blob/be2f6548701d4ba561cd61c7d4a2f1289b66c273/shared.go)
   JSON-decodes the embedded JWK before rejecting non-public material. The
   [JWK decoder](https://github.com/go-jose/go-jose/blob/be2f6548701d4ba561cd61c7d4a2f1289b66c273/jwk.go)
   calls `rawJSONWebKey.rsaPrivateKey`, which calls `rsa.PrivateKey.Validate`.
   Thus enabling this handler can expose the affected work before nonce/signature
   verification; a valid account or signature is not a prerequisite for parsing.

## Why the shipped proxy does not expose that path

The real Caddyfile adapter output has `admin.disabled: true`, only internal TLS
issuers, host-trust installation disabled, and HTTP handlers limited to `subroute`,
`rewrite` and `reverse_proxy`. The two upstreams are Map API and web. No ACME server
handler, HTTP JWT/JWK consumer or externally configurable authority is installed.
HTTP bodies and Authorization values are forwarded as data to the applications;
Map's own authentication is a separate implementation, not assessed here.

Internal certificate issuance is a different call path. Caddy's
[InternalIssuer.Issue](https://github.com/caddyserver/caddy/blob/72dd0fb067f6d7826c7f79907670ba4a713bfe37/modules/caddytls/internalissuer.go)
builds an authority without provisioners and calls `SignWithContext` with a locally
generated CSR and certificate-lifetime modifier. Smallstep
[initializes an empty provisioner list](https://github.com/smallstep/certificates/blob/6e8ec61405239cf3f37b2bbf260a587b7d2e4e31/authority/config/config.go);
[signX509](https://github.com/smallstep/certificates/blob/6e8ec61405239cf3f37b2bbf260a587b7d2e4e31/authority/tls.go)
checks/signs that CSR rather than parsing an inbound JWS. Root/intermediate key
material comes from generated or operator-controlled storage. An attacker able to
replace configuration or CA storage is outside this HTTP-input assessment.

## Reproducible controls and regression guard

`tests/proxy_jwk_boundary.py` adapts the actual Caddyfile with the actual proxy
binary and rejects changes to the reviewed admin/issuer/handler/upstream/trust
assumptions. Unit tests include a nested ACME handler and missing/changed controls.
The live probe uses temporary loopback listeners and disposable CA/storage, verifies
TLS against that fixture CA, starts no installed platform and enrolls no host trust.

- Shipped-route control: a tiny, deliberately invalid private RSA JWK is placed in
  the JWS POST body and Bearer header. `/acme/local/new-account` and its `/backend/`
  counterpart reach the echo applications with exact body/header hashes intact.
- Positive control: adding `acme_server` produces ACME `malformed` for that input.
  A public P-256 generator-point control with the same invalid nonce instead reaches
  `badNonce`. The server intentionally hides detailed parser errors; this response
  difference is interpreted together with the source trace, not as a timing proof.
- A separate bounded source-parser control on v3.0.5 returned the Go 1.27 RSA/FIPS
  validation error `modulus must be > 1`. Its parameters are one byte; no large-key
  denial-of-service input was executed.

The native development controls passed with the reviewed compiler/source recipe.
Linux CI repeats the configuration and live controls against the binary copied
from the built proxy image and retains a receipt binding its binary/template hashes.
Passing Linux evidence is required before promotion; native results are not Linux
release certification. Existing trusted-installation/renewal/recovery checks remain.

## Disposition and limits

Proposed for owner review: conditional non-exposure for the recorded source versions
and shipped configuration only. **Nothing is accepted automatically.** Keep the raw
v3 occurrence, track upstream migration/fixes, and re-review before enabling ACME
server/JWK authentication, changing issuers/provisioners, enabling dynamic admin
configuration, or changing these dependencies. Operator custom configurations are
not covered. No v3 source patch, plugin removal, TLS weakening or risk waiver is made.

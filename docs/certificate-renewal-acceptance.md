# Accelerated leaf certificate renewal

Run the disposable fixture with Docker Linux containers and Python 3.10+:

```sh
python tests/certificate_renewal_acceptance.py
```

The `certificate-renewal` CI job runs the same test. It builds the proxy from the
distribution's digest-pinned Dockerfile and uses a separate Caddyfile with a
two-minute internal leaf lifetime, one-second renewal scan and 0.5 renewal window.
The production Caddyfile keeps its defaults. Caddy documents the
[internal issuer lifetime](https://caddyserver.com/docs/caddyfile/directives/tls#internal)
and [renewal interval](https://caddyserver.com/docs/caddyfile/options#renew_interval).

The fixture requires:

1. A fresh browser rejects the installation before CA enrollment, then accepts
   the expected HTTPS response after an explicit import into its container's NSS store.
2. Fresh, authenticated TLS handshakes succeed every second, with session reuse
   rejected. A new leaf serial appears before the original certificate expires and
   its expiry extends beyond the original's.
3. Observation continues past the original expiry. A fresh browser still accepts
   HTTPS using the same public CA enrollment. Caddy is neither restarted nor
   reloaded during renewal; the test does not change clocks or delete certificates.
4. Root and intermediate certificate hashes stay unchanged through renewal and
   proxy stop/start. The restarted proxy remains trusted with the original public
   CA. Both CA private keys have no group/other file permissions.

Each invocation owns a uniquely named Compose project and removes its volumes in
cleanup. The proxy has no published host port and uses an internal Docker network.
Only its public root is copied to private temporary host storage and mounted
read-only in the browser container. Private CA keys stay in the disposable proxy
volume. The test changes no workstation trust store and starts no platform scans.

This establishes accelerated leaf renewal for the pinned proxy and a Linux browser
fixture. It does not establish weeks of default-lifetime operation, intermediate
renewal, root rollover, expiry of an enrolled root, or fresh-host Docker Desktop
acceptance. Those remain release acceptance items. Native Windows/macOS enrollment
and the macOS residual trust-record limitation are covered separately in
[native trust acceptance](native-trust-acceptance.md). Full Compose login, restart,
encrypted recovery and controlled updates have their own CI jobs.

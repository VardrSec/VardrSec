# Changelog

## Unreleased

- Pin merged Runner #91 (`bd184c6`): container httpx 1.12.0, Subfinder 2.17.0 and FFUF 2.3.0
  are rebuilt from recorded source with Go 1.27.3 and patched dependencies, extending the
  Katana/DNSx/Naabu/Gau contract. Native archives and runtime hash checks are unchanged.
  Image security gates remain blocked pending review of this pin's scan.

- Installed workflow acceptance no longer seeds client, testing window, scope or
  written authorization through the API: the real browser journey records them
  through the Map interface (merged Map #119, `6ea3792`) and the test then
  verifies what the backend holds.

- Record the exposure review of the remaining libxml2 and ncurses findings: no
  reachable path demonstrated in the packaged configuration, none accepted as risk,
  gates unchanged. Documentation only.

- Add networking and VPN guidance: when to use the native Runner, what is verified,
  and what remains unverified (genuine VPN routing, split tunnelling, kill switch).
  Documentation only; no host network, firewall or VPN behavior changes.

- Rebuild the gosu helper in the pinned PostgreSQL image from its v1.19.0 module with the
  distribution's patched Go 1.27.3 toolchain (`db/Dockerfile`). The reviewed PostgreSQL
  base digest and gosu release are unchanged; only the Go standard library bundled in
  that helper is replaced. Image evidence now builds the database image instead of
  pulling it. Remaining Debian-package findings in the base image are unchanged and
  unresolved.

- Pin merged Runner #89 (`4fae92f`, squash of reviewed head `0fdb1c2`): container Gau is rebuilt from
  checksum-verified upstream source with four hash-pinned substitutions that enable
  provider TLS verification and make provider failures fatal. Runner CI exercised
  untrusted, wrong-host, trusted, valid-empty, malformed and initialization cases
  through the producing handler. Native Gau archives do not gain the fix, no alpha
  tool-scope decision is made, and image security gates remain blocked pending the
  rescan of this pin.

- Pin merged Runner #88: build existing Naabu 2.6.1 with patched Go dependencies,
  recorded source provenance and unchanged runtime libpcap/privileges. Record
  audited DNSx integration evidence and the separately confirmed Gau provider TLS
  verification blocker; no dependency-only Gau rebuild is promoted.

- Pin merged Runner #87: extend recorded container source builds to existing
  DNSx 1.3.1, verify a real isolated DNS lookup and preserve native archives.
  Record independently audited Katana integration evidence; residual image
  findings and release gates remain blocked.

- Pin merged Runner #86: build existing Katana 1.8.0 with patched dependencies
  and explicit source provenance while retaining all nine tools, native archive
  installation and runtime integrity checks. Revalidate the combined development
  images; remaining security findings still block release.

- Align the existing age acceptance-tool builds with reviewed Go 1.27.3 and
  disable implicit compiler downloads. Keep age v1.3.2, backup format and
  application images unchanged; verify the existing encryption/recovery cases.

- Record partial Debian vulnerability exposure review with vendor conditions,
  split-package context and bounded local file probes. Retain all blocked image
  findings and the need for reviewed per-finding dispositions.

- Exercise first-run Runner key creation through the real Settings UI before
  authenticated CLI diagnostics and status reporting. Keep its one-time secret
  out of shared logs/screenshots and clarify the installation guide's key step.

- Rebuild the existing proxy with chi 5.4.0 to remove CVE-2026-114437 from
  the dependency inventory. Caddy version, standard modules and TLS configuration
  remain unchanged; other image-security findings remain under review.

- Record the verified clean Ubuntu first-run and residual security checkpoint;
  align current acceptance with the Linux-first alpha scope. Keep security,
  unfamiliar-user and experimental-platform limits explicit.

- Improve first-run prerequisite errors and safe retry of an interrupted initial
  source fetch; preserve existing configuration and changed checkouts. Expose the
  existing generated-password bootstrap mode and display the public CA fingerprint.
  Verify genuinely clean Ubuntu setup, explicit native CA enrollment/removal and
  CLI bootstrap in the installed acceptance job. No automatic trust or routing changes.

- Adopt the owner's Linux-first Community Alpha stabilization priorities and
  refresh proxy OS packages during the development image build. Remaining image
  vulnerability findings still require review; no release is published.

- Add explicit development image SBOM/vulnerability evidence collection and a
  separate strict review command. Blocking findings remain visible; no image
  publication or release readiness is implied by collection success.

- Record the agreed component responsibilities and the first readiness/diagnostics
  implementation reviews. Add a candidate source manifest and validation CI.
- Compose lifecycle, local authentication, component images and the Map status UI
  remain planned; no runnable distribution or release is published by this change.

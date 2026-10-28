# Gau provider TLS review — remediation under review

Update: [Runner #89](https://github.com/VardrSec/VardrRunner/pull/89) contains a
source-patched container Gau (ADR 0021) whose Runner CI fixtures reject untrusted
and wrong-host certificates and accept an explicitly trusted one. This distribution
PR pins it; installed-workflow, tool/network and image-evidence results for this pin
are still required. The native archive keeps the defect but is excluded: Runner #94 refuses to install or run it, and the finding below is
unresolved until those pass and the alpha Gau scope is decided.

Confirmed existing behavior, 2026-10-27. This is a release blocker for a toolkit
that includes this Gau behavior. The nine-tool development baseline remains;
alpha shipping scope and any exception require a separate reviewed decision.
No fix, release clearance or vulnerability suppression is claimed here.

## Source and observed behavior

Gau 2.2.4's [provider-client configuration](https://github.com/lc/gau/blob/v2.2.4/runner/flags/flags.go)
sets `tls.Config.InsecureSkipVerify` to `true`. This disables ordinary certificate
chain and hostname verification for that client. This finding concerns Gau's
provider HTTPS transport; Map/Runner API transport has its own validation path.

A bounded local test used a synthetic URLScan-format provider over HTTPS on an
isolated internal Docker network. It published no host ports, supplied no API
credentials and changed no host trust. Its self-signed certificate was untrusted
and mismatched the provider address. An ordinary Python HTTPS client rejected
it with certificate verification failure. Both the existing Linux/amd64 Gau
archive and an unpromoted dependency rebuild accepted it and parsed the synthetic
provider result. They ran as UID 10001 with no capabilities and bounded timeouts.

| Reviewed binary | SHA256 | Observed result |
| --- | --- | --- |
| Existing Gau 2.2.4 Linux/amd64 archive binary | `22a7061bfa74e90b2995b2d82cab7d432ddb4ba85e3665dc5c06ac6eaad36cc3` | Accepted the untrusted/mismatched provider certificate. |
| Unpromoted Gau 2.2.4 dependency rebuild | `9456313f49a9bf7a124bf86fd869afaac2910bcadab53753cca504d9bc77412e` | Retained the same behavior. |

The experiment rebuilt the same upstream command with Go 1.27.3, x/net 0.60.0,
compress 1.18.7, logrus 1.9.3 and fasthttp 1.34.0. Its standalone Trivy 0.76.1
scan against the frozen 2026-10-27 database reported no findings. That result
does not detect or repair this TLS configuration defect. The rebuild has **not**
replaced the managed toolkit binary or native archive pins. Local receipts,
binary/build hashes and synthetic logs are retained privately; this is not CI
acceptance or authenticated release provenance.

## Required remediation and limits

Enable ordinary chain/hostname verification and test rejection of untrusted and
wrong-host certificates plus success with explicitly trusted valid certificates.
Keep source patches and dependency/build provenance explicit. Do not introduce an
automatic insecure fallback or change host trust to obtain a passing result.
Retest the producing Runner path and error reporting before integrating a fix.

An interceptor able to control provider traffic could potentially falsify
collected URLs; configured provider API credentials could also be exposed. These
are implications of disabled verification, not evidence that an actual engagement
or credential was compromised. Runtime confirmation here covers the named
Linux/amd64 binaries and controlled provider, not every provider/platform mode.
Keep the [alpha security task](community-alpha.md) open and retain the raw image
findings independently of this behavioral finding.

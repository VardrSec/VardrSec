# Community Alpha checkpoint — 2026-10-27

Development evidence only. No alpha, images or deployment is published. The
[stabilization plan](community-alpha.md) controls work order; this checkpoint
records tasks 1–3 without claiming an unfamiliar-user exercise has occurred.

## Security review

Map #117, Runner #85 and distribution #14/#15 are merged. The source-pinned
[five-image collection](https://github.com/VardrSec/VardrSec/actions/runs/40488109681)
passed with independently verified input/report hashes. Critical/high package
occurrences fell from 13/518 to 7/455. The [security assessment](alpha-security-assessment.md)
records remaining findings, vendor status, binary-symbol review and exposure
limits. Every strict image gate remains blocked. No suppression or release
exception was introduced. Task 1 remains open for residual review/remediation.

## Clean Ubuntu setup

[PR #15's Compose run](https://github.com/VardrSec/VardrSec/actions/runs/40490143688)
passed at head `7d9cdc3aa5a535ef30a0cd829443f259299d305e`, merged as
`9e59dd890a9691e2d999547345be0a90693265c8`. Its retained installation receipt records:

- Ubuntu 24.04 x86_64, Docker 28.0.4 and Compose 2.38.2.
- No configuration, component checkout, application image, container or volume
  before setup. Docker/Python/Git were already installed on the hosted machine.
- Distribution-only source acquisition/build/start and real database migrations.
- Native curl rejection before enrollment, ordinary verified HTTPS after explicit
  OS enrollment, exact public-CA removal and renewed rejection afterward.
- Separate fresh Chromium/NSS trust, generated-password CLI bootstrap, UI login,
  secure cookie/CSRF checks, authenticated CLI Doctor and explicit one-shot status.
- Installed reviewed Gate execution, write/readback, finding/retest/report workflow,
  stop/start retention and encrypted restore with accepted evidence hashes.
- Successful controlled update, failed update/recovery and certificate renewal in
  separate jobs. Platform startup still starts no scans or background Runner.

Forty-two unit cases ran in Windows/Linux compatibility CI with the real age
tools. Full installation/recovery/update, native trust, bounded tool/network and
image collection checks passed before merge. Unit counts alone are not readiness.

Setup improvements preserve existing credentials and source work, provide missing
command/Compose/container-mode errors, allow a safe interrupted initial fetch
retry, expose existing secure generated-password bootstrap and print the public
CA fingerprint. Doctor keeps JSON stdout. No new installer framework, automatic
host trust, routing, firewall change or authorization bypass was added.

This is an automated clean application environment with preinstalled prerequisites,
not proof that an unfamiliar researcher can complete the guide without help. A
fresh Ubuntu browser process is tested in an isolated container; the native OS
trust check uses curl. Their boundaries must not be conflated. No reproducible
Ubuntu installation failure occurred in this run. The retained Windows checkout
cache failure described in the security assessment remains a separate local issue.

## Platform and next-work boundary

| Environment | Current evidence / alpha status |
| --- | --- |
| Ubuntu 24.04 Linux/amd64 | First alpha candidate; automated clean application installation and workflow passed. Security and unfamiliar-user gates remain open; no supported release yet. |
| Ubuntu 22.04 Linux/amd64 | Bounded synthetic tool/network CI passed; full clean installation is not certified. |
| Windows 11 / macOS Docker Desktop | Experimental. Existing Windows Desktop runs and native hosted OS trust tests do not establish fresh full Desktop installation. Their incomplete acceptance does not block a Linux-only alpha. |
| Linux arm64 / other hosts | Full candidate installation and workflow not established. |

Next: finish residual security decisions/fixes and observe first-run friction.
Then validate task 4 from the researcher's UI, including client, authorization and
scope setup: the existing installed fixture still seeds those three records via
the authenticated API. It is strong execution/recovery evidence, not yet the
complete no-workaround researcher journey. Real VPN remains unverified. Preserve
these limits while reusing the existing tests; no additional architecture is
needed. Actual timed first-user testing remains task 9.

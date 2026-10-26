# Native certificate trust acceptance

The native trust workflow uses disposable GitHub-hosted Windows and macOS machines.
It downloads official Caddy 2.11.7 assets only after SHA-256 verification, creates
fresh installation-specific CA material in a temporary directory and disables
automatic trust installation. Each probe starts a new Chromium process with its
normal certificate validation.

The required sequence is:

1. Reject HTTPS before the fresh root CA is trusted.
2. Explicitly enroll only that public root through elevated LocalMachine Root on Windows or
   the system keychain/admin trust domain on macOS.
3. Accept the expected HTTPS response with default browser certificate validation.
4. Remove the exact fixture certificate/trust entry and reject HTTPS again.

The harness refuses ordinary workstations and self-hosted runners before any trust
store change. Windows' store script has the same guard independently. Cleanup
attempts exact-fingerprint removal even on failure. Private CA keys and logs stay
in the ephemeral fixture and are never uploaded. Linux already has the real
Compose/login/CA enrollment acceptance with an isolated browser certificate store.

See the **Native certificate trust** checks on the PR for measured results. These
checks validate native CA enrollment, browser trust and trust removal; they do
not certify Docker Desktop installation, VPN/network reachability or the full
Compose application on a newly installed Windows/macOS computer. Those remain
separate end-to-end release acceptance checks. The manual procedures are in the
[installation guide](installation.md#explicit-certificate-trust).

Windows CurrentUser enrollment requests a consent UI and cannot complete in the
non-interactive hosted session. CI therefore exercises the explicit administrative
LocalMachine alternative. It does not certify the interactive CurrentUser prompt.

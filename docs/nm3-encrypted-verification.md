# NM-3 isolated encrypted recovery verification

Branch-only synthetic acceptance extends CLI harness commit
`c01755bd14c8eca18aaf69d1b7eff86aa18f0de9` (successful run 41966449295).
The installed source remains exactly
`07307a2707eefd772f00eeac6d4977680f854c4d`; component pins are unchanged.
No production state, external scans, release, deployment or broad PR is involved.

The workflow builds the already approved official age v1.3.2 module with the
existing pinned Go 1.27.3 and checksum database verification. Its module and
module-file checksums are additionally matched literally before installation.
Official `FiloSottile/age` tag v1.3.2 and the Go module proxy independently resolve
to commit `b74dce4cdbe35b5e5f66c06d9612b72f89028758`.

A fresh GitHub-hosted Ubuntu 24.04 VM must pass the existing empty local Docker
daemon guard. It installs the unchanged Full candidate, seeds only synthetic
rows, generates a v4 backup and retains that plaintext bundle. Ephemeral age
identities live only in the private VM directory. It seals the bundle, verifies
wrong identity, truncation and tampering publish no unsealed destination, then
authenticates the original ciphertext into a new bundle. Source-bound bundle CLI
restoration checks database and volume fingerprints, retained locks, and refusal
to reinitialize restored state. The source fixture remains retained.

Only the allowlisted receipt at `nm3-full-fresh/public/receipt.json` is uploaded.
No keys, recipients, backups, configuration, raw subprocess output or private
logs are uploaded. No explicit fixture volume, backup or CA deletion is added;
the hosted VM is disposed by GitHub. Standard recovery helpers and private
unseal staging retain their existing lifecycle.

This is a verification-only branch change; the source changelog is deliberately
unchanged so the existing exact-candidate byte guard continues to hold.
It does not establish final NM-3 cohort, Mapless, Windows, upgrade/no-loss, or
SQLite snapshot non-mutation acceptance. Hosted results remain unproven until
the exact committed workflow completes successfully.

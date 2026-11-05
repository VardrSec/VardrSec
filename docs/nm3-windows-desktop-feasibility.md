# Windows 11 Docker Desktop feasibility

Verified 2026-11-05 on an actual Windows 11 host, Docker Desktop 4.96.3,
Docker Engine 29.9.2 and Compose 5.6.1, using Linux/amd64 containers under WSL2.
This is a bounded development feasibility trial, not Windows installation or
Community release acceptance.

## Exact sources and isolation

| Component | Commit |
| --- | --- |
| Distribution | `befe929870107c5a27d291078088fbceaeb58512` |
| Map | `aad63c8151789cd9bf56864456b5fdf1fdcfde41` |
| Runner | `440ebda7405d9f19f2e5c6f954996b525f0ac5da` |
| Gate | `54536ea1d900d0e35adf93b4e026962c4d45d34a` |

Frozen source files were checked against raw Git blob IDs before building. The
private fixture used the shipped Full Compose model with a private image/resource
override, five unique build tags and a new project, volumes and networks. After
building, the override selected the exact resulting image IDs with pulling
disabled. The actual Runner `toolkit` target was used.

Canonical `install` was deliberately not invoked on this shared engine: its
development image tags could overwrite retained installations. Production pins,
operator checkouts, host trust stores and retained installations were not changed.
Private configuration and logs were placed under a restricted Windows DACL.

## Observed behavior

- All five images built successfully in approximately 190 seconds. Map's embedded
  frontend build tests passed 29 suites and 259 tests.
- Real `database-role`, `start`, `export-ca`, bootstrap and diagnostics commands
  worked with the private image selection. CA-validated HTTPS readiness, local
  login, unauthenticated session denial, CSRF denial without mutation and a scoped
  Runner key passed. Certificate verification remained enabled.
- Only database, API, web and proxy services ran. Authenticated Runner diagnostics
  succeeded through the container-to-Map HTTPS route. The trial did not enable
  controlled Linux execution or a managed worker.
- The project stopped with its state retained. Three separate unprivileged,
  read-only, network-disabled containers then created, listed and showed an inert
  local workspace using the same owned Runner state volume, without Map credentials.
- Final identity checks confirmed that all 25 original containers remained stopped
  and unchanged and every original image tag still selected its original image ID.
  Four new stopped services, four owned volumes and three owned networks were
  retained for follow-up verification. No Docker-wide cleanup ran.

The local verification receipt retains exact image IDs, source manifests,
environment details and private-log hashes. It is development evidence, not an
independent attestation. Generated credentials, machine-specific paths and raw
logs are not published with this document.

## Encryption tooling and stopped recovery extension

Official `age` 1.3.2 was subsequently built for Windows/amd64 with the existing
Go 1.27.3 image and normal module checksum/TLS verification. The binaries remain
private and were added only to a test subprocess PATH. Four existing native
synthetic-file tests passed without skips: round trips and exclusive destinations,
wrong-key/corruption/truncation refusal, and 32 MiB streaming integrity. Those
tests ran no Docker commands. Private ACL and temporary-file cleanup checks passed.
The earlier eight native symlink-privilege skips remain separate.

The installed-state recovery extension stopped before backup: one baseline
network ID was missing and the current built-in bridge had a new creation record.
Saved evidence could not prove the missing network's original name/configuration
or explain the change. Project network IDs, volumes, original container states
and original image tags remained intact. The invariant was not relaxed, no
network was recreated, and the installed backup/unseal/restore chain did not run.
The labelled age build container was removed after exact identity checks.

The initial passing lifecycle receipt and later invariant-refusal receipt remain
separate. A new Windows recovery attempt needs a consistent, fully recorded
engine baseline; passing file-crypto tests do not substitute for that trial.

## Required work that remains open

This trial does not prove the canonical Windows installer, browser UI journey,
authorized Gate/recon execution, Mapless installation, managed Linux containment,
active-WAL/journal snapshots, recovery, upgrade or a no-loss transition. Host,
private and VPN target reachability beyond the tested platform route also remains
unverified. The offline workspace check proves metadata persistence only.

Full and Mapless Docker installations, cross-platform execution and native Runner
exceptions remain accepted New Moon requirements. See the
[acceptance ledger](new-moon-acceptance.md) and the separate
[hosted Full workflow](nm3-community-full-verification.md).

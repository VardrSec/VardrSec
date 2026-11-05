# Legacy controlled-ownership recovery checkpoint

This branch binds distribution source `4998e5dfd1554beec88690880c4ac269d4f12240`.
Production `versions.json` remains unchanged. Only the newly copied, disposable
hosted fixture replaces Map `41d3ef6475f1b81f973dd4a73944b6e549500fd6` with
`9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045` and Runner
`668dc56f8685dc6a6225438ad443e26901828069` with
`602a5423dcede0e37dacad52aab3bdad900c9021`. Gate remains
`7f82e499ec407eba072e129e3f3b94f1a4eabe94`. These are the historical NM-2 target
cohort verified by runs 41730266134 and 41973441580, not the final NM-3 cohort.
The old 0031 baseline lacks these records; this check starts directly at 0038
rather than repeating the migration checkpoint.

The existing local-account bootstrap and CSRF-protected authenticated APIs create
one operator, two distinct runner API keys for that same operator, one internal
engagement, a 120-second duration policy and one-slot concurrency policy, and an
ordinary unmarked empty-scope `httpx` job. A controlled claim allocates 30 seconds
and reserves the slot. No worker, tool, scan or target request runs. A second key
must receive exactly 404 for control of the first key's claim, despite same-owner
engagement access. There are no direct SQL writes; SQL only checks actual records.

The existing real v4 backup and trusted generated-bundle CLI restore run in fresh
synthetic projects. Bundle code is compared against the bound checkout before
execution in an isolated Python process. Full restored database/volume fingerprints
must match before startup. Retained execution owner/principal/token hashes,
runner/origin binding, expiry and nonrefundable duration/concurrency accounting
must match. The restored API is explicitly started only on the disposable VM,
using the same restored images and CA, while source apps remain stopped. The
second principal must still receive 404 without changing those records. The first
principal's elapsed lease must report uncertain and return cancel without renewal
or releasing/refunding accounting. No completion or termination is invented.

Source state and snapshot integrity are rechecked. The bundle CLI retains its own
empty `.update-lock`; this is not a snapshot non-mutation claim. Backup, restore,
source projects, volumes and CA material are retained. Only normal temporary
synthetic helper-container auto-removal occurs; there is no explicit teardown.

The branch-only workflow requires a fresh GitHub-hosted Ubuntu 24.04 VM and local
empty non-Swarm daemon, rejects inherited source/config/credential overrides,
uses only synthetic credentials and has read-only repository permissions. Only
an allowlisted receipt containing bound source pins, fixed stage/category and
boolean assertions is uploaded for seven days, visible to repository readers.
Private logs, keys, database content and raw HTTP errors are never artifacts.

Local verification: 12 focused offline unit tests passed, Python compilation and
diff checks passed. These tests cover source/daemon guards, fixture-only pin
changes, corruption/refusal checks and API metadata creation. They do not establish
installed acceptance; the hosted run is separate.

Open: managed enrollment/approval/grant preservation (unregistered issuer), target
budget accounting, final NM-3 cohort, Windows, Mapless-to-Full no-loss, hard-crash
recovery, SQLite snapshot and journal replacement-race safety. Recon and managed
Docker execution remain disabled; the watchdog-hang gate remains failed.

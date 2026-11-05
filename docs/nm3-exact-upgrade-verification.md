# Exact distribution-head historical Full upgrade checkpoint

Candidate: `4998e5dfd1554beec88690880c4ac269d4f12240`. All its tracked files remain
unchanged and are verified before a clean fixture copy is used. Exact push trigger:
`codex/nm3-exact-upgrade-verification`; no PR/manual/main trigger or production
manifest change. Fresh GitHub-hosted Ubuntu 24.04, matching empty local non-Swarm
daemon, no existing containers/volumes/custom networks, no inherited config/source/
secret overrides and new private paths remain required.

Historical run 41730266134 passed only at
`f289a0ce378b9fce382fdaa50a9cc09d4a73f2d4`. Its community_ci,
community_upgrade_acceptance, acceptance_retention and acceptance_diagnostics
modules and helper tests are reused unchanged. Only builder/source verification
and retention/assertion helpers are called; the wider historical run(), Gate
journeys, browser fixtures, OS trust enrollment and cleanup are not invoked.
This is a final exact-source integration checkpoint, not a novel migration test.

| Component | Baseline | Historical upgrade target |
|---|---|---|
| Map | 41d3ef6475f1b81f973dd4a73944b6e549500fd6 | 9f1f5d50d2b3c4aeb4c27ec0a53e077adf758045 |
| Runner | 668dc56f8685dc6a6225438ad443e26901828069 | 602a5423dcede0e37dacad52aab3bdad900c9021 |
| Gate | 7f82e499ec407eba072e129e3f3b94f1a4eabe94 | unchanged |

Install the baseline using the frozen distribution candidate. Build target images
under separate tags from verified clean source commits in a second private copy;
only that disposable copy's versions.json changes. The source installation's pins
and PostgreSQL image remain unchanged. Capacity guards refuse without pruning.
No age, browser, compiler or host package installation step is introduced; normal
component image builds retain their existing dependency/build behavior.

Create a synthetic initial local operator and scoped diagnostic key using the
existing TLS-verified localhost/CSRF flow, without account reset. Run the existing explicit baseline Runner platform/offline diagnostic with that
key and require healthy success, initializing its normal identity/journal/runs
state before measuring retention. No Gate or scan is executed. Seed a dedicated
synthetic table/sequence. Record all original columns/row hashes, existing sequence
definitions/state, restricted application role, Runner/proxy volume fingerprints
and public CA. Normalize only last_used_at of the newly issued diagnostic key,
with the historical separate bounded/nondecreasing telemetry assertion.

Run the real updater with exact immutable target image IDs. Its existing v4 backup,
private rehearsal, explicit local Runner diagnostics, source quiescence checks,
private apply and loopback publication must succeed. Verify actual migration
0031localauth → 0038managedstops, original rows/sequences, role, state volumes, CA,
unchanged source pins/heads, exact final images, successful updater record and
retained validated v4 backup. Anonymous protected readback must remain denied.
No mocked updater or migration is used in the installed journey.

Side effects are restricted to the fresh synthetic VM: source/image acquisition,
local account/key/data creation, component builds, private backup/image archives,
new rehearsal project/volumes, service stops/recreation and local platform
networking. Offline diagnostics do not mean zero local network traffic. Existing
temporary maintenance/diagnostic containers may self-remove, and the updater
clears only its own completed pending record. Source/rehearsal data, named volumes,
backups and CA remain retained; no explicit teardown, image prune, user environment,
external scan, production deployment, recon/managed worker or Mapless activation.

Public output is only the fixed seven-day receipt: candidate/workflow identifiers,
baseline and target pins, fixed status/stage/scope, and six allowlisted booleans.
Repository readers may see it. No raw logs, exception text, paths, config, keys,
row data, fingerprints or archives are uploaded. Normal hosted VM disposal is not
durable private backup retention. Artifact readback may remain blocked locally.

Local checks: 30 focused tests (14 reused migration-helper tests, 7 reused builder
checks, 6 hosted guard checks, 3 orchestration/diagnostic tests); AST/YAML/diff and exact-source
checks. Independent source review precedes publication. Prior candidate full-suite
results retain their original attribution and are not claimed rerun here.

A pass covers this exact distribution candidate and historical component upgrade.
It does not establish final NM-3 cohort selection, nonempty managed authorization
state, Windows, Mapless-to-Full/no-loss, unrelated external/native data, hard-crash
recovery, encrypted roundtrip or SQLite/journal safety. Failed watchdog-hang evidence
remains failed; managed worker and recon execution remain disabled.

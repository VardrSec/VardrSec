# Installed authorization workflow acceptance

The disposable Compose installation check now extends beyond readiness and
heartbeat reporting. `tests/compose_acceptance.py` invokes
`tests/gate_acceptance.py` after the existing trusted-browser login journey.
It uses the exact Map/Runner/Gate sources in `versions.json` and the built toolkit
image. No component source or authorization engine is copied into this repository.
The Map pin includes [Runner policy warning retention #116](https://github.com/VardrSec/VardrMap/pull/116),
the small event-contract correction exposed by this installed workflow.

## What the test requires

1. Log in through the installed UI with its ordinary local session and CSRF
   handling, using normal certificate verification and a CA enrolled only in the
   disposable browser container.
2. Generate an OpenAPI draft in Review → API Surface. Confirm its decisions start
   as `skip`, edit the three fixture cases to explicit allow/deny decisions and
   local credential references, acknowledge review and save through the UI.
3. Queue each case through Dashboard's Gate composer. While it is pending, run
   platform diagnostics and verify the job remains pending with no target traffic
   or execution evidence. No background worker runs.
   The fixture engagement deliberately retains its planned status to exercise
   the existing advisory policy path: Runner's `policy_warning` event must be
   retained in Map's job history without changing execution/stop-work semantics.
4. Explicitly invoke the real toolkit container's `jobs run --yes`. The first run
   omits private-target permission and must fail inconclusively without contacting
   the fixture. Subsequent runs explicitly permit this disposable private target.
5. Execute owner, peer and anonymous identities against vulnerable, fixed and
   unavailable routes. Authenticated identities first check their public subject
   at a known-good session endpoint. Verify request order, identity coverage and
   the multi-parameter resource URL at the actual target.
6. Require vulnerable results to produce triage candidates, fixed results to
   produce no candidates, and unavailable results to remain inconclusive with no
   working resource baseline. `done` is execution completion, never assurance.
7. Check claimed-case hashes, job/case/identity provenance and evidence SHA-256
   hashes through Map's authenticated API. Credential values, response cookies
   and private response canaries must be absent from uploaded records and captured
   output. No confirmed finding is created or evidence linked automatically.
8. Require the installed UI to render each assessment and redacted execution
   evidence. Stop/start the platform and compare the saved assessments/evidence
   hashes against the same authenticated account.

The synthetic target runs on the disposable project's Runner network without any
host-published port. It serves only test records, enforces a request ceiling and
receives generated per-run credentials only through its environment. Target and
browser containers are removed even on failure. No real engagement, external
target, workstation trust store or production service is used.

## Reproduce and inspect

Follow the source-build prerequisites in [installation](installation.md), then use
the same disposable setup as Compose CI:

```sh
python vardrsec.py configure
python vardrsec.py sources
python vardrsec.py build
docker build -t vardrsec-browser:acceptance tests/browser
COMPOSE_PROJECT_NAME=vardrsec-compose-review python vardrsec.py start
COMPOSE_PROJECT_NAME=vardrsec-compose-review python vardrsec.py export-ca
python tests/compose_acceptance.py
```

On PowerShell, set `$env:COMPOSE_PROJECT_NAME='vardrsec-compose-review'` before the
lifecycle commands. Use a fresh disposable project: bootstrap intentionally refuses
an existing administrator, and the job check requires an empty fixture engagement.
The script does not replace existing credentials or clear data to enable a rerun.
After inspection, stop this named test project with
`docker compose -p vardrsec-compose-review stop`. Removing its volumes is a separate
destructive cleanup action; never use that action against an ordinary installation.

Each run under `artifacts/installed-gate/` contains screenshots for each scenario,
sanitized Runner logs and a JSON
receipt with public fixture IDs, assessment metadata and evidence hashes.
These ignored artifacts contain no target credentials or private response bodies.
CI retains them for seven days. The existing recovery drill then snapshots and
restores this installation, including its actual Gate evidence, separately from
the stop/start check.

This is source-built development acceptance on Linux containers, including Docker
Desktop. It does not establish a published release, real-target coverage, host/VPN
routing, a fresh-host trust experience or full tool-mode compatibility. Those
remain in the [acceptance plan](acceptance.md).

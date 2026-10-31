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
   disposable browser container. Generate a Runner-only key through Settings's
   existing Connect Runner flow and verify the one-time key is displayed. The
   fixture captures it only in memory, never in screenshots or public logs, then
   uses that key for real CLI Doctor/heartbeat and Gate execution. A later key
   listing must retain metadata without returning the plaintext key.
2. Generate an OpenAPI draft in Review → API Surface. Confirm its decisions start
   as `skip`, edit the four fixture cases to explicit allow/deny decisions and
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
8. Run the same reviewed mutating case before and after explicitly enabling the
   disposable target's ownership check. Both actors receive HTTP 204; a separate
   reader identity, its own session preflight and reset/before/after checks must
   prove the unauthorized effect before the fix and no effect after it. Verify
   actual target traffic, reader/reset ownership and the unchanged case hash.
9. Explicitly create a triaged finding in the UI, link the vulnerable write
   evidence, record a still-open retest and deliver/export revision 1. Record the
   repair and a verified-fixed retest using new linked evidence. A retest must
   leave the finding status unchanged until the operator explicitly closes it.
10. Create/deliver/export revision 2 with both evidence sets. Check actual browser
    downloads against persisted Markdown and SHA-256 hashes; reopen revision 1
    and prove its content did not change after the repair and retest. Delivery
    here is the operator's report status and local export, not email or proof of
    receipt by an external client.
11. Require all six assessments and redacted execution records to render. The
    synthetic engagement has a client, scope and time-bounded authorization
    record. Stop/start must retain assessments, evidence links, finding history,
    delivered report status and revision hashes for the authenticated account.
    The encrypted backup/restore drill checks those same records after restoring
    into a fresh installation and resetting its fixture administrator password.

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
receipt with public fixture IDs, assessment metadata, evidence hashes and frozen
finding/report snapshots. Browser report downloads are retained beside screenshots.
These ignored artifacts contain no target credentials or private response bodies.
CI retains them for seven days. The existing recovery drill then snapshots and
restores this installation, including its actual Gate evidence, separately from
the stop/start check. A successful installation also writes
`artifacts/installed-gate/accepted.json`; recovery requires that exact accepted
receipt and checks the restored account's records against it.

This is source-built development acceptance on Linux containers, including Docker
Desktop. It does not establish a published release, real-target coverage, host/VPN
routing, a fresh-host trust experience or full tool-mode compatibility. Those
remain in the [acceptance plan](acceptance.md). Write readback is tested only in
the declared synchronous isolated fixture; asynchronous/shared-system strategies,
additional tool modes and external client delivery are not established here.


## Authorization coverage and boundary drafts

The integration pins Map #132 (including the reviewed authorization coverage and
boundary features), Runner v0.54.0 (PR #101), and Gate v0.2.0 (PR #26). Before the
first queued Gate job executes, the disposable fixture approves its three synthetic
identity credential references for the engagement and fixture origin using Runner's
`credentials approve` command. Approvals are stored in the fixture's Runner state;
no credential values are written to logs or receipts. Older Gate builds without
`--literal-job` are incompatible with Runner v0.54.0.
After the real Gate assessments, the disposable fixture captures synthetic observed
exchanges through Map's ordinary ingest API. It checks the installed coverage API:
vulnerable results remain evidence-backed candidates, fixed results are conclusive,
and unavailable results are inconclusive. The browser opens the coverage and boundary
panels, generates a same-tenant boundary draft, and verifies references and all-`skip`
decisions with `ready_to_run: false`. Cases, jobs and target traffic must remain
unchanged by viewing and drafting. Existing UI-only setup, execution, reports,
restart and recovery checks are retained. Passing results are recorded in CI;
advancing the candidate pins does not publish a release or deploy an installation.

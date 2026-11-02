# NM-1 baseline — 2026-11-01

Source inventory, not a release or Windows certification. NM-1 changes are isolated
on `codex/nm1-foundations`; main, existing installations and retained data stay intact.

| Repository | Implementation base (origin/main after fetch) |
|---|---|
| VardrSec | `cbdd6b7833d1551edd60212a80690b65dbb64cef` |
| VardrMap | `41d3ef6475f1b81f973dd4a73944b6e549500fd6` |
| VardrRunner | `668dc56f8685dc6a6225438ad443e26901828069` |
| VardrGate | `2d7424f778d415886b2043ebeb1ae8a6ffb11850` |
| VardrLab | `99d40444311900f05c02e62f1dc5984a9f184313` |

Lab advanced from the assessed `6433720` to #22 before implementation: native Gate
now assesses two stateful export scenarios. Existing untracked release-note and
Lab evidence files are excluded from NM-1 changes. No tracked baseline changes existed.

## Declared build versus observed source snapshots

`versions.json` still pins Map `41d3ef6`, Runner `668dc56`, Gate `7f82e49`.
Gate's local main differs from its pin only in documentation/instructions.
The pre-existing clean detached `.sources` checkouts were Map `3c30cd2`, Runner
`e63b1cb`, Gate `af29a93`: they are older than the manifest. They were not refreshed.
Actual installed image identities are a separate fact, never inferred from a pin.

Latest observed baseline GitHub checks: distribution Compose acceptance
`41265645021` passed; Map CI `41258666822` passed; Gate CI `41173752635` passed;
Lab Verify `41319048393` passed. Runner's latest listed run was a successful
Dependabot update, not a regression-suite result. These are dated observations.

## Preserved boundaries and compatibility

- Distribution owns Compose, HTTPS/trust, pins, backup, encrypted restore and
  rehearsed updates; the ordinary stack starts no execution worker.
- Map owns engagement/team access, authorization records, scope, reviewed cases,
  atomic pending-job claims, claim-time Gate snapshots, receipt-idempotent Gate
  uploads, evidence, triage and immutable client report revisions.
- Runner owns typed adapters, explicit CLI execution, local credential references,
  safe subprocesses, SQLite journal/manifests and conservative interrupted-upload
  recovery. Keep `jobs run`, direct `run`, pipelines and native operation intact.
- Gate owns reviewed multi-identity HTTP assessment, mutation safety, principal
  preflight, independent readback and result semantics. Keep existing case hashes,
  literal-job behavior and historical/unbound inconclusive results unchanged.
- Lab owns independent vulnerable/fixed targets, behavioral oracles and scoring;
  a scanner adapter cannot assign its own ground truth.
- Keep `program_id`, legacy `/programs` paths, existing advisory engagements,
  hosted/local Map authentication, Linux, native Runner and current tool exclusions.
  No silent engagement migration and no changes to development source pins.

## Verified limitations

- No common signed execution permission exists. Direct Runner/pipeline workflows
  still require Map; queue policy is advisory except stop-work.
- Map's job target preview reads scope/recon rather than Gate's actual request
  graph. Gate setup, all identities (including `skip`), reader preflight, repeated
  verification and resets must be bound before Strict support is advertised.
- Authorization rows are editable; enforcement chooses the latest row while the
  active-authorization read searches active/in-window rows. New contracts must
  bind one explicit immutable snapshot, never infer fallback permission.
- Claims arbitrate pending status, not enrolled Runner ownership or an execution
  fence. Stop-work does not cancel active subprocesses. No lease, aggregate budget,
  managed worker or Mapless installer is part of the existing baseline.
- Credential approvals lack TTL and issuer namespace. Run-directory age pruning
  does not consult unfinished journal records. Both remain separately tracked gaps.
- Current Linux acceptance and old Windows Desktop receipts do not certify a
  fresh Windows installation, current toolkit pins, real VPN/DNS or recovery.
- Source-built images have build-time package resolution; pinned inputs do not
  establish hermetic builds, authentic execution provenance or release readiness.

## NM-1 scope and acceptance

Use additive opt-in contract prototypes, one Runner reference validator and narrow
request-guard profiles. Approval may authorize multiple unchanged-plan executions
within an explicit count, scope, limits and validity; each issued execution
contract is single-use. AI can never approve its own work.

NM-1 requires conformance/security fixtures, equivalent local/Map issuance,
execution-plan binding, explicit compatibility/rollback, and a measured Windows
feasibility decision. NM-2 cancellation/workers/budgets and NM-3 installers remain
excluded. Missing runtime enforcement is unsupported, not Strict assurance.

Windows trials must use fresh disposable project names, volumes, credentials,
source exports and image tags; never mutate the retained `.sources`, artifacts,
installed images/tags or default project. Public/customer targets and real VPN
routes require separate explicit target authorization. Record unavailable routes
as unverified and retain native compatibility.

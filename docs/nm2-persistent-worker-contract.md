# NM-2 persistent worker implementation contract

Status: implementation contract, with persistent STOP reporting approved for
isolated testing on 2026-11-06. No persistent runtime has been enabled or accepted.
NM-2 remains open and NM-3 remains paused.

The owner clarified the required behavior: an explicitly enabled background
Runner stays available until explicitly stopped. The current 60-second idle and
32-job controls remain optional finite-session controls. Normal startup remains
disabled. Starting the Runner never grants indefinite execution authority: every
job still requires current authorization, credentials, duration, target,
concurrency, cancellation and evidence controls.

The finite v1/v2 baseline and receipts remain valid within their declared scope;
they do not satisfy persistent availability. This is an additive versioned
extension using the existing Map database, Runner journal, native owner,
Distribution CLI, Docker profile and protected host storage. It adds no host
service, Docker socket, execution engine, capability, privilege or mount.

## Authority and lifetime

Persistent admission records an exact physical identity, enrolled Runner and
immutable availability policy. It supplies no permission to launch a job. The
same six-field physical identity/hash remains; a separate canonical admission
snapshot/hash binds protocol, mode and optional limits. No existing incarnation
is upgraded or rebound in place.

The owner-approved isolated-testing policy is a purpose-limited STOP capability that
lasts until explicit revocation or physical retirement of that incarnation. It
cannot claim, consume, renew permission, publish success, authorize new targets or
refund budgets. The existing trusted-host risk remains: a compromised host or
secret holder could falsely report exit and release capacity prematurely. The
longer reporting lifetime is an explicit authority decision; it must not be
presented as merely an identity TTL change.

After reviewing this concrete departure from ADR0043's finite reporting lifetime,
the owner selected "Approve persistent STOP reporting for isolated testing" on
2026-11-06. Default startup remains disabled. This decision waives no independent
review or platform acceptance and authorizes no release. An alternative
finite reporting grant would require explicit owner-authenticated renewal,
reporting epochs, retained old-grant lookup and late-send fences; no automatic
renewal is implied or implemented by choosing persistent availability.

Disabling new work must remain separate from revoking reporting authority.
Normal operator stop disables new claims and stops the exact incarnation; only
typed physical-exit observation permits its report and retirement. Loss of a
disable/report reply never authorizes replay. Physical emergency stop remains
available when Map is unreachable. Explicit reporting-capability revocation may
leave recovery held; it never fabricates a receipt or substitutes a new key.

## Versions and counters

- Persistent admission is explicit `vardr.worker-admission/3`, `mode:"persistent"`.
  Its `limits` contain `max_attempts:null|canonical-positive-decimal-string` and
  `idle_timeout_seconds:null|strict-bounded-positive-integer`. Both default NULL;
  choosing finite controls is an explicit operator choice. No admission/reporting
  expiry becomes a job hard ceiling.
- The v3 admission has exactly the existing identity/enrollment/origin/capability
  fields, replacing legacy `expires_at`/top-level `max_attempts` with `mode`,
  `limits`, `reporting_authority`, and `admission_sha256`.
  `reporting_authority` is exactly
  `{purpose:"worker-stop-only",expires_at:null}` for the proposed policy. The
  admission digest covers every other admission field, including that policy.
  Optional idle limits are strict integer seconds in `1..86400`; optional attempt
  limits are canonical positive decimal strings within the counter range.
- v3 JSON sequence/cursor numbers are canonical ASCII decimal strings, range
  `0..9223372036854775807`; active attempts start at 1. No signs, leading zeroes,
  floating-point conversion or wrap. Database and local journal counters use
  signed 64-bit integers; native uint64 fields enforce the same maximum. Existing
  finite v1/v2 wire formats and numeric bounds remain unchanged.
- Bindings and observations carry the immutable admission hash and exact v3
  sequence. Each binding digest covers physical identity/hash, admission hash,
  sequence and the existing seven-field job binding. Fresh per-job contracts,
  original one-use tokens and durable send fences remain mandatory.
- Existing generic job completion, result and stop receipts remain unchanged.
  New versioned runtime bind/release/history/retirement observations wrap those
  exact receipts; no synthetic completion or missing-history absence is accepted.

Runtime wrappers are versioned explicitly: bind/ack `/3`, idle-release `/2`,
attempt-history observation `/2`, current runtime observation `/3`, original-key
claim/receipt observation `/4`, claim association `/3`, and retirement `/3`.
The existing four-field host-stop envelope can retain its shape while carrying
the new canonical retirement. All persistent wrappers include the admission hash
and decimal-string cursor where applicable; old-version parsers must reject them.

## Native owner and execution epochs

Keep an explicit persistent-image/protocol path beside the matching finite
images. The PID-1 bootstrap, credential separation, five empty capability sets,
NNP, private channel and descriptor isolation remain unchanged. No implicit
protocol negotiation or downgrade is allowed.

Startup remains bounded until authenticated HELLO. The v3 private protocol has a
distinct magic and the existing bounded frame size. HELLO establishes only
nonspawning idle and fixes any optional finite idle/job limits; it installs no
execution lease. Defaults impose no 60-second idle expiry or 32-job cap.

The first LEASE for the exact next sequence pins its fresh verified finite job
hard ceiling and binding. Refreshes require that exact sequence/binding and may
never widen or revive the hard ceiling. Capture a conservative clock anchor per
attempt before claim and never rebase an active attempt. Idle availability is
not passed to `owner.run` as permission.

Return to idle requires normal native return, actual empty lineage, sealed
callbacks, the joined exact Control thread with no RPC in flight, no stop reason,
durable canonical terminal/result acknowledgement, native DONE and acknowledged
Map release. A naturally failed result can use this path only with every same
proof and no Stop row. Confirmed-stop partial evidence, cancellation, control or
lease loss, hard expiry and unknown replies remain non-reusable. The existing
namespace-exit containment boundary stays intact. Persistent normal operation
does not imply automatic crash restart or replay of an unresolved attempt.

## History and host custody

Keep every attempt/tombstone in the existing Map/Runner stores. Use indexed exact
latest/active/requested rows; do not download or truncate an unlimited history at
32. Preserve continuity with an explicit predecessor invariant and verify the
current head. Missing/conflicting/orphaned history remains held. Preserve the
existing lock order: engagement/job/execution/contract/approval before Runtime,
and Runtime before the first ManagedClock acquisition. Admission policy is
rechecked under that lock before any allowance charge.

Host record/3 uses a structured cursor
`{last_sequence:"N",phase:"active"|"idle"}` with numeric comparison. Valid progress
is active-N to idle-N to active-(N+1), never lexical comparison or receipt change
alone. The host's 65 protected report-intent sidecars are indexed by independent
ordinals 0..64, not by job sequence. The 64-KiB MAC record stores bounded cursor
and intent-digest entries only. Exhaustion holds reporting; it does not cap
healthy jobs. No eviction, truncation or replacement of old intents is allowed.

Explicit report continuation still needs selected immutable history proving the
old predicate cannot commit, the identical physical-exit proof, final exact
reinspection, and one durable new intent before one POST. Ordinary reconciliation
is read-only. An idle projection or missing reply alone is insufficient.

## Operator status and compatibility

Normal explicitly enabled background operation selects persistent v3. Explicit
finite-v2 and legacy-v1 selections retain matching image/contract paths; a missing
option must not silently fall back to v1. Document the changed normal CLI default
and retain explicit legacy access. Optional finite controls remain visible.

Keep owner-ready/3 immutable. Advisory presence may piggyback on authenticated
discovery and current/refresh after native/local no-hold checks; it never grants
permission or releases a reservation. Host status combines exact direct daemon
observation with a fresh matching server cursor: idle-ready, active, held, or
stopped. Stale, unreachable or inconsistent presence is held/unconfirmed.

## Required acceptance

Exercise a job arriving after more than 60 idle seconds without operator
reenablement, more than 32 healthy jobs in one admitted incarnation, explicit
operator stop, and the optional finite controls. Every job must retain fresh
approval/credential/budget/lease/result evidence. Repeat the original complete
NM-2 failure matrix on Linux and Docker Desktop with exact cohorts. Component
tests, a healthy slice or the behavior clarification cannot close those gates.

Previously stopped adversarial experiments remain stopped. Owner loss,
channel/credential isolation, pressure and supported-host clock proof remain open
where unverified. No risk is silently accepted or moved to NM-5, and no NM-3 work
resumes before the original preceding phase exits close.

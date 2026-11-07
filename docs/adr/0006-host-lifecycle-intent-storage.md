# ADR 0006: Store lifecycle uncertainty before effects

Status: Private storage candidate. No launcher, activation, registration fence,
publication fence, recovery action or platform acceptance is implemented here.

Existing HostRecords require real registration and a runtime STOP secret. A
pre-start preparation cannot use that schema or reserve the future runtime's
STOP slot, which ordinary registration requires to be absent. A separate closed
`vardr.worker-lifecycle-intent/1` record uses a distinct operation UUID and a fixed
MAC-only purpose in the existing current-user custody backend. The STOP target,
policy and ordinary calls remain unchanged. No provider or dependency is added.

The new store constructor is inert. Every storage/key access requires the exact
live operationV3 capability, records instance, installation/private root and
thread before I/O. Initial record publication is atomic and exclusive; updates
read and authenticate the old record, compare revision and canonical previous
digest, preserve immutable bindings, make flags sticky and observations additive,
then flush/fsync and publish durably before returning readback. Partial private
artifacts and key slots remain on failure; no automatic replay or adoption runs.
Windows publication uses a non-replacing write-through move for creation and the
existing write-through replacement for updates; POSIX syncs the directory.

Source and resource bindings are descriptive metadata. Future orchestration must
independently validate complete live resources and sealed observations before
effects. Retained Created/running JSON never constructs an observation proof.
`environment_contract_sha256` may cover only variable names and fixed public
settings: API keys, target credentials, rendered Config.Env and env-file contents
must never be retained or hashed. Predecessor order is contiguous and no row cap
truncates history; bounded record exhaustion is held, never partial zero.

Compare-and-swap and sticky flags discipline a trusted host's interrupted work.
The key holder can restore an older valid MAC file: this is not anti-rollback
storage, remote attestation or independent proof. Missing/corrupt key/file or
unknown state stays held. A marker, prepared record, absent file or later404
cannot establish execution permission or that an external mutation was unsent.

The storage supports only closed typed metadata and conservative terminal
dispositions. Its abandoned-preparation representation is restricted to described
Created/start-unsent metadata; it implements no abandonment or stop operation.
No registration/publication/create/start calls are wired. A later increment must
place flags immediately before the actual effects in the existing engines.
The create/start wrapper cannot call public `enable` while holding an operation:
that function builds its own HostRecords and lock. Factor one shared private
enable path accepting the same records/token, preserve public defaults and
diagnostic order, and add neither a duplicate engine nor an already-locked flag.

Focused tests use actual storage methods, synthetic custody and private temporary
files. Native credential/MoveFileEx calls are mocked or denied before imports;
native publication durability therefore remains untested by these models. Full
ordinary tests, qualified immutable images and fresh Linux/Desktop lifecycle
acceptance remain required. NM-2 and release gates remain open.

## Schema/2: bind reviewed public registration policy

The current format is `vardr.worker-lifecycle-intent/2` with a separate `/2` MAC
domain. An immutable `registration_policy` has exactly seven mandatory fields:
`origin`, `enrollment_id`, `runner_id`, `protocol`, `expires_in_seconds`, `limits`
and `reporting_authority`. Limits always has exactly `max_attempts` and
`idle_timeout_seconds`; unused fields are explicitly null, never inferred.

Use existing named modes `legacy-v1`, `finite-v2` and `persistent-v3`. Persistent
mode requires null lifetime, the existing strict persistent limits validator and
the exact STOP-only reporting declaration. Legacy/finite modes require an integer
lifetime60..604800, null idle/reporting fields, and respectively null max or an
integer max1..32. No strings/booleans/floats are coerced. Origins/IDs reuse the
existing validators. The policy contains only reviewed public settings: no key,
password, target credential, environment contents or digest of those values.

Public registration defaults remain unchanged. In the existing generic call,
`protocol=None` is interpreted by its already validated registration shape:
`max_attempts` present identifies finite-v2; absent identifies legacy-v1. The
durable policy must explicitly name that selected mode; policy null or a new
alias is refused. This schema increment adds no registration/fence invocation.

Old intent/1 records are held before key access, never migrated, overwritten or
replayed. Creation also refuses a colliding existing file or orphan purpose key.
The fixed `LifecycleIntent/v1` custody namespace and `.intent-key` remain unchanged:
their version describes the format-independent MAC-only key purpose, not the data
schema. A new data domain prevents an old MAC authenticating relabelled bytes.
No key rotation/deletion or future-runtime STOP-slot reservation is introduced.
`observations.host_record_sha256` remains reserved for the acknowledged record;
it must not be consumed by a prepared-record digest in a later registration fence.

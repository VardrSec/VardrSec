# ADR 0006: Store lifecycle uncertainty before effects

Status: Private lifecycle candidate. The sections below record incremental storage,
original registration and publication boundaries. No supported create/start launcher,
recovery action or platform acceptance is provided.

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

The Schema/2 increment uses `vardr.worker-lifecycle-intent/2` with a separate `/2` MAC
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

## Original live registration sequence

The private registration capability binds the exact records/live operation and
intent revision/digest, future runtime identity, immutable reviewed policy, exact
client/observer objects and their existing public pin/context/layout/protocol/max
settings. Its factory requires active, unissued intent metadata and an absent
future-runtime host record. RuntimeIdentity and retained running JSON remain
descriptive: the existing engine's fresh capture and mount validation are still
authoritative. The capability adds no observation proof or execution authority.

Only a sealed, noncopyable, nonserializable in-memory object reaches the fixed
fence. The first attempted fence consumes it before argument validation or I/O,
including failure and interruption. After the existing secret and initial MAC
host record are written, each existing first-registration engine invokes that
fence immediately before its existing session.register call. It rechecks exact
inputs and the authenticated prepared record, then CAS-publishes and reads back
registration_sha256 and registration_may_have_sent. No second registration engine
or callback is introduced. A prepared-record digest stays private on the object;
host_record_sha256 and admission_sha256 remain reserved for later ACK evidence.

Single-use applies to each in-memory object, not to universal factory issuance.
Before any engine preparation, multiple objects can exist, and a fresh object may
be minted after a purely malformed pre-preparation attempt consumed another one.
Such a failed attempt has no external send or storage effect. The existing first
engine's exclusive host record/STOP slot and exact intent revision/CAS remain
the at-most-one-first-send boundary, including lost ACKs and failed fences.

Once an actual engine prepares its host record, prepared, interrupted, unknown or
acknowledged state never mints a replacement capability. A true persisted flag
supplies no replay authority, including when a host record is absent. The existing explicit legacy library
replay_registration helper keeps its original behavior and diagnostics; this
new lifecycle path never calls it, and its existence clears no held intent.
Ordinary None defaults omit the new imports/delegate keyword and preserve the
existing validation, diagnostic and request order. Public enable is unchanged;
its private already-owned path only threads a supplied capability.

The private successful-fence digest proves CAS/readback before send, not that
the original call returned an ACK. There is no publication API in this increment.
A later publication sequence must require the same original live object and an
ACK-success marker set only after the original engine's validated ACK and final
store succeed. Reading any later ACKed record, including explicit legacy recovery,
cannot synthesize that marker or publication authority. Owner-before-start timing,
publication fencing, create/start, recovery and platform acceptance stay separate.

## Original ACK success is live-only

An optional registration capability now opens one sealed scope around the existing
first send, ACK validation and final host-record save. Only that original engine
stages authenticated readback of the exact acknowledged record and admission.
Normal scope exit commits private immutable hashes; failures or interruptions,
including those after staging or after a committed final write, leave no success
marker. Exceptional scope exit performs no I/O and never replaces the original
exception. A retained acknowledged record or explicit legacy replay cannot supply
this original-call marker. Staging is one-use and rechecks the live operation,
thread, exact client/observer pins, fenced intent digest and prepared-record binding.

The marker remains private and has no publication, launcher, observation-proof or
execution authority. ACK hashes are not yet written into intent observations.
Ordinary None defaults import/call no lifecycle code and preserve the existing
request and diagnostic order. Publication fencing, create/start orchestration,
recovery and fresh Linux/Desktop qualification remain open requirements.

TLS CA pins (HostClient.ca_sha256) and signing-anchor bytes (public_trust) are
distinct. Future publication must bind the reviewed canonical signing anchors and
literal destination; it must not substitute the CA hash. No field is reinterpreted
or schema migrated in this ACK-only increment.


## Schema/3 and original publication sequence

The current `vardr.worker-lifecycle-intent/3` uses a distinct `/3` MAC domain and
requires immutable `resources.signing_trust_sha256`: SHA-256 of the reviewed
canonical signing-anchor bytes returned by the existing `public_trust` validator.
The mounted-trust metadata and HostClient's TLS CA pin remain separate; neither
can substitute for these signing bytes. This field closes a demonstrated binding
gap before a future wrapper publishes permission. Old intent/1 and intent/2 files
are held before custody-key access, never migrated, overwritten or adopted.

One noncopyable live sequence can be claimed from the original registration
capability only after its original ACK/save scope completed. Claiming burns that
choice before validation or I/O. Exact original ACK hashes, intent digest, records,
operation/thread and client/observer pins are rechecked. Literal destination paths
and immutable trust/admission bytes are bound; retained ACK files and persisted
flags cannot reconstruct this authority.

The already-owned enable path preserves its fresh capture and mount-custody
checks and uses the existing atomic public writer. Its fixed optional sealed-type
hook runs immediately before that writer's first temporary-file open. Before the
first public effect it CAS-publishes and authenticates readback of the original
ACK hashes and sticky publication-may-have-happened flag. Trust must finish its
existing write/publication/sync path before admission can be attempted. An existing
trust file may instead pass the existing validator with identical canonical bytes;
it is never overwritten. Admission then requires that same live successful
sequence and exact post-fence intent. No callback or second writer is introduced.

A malformed reserved step, failed CAS/readback, partial write, failed publication,
sync/cleanup failure or interruption cannot mint a replacement or retry. The
writer now checks its write count before publishing, including ordinary calls.
Already visible files and uncertain flags stay held. Only successful completion
of both existing publication paths permits the final enabled-disposition CAS.
An unknown final save remains a held operation even if permission is visible.
Scope exit performs no I/O and does not mask the original exception.

None defaults omit all new lifecycle imports/keywords/hooks. Ordinary CLI behavior,
registration engines, diagnostic order and startup remain unchanged. These are
trusted-host sequencing controls, not anti-rollback storage, remote attestation,
protection from a concurrent privileged filesystem writer, or a power-loss
durability guarantee. Model receipts are not platform containment evidence.

Owner authentication before startup, actual create/start orchestration and source/
resource inventories, abandoned preparation and ambiguous recovery, a matched
immutable image and fresh same-installation Linux/Desktop acceptance remain open.
No requirement is moved to NM-3, and no release or deployment is authorized.

# Coupled NM-2 worker acceptance plan

Status: both the earlier one-attempt slice and the frozen two-job Windows Docker
Desktop slice passed. The [two-job evidence](nm2-worker-acceptance-evidence.md)
records its exact scope and preserved-resource guard. Native Linux is being
verified separately; no Desktop result establishes its acceptance. The existing
NM-3 evidence and component pins remain unchanged.

`tests/nm2_worker_acceptance.py` now prepares the first coupled slice: default
disabled, owner/CSRF transport denial, Strict out-of-scope approval refusal, and
two distinct happy fixed-case jobs under one admission with `max_attempts=2`.
Its default command validates source inputs without contacting Docker. Missing
local grant, cancellation, failures and the remaining matrix stay explicitly
`not_run`; this slice cannot close NM-2 alone.

## Fixture and component boundaries

Use a new `vardrsec-nm2-<random-id>` installation/project, exact reviewed image IDs
and an explicit source cohort. Refuse an existing project, nonempty installation
directory or mismatched image/source receipt. Give every created network, volume
and container the exact project/fixture ownership labels. No target port is
published. Only the normal HTTPS proxy may bind one selected loopback host port.
Never select or delete resources by a broad name pattern.

Reuse these existing sources:

- `tests/gate/target.py`: owned fixed/vulnerable/session behavior and bounded
  request observations. A thin subclass may add a fixed 0–15 second response delay
  for the existing read-only resource route and tolerate a closed client socket.
- `tests/gate_acceptance.py`: the pure fixed-case definition and evidence/hash
  checks, without invoking its old fixed-project lifecycle.
- `tests/nm1_guarded_execution.py`: shared controlled-Gate case/approval semantics;
  no copied execution engine and no reuse of old candidate hashes or key material.
- Normal installation `compose.yaml`, `start.sh`, least-privilege database-role
  setup, terminal local bootstrap, trusted CA export and Runner doctor.
- `compose.worker.json`, `worker_runtime.LocalDocker`, `worker_host` and its native
  host custody. The harness must not construct physical-proof objects from JSON.

Before creation, the direct observer verifies the selected Docker context is
local and the daemon runs Linux containers. Separate ordinary UID10001,
capability-free, network-none image helpers compare all production Map/Runner
Python files to the exact clean tracked source cohort, normalizing CRLF to LF.
The receipt records the measured owner/Gate executable hashes separately. These
checks do not independently attest compilation of the native owner or Gate;
retain the reviewed build/source receipts for those binaries.

Actual Docker proof exposed a narrow storage need: `docker cp` cannot observe the
original tmpfs readiness path. The reviewed worker profile therefore uses one
fresh named readiness volume, preseeded by the image for UID/GID10000 and marked
`io.vardrsec.managed-worker-ready=1`; `/tmp` remains tmpfs. This harness selects
`<new-project>_worker-ready` through `VARDRSEC_WORKER_READY_VOLUME`, records it, and
refuses any existing volume at that exact name. One project runs one incarnation;
it cannot recycle the volume or restart an unresolved worker. This adds no service
or secret store. The corrected volume path passed the earlier basic and coupled
one-attempt Desktop proofs; earlier tmpfs-proof refusals remain refusals. Those
proofs do not establish the new two-job sequence or Linux acceptance.

The target accepts only synthetic identities and fixture data. Its request log
records method, route, identity and timestamps, never authorization headers or
credential values. Delayed responses are ordinary bounded HTTP work; no detached
processes, signal/ptrace experiments, executable injection or previously blocked
kernel adversarial operations belong in this harness.

## Setup sequence

1. Stage a fresh private installation using the public distribution files and
   explicit immutable image overrides. Preserve the product `versions.json`.
   Start only database/API/web/proxy with managed assembly disabled. Use the normal
   startup migration path and verify schema `0040runtimesequence` through existing
   readiness/doctor behavior, rather than creating tables in the harness.
   The fixture wrapper reuses the existing `configure` and `database_roles.apply`
   implementations with its explicit Compose files/project; it does not teach
   production lifecycle commands to accept an unreviewed Compose override.
2. Run the existing terminal local-account bootstrap. Log in over CA-validated
   HTTPS; use the actual local-owner cookie, Origin and session CSRF token. Verify
   an unauthenticated request and a cookie write without CSRF are refused without
   mutation. Create a Runner-scoped key through the normal API and retain its
   one-time value only in private process memory/approved private configuration.
3. Generate separate ephemeral operator-approval and Map-contract Ed25519 keys.
   Both keys use the same fixture issuer ID, distinct key IDs and distinct public
   keys. The operator private key stays only in the harness signer; Map receives
   only its public anchor bound to the real local-owner ID. The Map contract key
   is mounted read-only into Map only. Neither private key enters Worker, ordinary
   Runner helpers, public admission, images, command arguments or receipts.
4. Restart only the disposable API with the explicit strict managed assembly flag,
   configured full API origin and protected key/trust files. Keep its normal
   `start.sh`/Alembic path. The same owner/database identity remains authoritative.
   This two-stage setup avoids guessing the local-owner ID before bootstrap.
5. Use a separate ordinary UID/GID-10001, cap-drop-ALL, no-new-privileges helper from
   the **new worker image** for stable identity, existing plan compilation and
   credential grants. It is not an admitted worker and starts no tool. Persist its
   state in the selected fixture Runner volume.
6. Enrollment has no HTTP bootstrap endpoint: invoke the existing terminal
   `managed_enrollment bind`, passing the existing key through bounded stdin.
   Approval review/register and runtime admission then use their real HTTPS
   endpoints. Use Runner's existing plan compiler and approval contract functions
   in the isolated test signer; never add an approval bypass to product code.
7. Record engagement scope/window/written authority, reviewed fixed case, finite
   concurrency/target/duration policies and exact credential grants through the
   existing interfaces. Register a separately signed owner approval. None of these
   preparation steps may dispatch the Gate case. The fixture's bounded control
   `/health` poll establishes readiness separately from measured business requests.
8. Explicitly start the reviewed worker profile. Capture actual native-owner
   readiness through `LocalDocker`, then invoke the public `vardrsec.py worker
   enable` command with every exact cohort/layout field. The existing owner
   password enters only through bounded stdin. The CLI registers the incarnation
   through the real owner session with explicit `--max-attempts 2` and atomically
   publishes only acknowledged v2 public admission and Runner trust. Both direct
   observers also require `max_attempts=2`; neither path accepts a v1 downgrade.
   Admission TTL is 900 seconds; the worker preserves its separate 150-second
   reporting runway.

The host HTTPS endpoint may be `https://localhost:<port>/backend`; the exact managed
Runner/issuer origin remains `https://vardrsec.localhost:<port>/backend`, reachable
through the owned Runner network alias. Both use the same exported public CA.
Do not strip the configured `/backend` API prefix to make a test pass.

## Incremental cases

The two healthy jobs use separate engagements, reviewed cases and jobs, but share
one enrolled Runner and one admitted container incarnation. Both are pending,
unissued and uncharged before explicit enablement, with zero target requests.
Each receives a distinct inert `nm2_case` query marker on its primary request and
both preflights. Cases that retain an unknown local hold use a separate fixture
state volume so a later case cannot silently clear it. A new container incarnation
always needs fresh admission.

| Stage | Case | Required measured result |
| --- | --- | --- |
| 1 | Default startup | Only core services run; a queued approved job remains pending and target request count stays zero before explicit worker enablement. |
| 1 | Happy fixed-Gate queue | One exact claim/ordinal/fence; consumed and runtime-confirmed before target work; conclusive expected owner/peer/anonymous decisions; case-bound hashed evidence; one immutable result/completion; capacity released, target/duration charges retained. |
| 1 | Healthy sequence | Two distinct jobs complete in the same physical runtime, each with five measured requests and five redacted evidence rows. Durable release of sequence 1 precedes binding of sequence 2. Both canonical completions and native-DONE/release hashes remain distinct; final runtime is idle at sequence 2 with maximum 2. |
| 1 | Strict denial | Missing/out-of-scope/expired authority or changed signed context is rejected before issuance/launch; no target traffic or budget refund is fabricated. Ordinary legacy advisory behavior is unchanged. |
| 1 | Missing local grant | Worker refuses before claim/target traffic; job stays unissued; any known zero-RPC local marker retires only by its explicit local rule. |
| 2 | Local emergency stop | A separate ordinary helper invokes existing `jobs stop RUN_ID`; bounded graceful/forced handling is measured, partial artifacts remain, and no new target dispatch follows confirmed termination. |
| 2 | Engagement stop-work | Real owner/CSRF stop-work change prevents new claims and stops an active ordinary delayed HTTP case within the existing permission bounds. |
| 2 | Target grant expiry/revocation | Keep original Runner enrollment/key active. Revoke/expire the exact target credential grant and measure refusal/stop with no grant widening or fallback. |
| 2 | Budget exhaustion | Concurrency/represented-origin/allocated-duration limits prevent excess claims; one-use approvals, spent targets and allocated duration never reset after failure. |
| 3 | Map disconnect | Stop only this project's API during an already observed bounded slow HTTP resource request. The independent owner stops the incarnation by its last valid lease/hard ceiling; API restart starts no worker. |
| 3 | Ordinary worker crash/stop | Stop only the exact owned container. Direct wait/inspect proves its exit; host capability reports only the exact atomic runtime-associated failure, never success or permission renewal. |
| 3 | Lost claim/consume/bind reply | Use a reviewed fixture-only response-loss seam, without changing product authorization. Exact server runtime association and durable local send fences prevent replay; physical exit precedes host reporting. |
| 3 | Restart/duplicate claim | No automatic restart or new claim while an old incarnation is unresolved. Competing explicit claims yield at most one physical attempt/ordinal/reservation; ambiguous losers remain held. |
| 3 | Lost terminal reply | Observe the exact immutable receipt. A retained result without completion stays held until the trusted host has proved exit and failed that existing result; preserve its artifact/receipt and never replace it with a stop or replay publication. |

Do not infer a completed stop from an expired lease, a numeric PID, owner intent,
container name, health response or a restarted service. Record actual direct
Docker state and exact runtime receipt. A negative case passing because a later
unrelated step failed is not acceptance.

## Local metadata and retained limits

After the worker stops, separate ordinary helpers may use existing `audit list
--json` to derive the original run ID and `audit reconcile-managed RUN_ID` to
observe its exact server receipt. They share only the selected Runner state,
original active enrolled API key, public CA and owned network. They receive no
owner session, host STOP secret or private approval key, and never insert a process
into a live worker's PID lineage.

Record the initial profile's credential pass-list/name limits and unsupported
proxy settings explicitly. A revoked/lost original Runner enrollment/key leaves
local metadata reconciliation held; the harness cannot replace that boundary with
a new key or caller JSON. This differs from revoking a target credential grant
while retaining the original enrolled observer.

## Receipts and cleanup

Emit a versioned receipt containing source commits/file inventories, exact local image IDs,
Docker OS/architecture/context identity, schema revision, public CA fingerprints,
case/plan/artifact/receipt hashes, scenario outcomes, request-count deltas and
measured stop bounds. Record `not_run`, `passed`, `failed` and `held` separately.
Do not replace missing evidence with constant success booleans.

The new raw receipt is `vardr.nm2-worker-acceptance/2`. It retains
`happy_fixed` for the first job and adds `healthy_sequence` with both exact
bindings, canonical terminal/release receipts, UTC microsecond binding,
confirmation and release timestamps, per-job case/evidence/artifact hashes and
request observations. The read-only `vardr.nm2-fixture-inventory/2` selects runtime
attempt history by job ID; it cannot depend on the legacy Runtime job columns,
which remain NULL in v2. It refuses history above 32 attempts instead of truncating
it. Verification requires the same runtime ID, container/nonce identity and
enrollment, sequences 1 and 2, release 1 no later than binding 2, distinct artifacts
and full completion hashes, ten total requests/evidence rows, two spent targets
and 60 allocated seconds. Existing result hashes and full completion hashes have
separate fields and are recomputed independently.

The hosted wrapper correlates this private receipt with retained database history
and exports only selected statuses, counts and hashes. Older held `/1` receipts
remain diagnostic evidence; they are not rewritten as two-job acceptance.

Passwords, API keys, fixture tokens, private signing keys, host STOP secrets,
cookies, CSRF values and unredacted command output are excluded from receipts and
logs. Test credentials stay in private memory or protected fixture-private paths
outside public mounts; failure to provide native protection refuses the run.

Preserve failed/held evidence and stopped incarnations for review. Any later
cleanup verifies each exact container/network/volume ID and project label before
removing that resource; no wildcard deletion, default project or recursive host
cleanup is part of acceptance. Run the same reviewed harness on Linux later,
without claiming that a Desktop receipt establishes Linux acceptance or vice versa.

## Reviewable invocation and Docker commands

Prepare one private JSON cohort file with schema `vardr.nm2-worker-cohort/1` and
these exact keys:

- `sources`: `distribution`, `map`, `runner`, `gate`, each containing an absolute
  `path` and exact clean 40-hex `commit`. The new public fixture helpers must be
  tracked in the Distribution commit.
- `images`: `db`, `api`, `web`, `proxy`, `worker`, each an already available local
  `sha256:<64-hex>` image ID. No build, pull, tag or image publication is performed.
- `docker_context`: an explicit local context name; `project`: a new
  `vardrsec-nm2-<8-to-24 lowercase alphanumeric characters>` name.
- `installation`, `private_root`: separate new absolute paths outside all four
  source trees. The latter contains host custody and private fixture inputs and
  is never mounted as a directory.
- `https_port`: selected unused loopback port above 1023;
  `application_subnet`: selected unused private IPv4 `/24`.
- `allow_empty_builtin_bridge_id_change`: explicit boolean. `true` admits only
  an ID-only change with both bridge memberships empty and other recorded
  semantic fields equal; the before/after IDs remain in the receipt.

Run `python tests/nm2_worker_acceptance.py --cohort <private-cohort.json>` for source
validation only. Add `--execute` only after reviewing this command surface and
the exact cohort. A source-validation receipt records no actual Docker result.
Use an environment with Runner's existing dependencies
available for the separate fixture approval signer.

All Docker invocations use `docker --context <selected-context>`. Compose always
uses `--project-directory <new-install> -p <new-project> -f compose.yaml -f
fixture.compose.json`; the worker invocation adds `-f compose.worker.json`.
The command surface is:

1. Read context endpoint and daemon Linux/architecture/ID; list/inspect exact
   public container/network/volume/image metadata. No container environment is
   exported. Capture existing stopped fixtures and mutable image tags too.
2. Two `docker run --rm -i --network none --user 10001:10001 --cap-drop ALL
   --security-opt no-new-privileges:true --read-only --label
   com.docker.compose.project=<new-project> --entrypoint /usr/local/bin/python
   <exact-api-or-worker-image> -I -c <fixed-public-image-inventory-program>`
   helpers. Input contains only selected source filenames/component names;
   output contains file and executable hashes.
3. Existing `database_roles.apply` invokes scoped `compose up -d --wait db` and
   normal `compose exec -T db psql` role setup/verification. Then scoped
   `compose up -d --no-build --pull never --wait ... db api web proxy`,
   `compose cp` of the public CA, and `compose exec -T api python -m
   local_accounts init --username operator --generate-password`. Output stays
   private; passwords are never passed in arguments.
4. After real owner login/CSRF setup, recreate only the disposable API with
   `compose up -d --no-build --pull never --wait ... api`. Start the existing
   Gate HTTP fixture using the same safe image and public target wrapper.
5. Separate `compose run --rm --no-deps --user 10001:10001 --entrypoint
   vardrrunner runner ...` helpers run existing doctor/identity/grant commands.
   A separate Python helper hashes the installed Gate binary. Terminal enrollment
   uses `compose exec -T api python -m managed_enrollment bind ... --key-stdin`;
   the one-time Runner key is stdin only. Read-only selected inventory uses a
   fixed public Python program in a separate Map metadata process.
6. Explicit worker profile `compose --profile managed-worker up -d --no-build
   --pull never --no-deps managed-worker`. Direct inspect/cp obtains readiness;
   `vardrsec.py worker enable` registers the actual incarnation through its
   existing HostClient/HostRecords. Owner password is bounded stdin only. The
   acknowledged public admission/trust files enter the read-only worker mount.
   Direct wait/inspect observes its exit. No `exec` runs inside the worker.
7. Request observations and the bounded control-health poll use `compose exec -T
   gate-fixture` only. Finally, directly inspect each newly created exact fixture
   CID/image/project, issue one bounded `docker container stop -t 10 <exact-IDs>`
   for its running containers, and observe their stopped state. Retain containers,
   volumes, networks and custody. Final inventory preserves exact pre-existing
   resources/tags and writes private before/after snapshots plus a redacted receipt.
   No rm, down, prune, auto-replay or recursive host cleanup occurs. Ordinary
   `--rm` helpers remove only their own one-off containers.

The first implementation uses the zero-delay target and one physical worker
attempt. The bounded 15-second read-only delay wrapper is prepared for subsequent
reviewed cancellation/disconnect cases; it is not currently exercised by the
initial stages. The web image is a reviewed core dependency here; this harness
does not claim a browser UI journey or frontend URL compatibility at the selected
port.

## Explicit hosted Linux counterpart

The existing `compose.yml` workflow has a default-false `nm2_coupled` manual input.
Set it only after the same reviewed Distribution commit passes the Desktop initial
stages. Supply all four exact `nm2_*_sha` values; Distribution must equal the selected
workflow commit. Keep `unit_only=true` to skip unrelated installer/update jobs.

`tests/nm2_worker_hosted.py --execute` refuses other repositories, branches, events,
hosts or dirty/mismatched source cohorts. It uses a fresh GitHub-hosted Ubuntu24.04
Docker daemon, existing component Dockerfiles, the toolkit's named Gate context and
the separate worker overlay. Private clones, signer dependencies, custody and raw
outputs remain under isolated temporary paths. It runs this same coupled harness;
the remaining matrix stays `not_run`. No image is published and no service is added.

Only a whitelisted public receipt is uploaded: exact source/tree/image IDs, case
statuses, validated request/evidence counts, case/artifact/receipt/CA hashes,
executable/source inventories and the retained stopped-container count. A failed
stage remains `held`; raw logs, snapshots, sessions, keys, paths and custody are
excluded. Hosted success does not establish Desktop/native Windows acceptance.

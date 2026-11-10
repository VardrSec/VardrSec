# Prepared managed-worker controls

## Explicit launch

`python vardrsec.py worker launch` selects one worker in the existing Full
installation. It uses the same API, enrollment, Runner ID, owner login and
public signing trust options as `enable`. Run `worker launch --help` for the
exact selectors. Supply an existing, dedicated `--admission-root` outside
the private host root and CA directory, the original `--state-volume` and
`--runner-network`, and the reviewed `--launch-config`. Each launch gets
its own public subdirectory and readiness volume. The existing explicit
Runner setup initializes the original journal before the first launch.

The launch config is a JSON object with `docker`, `docker_sha256`, `compose`,
`compose_sha256`, `docker_config`, `local_endpoint`, `daemon_id`, `override`,
`empty_env`, `credential_file`, `credential_names`, `https_port`,
`core_images` and `source`. Use absolute local paths and the existing
Docker context. The override contains only external `runner` network and
`runner-state` volume mappings. `core_images` maps api, db, proxy and web
to their reviewed full image IDs. Preserve the exact `source` binding generated
by worker preparation. Use the
raw override SHA-256, the normalized worker model SHA-256, and the canonical
JSON digests of `core_images` and of the object containing
`credential_names` and `https_port`.

Keep the explicit credentials file and a separate zero-byte dotenv file
in the existing protected private root. Supply the enrolled Runner key via
the process environment. Launch passes no credential values in argv or
lifecycle records. Keep the credential file at mode 0600 on Linux and
inside the operator's restricted directory on Windows.

A subsequent launch requires each prior worker from this command to be
physically exited, retired in Map, and locally reconciled. A held result
preserves the resources and durable intent for inspection. Follow the
original report and reconciliation flow for an admitted worker.

## Admission of a prepared worker

Managed admission is disabled by default. Ordinary installation, Full/Mapless
startup and manual Runner commands retain their behavior. Admission does not
build, start or automatically restart a container.

The normal CLI protocol selects `persistent-v3`; legacy and finite protocols
must be chosen explicitly. Availability continues until explicit operator stop.
STOP reporting ends on revocation or physical retirement. Its trusted host can
falsely report exit, so protect host custody and preserve physical-exit checks.

Every job retains fresh finite authorization, grant, budget, lease and result
checks; persistent idle availability grants no execution permission.

Before admission, prepare the reviewed immutable worker image and separate
`compose.worker.json` profile, fresh readiness volume, existing enrolled Runner
key, public Runner trust, local grants and human-signed job approval. Map needs
its explicit managed configuration and matching schema: persistent-v3 requires
`0041persistentruntime`; finite v1/v2 retain their versioned migration boundaries.
Private approval keys stay outside Map/Runner; the host STOP secret uses native
host custody. See host boundaries and
[local managed setup](local-managed-setup.md).

The worker's startup wait is finite. Start its explicitly selected profile only
when these preparations are complete, then invoke:

```text
python vardrsec.py worker enable
  --api-url <exact-external-HTTPS-API-base>
  --ca <absolute-public-CA-file>
  --private-root <existing-protected-host-directory>
  --context <explicit-local-Docker-context>
  --container-id <full-running-CID>
  --image-id <sha256:immutable-image-ID>
  --project <exact-Compose-project>
  --trust-source <absolute-host-public-CA-directory>
  --admission-source <absolute-host-public-admission-directory>
  --state-volume <exact-Runner-state-volume>
  --readiness-volume <fresh-exact-readiness-volume>
  --enrollment-id <existing-enrollment-ID>
  --runner-id <original-Runner-UUID>
  --origin <exact-managed-issuer-HTTPS-API-base>
  --public-trust <absolute-reviewed-Runner-public-anchor-file>
  --protocol finite-v2
  --max-attempts 2
  --username <existing-local-owner>
```

This lists arguments; use your shell's normal continuation syntax. The password
uses hidden terminal input. Explicit `--password-stdin` instead accepts one bounded
line from a protected process pipe; never put a password or STOP secret in argv.
For explicit `legacy-v1` and `finite-v2`, `--expires-in` defaults to 900 seconds.
Valid reporting TTLs are 60–604800 seconds,
but a worker allocation must fit before its immutable cutoff, which reserves
150 seconds for host reporting. A short grant may therefore refuse execution.

`--protocol finite-v2 --max-attempts N` selects v2 admission, with an integer from
1 to 32 and the matching owner-ready/2 image. `--protocol legacy-v1` explicitly
retains the matching v1 image. Omitting a protocol selects v3; it never downgrades
to v1 or v2. In finite v2, only healthy completed jobs may advance, after native
drain, refresh-thread quiescence, DONE and durable Map release. Failed or unknown
work ends that incarnation. The batch, finite idle
and admission limits remain development-candidate limits; ongoing service
availability is not accepted by the two-job test alone.

The proposed `persistent-v3` path requires owner-ready/3. Both optional limits are
absent by default: `--max-attempts N` can select a canonical positive decimal
count up to signed-64-bit maximum, and `--idle-timeout-seconds S` can select
1–86400 seconds. V3 refuses `--expires-in`; its reporting policy is separately
bound in admission. Existing finite receipts retain their original meaning.
Normal startup still enables no worker. A safety failure can exit the namespace;
persistent operation does not imply automatic crash restart or unknown-work replay.
The v3 contract permits a naturally failed, drained terminal to continue only
after the same exact completion, native DONE and durable release proofs.
Confirmed-stop partial results, cancellation and ambiguous work do not qualify.

Enablement derives actual owner readiness, registers through a real owner session,
persists host custody/intent and publishes public admission only after an exact
ACK and second running-incarnation check. An ambiguous registration leaves a held
host record; it does not publish permission or automatically replay the write.
The fixed JSON result contains the runtime ID needed by later commands.

All other actions require `--runtime-id` and the same `--private-root`:

| Action | Behavior |
| --- | --- |
| `status` | Read the MAC-protected local record and inspect its exact selected incarnation. |
| `disable` | V3 only: one request to stop new claims without revoking reporting authority or cancelling the current finite job. |
| `stop` | Inspect and stop only that exact CID; retain data and report actual observed exit. |
| `stop --report` | After exit proof, separately send the existing one-shot host report. |
| `report-exit` | Derive direct exit proof and send one exact bound or unbound report. |
| `report-exit --continue-after-transition` | Explicitly continue only after a fresh authenticated, irreversible cursor advance proves the previous report can no longer commit; retain its original intent and recheck the same physical exit. |
| `reconcile` | Read the immutable server receipt after an unknown reply; sends no mutation. |
| `revoke` | Use hidden owner authentication to revoke the registration grant; this is not active cancellation. |

V3 status reports `idle-ready`, `active`, `held` or `stopped`. Running status needs
a fresh, cursor-matching advisory server observation plus the exact local daemon
identity. Stale, unreachable or inconsistent observations remain held. Actual exit
comes from direct daemon observation, not the server's availability label. Status
never renews permission or sends a report. Physical inspection shares a bounded
30-second window; HTTPS has its separate ten-second bound, and stopped-incarnation
confirmation has its separate 30-second bound. Filesystem/host responsiveness is
still a limitation rather than a real-time guarantee.

A failed final physical inspection remains `physical_unconfirmed`, even when a
server availability observation was already read. It cannot be interpreted as
an advisory availability delay. Read-only availability polling never retries a
guard failure or an uncertain mutation.

Normal v3 stop first attempts the one-shot new-work disable, then stops only the
exact bound container. Physical emergency stop remains available when Map is
unreachable. A lost disable reply retains its send intent; reconcile only reads
the server state and does not fabricate the original acknowledgement or resend.

Pre-stop inspection and the one Docker stop share a 30-second deadline; direct
exit observation has its own 30-second bound. Reporting rechecks the incarnation
again before its durable send intent. The host and its STOP-secret holder remain
trusted: a forged physical-exit assertion could release bound concurrency early.
No socket, privileged mode, service or automatic enablement is introduced.

Report before revoking the reporting grant if recovery is needed. In finite
protocols, expiry or revocation preserves lookup but prevents a new host report;
the proposed v3 lifetime ends on revocation or retirement. A lost report reply
stays held until read-only receipt observation; there is no automatic resend or
bound/unbound fallback. The reporting runway is an opportunity, not a guarantee
when the host, network or grant is unavailable.

After terminal observation, use the original Runner state/identity and still-active
enrolled key with `vardrrunner audit reconcile-managed RUN_ID` to retire exact local
metadata. The host command cannot substitute another key, rebuild a control token,
refund allowances or clear older unlinked holds. Retain stopped incarnations,
artifacts, public admission and custody for review. Any later start needs fresh
admission and a fresh readiness volume; restart policy remains `no`.

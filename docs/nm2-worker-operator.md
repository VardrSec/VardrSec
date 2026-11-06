# Prepared managed-worker controls

This is a default-disabled NM-2 development candidate. The retained one-attempt
Desktop slice passed; current v2 Desktop/Linux acceptance remains open. Ordinary
installation, Full/Mapless startup and manual
Runner commands retain their behavior. This command does not build, start or
automatically restart a container.

Before admission, prepare the reviewed immutable worker image and separate
`compose.worker.json` profile, fresh readiness volume, existing enrolled Runner
key, public Runner trust, local grants and human-signed job approval. Map needs
its explicit managed configuration and current additive schema `0040runtimesequence`.
Private approval keys stay outside Map/Runner; the host STOP secret uses native
host custody. See [host boundaries](nm2-worker-host-observation.md) and the
[coupled acceptance plan](nm2-worker-acceptance-plan.md).

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
  --max-attempts 2
  --username <existing-local-owner>
```

This lists arguments; use your shell's normal continuation syntax. The password
uses hidden terminal input. Explicit `--password-stdin` instead accepts one bounded
line from a protected process pipe; never put a password or STOP secret in argv.
`--expires-in` defaults to 900 seconds. Valid reporting TTLs are 60–604800 seconds,
but a worker allocation must fit before its immutable cutoff, which reserves
150 seconds for host reporting. A short grant may therefore refuse execution.

`--max-attempts N` explicitly selects v2 admission, with an integer from 1 to 32
and the matching owner-ready/2 image. Omitting it retains the v1 path against its
matching old image; the new v2 image refuses v1 admission. Only healthy completed
jobs may advance, after native drain, refresh-thread quiescence, DONE and durable
Map release. Failed or unknown work ends the incarnation. The batch, finite idle
and admission limits remain development-candidate limits; ongoing service
availability is not accepted by the two-job test alone.

Enablement derives actual owner readiness, registers through a real owner session,
persists host custody/intent and publishes public admission only after an exact
ACK and second running-incarnation check. An ambiguous registration leaves a held
host record; it does not publish permission or automatically replay the write.
The fixed JSON result contains the runtime ID needed by later commands.

All other actions require `--runtime-id` and the same `--private-root`:

| Action | Behavior |
| --- | --- |
| `status` | Read the MAC-protected local record and inspect its exact selected incarnation. |
| `stop` | Inspect and stop only that exact CID; retain data and report actual observed exit. |
| `stop --report` | After exit proof, separately send the existing one-shot host report. |
| `report-exit` | Derive direct exit proof and send one exact bound or unbound report. |
| `report-exit --continue-after-transition` | Explicitly continue only after a fresh authenticated, irreversible cursor advance proves the previous report can no longer commit; retain its original intent and recheck the same physical exit. |
| `reconcile` | Read the immutable server receipt after an unknown reply; sends no mutation. |
| `revoke` | Use hidden owner authentication to revoke the registration grant; this is not active cancellation. |

Pre-stop inspection and the one Docker stop share a 30-second deadline; direct
exit observation has its own 30-second bound. Reporting rechecks the incarnation
again before its durable send intent. The host and its STOP-secret holder remain
trusted: a forged physical-exit assertion could release bound concurrency early.
No socket, privileged mode, service or automatic enablement is introduced.

Report before revoking the reporting grant if recovery is needed. Expiry or
revocation preserves lookup but prevents a new host report. A lost report reply
stays held until read-only receipt observation; there is no automatic resend or
bound/unbound fallback. The reporting runway is an opportunity, not a guarantee
when the host, network or grant is unavailable.

After terminal observation, use the original Runner state/identity and still-active
enrolled key with `vardrrunner audit reconcile-managed RUN_ID` to retire exact local
metadata. The host command cannot substitute another key, rebuild a control token,
refund allowances or clear older unlinked holds. Retain stopped incarnations,
artifacts, public admission and custody for review. Any later start needs fresh
admission and a fresh readiness volume; restart policy remains `no`.

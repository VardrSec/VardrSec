# NM-2 host observation candidate

Status: default-disabled candidate under the owner's bounded ADR 0043 development
authorization. NM-2 acceptance remains open. Ordinary startup and the shipped Full
and Mapless Compose definitions are unchanged.

`compose.worker.json` is the separate inactive candidate overlay. It declares the
reviewed worker-only bootstrap, finite resource bounds, retained no-restart state
and exact writable paths. It requires an explicitly selected local image, enrolled
key, public admission directory, private worker-only environment file and a fresh
per-incarnation `VARDRSEC_WORKER_READY_VOLUME` name. Existing
Map signing configuration and enrollment remain explicit prerequisites. The
[prepared-worker controls](nm2-worker-operator.md) expose admission, status, exact
stop and receipt reconciliation; actual integrated acceptance remains open. The
overlay is not loaded by ordinary distribution commands.

The worker-only environment file supplies explicitly declared local credential
references and existing profile limits. Never use the installation `.env` or
export a host credential store there. The native bootstrap retains only its finite
reviewed environment and declared credential names; this declaration creates no
grant or approval. Keep raw STOP capability custody entirely separate.

`worker_runtime.LocalDocker` selects an explicit **local** Docker context, verifies
the daemon ID and full container/image/owner identity, the private PID namespace,
approved bootstrap capabilities and retained no-restart configuration. It waits
for the exact container and requires consistent exited state, full start/finish
identity and exit code through repeated direct inspection. A restart, missing
container, timeout, changed identity or ambiguous state refuses proof. The final
inspection precedes creation of the local typed observation. Observation is capped
at thirty seconds overall, with at most fifteen seconds per command. The daemon
and trusted host remain part of the trust boundary; this is not attestation.

The caller supplies a protected `WorkerLayout` binding the exact public trust,
public admission, state-volume and separate readiness-volume sources. Only these
four data destinations and the reviewed `/tmp` tmpfs are allowed. The readiness
volume uses the default local driver without options and normal Compose ownership
labels plus `io.vardrsec.managed-worker-ready=1`. Code/socket/extra mounts, writable
admission, an alternate entrypoint/command, an exec health check, writable image
root or shared IPC refuse admission and exit proof. Ordinary Compose is unchanged.

`capture_running` derives the fresh startup nonce by reading the actual owner's
bounded `0400`, UID/GID-10000 readiness file through a direct Docker tar stream.
It never inserts an exec/health process. Strict readiness data must report the
fixed owner identity, no-new-privileges and five empty capability sets; pre/post
inspection must retain the same running incarnation. The reviewed image/code and
private owner-only readiness volume establish the file's producer; caller JSON
does not. The image precreates its empty directory as UID/GID 10000, mode 0700;
fresh-volume metadata copy needs no additional runtime capability. Every new
incarnation requires a new unused volume name. Existing files are never overwritten,
and stopped state is retained.

Two bounded pre-admission trials refused the earlier tmpfs readback. Docker's
[documented copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/#corner-cases)
exclude tmpfs resources. Those failed receipts remain unchanged; this small
metadata-volume correction still needs a fresh committed-image platform proof.
It introduces no service, Docker socket, exec/health process or raw secret mount.
The refusals do not establish that the native writer failed to publish its file.

Both volume records must match the selected daemon's default-local data paths,
project/role labels, exact names and mounts, with no driver options or plugins.
Host custody resolves actual host binds and private directories strictly. It
resolves accessible managed data paths too; only an actual permission refusal or
the separate Windows Docker-VM namespace permits the validated daemon path to be
compared lexically. Missing paths and other filesystem errors refuse. Windows
Desktop drive mappings are explicit; arbitrary POSIX bind sources are never
silently treated as VM volumes.

An observation alone cannot register authority, release a reservation or report
success. Host protocol composition requires the independently approved, exactly
bound STOP capability and preserves durable unknown holds after lost replies.
The helper does not deserialize a physical-proof assertion from caller JSON. It
does not establish the Runner's private control channel or subreaper readiness;
the separate live lifecycle connection must verify those before claiming work.

`worker_host` pins its HTTPS endpoint, loaded CA hash, selected context, layout and
installation/storage roots in MAC-authenticated public metadata. Owner sessions
remain ephemeral; separate STOP authentication is limited to report/receipt
routes. Each report reads the exact server association, repeats direct physical
confirmation and persists its one-send intent before its sole mutation request.
Unknown replies never cause an automatic resend.

When the authenticated lookup has no association, the same typed physical proof
can select `observed-unbound-exit`. Its distinct intent and canonical
`vardr.worker-unbound-retirement/1` receipt retire only that runtime and fence a
late tagged claim; no job, success, refund or capacity release is manufactured.
A lost reply is reconciled by immutable receipt lookup, including after grant
expiry/revocation. Null association without a receipt remains held. If a claim
wins the race, this invocation never falls back to a bound report; an unknown
intent remains held for explicit recovery. This branch requires the matching Map
runtime endpoint and does not change ordinary/manual/Mapless execution.

`worker_secrets` holds the raw STOP capability **on the host only**. Windows uses
the current user's existing native Credential Manager with local-machine
persistence; there is no plaintext fallback or enterprise roaming. Linux uses a
private `0700` directory and exclusive `0600` file, rejects symlink/hardlink/shared
files and uses descriptor-relative access. The host record must remain outside
every worker mount. Never pass the secret through argv, container environment,
labels, public admission, Runner journals or logs. Map receives only its
purpose-separated hash. Explicit retirement is distinct from timeout or failed
reconciliation; those failures must retain the secret and evidence.

The custody adapter follows Microsoft's [CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
and [CredReadW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw)
contracts. Its per-runtime guard prevents the native upsert API from replacing an
existing credential through this lane.

Run pure refusal tests with `python -m unittest discover -s tests -p
'test_worker_runtime.py'`. Linux custody tests use only a temporary private
directory. Native Windows custody tests are explicit:

```powershell
$env:VARDRSEC_NATIVE_WORKER_SECRETS = '1'
python -m unittest discover -s tests -p test_worker_secrets.py
Remove-Item Env:VARDRSEC_NATIVE_WORKER_SECRETS
```

Those Windows tests create only uniquely named disposable generic credentials and
remove their own entries in `finally`. A sandbox without a credential logon session
cannot substitute for this native proof; unavailable access refuses rather than
selecting a file fallback.

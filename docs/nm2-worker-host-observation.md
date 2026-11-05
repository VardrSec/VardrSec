# NM-2 host observation candidate

Status: inactive library increment under the owner's bounded ADR 0043 development
authorization. NM-2 acceptance remains open. Ordinary startup and the shipped Full
and Mapless Compose definitions are unchanged.

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
public admission and state-volume sources. Only those data destinations and the
two reviewed tmpfs destinations are allowed. Code/socket/extra mounts, writable
admission, an alternate entrypoint/command, an exec health check, writable image
root or shared IPC refuse admission and exit proof. Ordinary Compose is unchanged.

`capture_running` derives the fresh startup nonce by reading the actual owner's
bounded `0400`, UID/GID-10000 readiness file through a direct Docker tar stream.
It never inserts an exec/health process. Strict readiness data must report the
fixed owner identity, no-new-privileges and five empty capability sets; pre/post
inspection must retain the same running incarnation. The reviewed image/code and
private owner tmpfs establish the file's producer; caller JSON does not.

An observation alone cannot register authority, release a reservation or report
success. Future protocol composition must require the independently approved,
exactly bound STOP capability and preserve durable unknown holds after lost replies.
The helper does not deserialize a physical-proof assertion from caller JSON. It
does not establish the Runner's private control channel or subreaper readiness;
the separate live lifecycle connection must verify those before claiming work.

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

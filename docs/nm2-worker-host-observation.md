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

An observation alone cannot register authority, release a reservation or report
success. Future protocol composition must require the independently approved,
exactly bound STOP capability and preserve durable unknown holds after lost replies.
The helper does not deserialize a physical-proof assertion from caller JSON. It
does not establish lifecycle-owner readiness; that separate admission must verify
the reviewed image/entrypoint, fresh owner nonce and actual unprivileged state.

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

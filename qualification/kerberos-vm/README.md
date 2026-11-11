# Isolated Kerberos source qualification

`run.py` prepares the checksum-pinned official Debian guest from `inputs.json`, copies exact checksum-bound source inputs, then boots offline to run `db/build-krb5.sh`. Full Debian package tests, symbol checks and the stripped-library regression remain enabled. QEMU TCG needs no KVM device, privileged mode, host forwarding or policy relaxation.

`--source-only` supports ordinary Docker contexts without `.git`; its receipt records the source-input hash and a null distribution commit. Standalone CI records its checked-out commit. The database build-context harness is kept byte-identical to this harness and tested accordingly.

Preparation is bounded to 30 minutes and package build to 120 minutes. A failed or absent guest verdict fails closed. Serial diagnostics are retained on timeout. The guest has 4 GiB memory; allow additional Docker overhead.

See `../kerberos-image/README.md` for ordinary-image acceptance, source delivery and scope limits. Do not claim whole-image reproducibility or release clearance from this qualification.

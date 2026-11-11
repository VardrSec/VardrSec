# Isolated Debian Kerberos package qualification

This is a separate evidence workflow, not a replacement database image or a
release. Docker's default seccomp policy blocks kernel keyrings. The reviewed
Debian test suite deliberately rejects the resulting EPERM. This workflow does
not relax that policy or change the test to pass.

An official Debian 13 cloud image boots as a disposable QEMU guest under its
normal kernel policy. The first boot acquires ordinary build dependencies. The
second boot has **no virtual NIC** and runs the exact repository
`db/build-krb5.sh`, including the full Debian tests, symbol checks and stripped
package regression. A real guest keyring create/read/revoke prerequisite must
also succeed. The guest has no SSH access, public port forwarding, host directory
share, KVM permission adjustment, or persistent infrastructure. QEMU uses TCG
software emulation, bounded to two virtual CPUs and 4 GiB RAM.

QEMU tooling runs in a disposable, digest-pinned official Debian 13 container,
not an installation on the Ubuntu host. This avoids the unavailable Ubuntu
package mirrors without changing DNS, firewalls, proxy configuration or package
signature verification. The container uses Docker's default seccomp profile,
drops all capabilities, enables no-new-privileges, and runs the harness as the
runner's non-root UID. It is bounded to two CPUs, 6 GiB RAM and 512 processes.
Only its dedicated output directory is writable from the host; the repository
is mounted read-only. Neither privileged mode nor a KVM device is used. The
Debian tool image digest, installed package versions and preparation logs are
retained. Guest test requirements and the second boot's no-NIC check remain
unchanged.

The image is pinned to the official 20261103-2651 QCOW2 SHA512 in `inputs.json`.
The official HTTPS checksum manifest is preserved and checked against that
reviewed pin. A detached signature was not available at the reviewed image
location; do not describe this as GPG-authenticated image verification.

Preparation is bounded to 30 minutes and the offline build to 120 minutes, within
a 180-minute CI job. Dependency package versions, kernel details, exact source
and script hashes, raw build logs, package metadata/payload hashes and source
receipts are retained. Output is read from a separate guest disk using read-only
debugfs after the VM exits. A missing or nonzero guest verdict fails the job.

Successful qualification would establish this package build/test result in this
VM. It would not prove independently reproducible binaries, close unrelated
vulnerabilities, or automatically qualify a runtime image. Build dependencies
are recorded, not snapshot-locked. Production Dockerfiles are unchanged; any
future consumption must bind the verified packages and evidence by checksum and
rerun actual-image acceptance before making a release claim.

Local harness checks do not boot a VM:

```sh
python -m unittest discover -s qualification/kerberos-vm -p 'test_*.py' -v
bash -n qualification/kerberos-vm/guest.sh
```

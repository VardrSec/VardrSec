#!/bin/bash
# Runs only inside the disposable qualification VM; no host filesystem share.
set -euo pipefail
phase=${1:?phase required}
case "$phase" in prepare|build) ;; *) exit 2;; esac
mkdir -p /out /mnt/input
mount /dev/disk/by-label/VMOUT /out
mount -o ro /dev/disk/by-label/QUALINPUT /mnt/input
mkdir -p /out/vm
exec > >(tee -a "/out/vm/$phase.log") 2>&1
finish() {
    rc=$?
    trap - EXIT
    if [ -f /tmp/krb-build.log ]; then cp /tmp/krb-build.log /out/vm/package-build.log; fi
    cp /var/log/cloud-init-output.log "/out/vm/cloud-init-$phase.log" 2>/dev/null || true
    printf '%s\n' "$rc" > "/out/vm/$phase.exit"
    sync
    systemctl poweroff
}
trap finish EXIT
uname -a > "/out/vm/kernel-$phase.txt"
cat /proc/cmdline > "/out/vm/cmdline-$phase.txt"
cat /proc/self/status > "/out/vm/process-status-$phase.txt"
if [ "$phase" = prepare ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        build-essential byacc comerr-dev debhelper docbook-to-man libkeyutils-dev \
        libldap2-dev liblmdb-dev libnss-myhostname libsasl2-dev libssl-dev libverto-dev \
        pkgconf ss-dev keyutils libcmocka-dev python3-kdcproxy python3-pyrad \
        ca-certificates curl
    mkdir -p /build
    cp /mnt/input/build/* /build/
    (cd /build && sha256sum -c INPUT-SHA256SUMS)
    dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\n' > /out/vm/prepared-packages.txt
    apt-cache policy > /out/vm/apt-policy.txt
    cp /mnt/input/revision.txt /mnt/input/inputs.json /out/vm/
else
    # The host starts this second boot with -nic none. Fail if any non-loopback
    # network interface exists, rather than attempting to change network policy.
    test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n')" = lo
    (cd /build && sha256sum -c INPUT-SHA256SUMS)
    # Require real guest kernel-keyring support. This prerequisite is not a
    # substitute for the unchanged upstream tests, which must also all pass.
    # A child process keyring (@p) is not possessed by its later sibling.
    # Give the probe a dedicated session inherited by each keyctl invocation.
    # This changes no permissions, policy or upstream test expectations.
    keyctl session - sh -eu -c '
        key=$(keyctl add user vardr-qualification-probe qualification-data @s)
        test "$(keyctl pipe "$key")" = qualification-data
        keyctl revoke "$key"
    '
    printf '%s\n' 'Guest keyring create/read/revoke succeeded' > /out/vm/keyring-prerequisite.txt
    sh /build/build-krb5.sh
    test -s /out/source/evidence/sequence-regression.txt
    (cd /out/source && sha256sum -c SHA256SUMS)
fi

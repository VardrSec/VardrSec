#!/bin/sh
# Install the same Debian build dependencies in the native builder and the VM.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Languages=none -o Acquire::Retries=2 \
    -o Acquire::IndexTargets::deb-src::Sources::DefaultEnabled=false update
apt-get install -y --no-install-recommends \
    build-essential byacc comerr-dev debhelper docbook-to-man libkeyutils-dev \
    libldap2-dev liblmdb-dev libnss-myhostname libsasl2-dev libssl-dev libverto-dev \
    pkgconf ss-dev keyutils libcmocka-dev python3-kdcproxy python3-pyrad \
    ca-certificates curl "$@"

#!/usr/bin/env bash
# Run Debian's machine-isolated live C and Python tests on a disposable hosted VM.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
work=$(mktemp -d "$RUNNER_TEMP/libseccomp.XXXXXXXX")
guest="$work/guest"
mkdir "$guest"
image="libseccomp-qualification:$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
docker buildx build --load --target libseccomp-build --tag "$image" db
container=$(docker create "$image" /bin/true)
trap 'docker rm -v "$container" >/dev/null' EXIT
docker export "$container" | sudo tar -xpf - -C "$guest"
# The package build runs its regression suite with the ordinary Docker policy.
# Debian additionally marks these two autopkgtests isolation-machine. Run them
# with their unmodified test drivers on the fresh VM in the Trixie filesystem.
sudo mount -t proc -o nosuid,nodev,noexec proc "$guest/proc"
trap 'sudo umount "$guest/proc"; docker rm -v "$container" >/dev/null' EXIT
for device in null zero urandom; do
    if ! sudo test -e "$guest/dev/$device"; then
        minor=$(stat --printf='%T' "/dev/$device")
        sudo mknod -m 666 "$guest/dev/$device" c 1 "$((16#$minor))"
    fi
done
sudo chroot "$guest" sh -ec '
  dpkg -i /work/libseccomp2_*_amd64.deb /work/libseccomp-dev_*_amd64.deb /work/python3-seccomp_*_amd64.deb
  apt-get check
  cd / && sha256sum -c /out/source/runtime-library.sha256
'
for test in testsuite-live testsuite-live-python3; do
    sudo chroot "$guest" runuser -u builduser -- env DEB_BUILD_OPTIONS=parallel=4 sh -ec '
      cd /work/source
      AUTOPKGTEST_TMP=$(mktemp -d)
      export AUTOPKGTEST_TMP
      sh "debian/tests/$1"
    ' sh "$test"
done

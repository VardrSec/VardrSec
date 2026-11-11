#!/usr/bin/env bash
set -euo pipefail
q=$(cd "$(dirname "$0")" && pwd)
recipe=$(realpath "$1")
inputs=$(realpath "$2")
out=$(realpath -m "$3")
mkdir -p "$out/builder" "$out/run1" "$out/run2" "$out/bin"
python3 "$q/preflight.py" "$recipe" "$out/builder"
python3 "$q/prepare.py" "$q/inputs.json" "$inputs" "$recipe"
python3 "$q/configure.py" "$recipe"
cp "$q/curl-shim.py" "$out/bin/curl"
cp "$q/cargo-shim.py" "$out/bin/cargo"
chmod 755 "$out/bin/"*
# Build the candidate toolchain ONCE; both source builds use the resulting immutable image ID.
timeout 30m docker build --pull --iidfile "$out/builder/image.id" -t vardr-libvips-qualification "$recipe/platforms/linux-x64" 2>&1 | tee "$out/builder/build.log"
image=$(cat "$out/builder/image.id")
docker image inspect "$image" > "$out/builder/image-inspect.json"
docker run --rm --network none "$image" sh -c 'rpm -qa | sort; rustc -Vv; cargo -V; cargo cbuild --version; gcc --version; ld --version; meson --version; ninja --version' > "$out/builder/toolchain.txt"
for run in run1 run2; do
  mkdir -p "$out/$run/packaging" "$out/$run/receipts"
  cp -a "$recipe/." "$out/$run/packaging/"
  timeout 75m docker run --rm --network none --cpus 2 --memory 6g --pids-limit 1024 \
    -e CARGO_NET_OFFLINE=true -e SOURCE_DATE_EPOCH=1794355200 \
    -v "$out/$run/packaging:/packaging" -v "$inputs:/inputs:ro" \
    -v "$out/bin:/qual/bin:ro" -v "$out/$run/receipts:/receipts" \
    "$image" bash -c '
      export PATH="/qual/bin:$PATH"
      printf "[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"/inputs/vendor\"\n[net]\noffline = true\n" > "$CARGO_HOME/config.toml"
      /packaging/build/posix.sh
    ' 2>&1 | tee "$out/$run/build.log"
done
python3 "$q/compare.py" "$out" "$inputs/original.tgz"

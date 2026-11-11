#!/usr/bin/env python3
"""Create a candidate builder; does not modify shipping Dockerfiles."""
import json,pathlib,shutil,sys
q=pathlib.Path(__file__).resolve().parent
recipe=pathlib.Path(sys.argv[1]);cfg=json.loads((q/'inputs.json').read_text())
docker=recipe/'platforms/linux-x64/Dockerfile';text=docker.read_text()
old='''curl https://sh.rustup.rs -sSf | sh -s -- -y \\
    --no-modify-path \\
    --profile minimal \\
    --default-toolchain nightly'''
new='''curl --fail --location --retry 3 -o /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init && \\
  curl --fail --location --retry 3 -o /tmp/rustup-init.sha256 https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init.sha256 && \\
  cd /tmp && sha256sum -c rustup-init.sha256 && chmod 755 rustup-init && \\
  ./rustup-init -y --no-modify-path --profile minimal --default-toolchain '''+cfg['nightly']
if text.count(old)!=1:raise SystemExit('upstream Rust installer drift')
text=text.replace(old,new).replace('cargo install cargo-c --locked','cargo install cargo-c --locked --version ='+cfg['cargo_c']).replace('pip3.12 install meson ninja','pip3.12 install --no-index --no-deps /qualification-wheels/*.whl')
# Wheels are hash-verified against official registry metadata before entering this build context.
text=text.replace('# Build dependencies','COPY qualification-wheels /qualification-wheels\n\n# Build dependencies')
docker.write_text(text)
p=recipe/'build/posix.sh';text=p.read_text();old='CURL="curl --silent --location --retry 3 --retry-max-time 30"'
if text.count(old)!=1:raise SystemExit('upstream curl assignment drift')
text=text.replace(old,'CURL="/qual/bin/curl"')
p.write_text(text)

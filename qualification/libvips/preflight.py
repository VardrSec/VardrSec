#!/usr/bin/env python3
"""Candidate pin availability/checksums; no downloaded code is executed here."""
import hashlib,json,pathlib,subprocess,sys,urllib.request
q=pathlib.Path(__file__).resolve().parent;cfg=json.loads((q/'inputs.json').read_text());recipe=pathlib.Path(sys.argv[1]);receipts=pathlib.Path(sys.argv[2]);receipts.mkdir(parents=True,exist_ok=True)
def get(url):
    with urllib.request.urlopen(url,timeout=60) as f:return f.read()
url='https://static.rust-lang.org/dist/'+cfg['nightly'].removeprefix('nightly-')+'/channel-rust-nightly.toml'
manifest=get(url);checksum=get(url+'.sha256').decode().split()[0]
if checksum!=cfg['rust_manifest_sha256'] or hashlib.sha256(manifest).hexdigest()!=checksum:raise SystemExit('Rust manifest mismatch')
(receipts/'rust-channel.toml').write_bytes(manifest);(receipts/'rust-channel.sha256').write_text(checksum+'\n')
cargo_meta=json.loads(get('https://crates.io/api/v1/crates/cargo-c/'+cfg['cargo_c_registry_version']))['version']
if cargo_meta['checksum']!=cfg['cargo_c_sha256'] or cargo_meta['yanked']:raise SystemExit('cargo-c pin changed/yanked')
(receipts/'cargo-c-registry.json').write_text(json.dumps(cargo_meta,indent=2))
wheels=recipe/'platforms/linux-x64/qualification-wheels';wheels.mkdir(exist_ok=True)
subprocess.run([sys.executable,'-m','pip','download','--only-binary=:all:','--no-deps','--dest',str(wheels),'meson=='+cfg['meson'],'ninja=='+cfg['ninja']],check=True)
rows=[]
for name in ['meson','ninja']:
    metadata=json.loads(get('https://pypi.org/pypi/'+name+'/'+cfg[name]+'/json'))
    for p in wheels.glob(name+'-*.whl'):
        expected=next(x['digests']['sha256'] for x in metadata['urls'] if x['filename']==p.name)
        actual=hashlib.sha256(p.read_bytes()).hexdigest()
        if actual!=expected or actual!=cfg[name+'_wheel_sha256']:raise SystemExit('wheel checksum mismatch')
        rows.append({'file':p.name,'sha256':actual,'registry':'https://pypi.org/pypi/'+name+'/'+cfg[name]+'/json'})
if len(rows)!=2:raise SystemExit('expected exactly two verified wheels')
(receipts/'builder-wheel-checksums.json').write_text(json.dumps(rows,indent=2))

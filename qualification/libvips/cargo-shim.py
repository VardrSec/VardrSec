#!/usr/bin/env python3.12
import hashlib,json,os,pathlib,shutil,subprocess,sys
real='/usr/local/cargo/bin/cargo'; args=sys.argv[1:];root=pathlib.Path('/receipts');root.mkdir(exist_ok=True)
with (root/'cargo-invocations.jsonl').open('a') as f:f.write(json.dumps({'cwd':os.getcwd(),'args':args})+'\n')
if args and args[0]=='update':
    if args!=['update','--workspace']:raise SystemExit('unexpected Cargo update')
    shutil.copyfile('Cargo.lock',root/'Cargo.lock.before')
    subprocess.run([real,*args,'--offline'],check=True)
    shutil.copyfile('Cargo.lock',root/'Cargo.lock.after')
    (root/'Cargo.lock.sha256').write_text(hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest()+'\n')
    for name,cmd in [('metadata.json',['metadata','--locked','--offline','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu']),('target-tree.txt',['tree','--locked','--offline','--target','x86_64-unknown-linux-gnu','-p','librsvg-c','-e','normal,build,features'])]:
        with (root/name).open('wb') as f:subprocess.run([real,*cmd],stdout=f,check=True)
    raise SystemExit(0)
if args and args[0]=='cbuild':
    # This preserves Meson's actual package/features selection. All subsequent Cargo resolution is offline.
    manifest=pathlib.Path(args[args.index('--manifest-path')+1]).resolve() if '--manifest-path' in args else pathlib.Path.cwd()/'Cargo.toml'
    lock=next((p/'Cargo.lock' for p in [manifest.parent,*manifest.parent.parents] if (p/'Cargo.lock').is_file()),None)
    if lock is None:raise SystemExit('no Cargo workspace lock found')
    shutil.copyfile(lock,root/'Cargo.lock.cbuild')
    if (root/'Cargo.lock.after').read_bytes()!=lock.read_bytes():raise SystemExit('lock drift before cbuild')
os.execv(real,[real,*args])

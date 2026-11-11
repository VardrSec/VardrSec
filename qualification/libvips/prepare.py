#!/usr/bin/env python3
"""Fetch exact source inputs; never execute fetched archives."""
import concurrent.futures, hashlib, json, pathlib, shutil, tarfile, urllib.request, sys, time

def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def download(row, dest):
    if dest.exists() and sha(dest) == row['sha256']: return
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(row['url'], timeout=60) as src, dest.open('wb') as dst:
                count = 0
                while chunk := src.read(1024*1024):
                    count += len(chunk)
                    if count > row.get('size', 256*1024*1024) + 1024: raise ValueError('size bound exceeded')
                    dst.write(chunk)
            if sha(dest) != row['sha256']: raise ValueError('checksum mismatch: '+row['url'])
            return
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    raise RuntimeError(str(last))

def unpack_crate(archive, target, name, checksum):
    """No paths, links or special files are accepted from package metadata."""
    target.mkdir(parents=True, exist_ok=True)
    hashes = {}
    with tarfile.open(archive) as tf:
        for m in tf.getmembers():
            p = pathlib.PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != name:
                raise ValueError('unsafe crate member: '+m.name)
            rel = pathlib.Path(*p.parts[1:])
            if m.isdir(): continue
            if not m.isfile() or m.size > 64*1024*1024: raise ValueError('nonregular/oversized crate member')
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(m) as src, dest.open('wb') as dst: shutil.copyfileobj(src, dst)
            hashes[rel.as_posix()] = sha(dest)
    (target/'.cargo-checksum.json').write_text(json.dumps({'package': checksum, 'files':hashes},sort_keys=True))

def main():
    config = json.loads(pathlib.Path(sys.argv[1]).read_text())
    root = pathlib.Path(sys.argv[2]); root.mkdir(parents=True,exist_ok=True)
    sources=root/'sources';sources.mkdir(exist_ok=True)
    crates=root/'crates';crates.mkdir(exist_ok=True)
    jobs=[(x,sources/x['name']) for x in config['native']]
    jobs += [(x,crates/(x['name']+'-'+x['version']+'.crate')) for x in config['crates']]
    jobs += [(config['original'],root/'original.tgz')]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda pair:download(*pair),jobs))
    urlmap={x['url']:'sources/'+x['name'] for x in config['native']}
    # Freeze notices at the same reviewed recipe commit, not its moving main branch.
    recipe=pathlib.Path(sys.argv[3]);notice=recipe/'THIRD-PARTY-NOTICES.md'
    shutil.copyfile(notice,root/'THIRD-PARTY-NOTICES.md')
    urlmap['https://raw.githubusercontent.com/lovell/sharp-libvips/main/THIRD-PARTY-NOTICES.md']='THIRD-PARTY-NOTICES.md'
    (root/'request-map.json').write_text(json.dumps(urlmap,indent=2))
    for x in config['crates']:
        name=x['name']+'-'+x['version']
        unpack_crate(crates/(name+'.crate'),root/'vendor'/name,name,x['sha256'])
    inventory={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
    (root/'verified-input-inventory.json').write_text(json.dumps(inventory,indent=2,sort_keys=True))
    print('Verified',len(config['native']),'native inputs;',len(config['crates']),'registry packages; immutable original npm artifact')

if __name__ == '__main__': main()

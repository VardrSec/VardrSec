#!/usr/bin/env python3
"""Compare unpacked payloads, not tar timestamps. No shipping substitution."""
import gzip,hashlib,io,json,pathlib,subprocess,sys,tarfile,tempfile

def payload(path):
    rows={};data={}
    with tarfile.open(path) as t:
        for m in t.getmembers():
            p=pathlib.PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts: raise ValueError('unsafe archive path')
            name=m.name.removeprefix('./').removeprefix('package/')
            if not name.startswith('lib/'):continue
            if m.isfile():
                b=t.extractfile(m).read();data[name]=b
                rows[name]={'kind':'file','sha256':hashlib.sha256(b).hexdigest(),'size':len(b)}
            elif m.issym() or m.islnk():rows[name]={'kind':'link','target':m.linkname}
            elif not m.isdir():raise ValueError('special archive member')
    if not data:raise ValueError('no library payload')
    return rows,data

def normalized(data,path):
    with path.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0,filename='') as zipped,tarfile.open(fileobj=zipped,mode='w') as t:
        for name,b in sorted(data.items()):
            m=tarfile.TarInfo(name);m.size=len(b);m.mode=0o644;m.mtime=0;t.addfile(m,io.BytesIO(b))

def elf(data,out):
    result={};out.mkdir(parents=True,exist_ok=True)
    for name,b in data.items():
        if not b.startswith(b'\x7fELF'):continue
        p=out/(hashlib.sha256(name.encode()).hexdigest()+'.elf');p.write_bytes(b)
        reports={}
        for label,cmd in [('headers',['readelf','-hW']),('dynamic',['readelf','-dW']),('symbols',['nm','-D','--defined-only']),('versions',['readelf','-VW']),('notes',['readelf','-nW'])]:
            reports[label]=subprocess.check_output([*cmd,str(p)],text=True)
        (out/(p.stem+'.json')).write_text(json.dumps({'member':name,**reports},indent=2))
        result[name]={'exported_symbols':sorted(' '.join(l.split()[1:]) for l in reports['symbols'].splitlines() if len(l.split())>=2),'needed_soname':[l.strip() for l in reports['dynamic'].splitlines() if '(NEEDED)' in l or '(SONAME)' in l]}
    return result

def main():
    out=pathlib.Path(sys.argv[1]);original=pathlib.Path(sys.argv[2]);records={};abi={}
    for label,path in [('original',original),('run1',out/'run1/packaging/sharp-libvips-linux-x64.tar.gz'),('run2',out/'run2/packaging/sharp-libvips-linux-x64.tar.gz')]:
        records[label],data=payload(path); normalized(data,out/(label+'-normalized-library-files.tar.gz'));abi[label]=elf(data,out/('elf-'+label))
    result={'scope':'new same-version candidate qualification, not historical builder reproduction','repeat_library_payload_identical':records['run1']==records['run2'],'published_library_payload_identical':records['run1']==records['original'],'exports_and_dependencies_identical':abi['run1']==abi['original'],'payloads':records,'abi':abi,'shipping_substitution_performed':False,'release_clearance':False,'integration_and_security_regression_tests':'not run by this workflow'}
    (out/'comparison.json').write_text(json.dumps(result,indent=2,sort_keys=True))
    for k in ['repeat_library_payload_identical','published_library_payload_identical','exports_and_dependencies_identical']:print(k,result[k])
    if not result['repeat_library_payload_identical'] or not result['published_library_payload_identical']:raise SystemExit('qualification mismatch: retain existing published binary; inspect comparison evidence')
if __name__=='__main__':main()

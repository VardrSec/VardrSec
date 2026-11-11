#!/usr/bin/env python3.12
import json,pathlib,sys,urllib.parse
args=sys.argv[1:]; urls=[x for x in args if x.startswith('https://')]
if len(urls)!=1: raise SystemExit('offline curl requires one known HTTPS source')
root=pathlib.Path('/inputs'); m=json.loads((root/'request-map.json').read_text())
if urls[0] not in m: raise SystemExit('unrecorded network input: '+urls[0])
b=(root/m[urls[0]]).read_bytes()
if '-O' in args: pathlib.Path(urllib.parse.urlparse(urls[0]).path).name and pathlib.Path(pathlib.Path(urllib.parse.urlparse(urls[0]).path).name).write_bytes(b)
elif '-o' in args: pathlib.Path(args[args.index('-o')+1]).write_bytes(b)
else: sys.stdout.buffer.write(b)

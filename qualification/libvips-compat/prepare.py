"""Materialize verified npm packages and candidate into a NEW qualification directory.
No install scripts, production writes, builder runs, or shipping substitutions.
"""
import base64, hashlib, io, json, pathlib, sys, tarfile, urllib.request, zipfile
PINS = json.loads(pathlib.Path(__file__).with_name('pins.json').read_text())
def sha(b): return hashlib.sha256(b).hexdigest()
def unpack(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        entries = tf.getmembers()
        for m in entries:
            p = pathlib.PurePosixPath(m.name)
            if not p.parts or p.parts[0] != 'package' or '..' in p.parts or p.is_absolute() or not (m.isdir() or m.isfile()):
                raise ValueError('Unexpected package member: ' + m.name)
        for m in entries:
            target = dest.joinpath(*pathlib.PurePosixPath(m.name).parts[1:])
            if m.isdir(): target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(m) as f: target.write_bytes(f.read())
def prepare(artifact, output):
    data = artifact.read_bytes()
    assert sha(data) == PINS['artifact_sha256'], 'artifact digest mismatch'
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        comparison = json.loads(z.read('libvips-evidence/comparison.json'))
        assert comparison['repeat_library_payload_identical'] is True
        with tarfile.open(fileobj=io.BytesIO(z.read('libvips-evidence/run1/packaging/sharp-libvips-linux-x64.tar.gz'))) as tf:
            m = tf.getmember('lib/libvips-cpp.so.8.18.7')
            assert m.isfile()
            library = tf.extractfile(m).read()
    assert sha(library) == PINS['candidate_library_sha256']
    output.mkdir(exist_ok=False)
    for key, pin in PINS['packages'].items():
        assert pin['resolved'].startswith('https://registry.npmjs.org/')
        payload = urllib.request.urlopen(pin['resolved'], timeout=90).read()
        assert 'sha512-' + base64.b64encode(hashlib.sha512(payload).digest()).decode() == pin['integrity'], key
        for variant in ['original', 'candidate']: unpack(payload, output / variant / key)
    relative = pathlib.Path('node_modules/@img/sharp-libvips-linux-x64/lib')
    assert sha((output/'original'/relative/'libvips-cpp.so.8.18.7').read_bytes()) == PINS['original_library_sha256']
    # Only the isolated candidate shared library is replaced; upstream JS wrapper retained.
    (output/'candidate'/relative/'libvips-cpp.so.8.18.7').write_bytes(library)
    assert (output/'candidate'/relative/'index.js').read_bytes() == (output/'original'/relative/'index.js').read_bytes()
    (output/'provenance.json').write_text(json.dumps(PINS, indent=2)+'\n')
if __name__ == '__main__': prepare(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))

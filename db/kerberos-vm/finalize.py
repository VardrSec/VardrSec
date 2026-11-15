"""Fail-closed custody for source-built VM packages; never use stale binaries."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finalize(work, output):
    receipt = json.loads((work/'verified.json').read_text())
    assert receipt['full_debian_package_build_passed'] is True
    assert receipt['offline_build_boot'] is True
    assert receipt['distribution_commit'] is None
    assert len(receipt['source_inputs_sha256']) == 64
    result = work/'result-build'
    assert (result/'vm/build.exit').read_text().strip() == '0'
    pins = dict((name, h) for h, name in
                (line.split() for line in (HERE/'qualified-packages.sha256').read_text().splitlines()))
    assert len(pins) == 4
    assert {p.name for p in (result/'packages').iterdir()} == set(pins)
    for name, expected in pins.items():
        assert digest(result/'packages'/name) == expected, 'independently qualified package bytes changed: '+name
    # Verify source receipts before adding build-context provenance.
    source = result/'source'
    for line in (source/'SHA256SUMS').read_text().splitlines():
        expected, name = line.split(None, 1)
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts
        assert digest(source/rel) == expected, name
    shutil.copytree(result/'packages', output/'packages')
    shutil.copytree(source, output/'source')
    target=output/'source'/'vm-builder'
    target.mkdir()
    for name in ('run.py','guest.sh','inputs.json','finalize.py','qualified-packages.sha256'):
        shutil.copyfile(HERE/name,target/name)
    for name in ('verified.json','qualification-inputs.json','prepared-disk.sha256','prepare-command.json','build-command.json'):
        shutil.copyfile(work/name,target/name)
    shutil.copyfile(result/'vm/prepared-packages.txt',target/'prepared-packages.txt')
    shutil.copyfile(result/'vm/keyring-prerequisite.txt',target/'keyring-prerequisite.txt')
    source=output/'source'
    ledger=''.join(f'{digest(p)}  ./{p.relative_to(source).as_posix()}\n'
                   for p in sorted(source.rglob('*')) if p.is_file() and p.name!='SHA256SUMS')
    (source/'SHA256SUMS').write_text(ledger)

if __name__ == '__main__':
    finalize(Path(sys.argv[1]),Path(sys.argv[2]))

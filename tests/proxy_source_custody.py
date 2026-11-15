"""Verify retained source evidence and bind it to one stopped-image Caddy binary."""
import argparse
import hashlib
import json
from pathlib import Path
import re

EXPECTED_PATCHED_TAR = '15c1c8f321ecc13d14ad104d7d164175c9df62882624f42ab2cdd91742995b73'
FILES = {'upstream-module.zip', 'backport.json', 'LICENSE', 'patched-source.tar'}

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def verify(source, binary, plan, image_id, revision, expected_tar=EXPECTED_PATCHED_TAR):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('Exact image ID required')
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('Exact distribution commit required')
    receipt = json.loads((source / 'source.json').read_text())
    expected = json.loads(plan.read_text())
    if receipt.get('module') != 'github.com/go-jose/go-jose/v3' or receipt.get('upstream_version') != 'v3.0.5':
        raise ValueError('Unexpected module identity')
    for field in ('upstream_commit', 'security_commit'):
        if receipt.get(field) != expected[field]:
            raise ValueError('Unexpected source commit')
    if receipt.get('release_clearance') is not False or receipt.get('scanner_clearance') is not False:
        raise ValueError('Unexpected clearance claim')
    hashes = receipt.get('sha256', {})
    if set(hashes) != FILES:
        raise ValueError('Unexpected source evidence files')
    for name, digest in hashes.items():
        file = source / name
        if file.is_symlink() or not file.is_file() or sha(file) != digest:
            raise ValueError('Source checksum mismatch: ' + name)
    if hashes['upstream-module.zip'] != expected['upstream_zip_sha256'] or hashes['backport.json'] != sha(plan):
        raise ValueError('Source plan or upstream archive mismatch')
    if hashes['patched-source.tar'] != expected_tar:
        raise ValueError('Unreviewed patched source archive')
    return {'schema': 1, 'image_id': image_id, 'distribution_commit': revision,
            'binary_sha256': sha(binary), 'source_receipt_sha256': sha(source / 'source.json'),
            'verified_source_sha256': hashes, 'release_clearance': False}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--plan', type=Path, default=Path('proxy/sourceprep/backport.json'))
    p.add_argument('--image-id', required=True)
    p.add_argument('--distribution-commit', required=True)
    args = p.parse_args()
    result = verify(args.source, args.binary, args.plan, args.image_id, args.distribution_commit)
    (args.source / 'custody.json').write_text(json.dumps(result, indent=2) + '\n')

"""Bind the final DB library to the exact regression-tested backport payload."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

PATCH_SHA256 = '6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54'
API_PATCHES = {
    'libxml2-CVE-2026-86138.patch': '05e5da494f3e7b5ea9500ffe6c0ef0ebac762aae956c9b8808826dc24871f003',
    'libxml2-CVE-2026-86138-caller.patch': 'e0d86e3a080087a9790947964a4c11cb461dc93feb4ab4973c0230d61dc588bb',
    'libxml2-CVE-2026-86144.patch': '85809cce7c841d76de73d133fc681614850123dcf27f93b179e2e9ac5426c8f7',
}
API_SOURCES = {
    'dict.c': 'a68d3f4216116d4339b2405979f12a34dff064fb58be90c17f7a2c19f2f13b58',
    'xinclude.c': 'c95be9183f97050c2fa3034ddea6f850774997ca0ebc703b5edeee75dc89c173',
    'testdict.c': 'cf7a2e1aa582c0f13676651d1dc1ed3337e1616db076fac0d408a55d2bf8e8ab',
}
LIBRARY = 'usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14'
LEGACY_REQUIRED = {'CVE-2026-6653.patch', 'evidence/applied-patches.txt',
            'evidence/entity-amplification-regression.txt',
            'evidence/entity-regression-library-SHA256SUMS'}
REQUIRED = {*LEGACY_REQUIRED, 'evidence/patched-source-SHA256SUMS', 'evidence/dictionary-xinclude-checks.txt',
            *API_PATCHES}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def local_file(root, name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe source evidence path')
    target = root
    for part in path.parts:
        target = target / part
        if target.is_symlink():
            raise ValueError('Symlink source evidence')
    if not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('Missing source evidence: ' + name)
    return target


def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *](.+)', line)
        if not match:
            raise ValueError('Malformed source checksum')
        digest, name = match.groups()
        name = name.removeprefix('./')
        if name in result:
            raise ValueError('Duplicate source checksum')
        result[name] = digest
    return result


def verify_api_checks(source, inventory, applied):
    for patch, digest in API_PATCHES.items():
        if inventory[patch] != digest or patch.replace('libxml2-', 'vardr-') not in applied:
            raise ValueError('Dictionary or XInclude backport identity differs')
    compiled_sources = checksums(source / 'evidence/patched-source-SHA256SUMS')
    if not API_SOURCES.items() <= compiled_sources.items():
        raise ValueError('Dictionary or XInclude source differs from reviewed backport')
    api_cases = ['dictionary tests succeeded 20000 strings'] + [
        f'api={api} noblanks={flag} verdict=PASS'
        for api in ('document', 'tree') for flag in (0, 1)]
    if (source / 'evidence/dictionary-xinclude-checks.txt').read_text().splitlines() != api_cases:
        raise ValueError('Incomplete dictionary or XInclude API checks')


def verify(source, runtime, image_id, revision, require_api_checks=False):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('Exact image ID required')
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('Exact distribution commit required')
    if source.is_symlink() or runtime.is_symlink():
        raise ValueError('Symlink evidence root')
    inventory = checksums(local_file(source, 'SHA256SUMS'))
    has_api_checks = 'evidence/dictionary-xinclude-checks.txt' in inventory
    required = REQUIRED if require_api_checks or has_api_checks else LEGACY_REQUIRED
    if not required <= inventory.keys():
        raise ValueError('Incomplete source evidence')
    for name, expected in inventory.items():
        if sha(local_file(source, name)) != expected:
            raise ValueError('Source checksum mismatch: ' + name)
    if inventory['CVE-2026-6653.patch'] != PATCH_SHA256:
        raise ValueError('Unreviewed backport patch')
    applied = set((source / 'evidence/applied-patches.txt').read_text().splitlines())
    if 'vardr-CVE-2026-6653.patch' not in applied:
        raise ValueError('Backport absent from applied patch ledger')
    if has_api_checks:
        verify_api_checks(source, inventory, applied)
    expected_cases = {f'case={case} huge={huge} verdict=PASS'
                      for case in ('100000-byte-control', '20736000-byte-amplification')
                      for huge in (0, 1)}
    observed = (source / 'evidence/entity-amplification-regression.txt').read_text().splitlines()
    if len(observed) != 4 or set(observed) != expected_cases:
        raise ValueError('Incomplete or failed bounded entity regression')
    tested = checksums(source / 'evidence/entity-regression-library-SHA256SUMS')
    if set(tested) != {LIBRARY}:
        raise ValueError('Unexpected regression-tested library')
    with tarfile.open(runtime) as archive:
        manifests = [m for m in archive.getmembers() if m.name == 'manifest.json']
        if len(manifests) != 1 or not manifests[0].isfile() or manifests[0].size > 4 * 1024 * 1024:
            raise ValueError('Missing or unsafe runtime manifest')
        manifest = json.load(archive.extractfile(manifests[0]))
    if (manifest.get('schema') != 'vardr.runtime-notice-evidence/1'
            or manifest.get('service') != 'db'
            or manifest.get('image_id') != image_id
            or manifest.get('distribution_commit') != revision
            or manifest.get('component_inventory_export_completed') is not True):
        raise ValueError('Runtime evidence identity or completed-export mismatch')
    rows = [row for row in manifest['native_files'] if row['path'] == LIBRARY]
    if len(rows) != 1 or rows[0]['sha256'] != tested[LIBRARY]:
        raise ValueError('Final image library differs from regression-tested payload')
    return {'schema': 1, 'image_id': image_id, 'distribution_commit': revision,
            'library': LIBRARY, 'library_sha256': tested[LIBRARY],
            'backport_patch_sha256': PATCH_SHA256,
            'source_manifest_sha256': sha(source / 'SHA256SUMS'),
            'runtime_evidence_sha256': sha(runtime),
            'dictionary_and_xinclude_api_checks': has_api_checks,
            'scope': 'Exact package-payload identity and recorded library regressions',
            'vulnerability_gate_changed': False, 'release_clearance': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--runtime-notices', type=Path, required=True)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--distribution-commit', required=True)
    parser.add_argument('--require-api-checks', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.source, args.runtime_notices, args.image_id,
                            args.distribution_commit, args.require_api_checks), indent=2))

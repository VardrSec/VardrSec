"""Consume one reviewed VM artifact; never fall back to an unqualified build."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

ARCHIVE_SHA256 = '5cb8a64e59f2ff8f945adfa934e4e989d62fec754751f38f70bf3765495fdae9'
PREFIX = '_temp/kerberos-vm/qualification/'
MERGE = '5a0281ff0e3b6e97432a7c779211ff14c0110c94'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(archive, repo, output):
    assert digest(archive.read_bytes()) == ARCHIVE_SHA256, 'VM artifact checksum mismatch'
    output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        assert len(names) == len(set(names)), 'duplicate archive entry'
        receipt = json.loads(z.read(PREFIX + 'verified.json'))
        assert receipt['distribution_commit'] == MERGE
        assert receipt['full_debian_package_build_passed'] is True
        assert receipt['offline_build_boot'] is True
        assert receipt['release_clearance'] is False
        for name in names:
            if not name.startswith(PREFIX + 'result-build/') or name.endswith('/'):
                continue
            rel = PurePosixPath(name.removeprefix(PREFIX + 'result-build/'))
            assert not rel.is_absolute() and '..' not in rel.parts
            target = output / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(name))
    for manifest, root in [(output/'source/SHA256SUMS', output/'source'),
                           (output/'source/evidence/packages-SHA256SUMS', output/'packages')]:
        for line in manifest.read_text().splitlines():
            expected, name = line.split(None, 1)
            rel = PurePosixPath(name.lstrip('*'))
            assert not rel.is_absolute() and '..' not in rel.parts
            assert digest((root / rel).read_bytes()) == expected, name
    packages = list((output/'packages').glob('*.deb'))
    assert len(packages) == 4
    # Prevent stale artifacts being used with a different patch/build input.
    for name in ('build-krb5.sh', 'krb5-CVE-2026-119079.patch',
                 'krb5-keyring-test-diagnostic.patch', 'krb5-sequence-regression.c', 'Dockerfile'):
        assert (repo/'db'/name).read_bytes() == (output/'source'/name).read_bytes(), name
    original = (repo/'db/Dockerfile').read_text()
    marker = '\nFROM postgres@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6 AS libxml2-backport\n'
    assert original.count(marker) == 1
    # Only substitute acquisition of the exact qualified Kerberos bytes.
    # The rest of the actual database recipe is byte-for-byte unchanged.
    candidate = 'FROM scratch AS krb5-backport\nCOPY qualified-krb5/packages/ /out/packages/\nCOPY qualified-krb5/source/ /out/source/\n' + marker + original.split(marker, 1)[1]
    (repo/'db/Dockerfile.qualification').write_text(candidate)
    (output/'consumption.json').write_text(json.dumps({
        'artifact_id': 13875193642, 'workflow_run': 43060945526,
        'artifact_sha256': ARCHIVE_SHA256, 'qualified_revision': MERGE,
        'original_dockerfile_sha256': digest(original.encode()),
        'candidate_dockerfile_sha256': digest(candidate.encode()),
        'release_clearance': False, 'independent_reproducibility': False}, indent=2)+'\n')

if __name__ == '__main__':
    prepare(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))

"""Compare two separately prepared, successful offline VM package builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

PREFIX = '_temp/kerberos-vm/qualification/'
PACKAGE_PINS = Path(__file__).resolve().parents[2] / 'db/kerberos-vm/qualified-packages.sha256'
INPUTS = ['Dockerfile', 'build-krb5.sh', 'krb5-CVE-2026-119079.patch', 'krb5-CVE-2026-71199.patch',
          'krb5-keyring-test-diagnostic.patch', 'krb5-sequence-regression.c',
          'krb5_1.21.3.orig.tar.gz', 'krb5_1.21.3.orig.tar.gz.asc', 'krb5_1.21.3-5+deb13u2.dsc',
          'krb5_1.21.3-5+deb13u2.debian.tar.xz',
          'evidence/patched-source-SHA256SUMS']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, expected, job_receipt=False):
    assert sha(path.read_bytes()) == expected, 'archive digest mismatch'
    with zipfile.ZipFile(path) as z:
        if job_receipt:
            assert z.namelist() == ['kerberos-u2-receipt.json'], 'unexpected receipt archive'
            report = json.loads(z.read('kerberos-u2-receipt.json'))
            assert report['receipt']['full_debian_package_build_passed'] is True
            assert report['receipt']['offline_build_boot'] is True
            assert set(report['inputs']) == set(INPUTS), 'missing source/build input'
            pinned = {name: digest for digest, name in
                      (line.split() for line in PACKAGE_PINS.read_text().splitlines())}
            assert len(pinned) == 4 and report['packages'] == pinned, 'unexpected package or digest'
            digests = [report['prepared_packages_sha256'], report['receipt']['prepared_disk_sha256'],
                       *report['inputs'].values(), *report['packages'].values()]
            assert all(re.fullmatch('[a-f0-9]{64}', digest) for digest in digests), 'invalid SHA-256'
            return dict(report, archive_sha256=expected)
        receipt = json.loads(z.read(PREFIX + 'verified.json'))
        assert receipt['full_debian_package_build_passed'] is True
        assert receipt['offline_build_boot'] is True
        assert z.read(PREFIX+'result-build/vm/build.exit').strip() == b'0'
        packages = {Path(n).name: sha(z.read(n)) for n in z.namelist()
                    if n.startswith(PREFIX+'result-build/packages/') and n.endswith('.deb')}
        assert len(packages) == 4
        inputs = {n: sha(z.read(PREFIX+'result-build/source/'+n)) for n in INPUTS}
        dependencies = sha(z.read(PREFIX+'result-build/vm/prepared-packages.txt'))
        return dict(receipt=receipt, packages=packages, inputs=inputs,
                    prepared_packages_sha256=dependencies, archive_sha256=expected)


def compare(first, second):
    # Distinct builds must not merely reuse the same archive/prepared VM disk.
    assert first['archive_sha256'] != second['archive_sha256']
    assert first['receipt']['prepared_disk_sha256'] != second['receipt']['prepared_disk_sha256']
    assert first['inputs'] == second['inputs'], 'substantive source/build inputs changed'
    assert first['packages'] == second['packages'], 'runtime packages differ'
    return dict(schema=1, package_bytes_reproduced=True,
                separately_prepared_vm_disks=True,
                prepared_dependency_inventory_identical=(first['prepared_packages_sha256']==second['prepared_packages_sha256']),
                first=first, second=second, release_clearance=False,
                scope='Four linux-amd64 Kerberos runtime packages; not entire-image reproducibility or distribution clearance')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('first', type=Path)
    p.add_argument('first_sha256')
    p.add_argument('second', type=Path)
    p.add_argument('second_sha256')
    p.add_argument('output', type=Path)
    p.add_argument('--job-receipts', action='store_true',
                   help='Compare package hashes recorded inside two trusted CI jobs')
    a = p.parse_args()
    result = compare(read(a.first, a.first_sha256, a.job_receipts),
                     read(a.second, a.second_sha256, a.job_receipts))
    a.output.write_text(json.dumps(result, indent=2)+'\n')

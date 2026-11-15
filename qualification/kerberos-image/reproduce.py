"""Compare two separately prepared, successful offline VM package builds."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

PREFIX = '_temp/kerberos-vm/qualification/'
INPUTS = ['Dockerfile', 'build-krb5.sh', 'krb5-CVE-2026-119079.patch',
          'krb5-keyring-test-diagnostic.patch', 'krb5-sequence-regression.c',
          'krb5_1.21.3.orig.tar.gz', 'krb5_1.21.3-5+deb13u1.dsc',
          'krb5_1.21.3-5+deb13u1.debian.tar.xz',
          'evidence/patched-source-SHA256SUMS']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, expected):
    assert sha(path.read_bytes()) == expected, 'archive digest mismatch'
    with zipfile.ZipFile(path) as z:
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
    a = p.parse_args()
    result = compare(read(a.first, a.first_sha256), read(a.second, a.second_sha256))
    a.output.write_text(json.dumps(result, indent=2)+'\n')

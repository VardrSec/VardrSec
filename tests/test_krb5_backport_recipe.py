import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KerberosBackportRecipeTests(unittest.TestCase):
    def test_exact_upstream_patch(self):
        patch = ROOT / 'db/krb5-CVE-2026-119079.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(),
                         '1c9f5facbcb81930d9c7dac552750273045e35e85dbfbc873b2ce140acf96705')
        self.assertIn('782e5ac4fb1496a79de0b87e1fc485f897e97d6d', patch.read_text())

    def test_tests_and_source_retention_fail_closed(self):
        script = (ROOT / 'db/build-krb5.sh').read_text()
        self.assertIn('dpkg-buildpackage -us -uc -B', script)
        self.assertNotIn('nocheck', script)
        self.assertIn('dpkg-deb -x', script)
        self.assertIn('LD_LIBRARY_PATH="$libdir" timeout 15', script)
        self.assertIn('ulimit -v 262144', script)
        self.assertIn('packages-SHA256SUMS', script)
        self.assertIn('patched-source-SHA256SUMS', script)
        self.assertIn('dpkg-source --build', script)

    def test_only_qualified_library_packages_delivered(self):
        script = (ROOT / 'db/build-krb5.sh').read_text()
        self.assertIn('for name in libkrb5-3 libk5crypto3 libkrb5support0 libgssapi-krb5-2;', script)
        docker = (ROOT / 'db/Dockerfile').read_text()
        self.assertIn('run.py --source-only --work /work/qualification', docker)
        self.assertIn('USER 65534:65534', docker)
        harness=(ROOT/'db/kerberos-vm/run.py').read_text()
        self.assertIn("else 'none']", harness)
        self.assertIn('sh /build/build-krb5.sh', (ROOT/'db/kerberos-vm/guest.sh').read_text())
        self.assertIn('/usr/share/doc/libkrb5-3/vardr-source/', docker)

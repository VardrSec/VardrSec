import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('custody', Path(__file__).with_name('proxy_source_custody.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CustodyTests(unittest.TestCase):
    def fixture(self, root):
        for name in m.FILES:
            (root / name).write_bytes(name.encode())
        p = {'upstream_commit': '1'*40, 'security_commit': '2'*40,
             'upstream_zip_sha256': m.sha(root / 'upstream-module.zip')}
        (root / 'backport.json').write_text(json.dumps(p))
        plan = root / 'plan.json'
        plan.write_bytes((root / 'backport.json').read_bytes())
        r = {'module': 'github.com/go-jose/go-jose/v3', 'upstream_version': 'v3.0.5',
             'release_clearance': False, 'scanner_clearance': False,
             'sha256': {n: m.sha(root/n) for n in m.FILES}, **{k:p[k] for k in ('upstream_commit','security_commit')}}
        (root / 'source.json').write_text(json.dumps(r))
        binary = root / 'caddy'; binary.write_bytes(b'fixture-not-executable')
        return plan, binary
    def test_verified_and_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); plan,binary=self.fixture(r)
            result=m.verify(r,binary,plan,'sha256:'+'a'*64,'b'*40,m.sha(r/'patched-source.tar'))
            self.assertEqual(result['binary_sha256'],m.sha(binary))
            (r/'LICENSE').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                m.verify(r,binary,plan,'sha256:'+'a'*64,'b'*40,m.sha(r/'patched-source.tar'))
    def test_context_and_archive(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);plan,binary=self.fixture(r)
            with self.assertRaises(ValueError): m.verify(r,binary,plan,'latest','b'*40)
            with self.assertRaises(ValueError): m.verify(r,binary,plan,'sha256:'+'a'*64,'b'*40,'wrong')
    def test_workflow_captures_same_stopped_image(self):
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/image-evidence.yml').read_text()
        self.assertIn('docker cp "$id:/usr/share/licenses/caddy/go-jose-v3"',text)
        self.assertIn('go version -m "$RUNNER_TEMP/caddy"',text)
        self.assertIn('name: proxy-source-custody',text)

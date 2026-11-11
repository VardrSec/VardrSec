import hashlib,io,json,pathlib,tarfile,tempfile,unittest
import prepare,compare
class QualificationTests(unittest.TestCase):
    def test_inventory_counts_and_hashes(self):
        cfg=json.loads((pathlib.Path(__file__).parent/'inputs.json').read_text())
        self.assertEqual(len(cfg['native']),33);self.assertEqual(len(cfg['crates']),357)
        self.assertEqual(len({(x['name'],x['version']) for x in cfg['crates']}),357)
        for x in cfg['native']+cfg['crates']+[cfg['original']]:
            self.assertRegex(x['sha256'],r'^[0-9a-f]{64}$');self.assertTrue(x['url'].startswith('https://'))
    def archive(self,root,name,member,link=False):
        p=root/name
        with tarfile.open(p,'w:gz') as t:
            m=tarfile.TarInfo(member)
            if link:m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';t.addfile(m)
            else:m.size=3;t.addfile(m,io.BytesIO(b'abc'))
        return p
    def test_vendor_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d);p=self.archive(r,'x.crate','x-1/src/lib.rs')
            prepare.unpack_crate(p,r/'vendor','x-1','a'*64)
            x=json.loads((r/'vendor/.cargo-checksum.json').read_text())
            self.assertEqual(x['files']['src/lib.rs'],hashlib.sha256(b'abc').hexdigest())
    def test_vendor_rejects_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d)
            for n,name,link in [('a','x-1/../outside',False),('b','x-1/symlink',True)]:
                with self.assertRaises(ValueError):prepare.unpack_crate(self.archive(r,n,name,link),r/'vendor','x-1','a'*64)
    def test_payload_normalizes_package_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d);a=self.archive(r,'a','lib/example.so');b=self.archive(r,'b','package/lib/example.so')
            self.assertEqual(compare.payload(a),compare.payload(b))
    def test_normalized_archive_determinism(self):
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d);compare.normalized({'lib/a':b'a','lib/b':b'b'},r/'a');compare.normalized({'lib/b':b'b','lib/a':b'a'},r/'b')
            self.assertEqual((r/'a').read_bytes(),(r/'b').read_bytes())
if __name__=='__main__':unittest.main()

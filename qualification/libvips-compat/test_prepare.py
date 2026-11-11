import io,tarfile,tempfile,pathlib,unittest
from prepare import unpack, prepare
class ArchiveTests(unittest.TestCase):
 def archive(self,name,kind=tarfile.REGTYPE):
  b=io.BytesIO()
  with tarfile.open(fileobj=b,mode='w') as t:
   m=tarfile.TarInfo(name);m.type=kind;m.size=0;t.addfile(m)
  return b.getvalue()
 def test_regular(self):
  with tempfile.TemporaryDirectory() as d:
   unpack(self.archive('package/lib/index.js'),pathlib.Path(d));self.assertTrue((pathlib.Path(d)/'lib/index.js').exists())
 def test_wrong_artifact_before_creation(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); artifact=root/'wrong.zip';artifact.write_bytes(b'wrong')
   with self.assertRaisesRegex(AssertionError,'artifact digest mismatch'): prepare(artifact,root/'output')
   self.assertFalse((root/'output').exists())
 def test_rejected_members(self):
  for name,kind in [('package/../outside',tarfile.REGTYPE),('/package/out',tarfile.REGTYPE),('other/file',tarfile.REGTYPE),('package/link',tarfile.SYMTYPE)]:
   with self.subTest(name=name),tempfile.TemporaryDirectory() as d,self.assertRaises(ValueError):unpack(self.archive(name,kind),pathlib.Path(d))
if __name__=='__main__':unittest.main()

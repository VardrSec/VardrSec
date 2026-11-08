"""Byte hashes only. This source is data until reviewed controller execution."""
import hashlib, importlib.abc, json, pathlib, stat, sys, sysconfig

class NoProject(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'vardrrunner','wrapper','leaf'}:
            raise RuntimeError('project_import_forbidden')

sys.meta_path.insert(0, NoProject())
assert not any(name.split('.')[0] in {'vardrrunner','wrapper','leaf'} for name in sys.modules)
package = pathlib.Path(sysconfig.get_path('purelib')) / 'vardrrunner'
assert package.is_dir() and not package.is_symlink()
python = {}
for path in sorted(package.rglob('*.py')):
    assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink()
    python[path.relative_to(package).as_posix()] = hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()
fixed = ('/usr/local/bin/vardr-worker-owner',
         '/usr/local/libexec/vardrgate-57cfedfaf59b11cf626288c343f34a34c7b1df13',
         '/usr/local/bin/vardrgate','/opt/vardr-nm2-boundary/wrapper.py',
         '/opt/vardr-nm2-boundary/leaf.py')
assert sys.argv[1:] in (['base'], ['derived'])
if sys.argv[1] == 'base':
    fixed = ('/usr/local/bin/vardr-worker-owner', '/usr/local/bin/vardrgate')
files = {}
for name in fixed:
    path = pathlib.Path(name)
    assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink()
    files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
assert len(python) == 80
assert not any(name.split('.')[0] in {'vardrrunner','wrapper','leaf'} for name in sys.modules)
print(json.dumps({'python':python,'files':files,'project_imports':False}, sort_keys=True))

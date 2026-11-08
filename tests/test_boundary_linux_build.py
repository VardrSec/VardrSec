"""Inert Hosted-shaped mocks; no engine, SDK, fixture or operand invocation."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import nm2_worker_boundary_build as b

class Host:
    def __init__(self, folder, defect=None):
        self.root=folder/'run';self.root.mkdir()
        self.project='vardrsec-nm2-inertboundary';self.defect=defect;self.calls=[]
        self.pins={**b.SOURCES,'distribution':'1'*40}
        self.sources={name:folder/name for name in self.pins}
        for path in self.sources.values():path.mkdir()
        self.tracked=['vardrrunner/a'+str(i)+'.py' for i in range(80)]
        for name in self.tracked:
            path=self.sources['runner']/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'pass\n')
        self.base='sha256:'+'a'*64;self.derived='sha256:'+'b'*64
        self.receipt={'images':{'worker':self.base},'source_trees':dict.fromkeys(self.pins,'2'*40)}
        self.python={Path(name).relative_to('vardrrunner').as_posix():b.digest(b'pass\n') for name in self.tracked}
        self.genuine='e'*64;self.owner='f'*64

    def command(self,args,**kwargs):
        self.calls.append(('command',args,kwargs))
        if 'ls-files' in args:return '\n'.join(self.tracked)
        if 'status' in args:return ' M changed' if self.defect=='source' else ''
        name=next(name for name,path in self.sources.items() if str(path)==args[2])
        return self.pins[name]+'\n'+self.receipt['source_trees'][name]

    def docker(self,*args,**kwargs):
        self.calls.append(('docker',args,kwargs))
        if args[0]=='run':
            stage=args[-1]
            assert stage in {'base','derived'} and args[args.index('--entrypoint')+1]=='python'
            for pair in (('--network','none'),('--user','10001:10001'),('--cap-drop','ALL'),('--pids-limit','32'),('--memory','256m'),('--cpus','1')):
                assert args[args.index(pair[0])+1]==pair[1]
            assert '--read-only' in args and '--rm' in args and kwargs['timeout']==30
            hashes={b.OWNER:self.owner,b.GATE:self.genuine}
            if stage=='derived':hashes={b.OWNER:self.owner,b.GATE:b.digest(b.render_boundary_wrapper(self.genuine)),b.LIBEXEC:self.genuine,b.WRAPPER:b.digest(b.render_boundary_wrapper(self.genuine)),b.LEAF:b.LEAF_SHA}
            if stage=='derived' and self.defect in {'owner','genuine','wrapper'}:
                hashes[{'owner':b.OWNER,'genuine':b.LIBEXEC,'wrapper':b.WRAPPER}[self.defect]]='d'*64
            python=dict(self.python)
            if self.defect=='sdk':python['a0.py']='c'*64
            return json.dumps(dict(python=python,files=hashes,project_imports=False))
        assert args[:3]==('image','inspect','--format')
        form,image=args[3:]
        if form=='{{.Id}}':return 'sha256:'+'c'*64 if self.defect=='tag' else self.base
        if form.startswith('{{range'):
            return '\n'.join([*b.CONFIG_FIELDS,'Env',*(['Unknown'] if self.defect=='unknown-config' else [])])
        if form.startswith('{"os":'):return json.dumps(dict(os='linux',arch='amd64',variant=None))
        assert '"Env"' not in form
        values=dict.fromkeys(b.CONFIG_FIELDS)
        values['User']='10001:10001' if image==self.derived and self.defect=='profile' else '0:0'
        return json.dumps(values)

    def build(self,name,context,**kwargs):
        self.calls.append(('build',name,kwargs))
        assert name=='boundary-worker' and kwargs['extra']==('--pull=false','--network','none')
        assert (context/'wrapper.py').read_bytes()==b.render_boundary_wrapper(self.genuine)
        dockerfile=(context/'Dockerfile').read_text()
        assert dockerfile.count(self.project+':worker')==2 and b.OLD_BASE not in dockerfile
        assert all(line.startswith(('FROM ','COPY ')) for line in dockerfile.splitlines())
        return self.derived,self.project+':boundary-worker'

class LinuxBoundaryBuildTests(unittest.TestCase):
    def setUp(self):
        # Only the inert helper's namespace changes; Python/guard OS state does not.
        selected=patch.object(b,'sys',SimpleNamespace(platform='linux'))
        selected.start();self.addCleanup(selected.stop)

    def test_same_job_byte_recipe_returns_dynamic_closed_binding_before_any_job(self):
        with tempfile.TemporaryDirectory(dir=Path.home().parent) as folder:
            host=Host(Path(folder))
            raw,binding=b.qualify_boundary_image(host)
            q=json.loads(raw)
            self.assertEqual(set(binding),{'image_id','wrapper_sha256','genuine_gate_sha256','owner_sha256','source_recipe'})
            self.assertEqual(binding['image_id'],host.derived)
            self.assertEqual(binding['genuine_gate_sha256'],host.genuine)
            self.assertEqual(binding['wrapper_sha256'],b.digest(b.render_boundary_wrapper(host.genuine)))
            self.assertEqual(binding,b.binding_for_qualification(q,host.pins,host.receipt['source_trees']))
            self.assertEqual((host.root/'boundary-image-qualification.json').read_bytes(),raw)
            self.assertEqual(sum(call[0]=='build' for call in host.calls),1)
            self.assertEqual(sum(call[0]=='docker' and call[1][0]=='run' for call in host.calls),2)
            self.assertFalse(q['fixture_runtime_approval'])

    def test_unknown_profile_or_source_change_refuses_no_qualification(self):
        for defect in ('unknown-config','profile','source','tag'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory(dir=Path.home().parent) as folder:
                host=Host(Path(folder),defect)
                with self.assertRaises(ValueError):b.qualify_boundary_image(host)
                self.assertFalse((host.root/'boundary-image-qualification.json').exists())

    def test_sdk_owner_child_and_wrapper_byte_changes_refuse(self):
        for defect in ('sdk','owner','genuine','wrapper'):
            with self.subTest(defect=defect),tempfile.TemporaryDirectory(dir=Path.home().parent) as folder:
                host=Host(Path(folder),defect)
                with self.assertRaises(ValueError):b.qualify_boundary_image(host)
                self.assertFalse((host.root/'boundary-image-qualification.json').exists())

    def test_renderer_and_binding_are_closed_without_raw_expected_pin_selection(self):
        template=(b.TEMPLATES/'wrapper.py').read_bytes()
        rendered=b.render_boundary_wrapper('e'*64)
        self.assertEqual(rendered.replace(b"ORIGINAL_SHA = '"+b'e'*64+b"'",b"ORIGINAL_SHA = '"+b.ORIGINAL_SHA.encode()+b"'"),template)
        for value in ('','g'*64,'e'*63,True):
            with self.assertRaises(ValueError):b.render_boundary_wrapper(value)
        with tempfile.TemporaryDirectory(dir=Path.home().parent) as folder:
            host=Host(Path(folder));raw,_=b.qualify_boundary_image(host);q=json.loads(raw)
            for path,value in ((('source_recipe','copy_only'),False),(('source_recipe','template_sha256'),'a'*64),(('source_recipe','rendered_wrapper_sha256'),'a'*64),(('file_hashes',b.LIBEXEC),'a'*64)):
                changed=deepcopy(q);changed[path[0]][path[1]]=value
                with self.assertRaises(ValueError):b.binding_for_qualification(changed,host.pins,host.receipt['source_trees'])
            changed=deepcopy(q);changed['source_recipe']['extra']='denied'
            with self.assertRaises(ValueError):b.binding_for_qualification(changed,host.pins,host.receipt['source_trees'])

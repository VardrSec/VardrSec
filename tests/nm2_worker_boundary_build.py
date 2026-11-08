"""Closed Linux CI byte qualification; no operation occurs on module import."""
import hashlib
import json
from pathlib import Path
import re
import sys

TEMPLATES = Path(__file__).resolve().parent / 'fixtures/nm2-fixed-boundary'
TEMPLATE_SHA = '39c3f2b0f3df91eb36a464f1168bd66cf90462411fce9a0293f3aae1570e59f9'
LEAF_SHA = '341713cdebc59e190e097f9aa6f0321101b445cf8ee19d5a33053bd605b4fc40'
DOCKERFILE_SHA = 'b27701636ba2a14be2609193f535bf719c93a1d5352f67ea6a5b71ccd8ce3e44'
READBACK_SHA = '3b1d2af5f9c974b8a00fdcedfff5b8832eb5ac9bb66cc6885892e9ce8dc8491e'
ORIGINAL_SHA = 'cc08e48efe7c6a42bcb0bc02ec4fca7ec70c739451cfd54109064cc59e934ae7'
OLD_BASE = 'sha256:58bb6fafb5f416fedcc01b3dbb8a86a87d42e11e831dfac7089f5afab6c5b2df'
OWNER, GATE = '/usr/local/bin/vardr-worker-owner', '/usr/local/bin/vardrgate'
LIBEXEC = '/usr/local/libexec/vardrgate-57cfedfaf59b11cf626288c343f34a34c7b1df13'
WRAPPER, LEAF = '/opt/vardr-nm2-boundary/wrapper.py', '/opt/vardr-nm2-boundary/leaf.py'
SOURCES = dict(map='05dc78cf9a385255de459c8a5b833842d6528a63', runner='f3dc7e92ea0cc04f5aca4bb74cc739fd79f5be19', gate='57cfedfaf59b11cf626288c343f34a34c7b1df13')
CONFIG_FIELDS = tuple('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell'.split())
SOURCE_RECIPE_FIELDS = frozenset('schema sources source_trees base_image_id template_sha256 rendered_wrapper_sha256 genuine_gate_sha256 owner_sha256 sdk_inventory_sha256 defaults_sha256 copy_only template_changed_field'.split())
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
digest = lambda data: hashlib.sha256(data).hexdigest()

def require(value):
    if not value:
        raise ValueError('boundary_image_qualification_refused')

def render_boundary_wrapper(genuine_sha):
    require(type(genuine_sha) is str and re.fullmatch('[0-9a-f]{64}', genuine_sha))
    template = (TEMPLATES/'wrapper.py').read_bytes().replace(b'\r\n', b'\n')
    before = ("ORIGINAL_SHA = '"+ORIGINAL_SHA+"'").encode()
    after = ("ORIGINAL_SHA = '"+genuine_sha+"'").encode()
    require(digest(template) == TEMPLATE_SHA and template.count(before) == 1)
    rendered = template.replace(before, after)
    require(rendered.replace(after, before) == template)
    return rendered

def binding_for_qualification(q, sources, source_trees):
    """Validate TrustedHost's pre-job qualification, never authenticate worker JSON."""
    r = q['source_recipe']
    require(set(r) == SOURCE_RECIPE_FIELDS and r['schema'] == 'vardr.nm2-fixed-fixture-linux-source/1')
    require(r['sources'] == sources and r['source_trees'] == source_trees and all(sources[k] == v for k,v in SOURCES.items()))
    require(set(sources) == set(source_trees) == {'distribution','map','runner','gate'} and all(type(v) is str and re.fullmatch('[0-9a-f]{40}',v) for v in (*sources.values(),*source_trees.values())))
    require(r['copy_only'] is True and r['template_changed_field'] == 'ORIGINAL_SHA' and r['template_sha256'] == TEMPLATE_SHA)
    require(q['schema'] == 'vardr.nm2-fixture-image-byte-qualification/1' and q['status'] == 'passed_fixture_image_byte_qualification' and q['fixture_only'] is True and q['fixture_runtime_approval'] is False and q['genuine_gate_qualified_at_wrapper_path'] is False)
    require(q['runner_commit'] == SOURCES['runner'] and q['gate_commit'] == SOURCES['gate'] and q['source_before_after'] is True and q['project_imports'] is False and type(q['native_startups']) is int and q['native_startups'] == 0 and q['registry_pull'] is q['publication'] is False)
    require(type(q['python_files']) is int and q['python_files'] == 80 and r['sdk_inventory_sha256'] == q['python_inventory_sha256'])
    require(all(type(r[k]) is str and re.fullmatch('[0-9a-f]{64}',r[k]) for k in ('rendered_wrapper_sha256','genuine_gate_sha256','owner_sha256','sdk_inventory_sha256','defaults_sha256')))
    require(all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for v in (q['image'],r['base_image_id'])))
    require(r['rendered_wrapper_sha256'] == digest(render_boundary_wrapper(r['genuine_gate_sha256'])))
    require(q['file_hashes'] == {OWNER:r['owner_sha256'],GATE:r['rendered_wrapper_sha256'],LIBEXEC:r['genuine_gate_sha256'],WRAPPER:r['rendered_wrapper_sha256'],LEAF:LEAF_SHA})
    require(q['image_defaults'] == {'all_config_field_names_checked':True,'compared_non_env_fields':list(CONFIG_FIELDS),'identical':True,'environment_values_selected_or_output':False,'environment_preservation':'same base; COPY-only/no OnBuild/no ENV or RUN'})
    return dict(image_id=q['image'],wrapper_sha256=r['rendered_wrapper_sha256'],genuine_gate_sha256=r['genuine_gate_sha256'],owner_sha256=r['owner_sha256'],source_recipe=dict(r))

def _defaults(h, image):
    names = h.docker('image','inspect','--format','{{range $name, $value := .Config}}{{println $name}}{{end}}',image,capture=True).splitlines()
    require(names and len(names) == len(set(names)) and set(names) <= set(CONFIG_FIELDS)|{'Env'})
    form = '{'+','.join(json.dumps(k)+':{{json (index .Config '+json.dumps(k)+')}}' for k in CONFIG_FIELDS)+'}'
    values = json.loads(h.docker('image','inspect','--format',form,image,capture=True))
    require(set(values) == set(CONFIG_FIELDS))
    return sorted(names), values

def _measure(h, image, stage):
    require(stage in {'base','derived'})
    program = (TEMPLATES/'byte_readback.py').read_bytes()
    require(digest(program) == READBACK_SHA)
    observed = json.loads(h.docker('run','--rm','--name',h.project+'-boundary-byte-'+stage,'--label','com.docker.compose.project='+h.project,'--pull','never','--network','none','--read-only','--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','256m','--cpus','1','--entrypoint','python',image,'-I','-S','-B','-c',program.decode(),stage,capture=True,timeout=30))
    require(set(observed) == {'python','files','project_imports'} and observed['project_imports'] is False)
    require(set(observed['files']) == ({OWNER,GATE} if stage == 'base' else {OWNER,GATE,LIBEXEC,WRAPPER,LEAF}))
    require(all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in observed['files'].values()))
    return observed

def _platform(h, image):
    value = json.loads(h.docker('image','inspect','--format','{"os":{{json .Os}},"arch":{{json .Architecture}},"variant":{{json (index . "Variant")}}}',image,capture=True))
    require(set(value) == {'os','arch','variant'} and value['os'] == 'linux' and value['arch'] == 'amd64')
    return value

def qualify_boundary_image(h):
    """Existing Hosted.build owns effects; qualification starts no product/native code."""
    require(sys.platform == 'linux' and all(h.pins[k] == v for k,v in SOURCES.items()))
    base, base_tag = h.receipt['images']['worker'], h.project+':worker'
    require(h.docker('image','inspect','--format','{{.Id}}',base_tag,capture=True) == base)
    tracked = h.command(['git','-C',str(h.sources['runner']),'ls-files','--','vardrrunner'],capture=True).splitlines()
    def python_source():
        return {Path(name).relative_to('vardrrunner').as_posix():digest((h.sources['runner']/name).read_bytes().replace(b'\r\n',b'\n')) for name in tracked if name.endswith('.py')}
    expected, measured = python_source(), _measure(h,base,'base')
    require(len(expected) == 80 and measured['python'] == expected)
    before = _defaults(h,base)
    platform = _platform(h,base)
    require(before[1]['User'] == '0:0' and not before[1]['OnBuild'] and not before[1]['Volumes'])
    rendered = render_boundary_wrapper(measured['files'][GATE])
    leaf = (TEMPLATES/'leaf.py').read_bytes().replace(b'\r\n',b'\n')
    dockerfile = (TEMPLATES/'Dockerfile.PROPOSAL').read_text().replace('\r\n','\n')
    require(digest(leaf) == LEAF_SHA and digest(dockerfile.encode()) == DOCKERFILE_SHA and dockerfile.count(OLD_BASE) == 2 and all(line.startswith(('FROM ','COPY ')) for line in dockerfile.splitlines()))
    generated = dockerfile.replace(OLD_BASE,base_tag)
    require(generated.replace(base_tag,OLD_BASE) == dockerfile)
    context = h.root/'boundary-image'; context.mkdir(mode=0o700)
    for name,data in {'wrapper.py':rendered,'leaf.py':leaf,'Dockerfile':generated.encode()}.items():
        path = context/name
        with path.open('xb') as stream: stream.write(data)
    image, _ = h.build('boundary-worker',context,file=context/'Dockerfile',extra=('--pull=false','--network','none'))
    observed = _measure(h,image,'derived')
    hashes = {OWNER:measured['files'][OWNER],GATE:digest(rendered),LIBEXEC:measured['files'][GATE],WRAPPER:digest(rendered),LEAF:LEAF_SHA}
    require(observed['python'] == expected == python_source() and observed['files'] == hashes and _defaults(h,image) == before and _platform(h,image) == platform)
    require(h.docker('image','inspect','--format','{{.Id}}',base_tag,capture=True) == base)
    for name, source in h.sources.items():
        require(h.command(['git','-C',str(source),'rev-parse','HEAD','HEAD^{tree}'],capture=True).splitlines() == [h.pins[name],h.receipt['source_trees'][name]])
        require(not h.command(['git','-C',str(source),'status','--porcelain','--untracked-files=no'],capture=True))
    recipe = dict(schema='vardr.nm2-fixed-fixture-linux-source/1',sources=dict(h.pins),source_trees=dict(h.receipt['source_trees']),base_image_id=base,template_sha256=TEMPLATE_SHA,rendered_wrapper_sha256=digest(rendered),genuine_gate_sha256=measured['files'][GATE],owner_sha256=measured['files'][OWNER],sdk_inventory_sha256=digest(canonical(expected)),defaults_sha256=digest(canonical(before)),copy_only=True,template_changed_field='ORIGINAL_SHA')
    q = dict(schema='vardr.nm2-fixture-image-byte-qualification/1',status='passed_fixture_image_byte_qualification',scope='fixture_image_byte_qualification_only',image=image,file_hashes=hashes,python_files=80,python_inventory_sha256=recipe['sdk_inventory_sha256'],runner_commit=SOURCES['runner'],gate_commit=SOURCES['gate'],source_recipe=recipe,source_before_after=True,native_startups=0,project_imports=False,registry_pull=False,publication=False,fixture_runtime_approval=False,fixture_only=True,genuine_gate_qualified_at_wrapper_path=False,
             image_defaults={'all_config_field_names_checked':True,'compared_non_env_fields':list(CONFIG_FIELDS),'identical':True,'environment_values_selected_or_output':False,'environment_preservation':'same base; COPY-only/no OnBuild/no ENV or RUN'})
    binding = binding_for_qualification(q,h.pins,h.receipt['source_trees'])
    data = canonical(q)
    path = h.root/'boundary-image-qualification.json'
    with path.open('xb') as stream: stream.write(data)
    path.chmod(0o600)
    return data, binding

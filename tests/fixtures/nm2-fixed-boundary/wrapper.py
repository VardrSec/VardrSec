#!/usr/local/bin/python -I
"""UNEXECUTED TEST-ONLY Gate wrapper; not the genuine Gate executable."""
import hashlib, json, os, signal, stat, subprocess, sys, time
from pathlib import Path

ORIGINAL = '/usr/local/libexec/vardrgate-57cfedfaf59b11cf626288c343f34a34c7b1df13'
ORIGINAL_SHA = 'cc08e48efe7c6a42bcb0bc02ec4fca7ec70c739451cfd54109064cc59e934ae7'
LEAF = '/opt/vardr-nm2-boundary/leaf.py'
CASES = {'nm2-c07-orphan-drain': 20, 'nm2-c09-loaded-authority': 20, 'nm2-c08-live-runner-loss': 20}
GUARD_REST = {'nm2-c07-orphan-drain': '53b011334dbd118b9e52ada4ea98a6a592bc57d1799c112064823d7a5db27d18', 'nm2-c08-live-runner-loss': '3681d4c927e7870e697a964c00de5f4944ae4912e88e5d1a130d193d4c9aac4e', 'nm2-c09-loaded-authority': 'ed6673566f7bafc72aa097793ef4dab4e8dd1a6fe1454324eaa62ea3531e8317'}
RUNS = Path('/home/runner/.vardrmap/runs')
NS = 1_000_000_000
boot = lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME)

def require(value):
    if not value: raise ValueError('fixture_refused')

def pairs(items):
    out = {}
    for name, value in items:
        require(name not in out); out[name] = value
    return out

def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8')

def decoded(data):
    require(type(data) is bytes and 0 < len(data) <= 131072)
    value = json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _: require(False))
    def depth(node,level=0):
        require(level <= 32)
        for child in node.values() if type(node) is dict else node if type(node) is list else (): depth(child,level+1)
    depth(value); return value

def derive_guard(raw,mode,self_sha):
    guard = decoded(raw)
    require(type(mode) is str and mode in GUARD_REST and type(guard) is dict)
    require(set(guard) == {'schema','profile','tool_sha256','case_hash','execution','credential_references','dispatches','max_http_dispatches'})
    require(type(self_sha) is str and len(self_sha) == 64 and guard['tool_sha256'] == self_sha)
    rest = {key:value for key,value in guard.items() if key != 'tool_sha256'}
    require(hashlib.sha256(encoded(rest)).hexdigest() == GUARD_REST[mode])
    child = {**guard,'tool_sha256':ORIGINAL_SHA}; data = encoded(child)
    require(len(data) <= 131072 and {key:value for key,value in child.items() if key != 'tool_sha256'} == rest)
    proof = {'schema':'vardr.nm2-fixed-guard-delegation/1','mode':mode,'changed_field':'tool_sha256','child_signed':False,
             'original_raw_sha256':hashlib.sha256(raw).hexdigest(),'original_plan_sha256':hashlib.sha256(encoded(guard)).hexdigest(),
             'child_guard_sha256':hashlib.sha256(data).hexdigest(),'guard_rest_sha256':GUARD_REST[mode]}
    return data,proof

def child_guard(root,mode,raw):
    data,proof = derive_guard(raw,mode,hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    for name,body in (('nm2-original-request-guard.json',raw),('nm2-child-request-guard.json',data),('nm2-guard-delegation.json',encoded(proof))):
        fd = os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as stream:
            require(stat.S_IMODE(os.fstat(stream.fileno()).st_mode) == 0o600)
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
    return root/'nm2-child-request-guard.json'

def document(path,*,raw=False):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 10001 and info.st_nlink == 1)
    require(info.st_size <= 131072 and not path.is_symlink())
    data = path.read_bytes(); value = decoded(data)
    return data if raw else value

def emit(root, mode, role, event, counters=None):
    with open('/proc/self/status', encoding='ascii') as stream:
        status = dict(line.strip().split(':', 1) for line in stream if ':' in line)
    caps = {name: status[name].strip() for name in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')}
    require(os.getresuid() == (10001,)*3 and os.getresgid() == (10001,)*3 and not os.getgroups())
    require(set(caps.values()) == {'0000000000000000'} and status['NoNewPrivs'].strip() == '1')
    try: os.fstat(3)
    except OSError as error:
        require(error.errno == 9)
    else: raise ValueError('fixture_fd3_present')
    data = {'schema':'vardr.nm2-fixed-boundary/1','mode':mode,'role':role,'event':event,
            'uid':list(os.getresuid()),'gid':list(os.getresgid()),'groups':[], 'capabilities':caps,
            'no_new_privs':True,'fd3_absent':True,'pid':os.getpid(),'ppid':os.getppid(),
            'pgrp':os.getpgrp(),'session':os.getsid(0),'boottime_ns':boot(),'utc_ns':time.time_ns(),
            'cpu_ns':time.process_time_ns(),'counters':counters}
    path = root / (mode+'.'+role+'.'+event+'.json')
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, sort_keys=True, separators=(',',':')); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())

def start_leaf(root, mode, beginning):
    return subprocess.Popen([sys.executable,'-I',LEAF,mode,str(root),str(beginning)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ready(root, mode, beginning):
    path = root / (mode+'.leaf.ready.json')
    while not path.exists():
        require(boot() < beginning+35*NS); time.sleep(.01)

def main():
    parent = os.getppid()
    args = sys.argv[1:]
    if args == ['version']:
        require(hashlib.sha256(Path(ORIGINAL).read_bytes()).hexdigest() == ORIGINAL_SHA)
        os.execv(ORIGINAL, [ORIGINAL,'version'])
    require(len(args) == 9 and args == ['run','--job',args[2],'--literal-job','--out',args[5],
                                      '--require-identity-preflight','--request-guard',args[8]])
    job, original_guard = document(args[2]), document(args[8],raw=True)
    guard = decoded(original_guard)
    require(type(job) is dict and set(job) == {'config'} and set(job['config']) == {'test_case','execution'})
    mode = job['config']['test_case']['id']; require(type(mode) is str and mode in CASES)
    execution = {'timeout_seconds':CASES[mode],'max_response_bytes':65536,'allow_private_targets':True}
    require(job['config']['execution'] == execution and guard['execution'] == execution)
    require(guard['schema'] == 'vardr.execution-plan/1' and guard['profile'] == 'gate-fixed-http/1')
    root = Path(args[5]).parent
    require(root.is_absolute() and not root.is_symlink() and root.resolve(strict=True) == root)
    require(root.parent == RUNS and root.stat().st_uid == 10001 and not Path(args[5]).exists())
    require(hashlib.sha256(Path(ORIGINAL).read_bytes()).hexdigest() == ORIGINAL_SHA)
    child_args = list(args); child_args[8] = str(child_guard(root,mode,original_guard))
    beginning = boot(); emit(root,mode,'wrapper','begin')
    loaded = mode == 'nm2-c09-loaded-authority'
    if loaded:
        leaf = start_leaf(root,mode,beginning); ready(root,mode,beginning)
        require(leaf.poll() is None)
    gate = subprocess.Popen([ORIGINAL,*child_args], stdin=subprocess.DEVNULL)
    while gate.poll() is None:
        require(boot() < beginning+35*NS); time.sleep(.01)
    require(gate.returncode == 0); emit(root,mode,'wrapper','gate-return')
    if mode == 'nm2-c08-live-runner-loss':
        require(parent > 1 and os.getppid() == parent)
        leaf = start_leaf(root,mode,beginning); ready(root,mode,beginning)
        witness = document(root / (mode+'.leaf.ready.json'))
        earliest = min(document(root / (mode+'.wrapper.gate-return.json'))['boottime_ns']+8*NS,beginning+35*NS)
        require(witness['pid'] == leaf.pid and witness['ppid'] == os.getpid() and leaf.poll() is None)
        emit(root,mode,'wrapper','parent-kill-intent')
        require(boot()+NS < earliest and leaf.poll() is None and os.getppid() == parent)
        os.kill(parent,signal.SIGKILL)
        emit(root,mode,'wrapper','parent-kill-returned')
        while boot() < beginning+35*NS:
            require(leaf.poll() is None); time.sleep(.02)
        return 125
    if loaded:
        while boot() < beginning+35*NS:
            require(leaf.poll() is None); time.sleep(.02)
        emit(root,mode,'wrapper','ceiling'); return 125
    child = os.fork()
    if child == 0:
        try:
            emit(root,mode,'intermediate','begin'); start_leaf(root,mode,beginning)
            ready(root,mode,beginning); emit(root,mode,'intermediate','exit'); os._exit(0)
        except BaseException: os._exit(125)
    while True:
        ended, status = os.waitpid(child,os.WNOHANG)
        if ended == child:
            require(status == 0); break
        require(ended == 0 and boot() < beginning+35*NS); time.sleep(.01)
    emit(root,mode,'wrapper','exit'); return 0

if __name__ == '__main__':
    try: result = main()
    except BaseException: result = 125
    os._exit(result)

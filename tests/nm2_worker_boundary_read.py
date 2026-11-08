"""Test-only readback in the existing ordinary helper, never worker exec."""
import hashlib, json, os, re, stat, sys
from pathlib import Path
from vardrrunner import config
from vardrrunner.journal import Journal
from vardrrunner.authorization import worker_persistent as persistent, codec
s = json.load(sys.stdin)
mode = s.get('mode')
assert mode is None or mode == 'nm2-c08-live-runner-loss'
assert set(s) == ({'run_id','engagement_id','job_id'} if mode is None else {'run_id','engagement_id','job_id','mode'}) and re.fullmatch("[a-f0-9]{32}",s["run_id"])
journal = Journal(config.journal_file()); run = journal.get(s["run_id"])
assert run is not None and run.job_id == s["job_id"] and run.engagement_id == s["engagement_id"]
folder = Path(run.run_dir)
assert folder == config.runs_dir()/run.run_id and folder.is_dir() and all(not p.is_symlink() for p in (folder,*folder.parents))
with journal._connection() as con:
    claim = con.execute("SELECT state,utc_anchor,mono_anchor,plan_sha256,case_sha256,tool_sha256,consumption_sent,consumption_acknowledged FROM managed_claim_intents WHERE run_id=?",(run.run_id,)).fetchone()
    attempt = con.execute("SELECT * FROM managed_persistent_attempts WHERE run_id=?",(run.run_id,)).fetchone()
    assert claim is not None and attempt is not None
    persistent._validate_attempt(con,attempt)
    local = {k:(json.loads(attempt[k]) if k in {"binding","completion","release_intent","release_ack"} and attempt[k] is not None else attempt[k]) for k in ("state","binding","completion","native_done_sha256","release_intent","release_ack","retired_from_state")}
guard_names = {"nm2-original-request-guard.json","nm2-child-request-guard.json","nm2-guard-delegation.json"}
files, records, guards = [], [], {}
marker = None
for path in sorted(folder.iterdir()):
    if mode is not None and path.name == mode+'.parent-kill-returned.byte':
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before = os.fstat(stream.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_uid == 10001 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == 1
            data = stream.read(2); after = os.fstat(stream.fileno())
            assert data == b'1' and all(getattr(before,k) == getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns'))
        marker = dict(size=1,sha256=hashlib.sha256(data).hexdigest(),post_signal_call_returned=True)
        continue
    boundary = (path.name.startswith(("nm2-c07-orphan-drain.","nm2-c09-loaded-authority.")) if mode is None else
                path.name in {mode+'.wrapper.begin.json',mode+'.wrapper.gate-return.json',mode+'.leaf.ready.json',mode+'.wrapper.parent-kill-intent.json'})
    if mode is not None and path.name.startswith(mode+'.'):
        assert boundary or path.name == mode+'.wrapper.parent-kill-returned.json'
    guard_file = path.name in guard_names
    if not boundary and not guard_file and path.name not in {"vardrgate_result.json","vardrgate_stopped_result.json"}: continue
    assert path.suffix == ".json" and len(records) < 12
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,"rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 10001
        assert not (boundary or guard_file) or stat.S_IMODE(before.st_mode) == 0o600
        bound = 4096 if boundary else 131072 if guard_file else 1024*1024
        assert 0 < before.st_size <= bound
        data = stream.read(bound+1); after = os.fstat(stream.fileno())
        assert len(data) == before.st_size and (before.st_ino,before.st_size,before.st_mtime_ns) == (after.st_ino,after.st_size,after.st_mtime_ns)
    if guard_file:
        value = codec.decoded(data,131072)
        guards[path.name] = dict(size=len(data),sha256=hashlib.sha256(data).hexdigest(),canonical_sha256=hashlib.sha256(codec.encoded(value)).hexdigest(),document=value)
    elif boundary:
        value = codec.decoded(data,4096)
        assert path.name == value["mode"]+"."+value["role"]+"."+value["event"]+".json"
        records.append(value)
    else: files.append(dict(name=path.name,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
print(json.dumps(dict(run_id=run.run_id,engagement_id=run.engagement_id,job_id=run.job_id,
    phase=run.phase.value,started_at=run.started_at,artifact_sha256=run.artifact_sha256,local_stop_requested=journal.stop_requested(run.run_id),
    claim=dict(claim),attempt=local,files=files,records=records,guards=guards,**({'marker':marker} if mode is not None else {}))))

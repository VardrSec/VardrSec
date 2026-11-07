"""Actual operation definitions in a pure world; no project/runtime imports.

Normal module integration remains a separate full-suite requirement. Only the
registration function's explicit peer-module import is replaced by its supplied
AST-extracted definition; validation/critical-section bodies are left intact.
"""
import ast
import contextlib
import copy
from dataclasses import dataclass, FrozenInstanceError
import hashlib
import importlib
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1]
RID = "11111111-1111-4111-8111-111111111111"
RUNNER = "22222222-2222-4222-8222-222222222222"


class Refused(ValueError):
    def __init__(self, *_args, registration_failure=None):
        super().__init__("worker_host_refused")
        self.registration_failure = registration_failure


def require(value):
    if not value:
        raise Refused()


class VirtualPath:
    """No filesystem operation; all paths are closed synthetic identities."""
    files = {}
    def __init__(self, value): self.value = value.value if isinstance(value, VirtualPath) else str(value)
    def __truediv__(self, other): return VirtualPath(self.value + "/" + other)
    def __str__(self): return self.value
    def __eq__(self, other): return type(other) is VirtualPath and self.value == other.value
    def __hash__(self): return hash(self.value)
    def exists(self): return self.value in self.files
    def is_absolute(self): return True
    def is_dir(self): return True
    def resolve(self, strict=False): return self


def actual_definitions(filename, selected, namespace, *, record_methods=None):
    tree = ast.parse((SOURCE / filename).read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        name = getattr(node, "name", None)
        if isinstance(node, ast.Assign) and any(isinstance(t,ast.Name) and t.id == "_OPERATION_PROOF" for t in node.targets):
            nodes.append(node)
        elif name in selected:
            if name == "HostRecords":
                node = copy.deepcopy(node)
                node.body = [item for item in node.body if getattr(item,"name",None) in record_methods]
            if name == "register_runtime":
                class SuppliedPeer(ast.NodeTransformer):
                    def visit_Import(self, item):
                        assert filename == "worker_host.py" and [n.name for n in item.names] == ["worker_host_persistent"]
                        return None
                node = SuppliedPeer().visit(copy.deepcopy(node))
            nodes.append(node)
    assert {getattr(n,"name",None) for n in nodes} >= set(selected)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])), str(SOURCE/filename), "exec"),namespace)


class World:
    def __init__(self):
        self.events, self.depth, self.thread, self.fail = [], 0, 7, None
        self.error = None
        self.close_error = None
        self.acquisitions = self.releases = 0
        self.sequence = {}
        VirtualPath.files = {}
        @contextlib.contextmanager
        def installation_lock(path):
            self.acquisitions += 1
            if self.depth:
                raise ValueError("synthetic_busy")
            self.depth = 1
            self.events.append(("lock",str(path)))
            try: yield
            finally:
                self.depth = 0
                self.releases += 1
                self.events.append(("unlock",str(path)))
                if self.close_error is not None:
                    assert self.records._HostRecords__operation is None
                    raise self.close_error
        self.updater = SimpleNamespace(installation_lock=installation_lock, STATE=".update-state.json")
        g = {"__name__":__name__,"contextmanager":contextlib.contextmanager,"ExitStack":contextlib.ExitStack,"dataclass":dataclass,
            "Path":VirtualPath,"require":require,"HostRefused":Refused,
            "registration_diagnostic":lambda _error:None,"updater":self.updater,
            "threading":SimpleNamespace(get_ident=lambda:self.thread)}
        actual_definitions("worker_host.py",{"_HostOperation","HostRecords"},g,
            record_methods={"_require_operation","operation","locked"})
        self.operation_type, self.record_type = g["_HostOperation"], g["HostRecords"]
        self.records = self.record()
        self.identity = SimpleNamespace(container_id="a"*64,image_id="sha256:"+"b"*64,project="owned-project")
        world = self
        class Client:
            def __init__(self,*_args): pass
            def pin(self): return {"base_url":"https://map.example","ca_file":"synthetic-ca"}
        class Session:
            def __init__(self,client): self.client = client
            def register(self, runtime_id, registration):
                world.event("request")
                world.request = (runtime_id,copy.deepcopy(registration))
                return {"ack":"synthetic", "runtime_sha256":"e"*64}
        class Identity: pass
        self.identity = Identity()
        self.identity.container_id, self.identity.image_id, self.identity.project = "a"*64,"sha256:"+"b"*64,"owned-project"
        class Observer:
            protocol, max_attempts = "persistent-v3", None
            context, layout = "synthetic-context", SimpleNamespace(state_volume="state")
            def __init__(self,*_args,**_kwargs): pass
            def capture_running(self,**_kwargs): world.event("capture"); return world.identity
        self.client, self.session = Client(), None
        self.session = Session(self.client)
        self.observer = Observer()
        self.runtime = SimpleNamespace(RuntimeIdentity=Identity,LocalDocker=Observer,
            WorkerLayout=lambda *args:SimpleNamespace(values=args))
        class CaptureRefused(ValueError):
            checkpoint = "incarnation_recheck"
        self.runtime.RuntimeRefused = CaptureRefused
        def step(_checkpoint): return contextlib.nullcontext()
        self.host = SimpleNamespace(HostClient=Client,OwnerSession=Session,HostRefused=Refused,
            require=require,_uuid=lambda value:value,_identifier=lambda value:require(bool(value)),
            _url=lambda *_args,**_kwargs:None,_CAPABILITY=b"synthetic-prefix",
            registration_step=step,registration_diagnostic=lambda error:None)
        self.host.custody = SimpleNamespace(SecretRefused=type("SecretRefused",(Exception,),{}))
        def ack(_record,reply): self.event("ack"); return reply
        self.host._admission = ack
        pg = {"__name__":__name__,"host":self.host,"runtime":self.runtime,
            "limits":lambda value:value,"registration":lambda value:value,"admission":ack,
            "REPORTING_AUTHORITY":{"purpose":"worker-stop-only","expires_at":None},
            "secrets":SimpleNamespace(token_hex=lambda _n:"d"*64),"hashlib":hashlib,
            "asdict":lambda value:dict(vars(value))}
        actual_definitions("worker_host_persistent.py",{"register_runtime"},pg)
        self.persistent_register = pg["register_runtime"]
        hg = {"__name__":__name__,"require":require,"HostClient":Client,"OwnerSession":Session,
            "runtime":self.runtime,"_url":self.host._url,"_identifier":self.host._identifier,
            "_uuid":lambda value:value,"asdict":pg["asdict"],"secrets":pg["secrets"],
            "hashlib":hashlib,"_CAPABILITY":self.host._CAPABILITY,"_admission":ack,
            "HostRefused":Refused,"worker_host_persistent":SimpleNamespace(register_runtime=self.persistent_register)}
        actual_definitions("worker_host.py",{"register_runtime"},hg)
        self.register = hg["register_runtime"]
        self.host.register_runtime = self.register
        self.host._client = lambda *_args:None
        self.host._observer = lambda *_args:None
        self.host.canonical = lambda value:repr(value).encode()
        self.persistent_namespace = pg
        self.host_namespace = hg
        self.cli_args = SimpleNamespace(protocol="persistent-v3",max_attempts=None,idle_timeout_seconds=None,
            expires_in=None,container_id=self.identity.container_id,image_id=self.identity.image_id,
            project=self.identity.project,runner_id=RUNNER,public_trust="trust-input",admission_source="public",
            context="synthetic-context",trust_source="trust",state_volume="state",readiness_volume="ready",
            api_url="https://map.example",ca="ca",private_root="private",origin="https://issuer.example",
            enrollment_id="enrolled",runtime_id=RID)
        def owner(client,args):
            @contextlib.contextmanager
            def owned():
                self.event("auth")
                # Client construction is exact but this pure model needs one identity.
                session = Session(client)
                yield session
                self.event("logout")
            return owned()
        def publish(path,data):
            self.event("publish_"+str(path).rsplit("/",1)[-1])
            VirtualPath.files[str(path)] = data
        cg = {"__name__":__name__,"require":require,"Path":VirtualPath,"re":re,"runtime":self.runtime,
            "host":self.host,"runtime_id":lambda value:value,"public_trust":lambda path:b"[]",
            "records_for":lambda *_args:self.records,"owner":owner,"publish_public":publish,
            "updater":self.updater,"asdict":pg["asdict"],
            "persistent_limits":None}
        # enable's existing persistent import is a supplied pure limits namespace.
        class SupplyLimits(ast.NodeTransformer):
            def visit_Import(self,node):
                assert [a.name for a in node.names] == ["worker_host_persistent"]
                return None
        tree = ast.parse((SOURCE/"worker_cli.py").read_text(encoding="utf-8"))
        nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef)
            and n.name in {"_enable_setup", "_enable_owned", "enable"}]
        assert {n.name for n in nodes} == {"_enable_setup", "_enable_owned", "enable"}
        cg["worker_host_persistent"] = SimpleNamespace(limits=lambda value:value)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[SupplyLimits().visit(node) for node in nodes],type_ignores=[])),
            str(SOURCE/"worker_cli.py"),"exec"),cg)
        self.enable = cg["enable"]
        self.enable_setup = cg["_enable_setup"]
        self.enable_owned = cg["_enable_owned"]
        self.cli_globals = cg
        cg["CLIRefused"] = type("CLIRefused",(ValueError,),{})
        for item in tree.body:
            if isinstance(item,ast.Assign) and any(isinstance(t,ast.Name) and t.id in {"CAPTURE_FAILURE_PHASES","FAILURE_PHASES"} for t in item.targets):
                exec(compile(ast.Module(body=[item],type_ignores=[]),str(SOURCE/"worker_cli.py"),"exec"),cg)
        actual_definitions("worker_cli.py",{"failure_diagnostic"},cg)
        self.diagnostic = cg["failure_diagnostic"]

    def event(self,name):
        self.sequence[name] = self.sequence.get(name,0)+1
        self.events.append((name,self.depth))
        if self.fail in {name,name+"#"+str(self.sequence[name])}:
            raise self.error if self.error is not None else RuntimeError("synthetic_failure")

    def record(self):
        record = object.__new__(self.record_type)
        record._HostRecords__operation = None
        record.installation, record.private_root = VirtualPath("installation"),VirtualPath("private")
        record._directory = lambda:self.event("custody_directory")
        record.outside_mounts = lambda *_args:self.event("outside_mounts")
        record._path = lambda _runtime_id:VirtualPath("host-record")
        secrets = {}
        record.backend = SimpleNamespace(read=lambda key:secrets.get(key),create=lambda key,value:secrets.__setitem__(key,value))
        store = {}
        def write(value,create=False):
            name = "write_initial" if create else "write_"+value["registration_state"]
            self.event(name)
            store[value["runtime_id"]] = copy.deepcopy(value)
        record.write, record.read = write,lambda runtime_id:copy.deepcopy(store[runtime_id])
        return record

    def register_args(self,protocol="persistent-v3"):
        options = {"issuer_origin":"https://issuer.example","enrollment_id":"enrolled","runner_id":RUNNER,
            "identity":self.identity,"observer":self.observer,"runtime_id":RID,"protocol":protocol}
        if protocol == "persistent-v3": options["limits"] = {"max_attempts":None,"idle_timeout_seconds":None}
        else:
            options["expires_in_seconds"] = 900
            self.observer.protocol = protocol
            self.observer.max_attempts = 2 if protocol == "finite-v2" else None
            options["max_attempts"] = self.observer.max_attempts
        return options


class Operations(unittest.TestCase):
    def test_one_lock_borrow_preserves_lifetime_and_legacy_none_yield(self):
        w = World()
        with w.records.operation() as operation:
            with w.records.operation(operation) as borrowed:
                self.assertIs(operation,borrowed)
                self.assertEqual(w.depth,1)
            self.assertEqual(w.releases,0)
        self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
        with self.assertRaises(Refused):
            with w.records.operation(operation): pass
        with w.records.locked() as ordinary: self.assertIsNone(ordinary)
        self.assertEqual((w.acquisitions,w.releases),(2,2))

    def test_foreign_copied_stale_thread_or_retargeted_capabilities_refuse_before_io(self):
        w = World()
        with w.records.operation() as operation:
            before = len(w.events)
            for value in (True,object(),copy.copy(operation)):
                with self.subTest(kind=type(value).__name__),self.assertRaises(Refused):
                    with w.records.operation(value): pass
            other = w.record()
            with self.assertRaises(Refused):
                with other.operation(operation): pass
            w.thread += 1
            with self.assertRaises(Refused):
                with w.records.operation(operation): pass
            w.thread -= 1
            original = w.records.installation
            w.records.installation = VirtualPath("different-installation")
            with self.assertRaises(Refused):
                with w.records.operation(operation): pass
            w.records.installation = original
            self.assertEqual(len(w.events),before)
            self.assertEqual(w.acquisitions,1)
            with self.assertRaises(FrozenInstanceError): operation._thread = w.thread+1

    def test_exception_or_busy_lock_never_leaves_live_token_or_releases_anothers_lock(self):
        w = World()
        error = RuntimeError("synthetic_failure")
        with self.assertRaises(RuntimeError) as caught:
            with w.records.operation() as operation: raise error
        self.assertIs(caught.exception,error)
        self.assertEqual(w.depth,0)
        with self.assertRaises(Refused): w.records._require_operation(operation)
        with w.records.operation():
            other = w.record()
            with self.assertRaises(Refused):
                with other.operation(): pass
            self.assertEqual(w.depth,1)
        self.assertEqual(w.releases,2)

    def test_all_three_registration_modes_own_one_lock_or_borrow_one_exact_scope(self):
        for protocol in ("legacy-v1","finite-v2","persistent-v3"):
            for borrowing in (False,True):
                with self.subTest(protocol=protocol,borrowing=borrowing):
                    w = World()
                    options = w.register_args(protocol)
                    if borrowing:
                        with w.records.operation() as operation:
                            w.register(w.client,w.records,w.session,**options,operation=operation)
                    else: w.register(w.client,w.records,w.session,**options)
                    self.assertEqual((w.acquisitions,w.releases),(1,1))
                    self.assertEqual(w.request[0],RID)
                    self.assertEqual(w.sequence["request"],1)
                    self.assertTrue(all(depth == 1 for event,depth in w.events if event in {
                        "capture","outside_mounts","request","ack","write_initial","write_acknowledged"}))

    def test_actual_enable_auth_registration_recapture_and_publication_share_one_lock(self):
        w = World()
        result = w.enable(VirtualPath("installation"),w.cli_args)
        self.assertEqual(result["state"],"enabled")
        self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
        names = [event for event,_ in w.events]
        self.assertEqual([name for name in names if name in {"request","logout","publish_trust.json","publish_admission.json"}],
            ["request","logout","publish_trust.json","publish_admission.json"])
        self.assertEqual(w.sequence["capture"],3)
        self.assertEqual(w.sequence["request"],1)
        self.assertTrue(all(depth == 1 for event,depth in w.events if event not in {"lock","unlock"}))

    def test_enable_exception_at_each_existing_mutation_boundary_releases_exactly_once(self):
        for point in ("auth","capture#1","capture#2","request","ack","write_initial",
                "write_acknowledged","capture#3","outside_mounts#2","publish_trust.json","publish_admission.json"):
            with self.subTest(point=point):
                w = World()
                w.fail = point
                with self.assertRaises((Refused,RuntimeError)): w.enable(VirtualPath("installation"),w.cli_args)
                self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
                self.assertLessEqual(w.sequence.get("request",0),1)
                self.assertIsNone(w.records._HostRecords__operation)

    def test_invalid_registration_and_foreign_operation_never_reach_custody_or_secret_io(self):
        w = World()
        options = w.register_args("finite-v2")
        options["expires_in_seconds"] = 1
        with self.assertRaises(Refused): w.register(w.client,w.records,w.session,**options)
        self.assertEqual(w.acquisitions,0)
        with w.records.operation() as operation:
            other = w.record()
            before = list(w.events)
            with self.assertRaises(Refused): w.register(w.client,other,w.session,**w.register_args(),operation=operation)
            self.assertEqual(w.events,before)

    def test_capture_and_local_io_errors_keep_original_identity_and_fixed_diagnostics(self):
        for kind,code,phase in (("capture","runtime_refused","enable_capture_incarnation_recheck"),
                ("io","local_io_failed","enable_capture")):
            w = World()
            w.fail = "capture#1"
            w.error = w.runtime.RuntimeRefused("synthetic") if kind == "capture" else OSError("synthetic")
            with self.subTest(kind=kind),self.assertRaises(type(w.error)) as caught:
                w.enable(VirtualPath("installation"),w.cli_args)
            self.assertIs(caught.exception,w.error)
            self.assertEqual(w.diagnostic(w.cli_args,caught.exception),{"failure_phase":phase,"failure_code":code})
            self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
        w = World()
        with self.assertRaises(Refused):
            with w.records.locked(): raise OSError("synthetic")
        self.assertEqual(w.releases,1)

    def test_default_v3_delegate_omits_operation_keyword_and_owned_entry_error_clears_lock(self):
        w = World()
        captured = []
        w.host_namespace["worker_host_persistent"].register_runtime = lambda *args,**kwargs:captured.append(kwargs)
        w.register(w.client,w.records,w.session,**w.register_args())
        self.assertNotIn("operation",captured[0])
        self.assertEqual(w.acquisitions,0)
        with w.records.operation() as operation:
            w.register(w.client,w.records,w.session,**w.register_args(),operation=operation)
            self.assertIs(captured[1]["operation"],operation)
        w = World()
        w.fail,w.error = "custody_directory",OSError("synthetic")
        with self.assertRaises(Refused):
            with w.records.operation(): pass
        self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
        self.assertIsNone(w.records._HostRecords__operation)

    def test_owned_exit_failures_translate_once_after_invalidation_with_or_without_body_failure(self):
        for body in (None,RuntimeError("synthetic-body"),OSError("synthetic-body")):
            for close in (OSError("synthetic-close"),ValueError("synthetic-close")):
                with self.subTest(body=type(body).__name__,close=type(close).__name__):
                    w = World()
                    w.close_error = close
                    with self.assertRaises(Refused):
                        with w.records.operation() as operation:
                            if body is not None: raise body
                    self.assertEqual((w.acquisitions,w.releases,w.depth),(1,1,0))
                    with self.assertRaises(Refused): w.records._require_operation(operation)

    def test_borrowed_entry_failure_keeps_outer_owner_but_never_enters_body(self):
        w = World()
        with w.records.operation() as operation:
            w.fail,w.error = "custody_directory#2",OSError("synthetic-borrow")
            with self.assertRaises(Refused):
                with w.records.operation(operation): self.fail("borrow_body_entered")
            self.assertEqual((w.acquisitions,w.releases,w.depth),(1,0,1))
            w.records._require_operation(operation)
        self.assertEqual(w.releases,1)


    def test_private_enable_uses_existing_owner_and_public_reply_follows_release(self):
        w = World()
        setup = w.enable_setup(w.cli_args)
        with w.records.operation() as operation:
            admission, identity = w.enable_owned(w.cli_args, w.records, operation, setup)
            self.assertIs(identity, w.identity)
            self.assertEqual(admission["runtime_sha256"], "e" * 64)
            self.assertEqual((w.acquisitions, w.releases, w.depth), (1, 0, 1))
            w.records._require_operation(operation)
        self.assertEqual((w.acquisitions, w.releases, w.depth), (1, 1, 0))
        w = World()
        original = w.cli_globals["asdict"]
        def after_release(value):
            self.assertEqual(w.depth, 0)
            self.assertEqual(w.releases, 1)
            return original(value)
        w.cli_globals["asdict"] = after_release
        self.assertEqual(w.enable(VirtualPath("installation"), w.cli_args)["state"], "enabled")

    def test_private_enable_rejects_invalid_owner_before_unpack_or_effect(self):
        w = World()
        def refused(records, operation):
            before = list(w.events)
            with self.assertRaises(Refused):
                w.enable_owned(None, records, operation, None)
            self.assertEqual(w.events, before)
        refused(w.records, None)
        refused(w.records, True)
        refused(w.records, object())
        with w.records.operation() as operation:
            refused(w.records, copy.copy(operation))
            refused(w.record(), operation)
            w.thread += 1
            refused(w.records, operation)
            w.thread -= 1
            w.records._require_operation(operation)
        refused(w.records, operation)
        self.assertEqual(w.sequence.get("request", 0), 0)
        self.assertEqual(w.sequence.get("auth", 0), 0)

class ActualOperations(unittest.TestCase):
    """Normal full-suite coverage of real modules; pure runner excludes this class."""
    @staticmethod
    def modules():
        # Deliberately deferred: importing this test for the AST-only suite never
        # imports a project, credential backend or runtime module.
        return importlib.import_module("worker_host"),importlib.import_module("worker_cli")

    @staticmethod
    def record(host,temporary):
        records = object.__new__(host.HostRecords)
        records.installation,records.private_root = temporary,temporary/"private"
        records._HostRecords__operation = None
        records._directory = Mock()
        return records

    def test_real_hostrecords_token_owner_thread_lifetime_and_one_underlying_lock(self):
        host,_ = self.modules()
        with tempfile.TemporaryDirectory() as temporary:
            records = self.record(host,Path(temporary))
            depth,counts = [0],[0,0]
            @contextlib.contextmanager
            def lock(_installation):
                self.assertEqual(depth[0],0)
                depth[0]=1; counts[0]+=1
                try: yield
                finally:
                    self.assertIsNone(records._HostRecords__operation)
                    depth[0]=0; counts[1]+=1
            with patch.object(host.updater,"installation_lock",side_effect=lock):
                with records.operation() as operation:
                    with records.locked(operation=operation): self.assertEqual(depth[0],1)
                    for invalid in (True,copy.copy(operation)):
                        with self.assertRaises(host.HostRefused):
                            with records.operation(invalid): pass
                    with patch.object(host.threading,"get_ident",return_value=operation._thread+1):
                        with self.assertRaises(host.HostRefused):
                            with records.operation(operation): pass
                    self.assertEqual(counts,[1,0])
                with self.assertRaises(host.HostRefused):
                    with records.operation(operation): pass
                with records.locked() as value: self.assertIsNone(value)
            self.assertEqual(counts,[2,2])

    def test_real_enable_borrows_real_token_for_registration_and_publication(self):
        host,cli = self.modules()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            public=root/"public"; public.mkdir()
            records=self.record(host,root)
            identity=cli.runtime.RuntimeIdentity("owned","a"*64,"sha256:"+"b"*64,
                "owned-project","2026-11-06T02:00:00Z","c"*64)
            observer=Mock(); observer.capture_running.return_value=identity
            admission={"runtime_sha256":"e"*64}
            records.read=Mock(return_value={"registration_state":"acknowledged","admission":admission})
            records.outside_mounts=Mock()
            depth,counts,order=[0],[0,0],[]
            @contextlib.contextmanager
            def lock(_installation):
                self.assertEqual(depth[0],0)
                depth[0]=1; counts[0]+=1
                try: yield
                finally:
                    self.assertIsNone(records._HostRecords__operation)
                    depth[0]=0; counts[1]+=1
            args=SimpleNamespace(protocol="persistent-v3",max_attempts=None,idle_timeout_seconds=None,
                expires_in=None,container_id=identity.container_id,image_id=identity.image_id,project=identity.project,
                runner_id=RUNNER,public_trust=str(root/"trust-input.json"),admission_source=str(public),
                context="synthetic",trust_source=str(root/"trust"),state_volume="state",readiness_volume="ready",
                api_url="https://map.example",ca=str(root/"ca"),private_root=str(root/"private"),
                origin="https://issuer.example",enrollment_id="enrolled",runtime_id=RID)
            def registered(*positional,**kwargs):
                self.assertIs(positional[1],records)
                operation=kwargs["operation"]
                with records.locked(operation=operation):
                    self.assertEqual(depth[0],1)
                    records._require_operation(operation)
                    order.append("register")
                return admission
            def publish(path,_data):
                self.assertEqual(depth[0],1)
                records._require_operation(records._HostRecords__operation)
                order.append(path.name)
            with patch.object(host.updater,"installation_lock",side_effect=lock), \
                patch.object(cli,"records_for",return_value=records), \
                patch.object(cli,"public_trust",return_value=b"[]"), \
                patch.object(cli.runtime,"LocalDocker",return_value=observer), \
                patch.object(cli.host,"HostClient",return_value=Mock()), \
                patch.object(cli,"owner",return_value=contextlib.nullcontext(Mock())), \
                patch.object(cli.host,"register_runtime",side_effect=registered), \
                patch.object(cli.host,"_client"),patch.object(cli.host,"_observer"), \
                patch.object(cli,"publish_public",side_effect=publish):
                result=cli.enable(root,args)
            self.assertEqual(result["state"],"enabled")
            self.assertEqual(order,["register","trust.json","admission.json"])
            self.assertEqual((counts,depth),([1,1],[0]))
            self.assertEqual(observer.capture_running.call_count,2)

    def test_real_module_close_failure_normalization_and_successful_close_body_identity(self):
        host,_=self.modules()
        with tempfile.TemporaryDirectory() as temporary:
            for body in (None,OSError("body"),ValueError("body")):
                for closing in (False,True):
                    records=self.record(host,Path(temporary))
                    count=[0]
                    @contextlib.contextmanager
                    def lock(_installation):
                        try: yield
                        finally:
                            count[0]+=1
                            self.assertIsNone(records._HostRecords__operation)
                            if closing: raise OSError("close")
                    with self.subTest(body=type(body).__name__,closing=closing), \
                            patch.object(host.updater,"installation_lock",side_effect=lock):
                        if closing:
                            with self.assertRaises(host.HostRefused):
                                with records.operation():
                                    if body is not None: raise body
                        elif body is not None:
                            with self.assertRaises(type(body)) as caught:
                                with records.operation(): raise body
                            self.assertIs(caught.exception,body)
                        else:
                            with records.operation(): pass
                        self.assertEqual(count,[1])


    def test_real_private_enable_keeps_exact_owner_and_never_calls_public_enable(self):
        host, cli = self.modules()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / "public"
            public.mkdir()
            records = self.record(host, root)
            identity = cli.runtime.RuntimeIdentity("owned", "a" * 64, "sha256:" + "b" * 64,
                "owned-project", "2026-11-06T02:00:00Z", "c" * 64)
            observer = Mock()
            observer.capture_running.return_value = identity
            client, session = Mock(), Mock()
            admission = {"runtime_sha256": "e" * 64}
            records.read = Mock(return_value={"registration_state": "acknowledged", "admission": admission})
            records.outside_mounts = Mock()
            args = SimpleNamespace(runtime_id=RID, container_id=identity.container_id,
                image_id=identity.image_id, project=identity.project, origin="https://issuer.example",
                enrollment_id="enrolled", runner_id=RUNNER)
            setup = (observer, client, public, b"[]", {"protocol": "persistent-v3", "limits": {
                "max_attempts": None, "idle_timeout_seconds": None}})
            counts, order = [0, 0], []
            @contextlib.contextmanager
            def lock(_installation):
                counts[0] += 1
                try:
                    yield
                finally:
                    self.assertIsNone(records._HostRecords__operation)
                    counts[1] += 1
            def registered(*positional, **kwargs):
                self.assertEqual(positional, (client, records, session))
                self.assertIs(kwargs["operation"], operation)
                records._require_operation(operation)
                order.append("register")
                return admission
            def publish(path, _data):
                records._require_operation(operation)
                self.assertEqual(counts, [1, 0])
                order.append(path.name)
            with patch.object(host.updater, "installation_lock", side_effect=lock), \
                    patch.object(cli, "enable", side_effect=AssertionError("nested_public_enable")), \
                    patch.object(cli, "records_for", side_effect=AssertionError("new_records")), \
                    patch.object(cli, "owner", return_value=contextlib.nullcontext(session)), \
                    patch.object(cli.host, "register_runtime", side_effect=registered), \
                    patch.object(cli.host, "_client"), patch.object(cli.host, "_observer"), \
                    patch.object(cli, "publish_public", side_effect=publish):
                with records.operation() as operation:
                    result = cli._enable_owned(args, records, operation, setup)
                    self.assertEqual(result, (admission, identity))
                    self.assertEqual(counts, [1, 0])
                    records._require_operation(operation)
            self.assertEqual(counts, [1, 1])
            self.assertEqual(order, ["register", "trust.json", "admission.json"])
            self.assertEqual(observer.capture_running.call_count, 2)

    def test_real_private_enable_rejects_none_foreign_copied_thread_and_stale_tokens(self):
        host, cli = self.modules()
        with tempfile.TemporaryDirectory() as temporary:
            records = self.record(host, Path(temporary))
            other = self.record(host, Path(temporary))
            counts = [0, 0]
            @contextlib.contextmanager
            def lock(_installation):
                counts[0] += 1
                try:
                    yield
                finally:
                    counts[1] += 1
            def refused(selected, operation):
                with self.assertRaises(host.HostRefused):
                    cli._enable_owned(None, selected, operation, None)
            with patch.object(host.updater, "installation_lock", side_effect=lock), \
                    patch.object(cli, "owner") as owner, \
                    patch.object(cli.host, "register_runtime") as register, \
                    patch.object(cli, "publish_public") as publish, \
                    patch.object(cli.runtime.LocalDocker, "capture_running") as capture:
                refused(records, None)
                refused(records, True)
                refused(records, object())
                with records.operation() as operation:
                    refused(records, copy.copy(operation))
                    refused(other, operation)
                    with patch.object(host.threading, "get_ident", return_value=operation._thread + 1):
                        refused(records, operation)
                    records._require_operation(operation)
                refused(records, operation)
                for effect in (owner, register, publish, capture):
                    effect.assert_not_called()
            self.assertEqual(counts, [1, 1])

if __name__ == "__main__":
    unittest.main()

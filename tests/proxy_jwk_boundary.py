"""Review the shipped proxy boundary using bounded, temporary loopback fixtures."""

import argparse
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def handlers(value):
    if isinstance(value, dict):
        if "handler" in value:
            yield value
        for child in value.values():
            yield from handlers(child)
    elif isinstance(value, list):
        for child in value:
            yield from handlers(child)


def validate(config):
    if config.get("admin", {}).get("disabled") is not True:
        raise ValueError("The assessed proxy requires its admin API disabled")
    apps = config.get("apps", {})
    if set(apps) != {"http", "pki", "tls"}:
        raise ValueError("Unreviewed proxy applications")
    authorities = apps["pki"].get("certificate_authorities", {})
    if (
        set(authorities) != {"local"}
        or set(authorities["local"]) != {"install_trust"}
        or authorities["local"]["install_trust"] is not False
    ):
        raise ValueError(
            "The fixture must never install host trust or load operator CA keys"
        )
    if set(apps["tls"]) != {"automation"}:
        raise ValueError("Unreviewed TLS configuration or certificate loaders")
    policies = apps["tls"].get("automation", {}).get("policies", [])
    if not policies or any(
        p.get("issuers") != [{"module": "internal"}] for p in policies
    ):
        raise ValueError("Only the reviewed internal TLS issuer is allowed")
    http = apps["http"]
    found = list(handlers(http))
    if not found or any(
        h["handler"] not in {"subroute", "rewrite", "reverse_proxy"} for h in found
    ):
        raise ValueError("Unreviewed HTTP handler, including a possible JWK ingress")
    upstreams = {
        u["dial"]
        for h in found
        if h["handler"] == "reverse_proxy"
        for u in h.get("upstreams", [])
    }
    if upstreams != {"api:8000", "web:3000"}:
        raise ValueError("Unreviewed proxy upstreams")


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        encoded = json.dumps(
            {
                "path": self.path,
                "sha256": hashlib.sha256(body).hexdigest(),
                "authorization_sha256": hashlib.sha256(
                    self.headers.get("Authorization", "").encode()
                ).hexdigest(),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_):
        pass


def wait_for_tls(process, case, listener):
    certificate = case / "storage/pki/authorities/local/root.crt"
    deadline = time.monotonic() + 30
    while process.poll() is None and time.monotonic() < deadline:
        try:
            if certificate.exists():
                context = ssl.create_default_context(cafile=str(certificate))
                with socket.create_connection(
                    ("127.0.0.1", listener), timeout=0.5
                ) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost"):
                        return context
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(
        "Verified fixture TLS did not become ready: "
        + (case / "log.txt").read_text(encoding="utf-8")[-4000:]
    )


def post_json(url, body, context):
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/jose+json",
            "Authorization": bearer(body),
        },
    )
    try:
        client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        with client.open(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.load(error)


def bearer(body):
    fields = json.loads(body)
    return "Bearer " + ".".join(
        fields[key] for key in ("protected", "payload", "signature")
    )


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def check(caddy, caddyfile, work):
    work.mkdir(parents=True, exist_ok=True)
    work = work.resolve()
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    version = subprocess.run(
        [str(caddy), "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=flags,
    ).stdout.split()[0]
    if version != "v2.11.7":
        raise ValueError(
            "Proxy version changed; reassess the JWK source paths before extending this finding"
        )
    with tempfile.TemporaryDirectory(prefix="jwk-fixture-", dir=work) as temporary:
        root = Path(temporary).resolve()
        assert root.is_relative_to(work)
        env = {
            **os.environ,
            "HTTPS_PORT": "8443",
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_CONFIG_HOME": str(root / "config"),
        }
        env.pop("GODEBUG", None)
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        result = subprocess.run(
            [str(caddy), "adapt", "--config", str(caddyfile), "--adapter", "caddyfile"],
            env=env,
            check=True,
            capture_output=True,
            timeout=30,
            creationflags=flags,
        )
        config = json.loads(result.stdout)
        validate(config)
        receipt = {
            "schema_version": 1,
            "caddy_version": version,
            "binary_sha256": hashlib.sha256(caddy.read_bytes()).hexdigest(),
            "caddyfile_sha256": hashlib.sha256(caddyfile.read_bytes()).hexdigest(),
            "shipped_forwarded": [],
            "control": {},
            "system_trust_modified": False,
        }
        backend = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            for control in (False, True):
                case = root / ("control" if control else "shipped")
                case.mkdir()
                current = copy.deepcopy(config)
                listener = port()
                current["storage"] = {
                    "module": "file_system",
                    "root": str(case / "storage"),
                }
                for server in current["apps"]["http"]["servers"].values():
                    server["listen"] = [f"127.0.0.1:{listener}"]
                    for h in handlers(server):
                        if h["handler"] == "reverse_proxy":
                            h["upstreams"] = [
                                {"dial": f"127.0.0.1:{backend.server_port}"}
                            ]
                    if control:
                        server["routes"].insert(
                            0,
                            {
                                "match": [{"path": ["/acme/*"]}],
                                "handle": [{"handler": "acme_server"}],
                            },
                        )
                path = case / "caddy.json"
                path.write_text(json.dumps(current), encoding="utf-8")
                runtime = {
                    **env,
                    "XDG_DATA_HOME": str(case / "data"),
                    "XDG_CONFIG_HOME": str(case / "config"),
                }
                with (case / "log.txt").open("wb") as log:
                    process = subprocess.Popen(
                        [str(caddy), "run", "--config", str(path)],
                        env=runtime,
                        cwd=case,
                        stdout=log,
                        stderr=log,
                        creationflags=flags,
                    )
                    try:
                        context = wait_for_tls(process, case, listener)
                        header = {
                            "alg": "RS256",
                            "nonce": "fixture-nonce",
                            "url": f"https://localhost:{listener}/acme/local/new-account",
                            "jwk": {
                                "kty": "RSA",
                                "n": "AQ",
                                "e": "Aw",
                                "d": "AQ",
                                "p": "Aw",
                                "q": "BQ",
                            },
                        }
                        protected = b64(json.dumps(header).encode())
                        body = json.dumps(
                            {
                                "protected": protected,
                                "payload": "e30",
                                "signature": "AA",
                            }
                        ).encode()
                        for route in (
                            ["/acme/local/new-account"]
                            if control
                            else [
                                "/acme/local/new-account",
                                "/backend/acme/local/new-account",
                            ]
                        ):
                            status, parsed = post_json(
                                f"https://localhost:{listener}" + route, body, context
                            )
                            if control:
                                assert (
                                    status == 400
                                    and parsed["type"]
                                    == "urn:ietf:params:acme:error:malformed"
                                ), (status, parsed)
                                # A public P-256 generator point reaches nonce validation with the same nonce.
                                public = {
                                    "kty": "EC",
                                    "crv": "P-256",
                                    "x": b64(
                                        bytes.fromhex(
                                            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                                        )
                                    ),
                                    "y": b64(
                                        bytes.fromhex(
                                            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                                        )
                                    ),
                                }
                                public_header = {
                                    **header,
                                    "alg": "ES256",
                                    "jwk": public,
                                }
                                public_body = json.dumps(
                                    {
                                        "protected": b64(
                                            json.dumps(public_header).encode()
                                        ),
                                        "payload": "e30",
                                        "signature": "AA",
                                    }
                                ).encode()
                                status, parsed = post_json(
                                    f"https://localhost:{listener}" + route,
                                    public_body,
                                    context,
                                )
                                assert (
                                    status == 400
                                    and parsed["type"]
                                    == "urn:ietf:params:acme:error:badNonce"
                                ), (status, parsed)
                                receipt["control"] = {
                                    "private_jwk": "malformed",
                                    "public_jwk": "badNonce",
                                }
                                print(
                                    "PASS: enabled ACME rejects malformed private JWK before the nonce check reached by a public-key control"
                                )
                            else:
                                assert status == 200 and parsed == {
                                    "path": "/acme/local/new-account",
                                    "sha256": hashlib.sha256(body).hexdigest(),
                                    "authorization_sha256": hashlib.sha256(
                                        bearer(body).encode()
                                    ).hexdigest(),
                                }, (status, parsed)
                                receipt["shipped_forwarded"].append(route)
                        if not control:
                            print(
                                "PASS: shipped routes forward bounded JWK bytes unchanged; no ACME parsing response"
                            )
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
        finally:
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=5)
        (work / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy", type=Path, required=True)
    parser.add_argument(
        "--caddyfile",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "Caddyfile",
    )
    parser.add_argument(
        "--work",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "artifacts/proxy-jwk-boundary",
    )
    args = parser.parse_args()
    check(args.caddy.resolve(), args.caddyfile.resolve(), args.work)

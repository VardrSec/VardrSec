"""Explicit development-image evidence collection; never starts the platform."""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
SCANNER = "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
SCANNER_VERSION = "0.76.1"
SERVICES = {"db", "api", "web", "proxy", "runner"}
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_config_id(path, details):
    """Bind Docker's index/manifest/config ID to the scanned platform's config."""
    with tarfile.open(path) as archive:

        def blob(digest):
            require(
                re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "Invalid archive digest"
            )
            key = digest.split(":")[1]
            try:
                member = archive.getmember("blobs/sha256/" + key)
            except KeyError:
                member = archive.getmember(key + ".json")
            require(
                member.isfile() and member.size <= 4 * 1024 * 1024,
                "Invalid archive metadata",
            )
            payload = archive.extractfile(member).read()
            require(
                hashlib.sha256(payload).hexdigest() == key,
                "Archive metadata digest mismatch",
            )
            return json.loads(payload)

        digest = details["Id"]
        root = blob(digest)
        if "manifests" in root:
            candidates = [
                m
                for m in root["manifests"]
                if m.get("platform", {}).get("os") == details["Os"]
                and m["platform"].get("architecture") == details["Architecture"]
            ]
            require(len(candidates) == 1, "Ambiguous archive platform")
            root = blob(candidates[0]["digest"])
        if "rootfs" not in root and "config" in root:
            digest = root["config"]["digest"]
            root = blob(digest)
        require(
            root.get("os") == details["Os"]
            and root.get("architecture") == details["Architecture"],
            "Archive platform mismatch",
        )
        require(
            root.get("rootfs", {}).get("diff_ids") == details["RootFS"]["Layers"],
            "Archive layer identity mismatch",
        )
        return digest


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def timestamp(value):
    # Go database metadata uses RFC3339Nano; Python 3.10 accepts microseconds.
    value = re.sub(
        r"\.(\d{1,9})(?=Z$|[+-]\d{2}:\d{2}$)",
        lambda match: "." + match[1][:6].ljust(6, "0"),
        value,
    )
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(date.tzinfo is not None, "Database timestamp needs a timezone")
    return date


def check_database(metadata, now):
    require(metadata.get("Version") == 2, "Unsupported vulnerability database")
    age = now - timestamp(metadata["UpdatedAt"])
    require(
        timedelta(minutes=-5) <= age <= timedelta(hours=48),
        "Stale/future vulnerability database",
    )


def analyze(report, bom, image_id):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Invalid image ID")
    require(report.get("SchemaVersion") == 2, "Unsupported scan report")
    metadata = report["Metadata"]
    require(metadata.get("ImageID") == image_id, "Scan image ID mismatch")
    require(
        metadata.get("OS", {}).get("Family") in {"debian", "alpine"},
        "Unverified image OS",
    )
    results = report.get("Results")
    require(isinstance(results, list) and results, "Empty scan results")
    require(
        any(r.get("Class") == "os-pkgs" and r.get("Packages") for r in results),
        "Missing OS inventory",
    )
    require(
        bom.get("bomFormat") == "CycloneDX" and bom.get("specVersion"),
        "Missing CycloneDX SBOM",
    )
    require(
        isinstance(bom.get("components"), list) and bom["components"],
        "Empty SBOM inventory",
    )
    properties = bom.get("metadata", {}).get("component", {}).get("properties", [])
    require(
        [
            p.get("value")
            for p in properties
            if p.get("name") == "aquasecurity:trivy:ImageID"
        ]
        == [image_id],
        "SBOM image ID mismatch",
    )
    counts = Counter({s: 0 for s in sorted(SEVERITIES)})
    fixable = Counter()
    for result in results:
        require(isinstance(result.get("Packages"), list), "Missing package inventory")
        findings = result.get("Vulnerabilities", [])
        require(isinstance(findings, list), "Malformed vulnerabilities")
        for finding in findings:
            severity = finding.get("Severity")
            require(
                severity in SEVERITIES
                and finding.get("VulnerabilityID")
                and finding.get("PkgName"),
                "Malformed vulnerability",
            )
            counts[severity] += 1
            if finding.get("FixedVersion"):
                fixable[severity] += 1
    return {
        "findings": dict(counts),
        "with_fixed_version": dict(fixable),
        "os_end_of_support": metadata["OS"].get("EOSL", False),
        "inventory_types": sorted({r["Type"] for r in results}),
        "sbom_components": len(bom["components"]),
        "vulnerability_gate": "blocked"
        if any(counts[s] for s in ("HIGH", "CRITICAL", "UNKNOWN"))
        or metadata["OS"].get("EOSL")
        else "clear_at_scan_time",
    }


def review(folder, now=None):
    """Recompute the narrow vulnerability gate; never trust the receipt's verdict."""
    now = now or datetime.now(timezone.utc)
    receipt = read(folder / "receipt.json")
    require(
        receipt.get("schema_version") == 1 and receipt.get("complete") is True,
        "Incomplete image evidence",
    )
    require(
        receipt.get("scanner", {}).get("reference") == SCANNER, "Unreviewed scanner"
    )
    require(
        receipt["scanner"].get("version") == SCANNER_VERSION, "Scanner version mismatch"
    )
    check_database(receipt["database"]["metadata"], now)
    require(
        re.fullmatch(r"[0-9a-f]{64}", receipt["database"]["sha256"]),
        "Missing database identity",
    )
    require(set(receipt["images"]) == SERVICES, "All five service images are required")
    verdicts = {}
    for service in sorted(SERVICES):
        image = receipt["images"][service]
        require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]),
            "Missing Docker image identity",
        )
        require(
            re.fullmatch(r"[0-9a-f]{64}", image["archive_sha256"]),
            "Missing archive identity",
        )
        for suffix in ("vuln.json", "cdx.json"):
            name = f"{service}.{suffix}"
            require(
                sha256(folder / name) == image["sha256"][name],
                "Evidence hash mismatch: " + name,
            )
        verdicts[service] = analyze(
            read(folder / f"{service}.vuln.json"),
            read(folder / f"{service}.cdx.json"),
            image["config_id"],
        )
    return verdicts


def docker(*args, timeout=900):
    # Never print Compose's environment or the image Config/Env/history.
    return subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=timeout,
    )


def collect():
    folder = ROOT / "artifacts/image-evidence" / ("run-" + secrets.token_hex(6))
    folder.mkdir(parents=True)
    cache, output, inputs = [folder / n for n in ("cache", "reports", "input")]
    for path in (cache, output, inputs):
        path.mkdir()
    uid = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "0:0"

    def scanner(label, network, *args, scan=False):
        mounts = ["--mount", f"type=bind,source={cache},target=/cache"]
        if scan:
            mounts += [
                "--mount",
                f"type=bind,source={inputs},target=/input,readonly",
                "--mount",
                f"type=bind,source={output},target=/reports",
            ]
        try:
            result = docker(
                "run",
                "--rm",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec",
                "--network",
                network,
                "--user",
                uid,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                *mounts,
                SCANNER,
                *args,
            )
        except subprocess.CalledProcessError as error:
            (output / (label + ".log")).write_text(
                (error.stdout or "") + (error.stderr or ""), encoding="utf-8"
            )
            raise
        (output / (label + ".log")).write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        return result

    receipt = {
        "schema_version": 1,
        "complete": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scanner": {"reference": SCANNER, "version": SCANNER_VERSION, "uid": uid},
        "declared_source_manifest": read(ROOT / "versions.json"),
        "distribution_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "distribution_dirty": bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        ),
        "input_sha256": {
            name: sha256(ROOT / name)
            for name in (
                "versions.json",
                "compose.yaml",
                "proxy/Dockerfile",
                "proxy/main.go",
                "image_evidence.py",
            )
        },
        "images": {},
        "release_authorized": False,
    }
    write(output / "receipt.json", receipt)
    docker("pull", SCANNER)
    version = scanner("scanner-version", "none", "--version").stdout
    require(
        version.splitlines()[0] == "Version: " + SCANNER_VERSION,
        "Unexpected scanner version",
    )
    common = (
        "image",
        "--cache-dir",
        "/cache",
        "--config",
        "",
        "--ignorefile",
        "",
        "--skip-version-check",
        "--no-progress",
        "--timeout",
        "10m",
    )
    scanner("database-download", "bridge", *common, "--download-db-only")
    metadata = read(cache / "db/metadata.json")
    check_database(metadata, datetime.now(timezone.utc))
    db_hash = sha256(cache / "db/trivy.db")
    receipt["database"] = {"metadata": metadata, "sha256": db_hash}
    config = json.loads(
        docker(
            "compose",
            "-f",
            str(ROOT / "compose.yaml"),
            "--profile",
            "tools",
            "config",
            "--no-interpolate",
            "--format",
            "json",
        ).stdout
    )
    require(set(config["services"]) == SERVICES, "Unexpected Compose services")
    for service in sorted(SERVICES):
        reference = config["services"][service]["image"]
        details = json.loads(docker("image", "inspect", reference).stdout)[0]
        image_id = details["Id"]
        require(details["Os"] == "linux", "Evidence requires Linux images")
        archive = inputs / (service + ".tar")
        try:
            docker("image", "save", "-o", str(archive), image_id)
            config_id = archive_config_id(archive, details)
            archive_hash = sha256(archive)
            for kind, suffix in (("json", "vuln.json"), ("cyclonedx", "cdx.json")):
                scanner(
                    service + "-" + kind,
                    "none",
                    *common,
                    "--offline-scan",
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--scanners",
                    "vuln",
                    "--pkg-types",
                    "os,library",
                    "--list-all-pkgs",
                    "--exit-code",
                    "0",
                    "--format",
                    kind,
                    "--output",
                    f"/reports/{service}.{suffix}",
                    "--input",
                    "/input/" + archive.name,
                    scan=True,
                )
            summary = analyze(
                read(output / f"{service}.vuln.json"),
                read(output / f"{service}.cdx.json"),
                config_id,
            )
            receipt["images"][service] = {
                "reference": reference,
                "id": image_id,
                "config_id": config_id,
                "archive_sha256": archive_hash,
                "architecture": details["Architecture"],
                "created": details["Created"],
                "repo_digests": details.get("RepoDigests", []),
                "summary": summary,
                "sha256": {
                    f"{service}.{suffix}": sha256(output / f"{service}.{suffix}")
                    for suffix in ("vuln.json", "cdx.json")
                },
            }
            write(output / "receipt.json", receipt)
            print(
                service
                + ": evidence collected; vulnerability gate "
                + summary["vulnerability_gate"],
                flush=True,
            )
        finally:
            # Only the exact archive this invocation exported is removed.
            archive.unlink(missing_ok=True)
    require(
        sha256(cache / "db/trivy.db") == db_hash,
        "Database changed during offline scans",
    )
    receipt["complete"] = True
    write(output / "receipt.json", receipt)
    verdicts = review(output)
    blocked = any(v["vulnerability_gate"] == "blocked" for v in verdicts.values())
    lines = [
        "## Image vulnerability gate: "
        + ("BLOCKED" if blocked else "clear at scan time"),
        "",
        "Evidence collection succeeded. Other release gates and authorization remain separate.",
        "",
        "| Image | Critical | High | Medium | Low | Unknown | Verdict |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for service, verdict in verdicts.items():
        values = [
            str(verdict["findings"][s])
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        ]
        lines.append(
            "| " + " | ".join([service, *values, verdict["vulnerability_gate"]]) + " |"
        )
    summary = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(summary, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open(
            "a", encoding="utf-8"
        ) as stream:
            stream.write(summary)
    print("Evidence: " + str(output), flush=True)
    print(
        "Collection completed; vulnerability gate "
        + ("BLOCKED" if blocked else "clear at scan time")
        + ". Other release gates remain separate."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("collect")
    check = commands.add_parser("check")
    check.add_argument("folder", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "collect":
            collect()
            return 0
        verdicts = review(args.folder)
        blocked = False
        for service, verdict in verdicts.items():
            print(
                service
                + ": "
                + verdict["vulnerability_gate"]
                + " "
                + json.dumps(verdict["findings"])
            )
            blocked |= verdict["vulnerability_gate"] == "blocked"
        return 1 if blocked else 0
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        print("Image evidence failed: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

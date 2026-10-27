"""Guard against incomplete or changed evidence being reported as clear."""

import copy
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import image_evidence as evidence

IMAGE = "sha256:" + "a" * 64


def json_bytes(value):
    return json.dumps(value).encode("utf-8")


def inputs():
    report = {
        "SchemaVersion": 2,
        "Metadata": {"ImageID": IMAGE, "OS": {"Family": "debian"}},
        "Results": [
            {"Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "libc6"}]}
        ],
    }
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [{"name": "libc6"}],
        "metadata": {
            "component": {
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": IMAGE}]
            }
        },
    }
    return report, bom


class ImageEvidenceTests(unittest.TestCase):
    def test_archive_binds_classic_and_oci_ids_and_rejects_changed_metadata(self):
        config = {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"diff_ids": [IMAGE]},
        }
        details = {
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {"Layers": [IMAGE]},
        }
        with tempfile.TemporaryDirectory() as directory:
            for layout in ("classic", "oci"):
                with self.subTest(layout=layout):
                    blobs = {}

                    def add(value):
                        payload = json_bytes(value)
                        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                        blobs[digest] = payload
                        return digest

                    config_id = add(config)
                    root_id = config_id
                    if layout == "oci":
                        manifest_id = add({"config": {"digest": config_id}})
                        root_id = add(
                            {
                                "manifests": [
                                    {
                                        "platform": {
                                            "os": "linux",
                                            "architecture": "amd64",
                                        },
                                        "digest": manifest_id,
                                    }
                                ]
                            }
                        )
                    details["Id"] = root_id
                    path = Path(directory) / (layout + ".tar")

                    def save():
                        with tarfile.open(path, "w") as archive:
                            for digest, payload in blobs.items():
                                name = digest.split(":")[1]
                                member = tarfile.TarInfo(
                                    name + ".json"
                                    if layout == "classic"
                                    else "blobs/sha256/" + name
                                )
                                member.size = len(payload)
                                archive.addfile(member, io.BytesIO(payload))

                    save()
                    self.assertEqual(
                        evidence.archive_config_id(path, details), config_id
                    )
                    different = copy.deepcopy(details)
                    different["RootFS"]["Layers"] = ["sha256:" + "b" * 64]
                    with self.assertRaisesRegex(ValueError, "layer identity"):
                        evidence.archive_config_id(path, different)
                    blobs[config_id] = b"{}"
                    save()
                    with self.assertRaisesRegex(ValueError, "digest mismatch"):
                        evidence.archive_config_id(path, details)

    def test_high_and_critical_block_even_when_no_fix_is_available(self):
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            with self.subTest(severity=severity):
                report, bom = inputs()
                report["Results"][0]["Vulnerabilities"] = [
                    {
                        "VulnerabilityID": "CVE-fixture",
                        "PkgName": "libc6",
                        "Severity": severity,
                    }
                ]
                result = evidence.analyze(report, bom, IMAGE)
                self.assertEqual(result["vulnerability_gate"], "blocked")
                self.assertEqual(result["findings"][severity], 1)
                self.assertEqual(result["with_fixed_version"], {})

    def test_supported_inventory_without_blocking_findings_can_be_clear(self):
        report, bom = inputs()
        self.assertEqual(
            evidence.analyze(report, bom, IMAGE)["vulnerability_gate"],
            "clear_at_scan_time",
        )
        report["Metadata"]["OS"]["EOSL"] = True
        self.assertEqual(
            evidence.analyze(report, bom, IMAGE)["vulnerability_gate"], "blocked"
        )

    def test_missing_inventory_identity_and_malformed_findings_fail_closed(self):
        report, bom = inputs()
        mutations = [
            ("empty results", lambda r, b: r.update(Results=[])),
            ("missing packages", lambda r, b: r["Results"][0].pop("Packages")),
            (
                "unsupported OS",
                lambda r, b: r["Metadata"]["OS"].update(Family="unknown"),
            ),
            (
                "wrong image",
                lambda r, b: r["Metadata"].update(ImageID="sha256:" + "b" * 64),
            ),
            ("empty SBOM", lambda r, b: b.update(components=[])),
            (
                "wrong SBOM",
                lambda r, b: b["metadata"]["component"].update(properties=[]),
            ),
            (
                "null vulnerabilities",
                lambda r, b: r["Results"][0].update(Vulnerabilities=None),
            ),
            (
                "missing severity",
                lambda r, b: r["Results"][0].update(
                    Vulnerabilities=[
                        {"VulnerabilityID": "CVE-fixture", "PkgName": "libc6"}
                    ]
                ),
            ),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                r, b = copy.deepcopy(report), copy.deepcopy(bom)
                mutate(r, b)
                with self.assertRaises(ValueError):
                    evidence.analyze(r, b, IMAGE)

    def test_database_must_be_recent_and_timezone_aware(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        for offset in (timedelta(days=-3), timedelta(days=1)):
            with self.assertRaises(ValueError):
                evidence.check_database(
                    {"Version": 2, "UpdatedAt": (now + offset).isoformat()}, now
                )
        with self.assertRaises(ValueError):
            evidence.check_database(
                {"Version": 2, "UpdatedAt": "2026-10-27T00:00:00"}, now
            )

    def test_review_recomputes_verdict_and_rejects_changed_or_partial_evidence(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            report, bom = inputs()
            report["Results"][0]["Vulnerabilities"] = [
                {
                    "VulnerabilityID": "CVE-fixture",
                    "PkgName": "libc6",
                    "Severity": "HIGH",
                    "FixedVersion": "2",
                }
            ]
            receipt = {
                "schema_version": 1,
                "complete": True,
                "scanner": {
                    "reference": evidence.SCANNER,
                    "version": evidence.SCANNER_VERSION,
                },
                "database": {
                    "metadata": {"Version": 2, "UpdatedAt": now.isoformat()},
                    "sha256": "c" * 64,
                },
                "images": {},
            }
            for service in evidence.SERVICES:
                evidence.write(folder / f"{service}.vuln.json", report)
                evidence.write(folder / f"{service}.cdx.json", bom)
                receipt["images"][service] = {
                    "id": IMAGE,
                    "config_id": IMAGE,
                    "archive_sha256": "d" * 64,
                    "summary": {"vulnerability_gate": "clear_at_scan_time"},
                    "sha256": {
                        f"{service}.{suffix}": evidence.sha256(
                            folder / f"{service}.{suffix}"
                        )
                        for suffix in ("vuln.json", "cdx.json")
                    },
                }
            evidence.write(folder / "receipt.json", receipt)
            self.assertTrue(
                all(
                    r["vulnerability_gate"] == "blocked"
                    for r in evidence.review(folder, now).values()
                )
            )
            receipt["database"]["sha256"] = ""
            evidence.write(folder / "receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "database identity"):
                evidence.review(folder, now)
            receipt["database"]["sha256"] = "c" * 64
            receipt["images"]["api"]["archive_sha256"] = ""
            evidence.write(folder / "receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "archive identity"):
                evidence.review(folder, now)
            receipt["images"]["api"]["archive_sha256"] = "d" * 64
            evidence.write(folder / "receipt.json", receipt)
            (folder / "api.vuln.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                evidence.review(folder, now)
            evidence.write(folder / "api.vuln.json", report)
            receipt["images"].pop("api")
            evidence.write(folder / "receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "five service"):
                evidence.review(folder, now)
            receipt["complete"] = False
            evidence.write(folder / "receipt.json", receipt)
            with self.assertRaisesRegex(ValueError, "Incomplete"):
                evidence.review(folder, now)


if __name__ == "__main__":
    unittest.main()

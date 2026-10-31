"""Offline regression coverage for the development image vulnerability gate.

No Docker, network access, image execution or platform startup is required.
Run: python -m unittest discover -s tests -p 'test_image_evidence_unit.py'
"""

from datetime import datetime, timedelta, timezone
import unittest

import image_evidence as evidence


IMAGE_ID = "sha256:" + "a" * 64


def fixtures():
    report = {
        "SchemaVersion": 2,
        "Metadata": {
            "ImageID": IMAGE_ID,
            "OS": {"Family": "debian", "EOSL": False},
        },
        "Results": [
            {
                "Class": "os-pkgs",
                "Type": "debian",
                "Packages": [{"Name": "base-files"}],
                "Vulnerabilities": [],
            }
        ],
    }
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "properties": [
                    {"name": "aquasecurity:trivy:ImageID", "value": IMAGE_ID}
                ]
            }
        },
        "components": [{"name": "base-files", "type": "library"}],
    }
    return report, bom


class DatabaseEvidenceTests(unittest.TestCase):
    def test_current_utc_database_accepted(self):
        now = datetime.now(timezone.utc)
        metadata = {"Version": 2, "UpdatedAt": now.isoformat()}
        evidence.check_database(metadata, now)

    def test_old_database_rejected(self):
        now = datetime.now(timezone.utc)
        metadata = {
            "Version": 2,
            "UpdatedAt": (now - timedelta(hours=49)).isoformat(),
        }
        with self.assertRaisesRegex(ValueError, "Stale/future"):
            evidence.check_database(metadata, now)

    def test_future_database_rejected(self):
        now = datetime.now(timezone.utc)
        metadata = {
            "Version": 2,
            "UpdatedAt": (now + timedelta(minutes=6)).isoformat(),
        }
        with self.assertRaisesRegex(ValueError, "Stale/future"):
            evidence.check_database(metadata, now)

    def test_timezone_required(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            evidence.timestamp("2026-10-27T08:00:00")

    def test_rfc3339_nano_timestamp_supported(self):
        parsed = evidence.timestamp("2026-10-27T08:00:00.123456789Z")
        self.assertEqual(parsed.microsecond, 123456)
        self.assertEqual(parsed.utcoffset(), timedelta(0))


class ScanEvidenceTests(unittest.TestCase):
    def test_clean_inventory_is_not_blocked(self):
        report, bom = fixtures()
        result = evidence.analyze(report, bom, IMAGE_ID)
        self.assertEqual(result["vulnerability_gate"], "clear_at_scan_time")
        self.assertEqual(result["sbom_components"], 1)

    def test_high_finding_blocks_even_without_fix(self):
        report, bom = fixtures()
        report["Results"][0]["Vulnerabilities"].append(
            {"Severity": "HIGH", "VulnerabilityID": "CVE-TEST-1", "PkgName": "base-files"}
        )
        result = evidence.analyze(report, bom, IMAGE_ID)
        self.assertEqual(result["vulnerability_gate"], "blocked")
        self.assertEqual(result["findings"]["HIGH"], 1)
        self.assertEqual(result["with_fixed_version"].get("HIGH", 0), 0)

    def test_unknown_severity_blocks(self):
        report, bom = fixtures()
        report["Results"][0]["Vulnerabilities"].append(
            {"Severity": "UNKNOWN", "VulnerabilityID": "CVE-TEST-2", "PkgName": "base-files"}
        )
        self.assertEqual(evidence.analyze(report, bom, IMAGE_ID)["vulnerability_gate"], "blocked")

    def test_end_of_support_os_blocks(self):
        report, bom = fixtures()
        report["Metadata"]["OS"]["EOSL"] = True
        self.assertEqual(evidence.analyze(report, bom, IMAGE_ID)["vulnerability_gate"], "blocked")

    def test_nmap_in_the_sbom_is_rejected(self):
        report, bom = fixtures()
        bom["components"].append({"name": "nmap", "type": "library"})
        with self.assertRaisesRegex(ValueError, "Nmap"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_nmap_common_in_the_package_inventory_is_rejected(self):
        report, bom = fixtures()
        report["Results"][0]["Packages"].append({"Name": "nmap-common"})
        with self.assertRaisesRegex(ValueError, "Nmap"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_similarly_named_packages_are_not_mistaken_for_nmap(self):
        report, bom = fixtures()
        bom["components"].append({"name": "python-nmapper", "type": "library"})
        report["Results"][0]["Packages"].append({"Name": "libnmap0"})
        evidence.analyze(report, bom, IMAGE_ID)

    def test_mismatched_report_image_id_rejected(self):
        report, bom = fixtures()
        report["Metadata"]["ImageID"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "Scan image ID mismatch"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_mismatched_sbom_image_id_rejected(self):
        report, bom = fixtures()
        bom["metadata"]["component"]["properties"][0]["value"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "SBOM image ID mismatch"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_missing_os_package_inventory_rejected(self):
        report, bom = fixtures()
        report["Results"][0]["Packages"] = []
        with self.assertRaisesRegex(ValueError, "Missing OS inventory"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_invalid_severity_rejected(self):
        report, bom = fixtures()
        report["Results"][0]["Vulnerabilities"] = [
            {"Severity": "UNRECOGNIZED", "VulnerabilityID": "CVE-TEST-3", "PkgName": "base-files"}
        ]
        with self.assertRaisesRegex(ValueError, "Malformed vulnerability"):
            evidence.analyze(report, bom, IMAGE_ID)

    def test_missing_sbom_inventory_rejected(self):
        report, bom = fixtures()
        bom["components"] = []
        with self.assertRaisesRegex(ValueError, "Empty SBOM inventory"):
            evidence.analyze(report, bom, IMAGE_ID)


if __name__ == "__main__":
    unittest.main()

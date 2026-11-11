"""Offline tests for the non-approving license review queue."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import license_evidence


class LicenseEvidenceTests(unittest.TestCase):
    def test_preserves_occurrences_and_never_infers_clearance(self):
        component = {"name": "library", "version": "1", "licenses": [{"license": {"id": "MIT"}}]}
        result = license_evidence.summarize_components([component, component, {"name": "unknown"}])
        self.assertEqual(result["component_occurrences"], 3)
        self.assertEqual(result["with_license_metadata"], 2)
        self.assertEqual(result["missing_license_metadata"], 1)
        self.assertEqual(sum(item["review_status"] == "declaration_requires_review" for item in result["components"]), 2)

    def test_stable_order_and_expressions(self):
        a = {"name": "a", "licenses": [{"expression": "MIT OR Apache-2.0"}]}
        b = {"name": "b", "licenses": [{"license": {"name": "custom"}}]}
        self.assertEqual(license_evidence.summarize_components([a, b]), license_evidence.summarize_components([b, a]))

    def test_rejects_malformed_declarations(self):
        for value in (None, {}, [{"name": "a", "licenses": "MIT"}], [{"name": "a", "licenses": ["MIT"]}]):
            with self.assertRaises(ValueError):
                license_evidence.summarize_components(value)

    def test_refuses_manifest_mismatch_after_image_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "receipt.json").write_text(json.dumps({"declared_source_manifest": {"old": True}}))
            with patch.object(license_evidence.image_evidence, "review", return_value={}) as review:
                with self.assertRaisesRegex(ValueError, "does not match"):
                    license_evidence.assemble(folder, {"new": True})
                review.assert_called_once_with(folder)

    def test_propagates_invalid_image_evidence(self):
        with patch.object(license_evidence.image_evidence, "review", side_effect=ValueError("Evidence hash mismatch")):
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                license_evidence.assemble(Path("unused"), {})


if __name__ == "__main__":
    unittest.main()

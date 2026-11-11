"""Build an exact-image license review queue; never grant redistribution clearance."""

import argparse
import json
from pathlib import Path

import image_evidence


def summarize_components(components):
    """Preserve occurrences and declarations, not inferred compatibility decisions."""
    if not isinstance(components, list):
        raise ValueError("SBOM components must be a list")
    entries = []
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("name"), str):
            raise ValueError("Malformed SBOM component")
        declarations = component.get("licenses", [])
        if not isinstance(declarations, list):
            raise ValueError("Malformed SBOM license declarations")
        for declaration in declarations:
            if not isinstance(declaration, dict) or not (
                isinstance(declaration.get("expression"), str)
                or isinstance(declaration.get("license"), dict)
            ):
                raise ValueError("Malformed SBOM license declaration")
        entries.append({
            "bom_ref": component.get("bom-ref"),
            "type": component.get("type"),
            "name": component["name"],
            "version": component.get("version"),
            "purl": component.get("purl"),
            "declared_licenses": declarations,
            "review_status": "declaration_requires_review" if declarations else "missing_metadata",
        })
    entries.sort(key=lambda item: json.dumps(item, sort_keys=True))
    return {
        "component_occurrences": len(entries),
        "with_license_metadata": sum(bool(item["declared_licenses"]) for item in entries),
        "missing_license_metadata": sum(not item["declared_licenses"] for item in entries),
        "components": entries,
    }


def assemble(folder, expected_manifest):
    folder = Path(folder)
    # Reuse image/report identity, content-hash and scanner/database validation.
    # Blocked vulnerabilities are preserved, not treated as a license exception.
    verdicts = image_evidence.review(folder)
    receipt = image_evidence.read(folder / "receipt.json")
    if receipt["declared_source_manifest"] != expected_manifest:
        raise ValueError("Evidence source manifest does not match the candidate")
    result = {
        "schema": "vardr.license-review-queue/1",
        "release_clearance": False,
        "status": "transitive_review_required",
        "scope": "SBOM declarations only; not notice coverage, linked-code attribution, corresponding source or license compatibility",
        "receipt_sha256": image_evidence.sha256(folder / "receipt.json"),
        "distribution_commit": receipt["distribution_commit"],
        "declared_source_manifest": receipt["declared_source_manifest"],
        "images": {},
    }
    for name in sorted(image_evidence.SERVICES):
        image = receipt["images"][name]
        sbom = image_evidence.read(folder / (name + ".cdx.json"))
        result["images"][name] = {
            "config_id": image["config_id"],
            "sbom_sha256": image["sha256"][name + ".cdx.json"],
            "vulnerability_gate": verdicts[name]["vulnerability_gate"],
            **summarize_components(sbom["components"]),
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("versions.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args.reports, image_evidence.read(args.manifest))
        # Never replace a prior review. No destination directories are created.
        with args.output.open("x", encoding="utf-8") as target:
            json.dump(result, target, indent=2, sort_keys=True)
            target.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Cannot prepare license review queue: {error}\n")
    print("Prepared license review queue; release clearance remains false")


if __name__ == "__main__":
    main()

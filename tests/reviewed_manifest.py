"""Verify the exact reviewed distribution candidate manifest."""

import hashlib


# Explicitly reviewed release-gate candidate manifest; do not derive this expected
# value from the checkout being checked. An intentional pin update must review it.
REVIEWED_DISTRIBUTION_MANIFEST_SHA256 = (
    "9f599421cc4ef10db1c39d509bc54677242ae1d78906c4b6f8b4ac64831a2b94"
)


def verify_distribution_manifest(root):
    actual = hashlib.sha256(
        (root / "versions.json").read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert actual == REVIEWED_DISTRIBUTION_MANIFEST_SHA256, "distribution manifest differs from reviewed candidate baseline"
    return actual

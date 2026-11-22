"""Verify the exact reviewed distribution candidate manifest."""

import hashlib


# Explicitly reviewed release-gate candidate manifest; do not derive this expected
# value from the checkout being checked. An intentional pin update must review it.
REVIEWED_DISTRIBUTION_MANIFEST_SHA256 = (
    "2c7cf3003333d63e3bfe32ab05203753af97397d11d0c595873c30c6afa348d5"
)


def verify_distribution_manifest(root):
    actual = hashlib.sha256(
        (root / "versions.json").read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert actual == REVIEWED_DISTRIBUTION_MANIFEST_SHA256, "distribution manifest differs from reviewed candidate baseline"
    return actual

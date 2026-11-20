"""Verify the exact reviewed distribution candidate manifest."""

import hashlib


# Explicitly reviewed release-gate candidate manifest; do not derive this expected
# value from the checkout being checked. An intentional pin update must review it.
REVIEWED_DISTRIBUTION_MANIFEST_SHA256 = (
    "5f92c582922ea86141e86901399ed320661ae854dba5dcacff3296ec4aeaeae0"
)


def verify_distribution_manifest(root):
    actual = hashlib.sha256(
        (root / "versions.json").read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()
    assert actual == REVIEWED_DISTRIBUTION_MANIFEST_SHA256, "distribution manifest differs from reviewed candidate baseline"
    return actual

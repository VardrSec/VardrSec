import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci import native_cache


class NativeCacheTests(unittest.TestCase):
    def test_key_rotates_with_app_source_secret_and_runner(self):
        env = {"GITHUB_REPOSITORY": "VardrSec/VardrSec", "RUNNER_ARCH": "X64",
               "ImageOS": "ubuntu24", "PASSPHRASE": "fixture"}
        with patch.dict(os.environ, env), patch.object(native_cache, "map_pin", return_value="a" * 40) as pin:
            key = native_cache.cache_key()
            self.assertEqual(key, native_cache.cache_key())
            pin.return_value = "b" * 40
            self.assertNotEqual(key, native_cache.cache_key())
            pin.return_value = "a" * 40
            for field in ("PASSPHRASE", "ImageOS", "RUNNER_ARCH"):
                with self.subTest(field=field), patch.dict(os.environ, {field: "different"}):
                    self.assertNotEqual(key, native_cache.cache_key())

    def test_only_the_expected_oci_store_is_extracted(self):
        key = "full-native-v1-" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "native.tar"
            for bad_entry in (None, "../wrong", key + "/../escape", key + "/extra", "other/index.json",
                              key + "/blobs/sha256/" + "b" * 64):
                with self.subTest(bad_entry=bad_entry), tarfile.open(archive, "w") as out:
                    for name in ("index.json", "oci-layout", "blobs/sha256/" + "c" * 64):
                        entry = tarfile.TarInfo(key + "/" + name)
                        entry.size = 2
                        out.addfile(entry, io.BytesIO(b"{}"))
                    if bad_entry:
                        entry = tarfile.TarInfo(bad_entry)
                        if "/blobs/" in bad_entry:
                            entry.type = tarfile.SYMTYPE
                            entry.linkname = "outside"
                        out.addfile(entry)
                with tempfile.TemporaryDirectory(dir=root) as destination:
                    if bad_entry:
                        with self.assertRaises(ValueError):
                            native_cache.unpack(archive, destination, key)
                    else:
                        native_cache.unpack(archive, destination, key)
                        self.assertEqual((Path(destination) / key / "index.json").read_bytes(), b"{}")
                        blob = Path(destination) / key / "blobs" / "sha256" / ("c" * 64)
                        self.assertEqual(blob.read_bytes(), b"{}")
                        with self.assertRaises(FileExistsError):
                            native_cache.unpack(archive, destination, key)

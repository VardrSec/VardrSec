import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('reproduce', Path(__file__).with_name('reproduce.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class Reproduction(unittest.TestCase):
    def setUp(self):
        self.first = dict(archive_sha256='a', receipt={'prepared_disk_sha256':'a'},
                          inputs={'source':'a'}, packages={'package':'a'}, prepared_packages_sha256='a')
        self.second = copy.deepcopy(self.first)
        self.second.update(archive_sha256='b',receipt={'prepared_disk_sha256':'b'})

    def test_success(self):
        result = r.compare(self.first, self.second)
        self.assertTrue(result['package_bytes_reproduced'])
        self.assertFalse(result['release_clearance'])

    def test_reject_reused_disk(self):
        self.second['receipt'] = self.first['receipt']
        with self.assertRaises(AssertionError): r.compare(self.first,self.second)

    def test_reject_changed_package(self):
        self.second['packages']['package'] = 'b'
        with self.assertRaisesRegex(AssertionError,'packages differ'): r.compare(self.first,self.second)

    def test_reject_changed_source(self):
        self.second['inputs']['source'] = 'b'
        with self.assertRaisesRegex(AssertionError,'inputs changed'): r.compare(self.first,self.second)

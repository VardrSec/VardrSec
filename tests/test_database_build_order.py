import unittest
from unittest.mock import patch,call
import vardrsec

class BuildOrdering(unittest.TestCase):
    def test_full_database_before_parallel_images(self):
        env={'example':'unchanged'}
        with patch.object(vardrsec,'compose') as compose:
            vardrsec.build_images(mapless=False,environment=env)
        self.assertEqual(compose.call_args_list,[call('--profile','tools','build','db',env=env),call('--profile','tools','build',env=env)])

    def test_mapless_does_not_build_database(self):
        with patch.object(vardrsec,'compose') as compose:
            vardrsec.build_images(mapless=True,environment={})
        compose.assert_called_once_with('--profile','tools','build',env={})

    def test_failed_database_stops_remaining_builds(self):
        with patch.object(vardrsec,'compose',side_effect=RuntimeError('db failure')) as compose:
            with self.assertRaises(RuntimeError):vardrsec.build_images(mapless=False,environment={})
        self.assertEqual(compose.call_count,1)

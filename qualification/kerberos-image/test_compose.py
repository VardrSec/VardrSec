import json
from pathlib import Path
import unittest

class CandidateOverride(unittest.TestCase):
    def test_only_build_recipe_and_review_alias_change(self):
        data = json.loads(Path(__file__).with_name('compose.candidate.json').read_text())
        self.assertEqual(data, {'services': {'db': {
            'image': 'vardr-db-qualified-candidate',
            'build': {'dockerfile': 'Dockerfile.qualification'}}}})

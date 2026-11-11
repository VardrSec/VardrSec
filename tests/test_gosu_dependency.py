"""Keep the patched gosu module and built-binary evidence contract aligned."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class GosuDependencyTests(unittest.TestCase):
    def test_build_selects_reviewed_module(self):
        recipe = (ROOT / 'db/Dockerfile').read_text()
        self.assertIn('golang.org/x/sys v0.44.0', (ROOT / 'db/gosu.go.mod').read_text())
        self.assertIn('COPY gosu.go.sum /src/go.sum', recipe)
        self.assertIn('RUN --network=none go build -mod=readonly', recipe)
        self.assertIn('module-sources.tar', recipe)
        self.assertIn('-trimpath', recipe)
        self.assertIn('COPY --from=gosu /go/bin/gosu /usr/local/bin/gosu', recipe)

    def test_ci_checks_actual_binary_not_only_recipe(self):
        workflow = (ROOT / '.github/workflows/image-evidence.yml').read_text()
        self.assertIn('docker cp "$id:/usr/local/bin/gosu"', workflow)
        self.assertIn('go version -m "$RUNNER_TEMP/gosu"', workflow)
        self.assertIn('golang.org/x/sys[[:space:]]+v0\\.44\\.0[[:space:]]', workflow)
        self.assertIn('govulncheck" -mode=binary -show verbose "$RUNNER_TEMP/gosu"', workflow)
        self.assertIn('gosu-build-info.txt', workflow)

if __name__ == '__main__':
    unittest.main()

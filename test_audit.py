import unittest
from audit import scan_text, scan_path

class AuditTests(unittest.TestCase):
    def test_privileged_detected(self):
        self.assertEqual(scan_text('privileged: true\n', 'deploy.yaml')[0]['rule'], 'K8S_PRIVILEGED')
    def test_safe_manifest(self):
        self.assertEqual(scan_text('privileged: false\nrunAsNonRoot: true\n', 'deploy.yaml'), [])
    def test_unpinned_action(self):
        self.assertEqual(scan_text('- uses: actions/checkout@v4\n', '.github/workflows/ci.yml')[0]['rule'], 'ACTIONS_UNPINNED')
    def test_sha_pinned(self):
        self.assertEqual(scan_text('- uses: actions/checkout@' + 'a'*40 + '\n', '.github/workflows/ci.yml'), [])
    def test_example(self):
        self.assertEqual(scan_path('examples')['counts'], {'high': 3, 'medium': 2})

if __name__ == '__main__':
    unittest.main()

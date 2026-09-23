"""Exercise Dockerfile selection and failure propagation in the actual lint step."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/pr-security-gate.yml'
LINT = next(step['run'] for step in yaml.safe_load(WORKFLOW.read_text())
            ['jobs']['precheck']['steps'] if step.get('id') == 'lint')


class DockerfileLint(unittest.TestCase):
    def run_lint(self, files, directories=()):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / 'checkout'
            checkout.mkdir()
            for name, content in files.items():
                path = checkout / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            for name in directories:
                (checkout / name).mkdir(parents=True, exist_ok=True)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            docker = bin_dir / 'docker'
            docker.write_text('''#!/usr/bin/env python3
import json, os, sys
assert sys.argv[1:] == ['run', '--rm', '-i', 'hadolint/hadolint:latest-alpine',
                       'hadolint', '--failure-threshold', 'error', '-']
content = sys.stdin.read()
with open(os.environ['LINT_CALLS'], 'a') as log:
    log.write(json.dumps(content) + '\\n')
sys.exit(0 if content.startswith('FROM ') else 1)
''')
            docker.chmod(0o755)
            calls = root / 'calls'
            env = {**os.environ, 'PATH': f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
                   'LINT_CALLS': str(calls)}
            result = subprocess.run(['bash', '-c', LINT], cwd=checkout, env=env,
                                    capture_output=True, text=True)
            scanned = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            return result, scanned

    def test_real_variants_remain_scanned_and_ignore_companions_do_not(self):
        recipes = {name: f'FROM scratch\n# {name}\n' for name in (
            'Dockerfile', 'Dockerfile.dev', 'docker/development/Dockerfile.web',
            'folder with spaces/Dockerfile.test', 'Dockerfile.dockerignore.dev')}
        companions = {name: '*\n!source/\n' for name in (
            'Dockerfile.dockerignore', 'Dockerfile.dev.dockerignore',
            'docker/development/Dockerfile.web.dockerignore')}
        result, scanned = self.run_lint(recipes | companions, ['Dockerfile.directory'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertCountEqual(scanned, recipes.values())

    def test_only_ignore_companions_do_not_call_hadolint(self):
        result, scanned = self.run_lint({'Dockerfile.dev.dockerignore': '*\n!source/\n'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(scanned, [])

    def test_real_dockerfile_errors_still_fail_the_gate(self):
        result, scanned = self.run_lint({'nested/Dockerfile.broken': 'BROKEN recipe\n'})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(scanned, ['BROKEN recipe\n'])
        self.assertIn('hadolint reported errors in nested/Dockerfile.broken', result.stdout)

    def test_no_dockerfiles_do_not_call_hadolint(self):
        result, scanned = self.run_lint({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(scanned, [])


if __name__ == '__main__':
    unittest.main()

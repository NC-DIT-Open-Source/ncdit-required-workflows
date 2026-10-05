"""Exact public source association; no scanner or hosted execution claimed."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

H = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pr226_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
F = json.loads((H / 'fixtures/pr226-frontdoor-source.json').read_bytes())
BASE_BYTES = (H / 'fixtures/pr197-source-association.json').read_bytes()
BASE = json.loads(BASE_BYTES)['sources']
CURRENT = {**BASE, **F['sources']}


class SourcePR226(unittest.TestCase):
    def test_exact_fourteen_sources_and_only_two_pin_changes(self):
        self.assertEqual(hashlib.sha256(BASE_BYTES).hexdigest(), F['baseFixtureSha256'])
        self.assertEqual(F['applicationSource'], 'b46da5575e915e3cfa6492024e2398df961bc91f')
        self.assertEqual(F['status'], 'EXACT_PUBLIC_SOURCE_REFRESH_NOT_SCANNER_OR_HOSTED_EVIDENCE')
        self.assertEqual(len(CURRENT), 14)
        self.assertEqual({p: c.sha(b.encode()) for p, b in CURRENT.items()}, c.SOURCES)
        self.assertEqual(set(F['sources']), {
            'infra/aws/modules/public-frontdoor/main.tf',
            'infra/aws/public-frontdoor/main.tf',
        })
        for change in F['changes']:
            self.assertEqual(c.sha(BASE[change['path']].encode()), change['expected'])
            self.assertEqual(c.sha(CURRENT[change['path']].encode()), change['actual'])
        self.assertEqual({p for p in CURRENT if CURRENT[p] != BASE[p]}, set(F['sources']))

    def test_existing_cloudfront_finding_and_caller_lines_unchanged(self):
        finding = next(row for row in c.EXPECTED if row['rule'] == 'AWS-0010')
        for path, start, end in [
            ('infra/aws/' + finding['target'], finding['start_line'], finding['end_line']),
            *[('infra/aws/' + row['filename'], row['start_line'], row['end_line'])
              for row in finding['occurrences']],
        ]:
            self.assertEqual(BASE[path].splitlines()[start - 1:end],
                             CURRENT[path].splitlines()[start - 1:end])

    def test_real_git_exact_source_and_every_mutation_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='pr226-source-') as directory:
            root = Path(directory).resolve()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args],
                                               stderr=subprocess.PIPE).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'Synthetic fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            git('remote', 'add', 'origin', 'https://github.com/' + c.REPOSITORY + '.git')
            for name, body in CURRENT.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            git('add', '.')
            git('commit', '-qm', 'Explicit synthetic source fixture')
            baseline = git('rev-parse', 'HEAD')
            self.assertEqual(c.source(root, baseline, os.environ)['source_sha256'], c.SOURCES)
            for name in CURRENT:
                path = root / name
                path.write_text(CURRENT[name] + '\n# mutation\n')
                git('add', name)
                git('commit', '-qm', 'Synthetic source mutation')
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'reviewed-source-hash'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                git('reset', '--hard', baseline)
            for name in F['sources']:
                (root / name).write_text(BASE[name])
                git('add', name)
                git('commit', '-qm', 'Synthetic stale source')
                with self.subTest(stale=name), self.assertRaisesRegex(ValueError, 'reviewed-source-hash'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                git('reset', '--hard', baseline)


if __name__ == '__main__':
    unittest.main(verbosity=2)

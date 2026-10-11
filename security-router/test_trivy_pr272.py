"""Current exact source controls; projections are not scanner or hosted results."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

H = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pr272_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
from test_trivy_pr226 import CURRENT as BASE
from test_trivy_pr197 import triple as historical_triple, c as historical
F = json.loads((H / 'fixtures/pr272-frontdoor-source.json').read_bytes())
CURRENT = {**BASE, **F['sources']}


def projection():
    values = historical_triple()
    for report in values[:2]:
        changed = 0
        for row in report['Results']:
            for finding in row.get('Misconfigurations', []):
                if finding['ID'] == 'AWS-0010':
                    location = finding['CauseMetadata']['Occurrences'][0]['Location']
                    assert location == {'StartLine': 120, 'EndLine': 136}
                    location.update(StartLine=112, EndLine=129)
                    changed += 1
        assert changed == 1
    return values


class SourcePR272(unittest.TestCase):
    def test_exact_current_sources_and_only_reviewed_changes(self):
        self.assertEqual(hashlib.sha256((H / 'fixtures/pr226-frontdoor-source.json').read_bytes()).hexdigest(), F['baseFixtureSha256'])
        self.assertEqual(F['status'], 'EXACT_PUBLIC_SOURCE_ASSOCIATION_NOT_SCANNER_OR_HOSTED_EVIDENCE')
        self.assertFalse(F['scanPerformed']); self.assertFalse(F['hostedClearance'])
        self.assertEqual(F['sourceTree'], '056c6e46edce1cb3ffa6c1f114dbb27727542e6e')
        self.assertEqual(len(CURRENT), 14)
        self.assertEqual({p: c.sha(b.encode()) for p, b in CURRENT.items()}, c.SOURCES)
        self.assertEqual({p for p in CURRENT if CURRENT[p] != BASE[p]}, set(F['sources']))
        self.assertEqual(set(F['sources']), {'infra/aws/modules/public-frontdoor/main.tf', 'infra/aws/public-frontdoor/main.tf'})
        expected = copy.deepcopy(historical.EXPECTED)
        next(r for r in expected if r['rule'] == 'AWS-0010')['occurrences'][0].update(start_line=112, end_line=129)
        self.assertEqual(expected, c.EXPECTED)
        self.assertEqual([r for r in expected if r['severity'] == 'HIGH'], [r for r in historical.EXPECTED if r['severity'] == 'HIGH'])
        lines = CURRENT['infra/aws/public-frontdoor/main.tf'].splitlines()
        self.assertEqual(lines[111], 'module "public_frontdoor" {'); self.assertEqual(lines[128], '}')

    def test_synthetic_projection_preserves_reports_and_exception_scope(self):
        values = projection(); original = copy.deepcopy(values)
        decision, derived, removed = c.upload_view(*values)
        self.assertEqual(values, original)
        self.assertEqual(len(decision['iac_findings']), 10)
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(r['classification']['rule'] == 'AWS-0132' for r in removed))
        self.assertEqual(len(derived['runs'][0]['results']), 8)
        with self.assertRaisesRegex(ValueError, '^exact-iac-inventory$'):
            c.classify(*historical_triple())
        for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
            for severity in ('HIGH', 'CRITICAL'):
                changed = projection()
                changed[0]['Results'].append(dict(Target='foreign.txt', Class='secret', Type='synthetic', **{kind: [{'Severity': severity}]}))
                with self.subTest(kind=kind, severity=severity), self.assertRaisesRegex(ValueError, '^unaccepted-high-critical$'):
                    c.classify(*changed)

    def test_each_changed_coordinate_mutation_refused(self):
        for index in (0, 1):
            for field, bad in [('StartLine', 111), ('StartLine', 120), ('EndLine', 130), ('EndLine', 136)]:
                changed = projection()
                finding = next(f for r in changed[index]['Results'] for f in r.get('Misconfigurations', []) if f['ID'] == 'AWS-0010')
                finding['CauseMetadata']['Occurrences'][0]['Location'][field] = bad
                with self.subTest(index=index, field=field, bad=bad), self.assertRaisesRegex(ValueError, '^exact-iac-inventory$'):
                    c.classify(*changed)

    def test_actual_source_guard_and_fourteen_mutations(self):
        with tempfile.TemporaryDirectory(prefix='pr272-source-') as directory:
            root = Path(directory).resolve()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'Synthetic fixture'); git('config', 'user.email', 'fixture@example.invalid')
            git('remote', 'add', 'origin', 'https://github.com/' + c.REPOSITORY + '.git')
            for name, body in CURRENT.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(body)
            git('add', '.'); git('commit', '-qm', 'Explicit synthetic source fixture'); head = git('rev-parse', 'HEAD')
            self.assertEqual(c.source(root, head, os.environ)['source_sha256'], c.SOURCES)
            for name in CURRENT:
                (root / name).write_text(CURRENT[name] + '\n# mutation\n'); git('add', name); git('commit', '-qm', 'Synthetic source mutation')
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, '^reviewed-source-hash$'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                git('reset', '--hard', head)


if __name__ == '__main__':
    unittest.main(verbosity=2)

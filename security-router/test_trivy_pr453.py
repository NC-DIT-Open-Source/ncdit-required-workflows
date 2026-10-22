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
spec = importlib.util.spec_from_file_location('pr453_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
from test_trivy_pr364_general import CURRENT as BASE, projection as base_projection, c as previous
F = json.loads((H / 'fixtures/pr453-records-trail-source.json').read_bytes())
CURRENT = {**BASE, **F['sources']}
PROJECTION = 'modules/database-audit-projection/main.tf'


def findings(values, index):
    return [f for r in values[index]['Results'] for f in r.get('Misconfigurations', [])
            if f['ID'] == 'AWS-0066' and r['Target'].endswith(PROJECTION)]


def projection():
    values = base_projection()
    for index in (0, 1):
        rows = findings(values, index)
        assert len(rows) == 1
        metadata = rows[0]['CauseMetadata']
        assert (metadata['StartLine'], metadata['EndLine']) == (117, 135)
        metadata.update(StartLine=116, EndLine=134)
    changed = 0
    for run in values[2]['runs']:
        for result in run['results']:
            for location in result['locations']:
                physical = location['physicalLocation']
                if result['ruleId'] == 'AWS-0066' and physical['artifactLocation']['uri'] == 'infra/aws/' + PROJECTION:
                    assert (physical['region']['startLine'], physical['region']['endLine']) == (117, 135)
                    physical['region'].update(startLine=116, endLine=134)
                    changed += 1
    assert changed == 1
    return values


class SourcePR453(unittest.TestCase):
    def test_exact_current_sources_and_only_reviewed_changes(self):
        self.assertEqual(hashlib.sha256((H / 'fixtures/pr364-general-rate-source.json').read_bytes()).hexdigest(), F['baseFixtureSha256'])
        self.assertEqual(F['status'], 'EXACT_PUBLIC_SOURCE_ASSOCIATION_NOT_SCANNER_OR_HOSTED_EVIDENCE')
        self.assertFalse(F['scanPerformed']); self.assertFalse(F['hostedClearance'])
        self.assertEqual(len(CURRENT), 14)
        self.assertEqual({p: c.sha(b.encode()) for p, b in CURRENT.items()}, c.SOURCES)
        self.assertEqual({p for p in CURRENT if CURRENT[p] != BASE[p]}, set(F['sources']))
        self.assertEqual(set(F['sources']), {'infra/aws/' + PROJECTION})
        expected = copy.deepcopy(previous.EXPECTED)
        next(r for r in expected if r['rule'] == 'AWS-0066' and r['target'] == PROJECTION).update(start_line=116, end_line=134)
        self.assertEqual(expected, c.EXPECTED)
        self.assertEqual([r for r in expected if r['severity'] == 'HIGH'], [r for r in previous.EXPECTED if r['severity'] == 'HIGH'])
        lines = CURRENT['infra/aws/' + PROJECTION].splitlines()
        self.assertEqual(lines[115], 'resource "aws_lambda_function" "delivery" {'); self.assertEqual(lines[133], '}')
        self.assertNotIn('aws_cloudwatch_log_subscription_filter', CURRENT['infra/aws/' + PROJECTION])

    def test_synthetic_projection_preserves_reports_and_exception_scope(self):
        values = projection(); original = copy.deepcopy(values)
        decision, derived, removed = c.upload_view(*values)
        self.assertEqual(values, original)
        self.assertEqual(len(decision['iac_findings']), 10)
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(r['classification']['rule'] == 'AWS-0132' for r in removed))
        self.assertEqual(len(derived['runs'][0]['results']), 8)
        with self.assertRaisesRegex(ValueError, '^exact-iac-inventory$'):
            c.classify(*base_projection())
        for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
            for severity in ('HIGH', 'CRITICAL'):
                changed = projection()
                changed[0]['Results'].append(dict(Target='foreign.txt', Class='secret', Type='synthetic', **{kind: [{'Severity': severity}]}))
                with self.subTest(kind=kind, severity=severity), self.assertRaisesRegex(ValueError, '^unaccepted-high-critical$'):
                    c.classify(*changed)

    def test_each_changed_coordinate_mutation_refused(self):
        for index in (0, 1):
            for field, bad in [('StartLine', 115), ('StartLine', 117), ('EndLine', 133), ('EndLine', 135)]:
                changed = projection()
                findings(changed, index)[0]['CauseMetadata'][field] = bad
                with self.subTest(index=index, field=field, bad=bad), self.assertRaisesRegex(ValueError, '^exact-iac-inventory$'):
                    c.classify(*changed)

    def test_actual_source_guard_and_fourteen_mutations(self):
        with tempfile.TemporaryDirectory(prefix='pr453-source-') as directory:
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

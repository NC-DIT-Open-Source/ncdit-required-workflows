"""Current public source/config controls; synthetic conversion is not hosted CI."""
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
spec = importlib.util.spec_from_file_location('current_156dd_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
RAW = (H / 'fixtures/156dd-policy-source.json').read_bytes()
assert hashlib.sha256(RAW).hexdigest() == 'fa21c616473f896cf8d973f677c52b7b5765da30b25b6cde71dcd1ef9fd083db'
F = json.loads(RAW)


def findings(report):
    return [(r, f) for r in report['Results'] for f in r.get('Misconfigurations', [])]


def triple():
    return tuple(copy.deepcopy(F[k]) for k in ('synthetic_filesystem', 'actual_config', 'synthetic_sarif'))


class Source156dd(unittest.TestCase):
    def test_actual_scan_and_source_provenance(self):
        self.assertEqual(F['source_head'], '156ddce799adaa24f2a6c3af6bfc0cbdab8c021b')
        self.assertEqual(F['source_tree'], 'ad3633d691f8b6841cb1f3dc12e672f1d629c22f')
        self.assertEqual(hashlib.sha256(F['actual_config_raw'].encode()).hexdigest(), F['actual_config_sha256'])
        self.assertEqual(json.loads(F['actual_config_raw']), F['actual_config'])
        terminal = F['actual_config_native_terminal']
        self.assertEqual(terminal['stdout_sha256'], F['actual_config_sha256'])
        self.assertEqual(terminal['native_exit_code'], 0)
        self.assertTrue(terminal['supervisor_reaped'])
        self.assertEqual(terminal['cleanup_errors'], [])
        for field in ('hosted_clearance', 'whole_filesystem_scan_performed', 'vulnerability_scan_performed'):
            self.assertFalse(F[field])
        self.assertEqual(len(findings(F['actual_config'])), 10)
        self.assertEqual([c.normalized(r, f, '') for r, f in findings(F['actual_config'])], c.EXPECTED)
        self.assertEqual(c.report(F['actual_config'], '', config_only=True)['blockers'], [])

    def test_exact_source_delta_and_real_code_lines(self):
        self.assertEqual({p: c.sha(b.encode()) for p, b in F['sources'].items()}, c.SOURCES)
        self.assertEqual(len(c.SOURCES), 14)
        old = F['previous_policy']['sources']
        self.assertEqual(set(c.SOURCES) - set(old), {'infra/aws/origin-bootstrap/main.tf'})
        self.assertEqual({p for p in old if old[p] != c.SOURCES[p]}, {
            'infra/aws/operator-foundations/access-logging.tf',
            'infra/aws/public-frontdoor/main.tf', 'infra/aws/operator-database/hosted/stores.tf'})
        for result, finding in findings(F['actual_config']):
            source = F['sources']['infra/aws/' + result['Target']].splitlines()
            for line in finding['CauseMetadata'].get('Code', {}).get('Lines', []):
                if not line['Truncated']:
                    self.assertEqual(line['Content'], source[line['Number'] - 1])

    def test_only_existing_two_high_classifications(self):
        self.assertEqual([x for x in c.EXPECTED if x['severity'] == 'HIGH'],
                         [x for x in F['previous_policy']['expected'] if x['severity'] == 'HIGH'])
        self.assertEqual(len([x for x in c.EXPECTED if x['severity'] == 'HIGH']), 2)
        added = [x for x in c.EXPECTED if x['rule'] == 'AWS-0065']
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]['severity'], 'MEDIUM')
        self.assertEqual(added[0]['target'], 'origin-bootstrap/main.tf')

    def test_actual_coordinates_and_all_coordinate_negatives(self):
        front = next(x for x in c.EXPECTED if x['rule'] == 'AWS-0010')
        self.assertEqual((front['occurrences'][0]['start_line'], front['occurrences'][0]['end_line']), (120, 136))
        hosted = next(x for x in c.EXPECTED if x['target'] == 'operator-database/hosted/stores.tf')
        self.assertEqual((hosted['start_line'], hosted['end_line']), (172, 172))
        for index in range(10):
            for field in ('StartLine', 'EndLine'):
                value = copy.deepcopy(F['actual_config'])
                findings(value)[index][1]['CauseMetadata'][field] += 1
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    c.report(value, '', config_only=True)

    def test_raw_and_derived_view_keep_new_medium_visible(self):
        values = triple(); before = copy.deepcopy(values)
        decision, derived, removed = c.upload_view(*values)
        self.assertEqual(values, before)
        self.assertEqual(len(decision['iac_findings']), 10)
        self.assertEqual(len(removed), 2)
        self.assertEqual(len(derived['runs'][0]['results']), 8)
        self.assertTrue(any(x['ruleId'] == 'AWS-0065' for x in derived['runs'][0]['results']))
        restored = copy.deepcopy(derived)
        for row in sorted(removed, key=lambda x: x['raw_result_index']):
            index = row['raw_result_index']
            restored['runs'][0]['results'].insert(index, values[2]['runs'][0]['results'][index])
        self.assertEqual(restored, values[2])

    def test_full_inventory_and_high_critical_fail_closed(self):
        for which in (0, 1):
            for index in range(10):
                for mode in ('missing', 'duplicate', 'severity', 'resource', 'caller'):
                    values = triple(); r, f = findings(values[which])[index]
                    if mode == 'missing': r['Misconfigurations'].remove(f)
                    elif mode == 'duplicate': r['Misconfigurations'].append(copy.deepcopy(f))
                    elif mode == 'severity': f['Severity'] = 'CRITICAL'
                    elif mode == 'resource': f['CauseMetadata']['Resource'] = 'foreign'
                    else: f['CauseMetadata']['Occurrences'] = [{'Resource': 'foreign', 'Filename': 'foreign.tf', 'Location': {'StartLine': 1, 'EndLine': 2}}]
                    with self.subTest(which=which, index=index, mode=mode), self.assertRaises(ValueError):
                        c.classify(*values)
        for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
            for severity in ('HIGH', 'CRITICAL'):
                values = triple()
                values[0]['Results'].append(dict(Target='foreign.txt', Class='secret', Type='synthetic', **{kind: [{'Severity': severity}]}))
                with self.subTest(kind=kind, severity=severity), self.assertRaises(ValueError):
                    c.classify(*values)

    def test_new_medium_cannot_become_high_exception(self):
        for severity in ('HIGH', 'CRITICAL'):
            values = triple()
            for report in values[:2]:
                next(f for _, f in findings(report) if f['ID'] == 'AWS-0065')['Severity'] = severity
            with self.subTest(severity=severity), self.assertRaises(ValueError):
                c.classify(*values)

    def test_clean_current_source_and_each_hash_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q'); git('config', 'user.name', 'synthetic'); git('config', 'user.email', 'synthetic@example.invalid')
            git('remote', 'add', 'origin', 'https://github.com/' + c.REPOSITORY + '.git')
            for name, body in F['sources'].items():
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
            git('add', '.'); git('commit', '-qm', 'exact public fixture')
            self.assertEqual(c.source(root, git('rev-parse', 'HEAD'), os.environ)['source_sha256'], c.SOURCES)
            for name in c.SOURCES:
                p = root / name; original = p.read_bytes(); p.write_bytes(original + b'\n# changed\n')
                git('add', name); git('commit', '-qm', 'hash negative')
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'reviewed-source-hash'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                p.write_bytes(original); git('add', name); git('commit', '-qm', 'restore')


if __name__ == '__main__':
    unittest.main(verbosity=2)

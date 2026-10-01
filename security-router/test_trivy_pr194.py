"""Exact PR194 source admission; retained reports are compatibility controls only.

No fresh scan is claimed. Historical156dd data stays unchanged and labelled;
current source admission uses a separate unmodified production-module instance.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_trivy_156dd import F as HISTORICAL, findings, triple

H = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pr194_live_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
RAW = (H / 'fixtures/pr194-source-association.json').read_bytes()
assert hashlib.sha256(RAW).hexdigest() == '62a5d0b8e83d094ac4b4d1ae4788195ad1ec9041a6022f5aeeb1d9a0d88ed371'
F = json.loads(RAW)
CHANGED = {
    'infra/aws/modules/public-frontdoor/main.tf': '49f9c5d9a8854fbbfd67bae986eb00f78bd10c4ce6ce061589f0e8e1c7898cd1',
    'infra/aws/public-frontdoor/main.tf': '0863bede01821d13cc5c1dd24cec24a6e334425a9bbdb8c30027081eb1b575c6',
}
SOURCES = {**HISTORICAL['sources'], **F['sources']}


class SourcePR194(unittest.TestCase):
    def test_exact_current_source_association_and_historical_custody(self):
        self.assertEqual(F['schema'], 'cybercoach-pr194-source-association-v1')
        self.assertEqual(F['source_heads'], [
            dict(head='6931663af4711d0400d6d02f7e8312bc2d363bb0', tree='422c16964c5fc1e782e3cb51e84b0394188337ed'),
            dict(head='117b4e517363903c2da97b05dccdd57289a6946d', tree='b1a778df465b4adae5cde4d004e1bcac978a2049'),
        ])
        self.assertFalse(F['scan_performed'])
        self.assertFalse(F['hosted_clearance'])
        self.assertEqual(F['historical_fixture_sha256'], 'fa21c616473f896cf8d973f677c52b7b5765da30b25b6cde71dcd1ef9fd083db')
        self.assertEqual(c.sha((H / 'fixtures/156dd-policy-source.json').read_bytes()), F['historical_fixture_sha256'])
        self.assertEqual(set(F['sources']), set(CHANGED))
        self.assertEqual({p: c.sha(body.encode()) for p, body in F['sources'].items()}, CHANGED)
        self.assertEqual(len(SOURCES), 14)
        self.assertEqual({p: c.sha(body.encode()) for p, body in SOURCES.items()}, c.SOURCES)
        old = {p: c.sha(body.encode()) for p, body in HISTORICAL['sources'].items()}
        self.assertEqual({p for p in old if old[p] != c.SOURCES[p]}, set(CHANGED))

    def test_complete_finding_spans_and_classifications_stay_exact(self):
        expected = [c.normalized(r, f, '') for r, f in findings(HISTORICAL['actual_config'])]
        self.assertEqual(c.EXPECTED, expected)
        self.assertEqual(len(expected), 10)
        high = [x for x in expected if x['severity'] == 'HIGH']
        self.assertEqual(len(high), 2)
        self.assertTrue(all(x['rule'] == 'AWS-0132' for x in high))
        for row in expected:
            spans = [(row['target'], row['start_line'], row['end_line'])]
            spans += [(o['filename'], o['start_line'], o['end_line']) for o in row['occurrences']]
            for path, start, end in spans:
                name = 'infra/aws/' + path
                with self.subTest(path=name, start=start, end=end):
                    self.assertEqual(SOURCES[name].splitlines()[start-1:end], HISTORICAL['sources'][name].splitlines()[start-1:end])
        for result, finding in findings(HISTORICAL['actual_config']):
            body = SOURCES['infra/aws/' + result['Target']].splitlines()
            for line in finding['CauseMetadata'].get('Code', {}).get('Lines', []):
                if not line['Truncated']:
                    self.assertEqual(line['Content'], body[line['Number'] - 1])

    def test_current_source_real_git_and_every_committed_mutation(self):
        # A real local fixture Git repository, not a claim that it has the real PR HEAD.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q'); git('config', 'user.name', 'synthetic'); git('config', 'user.email', 'synthetic@example.invalid')
            git('remote', 'add', 'origin', 'https://github.com/' + c.REPOSITORY + '.git')
            for name, body in SOURCES.items():
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
            git('add', '.'); git('commit', '-qm', 'current source fixture')
            self.assertEqual(c.source(root, git('rev-parse', 'HEAD'), os.environ)['source_sha256'], c.SOURCES)
            for name in SOURCES:
                p = root / name; body = p.read_bytes(); p.write_bytes(body + b'\n# hostile source mutation\n')
                git('add', name); git('commit', '-qm', 'source mutation')
                with self.subTest(path=name), self.assertRaisesRegex(ValueError, '^reviewed-source-hash$'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                p.write_bytes(body); git('add', name); git('commit', '-qm', 'restore source')
            for name in CHANGED:
                p = root / name; body = p.read_bytes(); p.write_text(HISTORICAL['sources'][name])
                git('add', name); git('commit', '-qm', 'obsolete source')
                with self.subTest(obsolete=name), self.assertRaisesRegex(ValueError, '^reviewed-source-hash$'):
                    c.source(root, git('rev-parse', 'HEAD'), os.environ)
                p.write_bytes(body); git('add', name); git('commit', '-qm', 'restore source')
            with self.assertRaisesRegex(ValueError, '^checkout-head-tree$'):
                c.source(root, '0' * 40, os.environ)
            git('remote', 'set-url', 'origin', 'https://github.com/foreign/repository')
            with self.assertRaisesRegex(ValueError, '^origin$'):
                c.source(root, git('rev-parse', 'HEAD'), os.environ)
            git('remote', 'set-url', 'origin', 'https://github.com/' + c.REPOSITORY + '.git')
            stray = root / 'untracked'; stray.write_text('synthetic')
            with self.assertRaisesRegex(ValueError, '^dirty-checkout$'):
                c.source(root, git('rev-parse', 'HEAD'), os.environ)
            stray.unlink()
            name = next(iter(CHANGED)); p = root / name; body = p.read_bytes()
            p.unlink(); p.symlink_to(root / 'infra/aws/operator-foundations/access-logging.tf')
            git('add', name); git('commit', '-qm', 'linked source')
            with self.assertRaisesRegex(ValueError, '^checkout-links-or-submodules$'):
                c.source(root, git('rev-parse', 'HEAD'), os.environ)
            p.unlink(); p.write_bytes(body); git('add', name); git('commit', '-qm', 'restore source')
            self.assertEqual(c.source(root, git('rev-parse', 'HEAD'), os.environ)['source_sha256'], c.SOURCES)

    def test_current_context_and_hostile_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory).resolve() / 'event.json'
            head = F['source_heads'][1]['head']
            value = dict(repository=dict(full_name=c.REPOSITORY), pull_request=dict(base=dict(repo=dict(full_name=c.REPOSITORY)), head=dict(sha=head)))
            event.write_text(json.dumps(value))
            env = dict(CC_REPOSITORY=c.REPOSITORY, GITHUB_REPOSITORY=c.REPOSITORY,
                       CC_WORKFLOW_REF=c.WORKFLOW_REF, GITHUB_WORKFLOW_REF=c.WORKFLOW_REF,
                       CC_WORKFLOW_SHA='a'*40, GITHUB_WORKFLOW_SHA='a'*40,
                       CC_HEAD_SHA=head, GITHUB_EVENT_NAME='pull_request', GITHUB_RUN_ID='123',
                       GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_PATH=str(event))
            self.assertEqual(c.context(env)['event_head'], head)
            for field, bad, code in [
                ('CC_REPOSITORY', 'foreign/repo', 'repository'),
                ('CC_WORKFLOW_REF', c.WORKFLOW_REF + '-other', 'workflow-ref'),
                ('GITHUB_WORKFLOW_SHA', 'b'*40, 'workflow-sha'),
                ('GITHUB_WORKFLOW_REF', 'foreign', 'workflow-sha'),
                ('CC_HEAD_SHA', 'invalid', 'event-head'),
                ('GITHUB_EVENT_NAME', 'push', 'event-kind'),
                ('GITHUB_RUN_ATTEMPT', '0', 'run-identity'),
            ]:
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    c.context(env | {field: bad})
            value['pull_request']['head']['sha'] = '0'*40; event.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, '^event-binding$'):
                c.context(env)

    def test_current_classifier_retained_report_compatibility_and_raw_preservation(self):
        # Original reports retain their original metadata; these are compatibility inputs.
        values = triple(); before = copy.deepcopy(values)
        decision, derived, removed = c.upload_view(*values)
        self.assertEqual(values, before)
        self.assertEqual(len(decision['iac_findings']), 10)
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(x['classification']['rule'] == 'AWS-0132' for x in removed))
        self.assertEqual(len(derived['runs'][0]['results']), 8)
        kept = [r for i, r in enumerate(values[2]['runs'][0]['results']) if i not in [x['raw_result_index'] for x in removed]]
        self.assertEqual(derived['runs'][0]['results'], kept)
        self.assertTrue(any(x['ruleId'] == 'AWS-0065' for x in kept))

    def test_current_classifier_rejects_complete_inventory_and_high_critical_mutations(self):
        for which in (0, 1):
            for index in range(10):
                for mode in ('missing', 'duplicate', 'severity', 'resource', 'caller'):
                    values = triple(); r, f = findings(values[which])[index]
                    if mode == 'missing': r['Misconfigurations'].remove(f)
                    elif mode == 'duplicate': r['Misconfigurations'].append(copy.deepcopy(f))
                    elif mode == 'severity': f['Severity'] = 'CRITICAL'
                    elif mode == 'resource': f['CauseMetadata']['Resource'] = 'foreign'
                    else: f['CauseMetadata']['Occurrences'] = [] if f['CauseMetadata'].get('Occurrences') else [{'Resource':'foreign','Filename':'foreign.tf','Location':{'StartLine':1,'EndLine':2}}]
                    with self.subTest(which=which, index=index, mode=mode), self.assertRaises(ValueError):
                        c.classify(*values)
        for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
            for severity in ('HIGH', 'CRITICAL'):
                values = triple()
                values[0]['Results'].append(dict(Target='foreign.txt', Class='secret', Type='synthetic', **{kind:[{'Severity':severity}]}))
                with self.subTest(kind=kind, severity=severity), self.assertRaisesRegex(ValueError, '^unaccepted-high-critical$'):
                    c.classify(*values)

    def test_current_sarif_mismatch_and_suppression_fail_closed(self):
        values = triple(); values[2]['runs'][0]['results'][0]['message']['text'] = 'substitution'
        with self.assertRaisesRegex(ValueError, '^sarif-semantic-multiset$'):
            c.upload_view(*values)
        values = triple(); values[2]['runs'][0]['results'].append(copy.deepcopy(values[2]['runs'][0]['results'][0]))
        with self.assertRaisesRegex(ValueError, '^sarif-semantic-multiset$'):
            c.upload_view(*values)
        values = triple(); values[0]['Results'][0]['MisconfSummary']['Exceptions'] = 1
        with self.assertRaisesRegex(ValueError, '^suppressed-misconfigurations$'):
            c.upload_view(*values)


if __name__ == '__main__':
    unittest.main(verbosity=2)

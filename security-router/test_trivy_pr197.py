"""Focused current successor controls; no hosted or scanner success simulated."""
import ast
import copy
import difflib
import hashlib
import subprocess
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

H = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pr197_live_contract', H / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class GuardReceipts(unittest.TestCase):
    def receipt(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / 'checkout'; checkout.mkdir()
            runner = root / 'runner'; runner.mkdir()
            outputs = root / 'outputs'
            env = dict(GITHUB_WORKSPACE=str(checkout), RUNNER_TEMP=str(runner), GITHUB_OUTPUT=str(outputs))
            stdout = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(c, 'execute', side_effect=failure), contextlib.redirect_stdout(stdout):
                self.assertEqual(c.main(), 1)
            receipt = c.decode(next(runner.glob('*/receipt.json')).read_bytes())
            self.assertEqual(receipt['schema'], 'ncdit-trivy-contract-receipt-v2')
            self.assertEqual(receipt['contract'], c.CONTRACT)
            self.assertEqual(receipt['status'], 'blocked')
            self.assertEqual(receipt['organization_policy_acceptance'], 'not-established')
            self.assertEqual(stdout.getvalue(), '::error::CyberCoach Trivy contract blocked; inspect retained evidence.\n')
            self.assertNotIn('secret-value-never-emit', json.dumps(receipt))
            return receipt

    def test_owned_guard_labels_preserve_failure_type_and_blocks(self):
        for label in ('reviewed-source-hash', 'exact-iac-inventory', 'unaccepted-high-critical'):
            def failure(*args):
                c.need(False, label)
            with self.subTest(label=label):
                actual = self.receipt(failure)
                self.assertEqual(actual['error_type'], 'ValueError')
                self.assertEqual(actual['guard_code'], label)
                self.assertEqual(set(actual), {'schema','contract','status','organization_policy_acceptance','error_type','guard_code'})

    def test_unknown_exception_or_forged_label_never_emits_text(self):
        class DerivedGuard(c._GuardFailure):
            pass
        for error in (ValueError('secret-value-never-emit'), RuntimeError('secret-value-never-emit'),
                      ValueError('reviewed-source-hash'), c._GuardFailure('secret-value-never-emit'),
                      c._GuardFailure('reviewed-source-hash', 'secret-value-never-emit'),
                      c._GuardFailure(), DerivedGuard('reviewed-source-hash')):
            with self.subTest(error_type=type(error).__name__):
                actual = self.receipt(error)
                self.assertNotIn('guard_code', actual)
                self.assertEqual(set(actual), {'schema','contract','status','organization_policy_acceptance','error_type'})
                self.assertEqual(actual['error_type'], 'ValueError' if type(error) is c._GuardFailure else type(error).__name__)

    def test_all_guard_call_labels_are_owned_literal_constants(self):
        source = ast.parse((H / 'trivy_contract.py').read_text())
        calls = [n for n in ast.walk(source) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'need']
        self.assertGreater(len(calls), 50)
        for call in calls:
            with self.subTest(line=call.lineno):
                self.assertIsInstance(call.args[1], ast.Constant)
                self.assertIsInstance(call.args[1].value, str)
        with self.assertRaisesRegex(ValueError, '^reviewed-source-hash$'):
            c.need(False, 'reviewed-source-hash')
        self.assertIsNone(c.need(True, 'reviewed-source-hash'))


# All current report inputs below are PROJECTION, never current scanner output.
from test_trivy_156dd import F as HISTORICAL, findings
from test_trivy_pr194 import SOURCES as PR194_SOURCES
F = json.loads((H / 'fixtures/pr197-source-association.json').read_text())
P = json.loads((H / 'fixtures/pr197-inventory-projection.json').read_text())
SOURCES = F['sources']
CHANGED = {'infra/aws/operator-foundations/access-logging.tf': '122dee0c94a8d757ff2263ec1279d614a6c6dce4bf636c787ceb80fefa470cc9'}

def triple():
    return tuple(copy.deepcopy(P[k]) for k in ('projected_filesystem', 'projected_config', 'projected_sarif'))


class SourcePR197(unittest.TestCase):
    def test_exact_sources_and_preserved_real_baseline(self):
        self.assertEqual(c.sha((H/'fixtures/pr197-inventory-projection.json').read_bytes()), 'df3cea9ac43a42035cfcb70efa0b3de00fca925a0c3791f14cc1d322c184ad69')
        self.assertEqual(c.sha((H/'fixtures/pr197-source-association.json').read_bytes()), 'da8a77ce90af83719949da73ff213008bc2e3c9efe4f11fb2d4de8bc187d96ad')
        self.assertEqual(F['source_head'], '82fbb3fb334a9594fd304f79810dece51e694a9c')
        self.assertEqual(F['source_tree'], '6dc7ca9d228c35cdef3a7788d89267a5db02f401')
        self.assertEqual(P['classification'], 'PROJECTION')
        self.assertFalse(P['scan_performed']); self.assertFalse(P['hosted_clearance'])
        self.assertFalse(F['scan_performed']); self.assertFalse(F['hosted_clearance'])
        self.assertEqual(P['baseline_actual_config_sha256'], c.sha(HISTORICAL['actual_config_raw'].encode()))
        self.assertEqual(json.loads(HISTORICAL['actual_config_raw']), HISTORICAL['actual_config'])
        self.assertEqual(P['baseline_native_terminal'], HISTORICAL['actual_config_native_terminal'])
        self.assertEqual(P['baseline_scanner'], HISTORICAL['scanner'])
        self.assertEqual(P['baseline_scanner']['version'], c.VERSION)
        self.assertEqual(P['baseline_scanner']['platform'], 'darwin/arm64')
        self.assertEqual(P['baseline_scanner']['sha256'], '3122de2c39d6ae433c2355a87508fb18dca637cf7f149e0006b63ddefb0cdc52')
        self.assertEqual(len(SOURCES), 14)
        self.assertEqual({p:c.sha(b.encode()) for p,b in SOURCES.items()}, c.SOURCES)
        self.assertEqual(set(PR194_SOURCES),set(SOURCES))
        self.assertEqual({p for p in SOURCES if SOURCES[p]!=PR194_SOURCES[p]},set(CHANGED))
        p=next(iter(CHANGED)); a=PR194_SOURCES[p].splitlines(True); b=SOURCES[p].splitlines(True)
        self.assertEqual(difflib.SequenceMatcher(None,a,b,autojunk=False).get_opcodes(), [('equal',0,6,0,6),('replace',6,7,6,8),('equal',7,154,8,155)])
        self.assertEqual(''.join(a[7:]), ''.join(b[8:]))
        # Every resource/module/output/data/local block is in this byte-identical suffix.
        self.assertTrue(all(i>7 for i,l in enumerate(a,1) if l.startswith(('resource ', 'module ', 'output ', 'data ', 'locals '))))

    def test_complete_projection_changes_only_proved_locations(self):
        expected=[c.normalized(r,f,'') for r,f in findings(HISTORICAL['actual_config'])]
        shifted=[]
        for row in expected:
            if row['target']=='operator-foundations/access-logging.tf':
                self.assertIn((row['start_line'],row['end_line']), ((60,67),(89,100)))
                row['start_line']+=1;row['end_line']+=1;shifted.append(row)
        self.assertEqual(len(shifted),2);self.assertEqual(expected,c.EXPECTED)
        values=triple()
        # Reverse precisely four finding locations plus their excerpt line numbers and two SARIF regions.
        for report in values[:2]:
            count=0
            for result,finding in findings(report):
                if result['Target'].removeprefix('infra/aws/')!='operator-foundations/access-logging.tf':continue
                count+=1;cause=finding['CauseMetadata'];cause['StartLine']-=1;cause['EndLine']-=1
                for line in cause.get('Code',{}).get('Lines',[]):line['Number']-=1
            self.assertEqual(count,2)
        count=0
        for result in values[2]['runs'][0]['results']:
            for loc in result.get('locations',[]):
                loc=loc['physicalLocation']
                if loc['artifactLocation']['uri']=='infra/aws/operator-foundations/access-logging.tf':
                    count+=1;loc['region']['startLine']-=1;loc['region']['endLine']-=1
        self.assertEqual(count,2)
        self.assertEqual(values,tuple(HISTORICAL[k] for k in ('synthetic_filesystem','actual_config','synthetic_sarif')))
        for old,new in zip([c.normalized(r,f,'') for r,f in findings(HISTORICAL['actual_config'])],c.EXPECTED):
            oldspans=[(old['target'],old['start_line'],old['end_line'])]+[(o['filename'],o['start_line'],o['end_line']) for o in old['occurrences']]
            newspans=[(new['target'],new['start_line'],new['end_line'])]+[(o['filename'],o['start_line'],o['end_line']) for o in new['occurrences']]
            for (p,a,b),(q,x,y) in zip(oldspans,newspans):
                self.assertEqual(p,q)
                self.assertEqual(HISTORICAL['sources']['infra/aws/'+p].splitlines()[a-1:b],SOURCES['infra/aws/'+q].splitlines()[x-1:y])
        for result,finding in findings(P['projected_config']):
            body=SOURCES['infra/aws/'+result['Target']].splitlines()
            for line in finding['CauseMetadata'].get('Code',{}).get('Lines',[]):
                if not line['Truncated']:self.assertEqual(line['Content'],body[line['Number']-1])

    def test_every_coordinate_and_occurrence_negative_and_old_inventory(self):
        with self.assertRaisesRegex(ValueError,'exact-iac-inventory'):
            c.report(HISTORICAL['actual_config'],'',config_only=True)
        for which in (0,1):
            for index in range(10):
                for field in ('StartLine','EndLine'):
                    values=triple();findings(values[which])[index][1]['CauseMetadata'][field]+=1
                    with self.subTest(which=which,index=index,field=field),self.assertRaises(ValueError):c.classify(*values)
                for occ in range(len(findings(triple()[which])[index][1]['CauseMetadata'].get('Occurrences',[]))):
                    for field in ('StartLine','EndLine'):
                        values=triple();findings(values[which])[index][1]['CauseMetadata']['Occurrences'][occ]['Location'][field]+=1
                        with self.subTest(which=which,index=index,occ=occ,field=field),self.assertRaises(ValueError):c.classify(*values)

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
                p = root / name; body = p.read_bytes(); p.write_text(PR194_SOURCES[name])
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
            head = F['source_head']
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
        # Derived reports are labeled PROJECTION; retained actual baseline bytes are unchanged.
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

"""CyberCoach Trivy policy tests: accepted-list policy, real scanner fixture and workflow parity."""
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import zipfile

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('contract', HERE / 'trivy_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

# Real hosted CyberCoach precheck artifact (run 10716525352): complete Trivy 0.70.0
# repository JSON, infra/aws config JSON and native SARIF conversion.
ARTIFACT = HERE / 'fixtures/r26-trivy-10716525352.zip'
RAW_HASHES = {
    'filesystem.json': '339c244a84ff9472b18d36df222e9d9a93feadd02ff0d9623fee36d2a9555642',
    'config.json': 'af258ced0c36ed4353a72a119906aac6c2dfe3e77c385603b1089ccc81d16d9b',
    'trivy.sarif': '527ed8744669c0522b5c6f0e2448c005d5a0017dd19b3e609747d87ddc2eec53',
}
RECEIVERS = ('infra/aws/modules/audit-foundation/receivers.tf', 'infra/aws/operator-foundations/access-logging.tf')
# Digests of the three original non-CyberCoach Trivy step blocks after removing only the
# CyberCoach repository condition; they pin every other repository's Trivy behavior.
LEGACY_BLOCKS = {
    'Trivy — gate on CRITICAL/HIGH': '3af52b72b595333558414108a198a052d20b74f4c2d35cbfdf2b9440c14c0edc',
    'Trivy — SARIF for the Security tab': '7d9b019b16f4463bebf0722ff73b07331e57264c136a75f676460c5d12802c34',
    'Upload Trivy SARIF': '12bff075724c11683c92b93fb27404e33f88997beabef756ce4a5af2648d0ab9',
}
SUMMARY_SHA256 = 'f484aa6f6ce42c6bd849bf200910bfb1db84785a9279ac001820cc13d3f2f97a'


def reports():
    with zipfile.ZipFile(ARTIFACT) as z:
        return tuple(c.decode(z.read(n)) for n in ('filesystem.json', 'config.json', 'trivy.sarif'))


def misconfigs(report, target_suffix, rule=None):
    return [f for r in report['Results'] if r['Target'].endswith(target_suffix)
            for f in r.get('Misconfigurations', []) if rule is None or f['ID'] == rule]


def add_misconfig(report, target, rule, severity, prefix=''):
    """Append a well-formed Terraform misconfiguration to `target` (created if absent)."""
    target = target[len(prefix):] if prefix and target.startswith(prefix) else target
    row = next((r for r in report['Results'] if r['Target'] == target and r['Class'] == 'config'), None)
    if row is None:
        row = dict(Target=target, Class='config', Type='terraform',
                   MisconfSummary=dict(Successes=1, Failures=0))
        report['Results'].append(row)
    row.setdefault('Misconfigurations', []).append(dict(
        Type='Terraform Security Check', ID=rule, Severity=severity, Status='FAIL',
        Namespace='builtin.aws.synthetic.' + rule.lower().replace('-', ''),
        CauseMetadata=dict(Provider='AWS', Service='synthetic', StartLine=1, EndLine=2)))
    row['MisconfSummary']['Failures'] = len(row['Misconfigurations'])


def add_to_both(fs, config, target, rule, severity):
    add_misconfig(fs, target, rule, severity)
    add_misconfig(config, target, rule, severity, prefix=c.IAC_ROOT)


def sarif_error(rule, uri):
    return dict(ruleId=rule, ruleIndex=0, level='error', message=dict(text='synthetic'),
                locations=[dict(physicalLocation=dict(artifactLocation=dict(uri=uri, uriBaseId='ROOTPATH'),
                    region=dict(startLine=1, endLine=1, startColumn=1, endColumn=1)), message=dict(text=uri))])


def blockers_of(callable_, *args, **kwargs):
    try:
        callable_(*args, **kwargs)
    except c._GuardFailure as error:
        if error.args == ('unaccepted-high-critical',):
            return error.details
        raise
    return []


def env_fixture(root, temp):
    event = temp / 'event.json'
    event.write_text(c.canonical(dict(repository=dict(full_name=c.REPOSITORY),
        pull_request=dict(base=dict(repo=dict(full_name=c.REPOSITORY)), head=dict(sha='a'*40)))))
    return dict(PATH=os.environ['PATH'], HOME=str(temp), GITHUB_WORKSPACE=str(root), RUNNER_TEMP=str(temp),
        GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(temp/'output'), GITHUB_EVENT_NAME='pull_request',
        GITHUB_REPOSITORY=c.REPOSITORY, CC_REPOSITORY=c.REPOSITORY, CC_HEAD_SHA='a'*40,
        CC_WORKFLOW_REF=c.WORKFLOW_REF, CC_WORKFLOW_SHA='b'*40,
        GITHUB_WORKFLOW_REF=c.WORKFLOW_REF, GITHUB_WORKFLOW_SHA='b'*40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')


class AcceptedList(unittest.TestCase):
    def test_production_entries_are_rule_and_path_with_justification(self):
        index = c.accepted_index()
        self.assertEqual(set(index), {('AWS-0132', p) for p in RECEIVERS})
        for entry in c.ACCEPTED:
            self.assertEqual(set(entry), {'rule', 'path', 'justification'})
            self.assertTrue(entry['path'].startswith(c.IAC_ROOT))
            self.assertIn('https://docs.aws.amazon.com/', entry['justification'])

    def test_malformed_entries_rejected(self):
        good = dict(rule='AWS-0132', path='infra/aws/a.tf', justification='x' * 40)
        bad = [
            dict(good, justification=''), dict(good, justification='too short'),
            dict(good, justification=' ' * 60), dict(good, rule='aws-0132'), dict(good, rule='AWS-132'),
            dict(good, rule=''), dict(good, path='/infra/aws/a.tf'), dict(good, path='infra/../a.tf'),
            dict(good, path='infra//a.tf'), dict(good, path=''), dict(good, start_line=10),
            dict(good, sha256='0' * 64), {k: v for k, v in good.items() if k != 'justification'},
        ]
        for entry in bad:
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, 'accepted-list|noncanonical-path'):
                c.accepted_index([entry])
        with self.assertRaisesRegex(ValueError, 'accepted-list'):
            c.accepted_index([good, dict(good, justification='y' * 40)])
        self.assertEqual(c.accepted_index([]), {})


class Policy(unittest.TestCase):
    def test_fixture_is_the_retained_real_artifact(self):
        with zipfile.ZipFile(ARTIFACT) as z:
            for name, digest in RAW_HASHES.items():
                self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(), digest, name)

    def test_real_scan_passes_with_exactly_the_two_accepted_receivers(self):
        decision = c.classify(*reports())
        accepted = decision['accepted_high_critical_findings']
        self.assertEqual(sorted((a['rule'], a['path'], a['severity']) for a in accepted),
                         [('AWS-0132', p, 'HIGH') for p in RECEIVERS])
        self.assertTrue(all(a['justification'] for a in accepted))
        self.assertEqual(decision['unused_accepted_entries'], [])
        self.assertEqual(decision['unaccepted_high_critical_findings'], [])
        self.assertEqual(decision['finding_counts_by_kind_and_severity']['Misconfigurations/LOW'], 3)
        self.assertEqual(decision['finding_counts_by_kind_and_severity']['Misconfigurations/MEDIUM'], 2)
        self.assertGreater(decision['configuration_successes'], 0)

    def test_line_resource_and_source_changes_do_not_matter(self):
        fs, config, sarif = reports()
        for report in (fs, config):
            for f in misconfigs(report, '.tf'):
                f['CauseMetadata']['StartLine'] += 37; f['CauseMetadata']['EndLine'] += 41
                f['CauseMetadata']['Resource'] = 'module.renamed'
                f['CauseMetadata'].pop('Occurrences', None); f['CauseMetadata'].pop('Code', None)
        self.assertEqual(len(c.classify(fs, config, sarif)['accepted_high_critical_findings']), 2)

    def test_new_low_and_medium_findings_pass_and_stay_visible(self):
        fs, config, sarif = reports()
        add_to_both(fs, config, 'infra/aws/new/main.tf', 'AWS-0999', 'MEDIUM')
        add_to_both(fs, config, 'infra/aws/new/main.tf', 'AWS-0998', 'LOW')
        decision = c.classify(fs, config, sarif)
        self.assertEqual(decision['finding_counts_by_kind_and_severity']['Misconfigurations/MEDIUM'], 3)
        self.assertIn(dict(rule='AWS-0999', severity='MEDIUM', path='infra/aws/new/main.tf', type='terraform'),
                      decision['iac_findings'])

    def test_unaccepted_high_critical_misconfigurations_block(self):
        cases = [
            ('infra/aws/new/main.tf', 'AWS-0132', 'HIGH'),     # accepted rule, other file
            (RECEIVERS[0], 'AWS-0089', 'HIGH'),                # accepted file, other rule
            (RECEIVERS[1], 'AWS-0132', 'CRITICAL'),            # accepted key at CRITICAL is still that key
            ('infra/aws/new/main.tf', 'AWS-0001', 'CRITICAL'),
        ]
        for target, rule, severity in cases:
            with self.subTest(target=target, rule=rule, severity=severity):
                fs, config, sarif = reports()
                add_to_both(fs, config, target, rule, severity)
                found = blockers_of(c.classify, fs, config, sarif)
                if (rule, target) in c.accepted_index():
                    self.assertEqual(found, [])
                else:
                    self.assertEqual(found, [dict(kind='Misconfigurations', severity=severity, path=target, rule=rule)])

    def test_dockerfile_high_outside_iac_blocks(self):
        fs, config, sarif = reports()
        fs['Results'].append(dict(Target='services/new/Dockerfile', Class='config', Type='dockerfile',
            MisconfSummary=dict(Successes=1, Failures=1), Misconfigurations=[dict(
                Type='Dockerfile Security Check', ID='DS-0002', Severity='HIGH', Status='FAIL')]))
        self.assertEqual(blockers_of(c.classify, fs, config, sarif),
                         [dict(kind='Misconfigurations', severity='HIGH', path='services/new/Dockerfile', rule='DS-0002')])

    def test_other_categories_always_block_even_at_an_accepted_key(self):
        target = RECEIVERS[0]
        cases = [('Vulnerabilities', dict(VulnerabilityID='AWS-0132', PkgName='p', InstalledVersion='1')),
                 ('Secrets', dict(RuleID='AWS-0132', Match='AKIA-must-not-leak')),
                 ('Licenses', dict(Name='AGPL-3.0', PkgName='p'))]
        for kind, finding in cases:
            for severity in c.BLOCKING:
                with self.subTest(kind=kind, severity=severity):
                    fs, config, sarif = reports()
                    row = next(r for r in fs['Results'] if r['Target'] == target)
                    row.setdefault(kind, []).append(dict(finding, Severity=severity))
                    found = blockers_of(c.classify, fs, config, sarif)
                    self.assertEqual(len(found), 1)
                    self.assertEqual((found[0]['kind'], found[0]['severity'], found[0]['path']), (kind, severity, target))
                    self.assertNotIn('AKIA', c.canonical(found))

    def test_removed_accepted_finding_passes_and_reports_unused_entry(self):
        fs, config, sarif = reports()
        for report, target in ((fs, RECEIVERS[1]), (config, RECEIVERS[1][len(c.IAC_ROOT):])):
            row = next(r for r in report['Results'] if r['Target'] == target)
            row['Misconfigurations'] = [f for f in row['Misconfigurations'] if f['ID'] != 'AWS-0132']
            row['MisconfSummary']['Failures'] = len(row['Misconfigurations'])
        sarif['runs'][0]['results'] = [r for r in sarif['runs'][0]['results'] if c.sarif_key(r) != ('AWS-0132', RECEIVERS[1])]
        decision, derived, removed = c.upload_view(fs, config, sarif)
        self.assertEqual(decision['unused_accepted_entries'], [dict(rule='AWS-0132', path=RECEIVERS[1])])
        self.assertEqual(len(removed), 1)

    def test_scans_must_agree_on_iac_rules_and_files(self):
        fs, config, sarif = reports()
        add_misconfig(fs, 'infra/aws/new/main.tf', 'AWS-0999', 'LOW')
        with self.assertRaisesRegex(ValueError, 'paired-iac-projection'):
            c.classify(fs, config, sarif)
        fs, config, sarif = reports()
        misconfigs(config, 'access-logging.tf', 'AWS-0132')[0]['Severity'] = 'MEDIUM'
        with self.assertRaisesRegex(ValueError, 'paired-iac-projection'):
            c.classify(fs, config, sarif)

    def test_suppression_schema_and_identity_guards(self):
        mutations = {
            'suppressed-misconfigurations': lambda fs, cf: next(r for r in fs['Results'] if r['Class'] == 'config')['MisconfSummary'].update(Exceptions=1),
            'misconf-summary-count': lambda fs, cf: next(r for r in fs['Results'] if r.get('Misconfigurations'))['MisconfSummary'].update(Failures=99),
            'report-schema': lambda fs, cf: fs['Trivy'].update(Version='0.69.0'),
            'report-repository': lambda fs, cf: fs['Metadata'].update(RepoURL='https://github.com/foreign/repo'),
            'config-report-class': lambda fs, cf: cf['Results'].append(dict(Target='x', Class='secret')),
            'missing-results': lambda fs, cf: fs.update(Results=[]),
            'duplicate-result': lambda fs, cf: fs['Results'].append(copy.deepcopy(fs['Results'][0])),
            'finding-severity': lambda fs, cf: misconfigs(fs, '.tf')[0].update(Severity='high'),
            'misconfiguration-identity': lambda fs, cf: misconfigs(fs, '.tf')[0].update(Status='PASS'),
            'noncanonical-path': lambda fs, cf: fs['Results'][0].update(Target='../escape.tf'),
            'no-evaluated-configuration-successes': lambda fs, cf: [r['MisconfSummary'].update(Successes=0) for r in fs['Results'] if r['Class'] == 'config'],
        }
        for code, mutate in mutations.items():
            with self.subTest(code=code):
                fs, config, sarif = reports(); mutate(fs, config)
                with self.assertRaisesRegex(ValueError, code):
                    c.classify(fs, config, sarif)


class Sarif(unittest.TestCase):
    def test_upload_drops_only_the_accepted_results_and_keeps_order(self):
        fs, config, sarif = reports(); original = copy.deepcopy(sarif)
        decision, derived, removed = c.upload_view(fs, config, sarif)
        self.assertEqual(sarif, original)
        self.assertEqual(sorted((r['rule'], r['path']) for r in removed), [('AWS-0132', p) for p in RECEIVERS])
        indices = {r['raw_result_index'] for r in removed}
        self.assertEqual(derived['runs'][0]['results'],
                         [r for i, r in enumerate(original['runs'][0]['results']) if i not in indices])
        self.assertEqual({k: v for k, v in derived['runs'][0].items() if k != 'results'},
                         {k: v for k, v in original['runs'][0].items() if k != 'results'})

    def test_missing_or_duplicate_accepted_sarif_result_never_derives(self):
        fs, config, sarif = reports()
        sarif['runs'][0]['results'] = [r for r in sarif['runs'][0]['results'] if c.sarif_key(r) != ('AWS-0132', RECEIVERS[0])]
        with self.assertRaisesRegex(ValueError, 'sarif-accepted-correspondence'):
            c.upload_view(fs, config, sarif)
        fs, config, sarif = reports()
        sarif['runs'][0]['results'].append(sarif_error('AWS-0132', RECEIVERS[0]))
        with self.assertRaisesRegex(ValueError, 'sarif-accepted-correspondence'):
            c.upload_view(fs, config, sarif)

    def test_sarif_structure_and_invocation_guards(self):
        mutations = {
            'sarif-schema': lambda s: s.update(version='2.0.0'),
            'sarif-tool': lambda s: s['runs'][0]['tool']['driver'].update(version='0.69.0'),
            'sarif-failed-invocation': lambda s: s['runs'][0].update(invocations=[dict(executionSuccessful=False)]),
            'sarif-results': lambda s: s['runs'][0].update(results=None),
            'sarif-result-structure': lambda s: s['runs'][0]['results'].append(dict(ruleId='x', level='fatal', locations=[{}])),
        }
        for code, mutate in mutations.items():
            with self.subTest(code=code):
                fs, config, sarif = reports(); mutate(sarif)
                with self.assertRaisesRegex(ValueError, code):
                    c.upload_view(fs, config, sarif)

    def test_annotation_cannot_inject_workflow_commands(self):
        line = c.annotation(dict(kind='Misconfigurations', severity='HIGH', path='a,b:c\n::stop-commands::x.tf',
                                 rule='AWS-0001\r\n::add-mask::'))
        self.assertEqual(line.count('\n'), 0); self.assertEqual(line.count('\r'), 0)
        self.assertTrue(line.startswith('::error file=a%2Cb%3Ac%0A%3A%3Astop-commands%3A%3Ax.tf::HIGH '))


class Context(unittest.TestCase):
    def test_trusted_github_context_and_wrong_event_bindings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); env = env_fixture(root/'source', root)
            self.assertEqual(c.context(env)['workflow_ref'], c.WORKFLOW_REF)
            for k in ('CC_REPOSITORY', 'GITHUB_REPOSITORY', 'CC_WORKFLOW_REF', 'CC_WORKFLOW_SHA', 'CC_HEAD_SHA',
                      'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
                for value in ('', 'foreign'):
                    with self.subTest(key=k, value=value), self.assertRaises(ValueError):
                        c.context(dict(env, **{k: value}))
            path = Path(env['GITHUB_EVENT_PATH']); event = c.decode(path.read_bytes())
            event['pull_request']['head']['sha'] = 'c'*40; path.write_text(c.canonical(event))
            with self.assertRaisesRegex(ValueError, 'event-binding'):
                c.context(env)

    def test_no_inherited_target_configuration_credentials_or_python_code(self):
        env = dict(PATH='/usr/bin', HOME='/tmp', TRIVY_CONFIG='hostile', TRIVY_IGNOREFILE='hostile',
                   PYTHONPATH='.', GITHUB_TOKEN='secret', AWS_ACCESS_KEY_ID='secret', GIT_CONFIG_COUNT='1')
        actual = c.environment(env)
        self.assertFalse(any(k.startswith(('TRIVY_', 'PYTHON', 'AWS_')) for k in actual))
        self.assertNotIn('GITHUB_TOKEN', actual); self.assertNotIn('GIT_CONFIG_COUNT', actual)

    def test_commands_ignore_target_configuration_and_scan_everything(self):
        first, second, last = c.commands(Path('/tool/trivy'), Path('/source'), Path('/out'), Path('/cache'))
        self.assertEqual(first[first.index('--scanners')+1], 'vuln,misconfig,secret,license')
        for args in (first, second):
            self.assertEqual(args[args.index('--severity')+1], ','.join(c.SEVERITIES))
            self.assertEqual(args[args.index('--config')+1], '/dev/null')
            self.assertEqual(args[args.index('--ignorefile')+1], '/dev/null')
            self.assertIn('--skip-check-update', args)
            self.assertNotIn('--skip-files', args); self.assertNotIn('--skip-dirs', args)
        self.assertEqual(second[1], 'config'); self.assertEqual(second[-1], '/source/infra/aws')
        self.assertEqual((last[1], last[-1]), ('convert', '/out/filesystem.json'))

    def test_scanner_identity_is_pinned_and_measured(self):
        self.assertEqual(c.VERSION, '0.70.0')
        self.assertEqual(c.BINARY, '379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166')
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp).resolve()/'trivy'; binary.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'scanner-binary'):
                c.scanner(binary, dict(PATH='/usr/bin'))

    def test_external_policy_cache_or_link_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp).resolve(); c.no_policy(cache)
            (cache/'x.rego').write_text('')
            with self.assertRaises(ValueError):
                c.no_policy(cache)


class Source(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'source'; self.root.mkdir()
        self.env = dict(os.environ)
        self.git('init', '-q'); self.git('config', 'user.name', 'synthetic'); self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('remote', 'add', 'origin', 'https://github.com/'+c.REPOSITORY+'.git')
        for name in RECEIVERS:
            path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('resource "x" "y" {}\n')
        self.git('add', '.'); self.git('commit', '-qm', 'source')
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def test_committed_iac_changes_no_longer_need_a_policy_change(self):
        before = c.source(self.root, self.head, self.env)
        (self.root/RECEIVERS[0]).write_text('resource "x" "y" { changed = true }\n')
        self.git('add', '.'); self.git('commit', '-qm', 'iac change')
        after = c.source(self.root, self.git('rev-parse', 'HEAD'), self.env)
        self.assertNotEqual(before['tree'], after['tree'])
        self.assertEqual(set(after), {'commit', 'tree', 'clean'})

    def test_head_dirty_ignored_link_origin_and_missing_iac_rejected(self):
        with self.assertRaisesRegex(ValueError, 'checkout-head-tree'):
            c.source(self.root, 'f'*40, self.env)
        (self.root/'new.txt').write_text('dirty')
        with self.assertRaisesRegex(ValueError, 'dirty-checkout'):
            c.source(self.root, self.head, self.env)
        (self.root/'new.txt').unlink()
        self.git('remote', 'set-url', 'origin', 'https://github.com/foreign/repo.git')
        with self.assertRaisesRegex(ValueError, 'origin'):
            c.source(self.root, self.head, self.env)
        self.git('remote', 'set-url', 'origin', 'https://github.com/'+c.REPOSITORY)
        (self.root/'link').symlink_to(self.root/RECEIVERS[0]); self.git('add', '.'); self.git('commit', '-qm', 'link')
        with self.assertRaisesRegex(ValueError, 'checkout-links-or-submodules'):
            c.source(self.root, self.git('rev-parse', 'HEAD'), self.env)
        self.git('rm', '-rq', 'link', 'infra'); self.git('commit', '-qm', 'no iac')
        (self.root/'README').write_text('x'); self.git('add', '.'); self.git('commit', '-qm', 'readme')
        with self.assertRaisesRegex(ValueError, 'missing-iac-root'):
            c.source(self.root, self.git('rev-parse', 'HEAD'), self.env)


class Runtime(unittest.TestCase):
    def run_execute(self, failure):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        out = Path(temp.name).resolve(); root = out/'target'; root.mkdir(); env = env_fixture(root, out)
        fs, config, sarif = reports()
        fs['ArtifactName'] = str(root); config['ArtifactName'] = str(root/'infra/aws'); fs['Metadata']['Commit'] = 'a'*40
        if failure == 'blocked':
            add_to_both(fs, config, 'infra/aws/new/main.tf', 'AWS-0001', 'HIGH')
        if failure == 'report-commit':
            fs['Metadata']['Commit'] = 'f'*40
        identities = [dict(commit='a'*40), dict(commit='b'*40) if failure == 'source-change' else dict(commit='a'*40)]
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if failure == 'policy':
                (out/'cache'/'policy').mkdir(exist_ok=True)
            Path(argv[argv.index('--output')+1]).write_text(c.canonical((fs, config, sarif)[len(calls)-1]))
            return subprocess.CompletedProcess(argv, 9 if failure == 'scanner' else 0)
        with patch.object(c, 'context', return_value=dict(event_head='a'*40)), patch.object(c, 'source', side_effect=identities), \
             patch.object(c, 'scanner', return_value=dict(version=c.VERSION)), patch.object(c.shutil, 'which', return_value='/trusted/trivy'), \
             patch.object(c.subprocess, 'run', side_effect=run):
            try:
                return out, sarif, calls, c.execute(root, out, env)
            except ValueError as error:
                return out, sarif, calls, error

    def test_pass_writes_upload_view_and_receipt(self):
        out, sarif, calls, receipt = self.run_execute(None)
        self.assertEqual((receipt['status'], receipt['schema'], receipt['contract']),
                         ('passed', 'ncdit-trivy-policy-receipt-v1', c.CONTRACT))
        self.assertEqual(receipt['sarif_upload']['removed_result_count'], 2)
        self.assertEqual(receipt['sarif_upload']['upload_result_count'], len(sarif['runs'][0]['results']) - 2)
        self.assertEqual(receipt['sarif_upload']['upload_sha256'], c.sha((out/'trivy-upload.sarif').read_bytes()))
        self.assertEqual(c.decode((out/'trivy.sarif').read_bytes()), sarif)
        self.assertEqual(len(calls), 3)

    def test_failures_block_without_upload_view(self):
        for failure in ('scanner', 'policy', 'source-change', 'report-commit', 'blocked'):
            with self.subTest(failure=failure):
                out, _, calls, result = self.run_execute(failure)
                self.assertIsInstance(result, ValueError)
                self.assertFalse((out/'trivy-upload.sarif').exists())
                if failure == 'scanner':
                    self.assertEqual(len(calls), 1)

    def test_main_writes_blocked_receipt_with_finding_identities(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp).resolve(); (out/'ws').mkdir(); (out/'tmp').mkdir()
            env = dict(GITHUB_WORKSPACE=str(out/'ws'), RUNNER_TEMP=str(out/'tmp'), GITHUB_OUTPUT=str(out/'o'))
            detail = [dict(kind='Misconfigurations', severity='HIGH', path='infra/aws/x.tf', rule='AWS-0001')]
            def blocked(*_):
                raise c._GuardFailure('unaccepted-high-critical', detail)
            stdout = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(c, 'execute', side_effect=blocked), redirect_stdout(stdout):
                self.assertEqual(c.main(), 1)
            evidence = Path((out/'o').read_text().strip().split('=', 1)[1])
            receipt = c.decode((evidence/'receipt.json').read_bytes())
            self.assertEqual((receipt['status'], receipt['guard_code']), ('blocked', 'unaccepted-high-critical'))
            self.assertEqual(receipt['unaccepted_high_critical_findings'], detail)
            self.assertIn('::error file=infra/aws/x.tf::HIGH Misconfigurations AWS-0001', stdout.getvalue())


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT/'.github/workflows/pr-security-gate.yml').read_text()
        cls.workflow = yaml.safe_load(cls.text)
        cls.steps = cls.workflow['jobs']['precheck']['steps']
        cls.byid = {s.get('id'): s for s in cls.steps if s.get('id')}

    def test_other_repositories_keep_original_trivy_steps(self):
        lines = self.text.splitlines(keepends=True)
        for name, expected in LEGACY_BLOCKS.items():
            start = next(i for i, l in enumerate(lines) if l.strip() == '- name: '+name)
            end = next((i for i in range(start+1, len(lines)) if lines[i].startswith('      - name:') or lines[i].startswith('      #')), len(lines))
            block = ''.join(lines[start:end])
            block = block.replace("        if: github.repository != 'NC-DIT-Open-Source/CyberCoach-NC'\n", '')
            block = block.replace(" && github.repository != 'NC-DIT-Open-Source/CyberCoach-NC'", '')
            self.assertEqual(hashlib.sha256(block.encode()).hexdigest(), expected, name)

    def test_all_cybercoach_steps_are_scoped_to_cybercoach(self):
        names = [s['name'] for s in self.steps if s['name'].startswith('CyberCoach')]
        self.assertEqual(len(names), 5)
        for step in self.steps:
            if step['name'].startswith('CyberCoach'):
                self.assertIn("github.repository == '"+c.REPOSITORY+"'", step['if'])
                self.assertNotIn('continue-on-error', step)
            elif step.get('id') in ('trivy', 'trivy_sarif'):
                self.assertIn("github.repository != '"+c.REPOSITORY+"'", step['if'])

    def test_pinned_setup_and_every_action(self):
        setup = next(s for s in self.steps if s['name'] == 'CyberCoach pinned Trivy setup')
        self.assertEqual(setup['uses'], 'aquasecurity/setup-trivy@'+c.SETUP)
        self.assertEqual(setup['with'], dict(version='v'+c.VERSION, cache=False))
        for line in self.text.splitlines():
            if 'uses:' in line:
                self.assertRegex(line, r'@[0-9a-f]{40} #')

    def test_embedded_source_is_isolated_and_context_is_github_owned(self):
        step = self.byid['cybercoach_trivy']
        self.assertEqual(step['name'], 'CyberCoach full scan and Trivy policy check')
        self.assertIn("python3 -I - <<'CC_TRIVY_PY'", step['run'])
        self.assertNotIn('PYTHONPATH', step['run'])
        dollar = chr(36)
        self.assertEqual(step['env']['CC_WORKFLOW_REF'], dollar+'{{ github.workflow_ref }}')
        self.assertEqual(step['env']['CC_WORKFLOW_SHA'], dollar+'{{ github.workflow_sha }}')
        self.assertEqual(step['env']['CC_HEAD_SHA'], dollar+'{{ github.event.pull_request.head.sha }}')
        self.assertIn((HERE/'trivy_contract.py').read_text().strip(), step['run'])

    def test_gate_requires_classifier_sarif_and_artifact_for_every_outcome(self):
        gate = self.byid['cybercoach_gate']
        ok = dict(os.environ, CLASSIFICATION='success', SARIF='success', ARTIFACTS='success')
        for field in ('CLASSIFICATION', 'SARIF', 'ARTIFACTS'):
            for status in ('failure', 'cancelled', 'skipped', ''):
                result = subprocess.run(['bash', '-c', gate['run']], env=dict(ok, **{field: status}), capture_output=True)
                self.assertNotEqual(result.returncode, 0, (field, status))
        self.assertEqual(subprocess.run(['bash', '-c', gate['run']], env=ok, capture_output=True).returncode, 0)
        artifacts = self.byid['cybercoach_evidence']
        self.assertIn('always()', artifacts['if']); self.assertEqual(artifacts['with']['if-no-files-found'], 'error')
        self.assertEqual(artifacts['with']['retention-days'], 7)

    def test_summary_lint_and_jobs_unchanged(self):
        summary = next(s for s in self.steps if s['name'] == 'Precheck summary')
        self.assertEqual(hashlib.sha256(summary['run'].encode()).hexdigest(), SUMMARY_SHA256)
        for key, legacy, cybercoach in [('TRIVY', 'trivy', 'cybercoach_gate'), ('TRIVY_SARIF', 'trivy_sarif', 'cybercoach_sarif')]:
            expected = chr(36)+"{{ github.repository == '"+c.REPOSITORY+"' && steps."+cybercoach+".outcome || steps."+legacy+".outcome }}"
            self.assertEqual(summary['env'][key], expected)
        self.assertEqual(self.byid['lint']['if'], 'always()')
        self.assertEqual(set(self.workflow['jobs']), {'precheck'})


if __name__ == '__main__':
    unittest.main(verbosity=2)

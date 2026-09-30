"""Offline genuine-input regression and hostile controls; never extract raw reports.

Run with Python -B and --archive PATH --baseline ORIGINAL_SOURCE.
Only sanitized names/predicates/counts leave this process. No scanner or cloud call.
"""
import argparse, copy, hashlib, importlib.util, io, json, zipfile
from pathlib import Path

ARCHIVE_SHA = '2b609888bb597077c7205c8750b3775322411b70dfd5aefcc5c1117ac6144054'
MEMBERS = {
    'filesystem.json': '82b245c7d03bcf04c3306f78188aeb21bbf7f4c8cee8e389694fd613e2dc7bc6',
    'config.json': '6308c60b437949b07ff9613541d07aaf157b88cad6faa1ff4c3df0f2be2c82cb',
    'trivy.sarif': '281413e06ad7c9970375bc69d3391dc9a2935ddc384fe3437be55712f44f2ee3',
}

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def run(archive, baseline):
    old = load(baseline, 'baseline_contract')
    new = load(Path(__file__).with_name('trivy_contract.py'), 'candidate_contract')
    data = Path(archive).read_bytes()
    assert hashlib.sha256(data).hexdigest() == ARCHIVE_SHA, 'archive-pin'
    z = zipfile.ZipFile(io.BytesIO(data))
    reports = []
    for member, digest in MEMBERS.items():
        raw = z.read(member)
        assert hashlib.sha256(raw).hexdigest() == digest, 'member-pin'
        reports.append(new.decode(raw))
    fs, config, sarif = reports
    exits = new.decode(z.read('scanner-exits.json'))
    # The conversion input is independently bound to the retained native argv.
    def argv_rows(value):
        if isinstance(value, dict):
            if isinstance(value.get('argv'), list):
                yield value['argv']
            for item in value.values():
                yield from argv_rows(item)
        elif isinstance(value, list):
            for item in value:
                yield from argv_rows(item)
    convert = [a for a in argv_rows(exits) if 'convert' in a]
    assert len(convert) == 1, 'one-conversion-argv'
    conversion_input = convert[0][-1]
    outcomes = []
    def check(name, fn, expected=None):
        try:
            fn()
        except ValueError as error:
            predicate = str(error)
            # Never print an unexpected exception's body.
            assert expected is not None and (expected == '*' or predicate == expected), name
            assert predicate and all(c.islower() or c.isdigit() or c == '-' for c in predicate), name
            outcomes.append(dict(test=name, passed=True, predicate=predicate))
        else:
            assert expected is None, name
            outcomes.append(dict(test=name, passed=True))
    def yes(value):
        assert value, 'boolean-invariant'
    def run_new(x):
        return new.upload_view(*x, conversion_input)
    check('baseline-filesystem-reproduces', lambda: old.report(fs, 'infra/aws/'), 'iac-result-type')
    check('baseline-config-passes', lambda: old.report(config, '', True))
    check('baseline-full-sarif-correspondence', lambda: old.sarif_correspondence(fs, sarif, conversion_input))
    check('baseline-classifier-reproduces', lambda: old.classify(*reports, conversion_input), 'iac-result-type')
    for r in fs['Results']:
        for f in r.get('Misconfigurations', []):
            check('baseline-normalization-' + r['Target'] + '-' + f['ID'],
                  lambda r=r, f=f: old.normalized(r, f, 'infra/aws/'),
                  'iac-result-type' if r['Type'] == 'dockerfile' else None)
    original_report = old.report
    old.report = new.report  # Isolate the second original call site; not an execution claim.
    check('baseline-upload-second-call-site', lambda: old.upload_view(*reports, conversion_input), 'iac-result-type')
    old.report = original_report
    before = new.canonical(reports)
    decision, derived, removed = run_new(reports)
    check('actual-inputs-immutable', lambda: yes(new.canonical(reports) == before))
    check('policy-constants-unchanged', lambda: yes(all(getattr(old, k) == getattr(new, k)
        for k in ('EXPECTED', 'SOURCES', 'CONTRACT', 'REPOSITORY', 'WORKFLOW_REF', 'VERSION', 'ACTION', 'SETUP', 'BINARY', 'ARCHIVE'))))
    check('exact-two-existing-receiver-removals', lambda: yes(len(removed) == 2 and
        all(r['classification'] in old.EXPECTED and r['classification']['rule'] == 'AWS-0132' and
            r['classification']['severity'] == 'HIGH' for r in removed)))
    raw_results = sarif['runs'][0]['results']
    indices = {r['raw_result_index'] for r in removed}
    expected = copy.deepcopy(sarif)
    expected['runs'][0]['results'] = [r for i, r in enumerate(raw_results) if i not in indices]
    check('all-other-sarif-values-and-order-preserved', lambda: yes(derived == expected))
    check('287-raw-285-derived', lambda: yes(len(raw_results) == 287 and len(derived['runs'][0]['results']) == 285))
    check('all-three-docker-warnings-visible', lambda: yes(sum(r['ruleId'] == 'DS-0013' and r['level'] == 'warning'
        for r in derived['runs'][0]['results']) == 3))
    check('counts-preserved', lambda: yes(decision['finding_counts_by_kind_and_severity'] ==
        {'Licenses/LOW': 272, 'Licenses/UNKNOWN': 2, 'Misconfigurations/HIGH': 2, 'Misconfigurations/LOW': 4, 'Misconfigurations/MEDIUM': 7}))
    docker_indices = [i for i, r in enumerate(fs['Results']) if r.get('Type') == 'dockerfile' and r.get('Misconfigurations')]
    for idx in docker_indices:
        for key, value in [('ID', 'DS-9999'), ('Severity', 'HIGH'), ('Severity', 'CRITICAL'),
                           ('Severity', 'LOW'), ('Status', 'PASS'), ('Type', 'Terraform Security Check'),
                           ('Namespace', 'custom.rule'), ('Query', 'data.custom.deny')]:
            x = copy.deepcopy(reports); x[0]['Results'][idx]['Misconfigurations'][0][key] = value
            check('docker-' + fs['Results'][idx]['Target'] + '-' + key + '-' + value,
                  lambda x=x: run_new(x), 'retained-dockerfile-finding')
        for key, value in [('Target', 'unreviewed/Dockerfile'), ('Type', 'kubernetes'), ('Class', 'secret')]:
            x = copy.deepcopy(reports); x[0]['Results'][idx][key] = value
            check('docker-result-' + fs['Results'][idx]['Target'] + '-' + key,
                  lambda x=x: run_new(x), 'retained-dockerfile-finding')
        x = copy.deepcopy(reports); r = x[0]['Results'][idx]
        r['Misconfigurations'] *= 2; r['MisconfSummary']['Failures'] = 2
        check('docker-duplicate-' + r['Target'], lambda: run_new(x), 'retained-dockerfile-finding')
        x = copy.deepcopy(reports); x[0]['Results'][idx]['MisconfSummary']['Exceptions'] = 1
        check('docker-suppression-' + fs['Results'][idx]['Target'], lambda: run_new(x), 'suppressed-misconfigurations')
        x = copy.deepcopy(reports); x[0]['Results'][idx]['Target'] = '../Dockerfile'
        check('docker-path-traversal-' + fs['Results'][idx]['Target'], lambda: run_new(x), '*')
    for idx, r in enumerate(fs['Results']):
        if r.get('Type') != 'terraform':
            continue
        for fi, finding in enumerate(r.get('Misconfigurations', [])):
            for field in ('ID', 'Severity', 'CauseMetadata'):
                x = copy.deepcopy(reports); f = x[0]['Results'][idx]['Misconfigurations'][fi]
                if field == 'CauseMetadata': f[field]['StartLine'] += 1
                elif field == 'Severity': f[field] = 'CRITICAL'
                else: f[field] = 'AWS-9999'
                check('terraform-identity-' + r['Target'] + '-' + finding['ID'] + '-' + field,
                      lambda: run_new(x), '*')
    for kind in ('Vulnerabilities', 'Secrets', 'Licenses'):
        for severity in ('HIGH', 'CRITICAL'):
            x = copy.deepcopy(reports); x[0]['Results'].append({'Target': 'synthetic-hostile',
                'Class': 'secret' if kind == 'Secrets' else 'license' if kind == 'Licenses' else 'lang-pkgs',
                'Type': 'synthetic', kind: [{'Severity': severity}]})
            check('other-' + kind + '-' + severity, lambda: run_new(x), 'unaccepted-high-critical')
    for mutation in ('remove-docker', 'duplicate-docker', 'lower-docker', 'message', 'rule-index', 'uri', 'failed-invocation'):
        x = copy.deepcopy(reports); run = x[2]['runs'][0]; rows = run['results']
        i = next(i for i, r in enumerate(rows) if r['ruleId'] == 'DS-0013')
        if mutation == 'remove-docker': rows.pop(i)
        elif mutation == 'duplicate-docker': rows.append(copy.deepcopy(rows[i]))
        elif mutation == 'lower-docker': rows[i]['level'] = 'note'
        elif mutation == 'message': rows[i]['message']['text'] = 'synthetic-hostile'
        elif mutation == 'rule-index': rows[i]['ruleIndex'] = len(run['tool']['driver']['rules'])
        elif mutation == 'uri': rows[i]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = '../Dockerfile'
        else: run['invocations'] = [{'executionSuccessful': False}]
        check('sarif-' + mutation, lambda: run_new(x), '*')
    check('wrong-conversion-input', lambda: new.upload_view(*reports, '/wrong/filesystem.json'), 'sarif-conversion-input')
    receipt = new.decode(z.read('receipt.json'))
    check('observed-blocked-receipt-shape', lambda: yes(receipt == {
        'schema': 'ncdit-trivy-contract-receipt-v2', 'contract': old.CONTRACT,
        'status': 'blocked', 'organization_policy_acceptance': 'not-established', 'error_type': 'ValueError'}))
    return {'passed': True, 'tests': outcomes, 'test_count': len(outcomes), 'actual_archive_sha256': ARCHIVE_SHA,
            'historical_executed_source_proven': False, 'scanner_rerun': False,
            'raw_results': 287, 'derived_results': 285, 'receiver_removals': 2,
            'retained_docker_warnings': 3, 'counts': decision['finding_counts_by_kind_and_severity']}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()
    try:
        result = run(args.archive, args.baseline)
    except Exception as error:
        # Exception messages/tracebacks could contain protected fixture values.
        print(json.dumps({'passed': False, 'error_type': type(error).__name__}))
        raise SystemExit(1)
    print(json.dumps(result, indent=2))

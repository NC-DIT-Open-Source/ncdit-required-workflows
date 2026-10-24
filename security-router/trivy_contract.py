#!/usr/bin/env python3
"""Owner-maintained CyberCoach Trivy policy, embedded in the required workflow.

Policy: run a complete Trivy scan of the PR head and block on every HIGH/CRITICAL
finding except misconfigurations listed in ACCEPTED, keyed by rule ID and
repository path with a written justification. No source hashes or line numbers
are bound, so unrelated IaC edits and moved resources do not need a policy change.

No target-repository Python, configuration, ignore list or classifier is executed.
A receipt means this scanner policy passed, never AWS delivery/launch readiness.
"""
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

REPOSITORY = 'NC-DIT-Open-Source/CyberCoach-NC'
WORKFLOW_REF = 'NC-DIT-Open-Source/ncdit-required-workflows/.github/workflows/pr-security-gate.yml@refs/heads/main'
CONTRACT = 'ncdit-cybercoach-trivy-policy-v1'
VERSION = '0.70.0'
ACTION = 'ed142fd0673e97e23eac54620cfb913e5ce36c25'
SETUP = '3fb12ec12f41e471780db15c232d5dd185dcb514'
BINARY = '379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166'
ARCHIVE = '8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9'
IAC_ROOT = 'infra/aws/'
# Accepted HIGH/CRITICAL misconfigurations. Only Trivy misconfiguration findings can
# be accepted; vulnerabilities, secrets and licenses at HIGH/CRITICAL always block.
# An entry covers every finding of that rule in that file, so keep paths narrow.
SSE_S3_LOG_RECEIVER = (
    'Terminal S3 server-access-log receiver. AWS supports only SSE-S3 default encryption '
    'on server access logging destination buckets; SSE-KMS is not supported there, so '
    'the customer-managed-key requirement cannot be met. The bucket logs nowhere else '
    '(AWS-0089 stays visible). '
    'https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html')
ACCEPTED = (
    dict(rule='AWS-0132', path='infra/aws/modules/audit-foundation/receivers.tf',
         justification=SSE_S3_LOG_RECEIVER),
    dict(rule='AWS-0132', path='infra/aws/operator-foundations/access-logging.tf',
         justification=SSE_S3_LOG_RECEIVER),
)
SEVERITIES = ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
BLOCKING = ('HIGH', 'CRITICAL')
KINDS = ('Vulnerabilities', 'Misconfigurations', 'Secrets', 'Licenses')
RESULT_KEYS = {'Target', 'Class', 'Type', 'Packages', 'MisconfSummary', *KINDS}
RULE = r'[A-Z][A-Z0-9]*-[0-9]{4,}'


class _GuardFailure(ValueError):
    """A failed constant-label guard from this trusted module."""

    def __init__(self, code, details=None):
        super().__init__(code)
        self.details = details


def need(value, code):
    if not value:
        raise _GuardFailure(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def decode(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            need(k not in result, 'duplicate-json-key')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def regular(path, limit=256 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), 'linked-file')
    with path.open('rb') as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, 'file-size-or-type')
        raw = handle.read(limit + 1)
    need(len(raw) == info.st_size, 'file-changed')
    return raw


def full(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def relative(value):
    need(isinstance(value, str) and value and '\\' not in value and
         not value.startswith('/') and all(x not in ('', '.', '..') for x in value.split('/')), 'noncanonical-path')
    return value


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'invalid-integer')
    return value


def accepted_index(entries=None):
    """Validate the accepted list and index it by (rule, path)."""
    index = {}
    for entry in ACCEPTED if entries is None else entries:
        need(isinstance(entry, dict) and set(entry) == {'rule', 'path', 'justification'}, 'accepted-list')
        need(full(entry['rule'], RULE), 'accepted-list')
        relative(entry['path'])
        need(isinstance(entry['justification'], str) and len(entry['justification'].strip()) >= 40,
             'accepted-list')
        key = (entry['rule'], entry['path'])
        need(key not in index, 'accepted-list')
        index[key] = entry['justification']
    return index


def environment(env):
    # Allowlist rather than passing inherited TRIVY_*, Git config, cloud credentials,
    # Python paths, tokens or language package-manager configuration to the scanner.
    return {k: env[k] for k in ('PATH', 'HOME', 'TMPDIR', 'SYSTEMROOT') if k in env} | {
        'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}


def context(env):
    need(env.get('CC_REPOSITORY') == REPOSITORY and env.get('GITHUB_REPOSITORY') == REPOSITORY, 'repository')
    need(env.get('CC_WORKFLOW_REF') == WORKFLOW_REF, 'workflow-ref')
    need(full(env.get('CC_WORKFLOW_SHA'), '[a-f0-9]{40}') and
         env['CC_WORKFLOW_SHA'] == env.get('GITHUB_WORKFLOW_SHA') and
         env['CC_WORKFLOW_REF'] == env.get('GITHUB_WORKFLOW_REF'), 'workflow-sha')
    need(full(env.get('CC_HEAD_SHA'), '[a-f0-9]{40}'), 'event-head')
    need(env.get('GITHUB_EVENT_NAME') == 'pull_request', 'event-kind')
    need(full(env.get('GITHUB_RUN_ID'), '[1-9][0-9]*') and
         full(env.get('GITHUB_RUN_ATTEMPT'), '[1-9][0-9]*'), 'run-identity')
    event = decode(regular(Path(env['GITHUB_EVENT_PATH']), 8 * 1024 * 1024))
    need(event['repository']['full_name'] == REPOSITORY and
         event['pull_request']['base']['repo']['full_name'] == REPOSITORY and
         event['pull_request']['head']['sha'] == env['CC_HEAD_SHA'], 'event-binding')
    return dict(repository=REPOSITORY, event_head=env['CC_HEAD_SHA'],
                workflow_ref=env['CC_WORKFLOW_REF'], workflow_sha=env['CC_WORKFLOW_SHA'],
                run_id=env['GITHUB_RUN_ID'], run_attempt=env['GITHUB_RUN_ATTEMPT'])


def source(root, expected_head, env):
    """Bind the scan to a clean checkout of the event head, without pinning file bytes."""
    root = Path(root).absolute()
    need(not root.is_symlink(), 'linked-checkout')
    def git(*args, exact=False):
        output = subprocess.check_output(['git', '-C', str(root), *args], env=environment(env),
                                         stderr=subprocess.PIPE).decode()
        # Remove only Git's output newline when comparing the exact remote URL.
        return output.removesuffix('\n') if exact else output.strip()
    origin = 'https://github.com/' + REPOSITORY
    need(git('remote', 'get-url', 'origin', exact=True) in (origin, origin + '.git'), 'origin')
    commit = git('rev-parse', 'HEAD')
    tree = git('rev-parse', 'HEAD^{tree}')
    need(commit == expected_head and full(tree, '[a-f0-9]{40}'), 'checkout-head-tree')
    need(not git('status', '--porcelain=v1', '--untracked-files=all', '--ignored=matching'), 'dirty-checkout')
    need(all(line.split()[0] in ('100644', '100755') for line in git('ls-files', '-s').splitlines()),
         'checkout-links-or-submodules')
    iac = root / IAC_ROOT
    need(iac.is_dir() and not iac.is_symlink(), 'missing-iac-root')
    return dict(commit=commit, tree=tree, clean=True)


def report(value, prefix, accepted, config_only=False):
    """Validate one Trivy JSON report and apply the accepted-findings policy.

    `prefix` turns report targets into repository paths: '' for the repository
    scan, IAC_ROOT for the configuration scan rooted there.
    """
    need(isinstance(value, dict) and value.get('SchemaVersion') == 2 and
         value.get('Trivy', {}).get('Version') == VERSION and
         value.get('ArtifactType') == ('filesystem' if config_only else 'repository'), 'report-schema')
    need(set(value) <= {'SchemaVersion', 'CreatedAt', 'ArtifactName', 'ArtifactType', 'Metadata', 'Results', 'Trivy', 'ReportID', 'ArtifactID'}, 'report-schema-fields')
    if not config_only:
        need(value.get('Metadata', {}).get('RepoURL') in ('https://github.com/' + REPOSITORY,
                                                         'https://github.com/' + REPOSITORY + '.git') and
             full(value.get('Metadata', {}).get('Commit'), '[a-f0-9]{40}'), 'report-repository')
    results = value.get('Results')
    need(isinstance(results, list) and results, 'missing-results')
    counts = Counter(); misconfigurations = []; accepted_hits = []; blockers = []; successes = 0
    seen = set()
    for r in results:
        need(isinstance(r, dict) and set(r) <= RESULT_KEYS, 'result-schema')
        path = relative(prefix + relative(r['Target']))
        identity = (r['Target'], r['Class'], r.get('Type'))
        need(identity not in seen, 'duplicate-result'); seen.add(identity)
        need(r['Class'] in ('config', 'lang-pkgs', 'os-pkgs', 'secret', 'license', 'license-file'), 'result-class')
        if config_only:
            need(r['Class'] == 'config', 'config-report-class')
        if r['Class'] == 'config':
            summary = r.get('MisconfSummary')
            need(isinstance(summary, dict) and set(summary) <= {'Successes', 'Failures', 'Exceptions'}, 'misconf-summary')
            successes += integer(summary['Successes'])
            # Trivy exceptions are suppressions; none can come from this trusted invocation.
            need(integer(summary.get('Exceptions', 0)) == 0, 'suppressed-misconfigurations')
            need(integer(summary['Failures']) == len(r.get('Misconfigurations', [])), 'misconf-summary-count')
        for kind in KINDS:
            findings = r.get(kind, [])
            need(isinstance(findings, list), 'finding-list')
            for f in findings:
                need(isinstance(f, dict), 'finding-object')
                severity = f.get('Severity')
                # Trivy license notes may have no severity; they remain counted.
                if kind == 'Licenses' and severity in (None, ''):
                    severity = 'UNRANKED'
                need(severity in (*SEVERITIES, 'UNRANKED') and
                     (severity != 'UNRANKED' or kind == 'Licenses'), 'finding-severity')
                counts[kind + '/' + severity] += 1
                rule = None
                if kind == 'Misconfigurations':
                    need(r['Class'] == 'config' and full(f.get('ID'), RULE) and
                         f.get('Status') == 'FAIL', 'misconfiguration-identity')
                    rule = f['ID']
                    misconfigurations.append(dict(rule=rule, severity=severity, path=path, type=r.get('Type')))
                elif kind == 'Vulnerabilities':
                    rule = f.get('VulnerabilityID')
                elif kind == 'Secrets':
                    rule = f.get('RuleID')
                if severity not in BLOCKING:
                    continue
                if kind == 'Misconfigurations' and (rule, path) in accepted:
                    accepted_hits.append(dict(rule=rule, severity=severity, path=path))
                else:
                    # Identity only: never copy secret matches or code into the receipt/log.
                    blockers.append(dict(kind=kind, severity=severity, path=path,
                                         rule=rule if isinstance(rule, str) else None))
    need(successes > 0, 'no-evaluated-configuration-successes')
    return dict(counts=dict(sorted(counts.items())), misconfigurations=misconfigurations,
                accepted=accepted_hits, blockers=blockers, configuration_successes=successes)


def iac_keys(rows):
    return Counter((m['rule'], m['severity'], m['path']) for m in rows if m['path'].startswith(IAC_ROOT))


def sarif_check(sarif):
    need(isinstance(sarif, dict) and sarif.get('version') == '2.1.0' and
         isinstance(sarif.get('runs'), list) and len(sarif['runs']) == 1, 'sarif-schema')
    run = sarif['runs'][0]
    need(isinstance(run, dict), 'sarif-run')
    tool = run.get('tool')
    need(isinstance(tool, dict) and isinstance(tool.get('driver'), dict) and
         tool['driver'].get('name') == 'Trivy' and tool['driver'].get('version') == VERSION, 'sarif-tool')
    invocations = run.get('invocations', [])
    need(isinstance(invocations, list), 'sarif-invocations')
    for invocation in invocations:
        need(isinstance(invocation, dict) and invocation.get('executionSuccessful') is True,
             'sarif-failed-invocation')
        if 'exitCode' in invocation:
            need(type(invocation['exitCode']) is int and invocation['exitCode'] == 0, 'sarif-invocation-exit')
    results = run.get('results')
    need(isinstance(results, list), 'sarif-results')
    for r in results:
        need(isinstance(r, dict) and isinstance(r.get('ruleId'), str) and
             r.get('level') in ('error', 'warning', 'note', 'none') and
             isinstance(r.get('locations'), list) and r['locations'], 'sarif-result-structure')


def sarif_key(result):
    """(ruleId, uri) for a single-location error result, else None."""
    locations = result['locations']
    if result['level'] != 'error' or len(locations) != 1:
        return None
    uri = locations[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri')
    return (result['ruleId'], uri) if isinstance(uri, str) else None


def classify(fs, config, sarif, entries=None):
    accepted = accepted_index(entries)
    whole = report(fs, '', accepted)
    scoped = report(config, IAC_ROOT, accepted, config_only=True)
    # The two scans must agree on which IaC rules fire in which files, independent of lines.
    need(iac_keys(whole['misconfigurations']) == iac_keys(scoped['misconfigurations']), 'paired-iac-projection')
    sarif_check(sarif)
    blockers = whole['blockers'] + [b for b in scoped['blockers'] if b not in whole['blockers']]
    if blockers:
        raise _GuardFailure('unaccepted-high-critical', blockers)
    used = {(a['rule'], a['path']) for a in whole['accepted']}
    return dict(finding_counts_by_kind_and_severity=whole['counts'],
                iac_findings=whole['misconfigurations'],
                configuration_successes=whole['configuration_successes'],
                accepted_high_critical_findings=[dict(a, justification=accepted[(a['rule'], a['path'])])
                                                 for a in whole['accepted']],
                unused_accepted_entries=[dict(rule=k[0], path=k[1]) for k in accepted if k not in used],
                unaccepted_high_critical_findings=[])


def upload_view(fs, config, sarif, entries=None):
    """Drop only accepted HIGH/CRITICAL misconfigurations from the uploaded SARIF.

    The raw SARIF and JSON reports stay unchanged in the retained evidence.
    """
    decision = classify(fs, config, sarif, entries)
    expected = Counter((a['rule'], a['path']) for a in decision['accepted_high_critical_findings'])
    derived = copy.deepcopy(sarif)
    retained = []
    removed = []
    for index, result in enumerate(sarif['runs'][0]['results']):
        key = sarif_key(result)
        if key in expected:
            removed.append(dict(raw_result_index=index, rule=key[0], path=key[1],
                                result_sha256=sha(canonical(result).encode())))
        else:
            retained.append(copy.deepcopy(result))
    # Each accepted JSON finding must map to exactly one SARIF result, so the
    # filter cannot hide anything the JSON policy did not accept.
    need(Counter((r['rule'], r['path']) for r in removed) == expected, 'sarif-accepted-correspondence')
    derived['runs'][0]['results'] = retained
    return decision, derived, removed


def scanner(binary, env):
    need(sha(regular(Path(binary), 256 * 1024 * 1024)) == BINARY, 'scanner-binary')
    value = decode(subprocess.check_output([str(binary), '--version', '--format', 'json'], env=environment(env)))
    need(value.get('Version') == VERSION, 'scanner-version')
    return dict(version=VERSION, binary_sha256=BINARY, official_archive_sha256=ARCHIVE,
                archive_hash_basis='reviewed official release checksum; installed binary verified',
                setup_action=SETUP, legacy_action=ACTION, embedded_checks=True)


def no_policy(cache):
    need(not any(p.is_symlink() or p.name == 'policy' or p.suffix == '.rego' for p in Path(cache).rglob('*')), 'external-policy-content')


def commands(binary, root, out, cache):
    common = ['--config', '/dev/null', '--ignorefile', '/dev/null', '--skip-check-update',
              '--skip-version-check', '--cache-dir', str(cache), '--severity', ','.join(SEVERITIES), '--exit-code', '0']
    return [
        [str(binary), 'fs', *common, '--scanners', 'vuln,misconfig,secret,license', '--secret-config', str(out / 'secret-config.yaml'),
         '--ignore-unfixed', '--format', 'json', '--output', str(out / 'filesystem.json'), str(root)],
        [str(binary), 'config', *common, '--format', 'json', '--output', str(out / 'config.json'), str(root / IAC_ROOT.rstrip('/'))],
        [str(binary), 'convert', '--config', '/dev/null', '--format', 'sarif', '--output', str(out / 'trivy.sarif'),
         str(out / 'filesystem.json')],
    ]


def execute(root, out, env):
    identity = context(env)
    before = source(root, identity['event_head'], env)
    binary = shutil.which('trivy', path=env['PATH'])
    need(binary is not None, 'missing-scanner')
    binary = Path(binary).absolute()
    tool = scanner(binary, env)
    cache = out / 'cache'; cache.mkdir(mode=0o700)
    need(not list(cache.iterdir()), 'nonempty-initial-cache')
    # An empty YAML mapping keeps Trivy's built-in secret rules enabled. An
    # empty /dev/null file is rejected by Trivy 0.70's secret parser.
    (out / 'secret-config.yaml').write_text('{}\n')
    exits = []
    for index, argv in enumerate(commands(binary, root, out, cache)):
        no_policy(cache)
        with (out / ('scanner-' + str(index) + '.stdout')).open('wb') as stdout, \
             (out / ('scanner-' + str(index) + '.stderr')).open('wb') as stderr:
            result = subprocess.run(argv, env=environment(env), cwd=root, stdout=stdout, stderr=stderr, timeout=600)
        exits.append(dict(argv=argv, exit_code=result.returncode))
        (out / 'scanner-exits.json').write_text(canonical(exits))
        # A full scanner failure never becomes a passing policy decision.
        need(result.returncode == 0, 'scanner-nonzero')
        no_policy(cache)
    need(source(root, identity['event_head'], env) == before, 'source-changed-during-scan')
    raw = {name: regular(out / name) for name in ('filesystem.json', 'config.json', 'trivy.sarif')}
    fs, config, sarif = (decode(raw[name]) for name in ('filesystem.json', 'config.json', 'trivy.sarif'))
    need(fs.get('Metadata', {}).get('Commit') == before['commit'], 'report-source-commit')
    need(fs.get('ArtifactName') == str(root) and config.get('ArtifactName') == str(root / IAC_ROOT.rstrip('/')),
         'report-source-root')
    decision, derived, removed = upload_view(fs, config, sarif)
    upload = (canonical(derived) + '\n').encode()
    # Raw SARIF is immutable evidence; never overwrite it or filter JSON scans.
    with (out / 'trivy-upload.sarif').open('xb') as handle:
        handle.write(upload)
    upload_receipt = dict(raw_sha256=sha(raw['trivy.sarif']), upload_sha256=sha(upload),
        raw_result_count=len(sarif['runs'][0]['results']),
        upload_result_count=len(derived['runs'][0]['results']),
        removed_result_count=len(removed), removed_results=removed)
    return dict(schema='ncdit-trivy-policy-receipt-v1', contract=CONTRACT, status='passed',
        organization_policy_acceptance='established-for-this-policy', **identity, source=before, scanner=tool,
        private_cache_path=str(cache), external_policy_files=[], inherited_trivy_configuration='not-forwarded',
        secret_config_sha256=sha(regular(out / 'secret-config.yaml')),
        report_sha256={**{name: sha(data) for name, data in raw.items()}, 'trivy-upload.sarif': sha(upload)},
        sarif_upload=upload_receipt, scanner_exits=exits, **decision)


def annotation(blocker):
    """A workflow-command line whose scanner-derived parts cannot inject other commands."""
    def data(value):
        return value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    def prop(value):
        return data(value).replace(':', '%3A').replace(',', '%2C')
    return ('::error file=' + prop(blocker['path']) + '::' + data(
        blocker['severity'] + ' ' + blocker['kind'] + ' ' + (blocker['rule'] or 'unidentified') +
        ' is not in the accepted list'))


def main():
    env = dict(os.environ)
    # Code runs on stdin with Python -I. Only data is written, outside checkout.
    root = Path(env['GITHUB_WORKSPACE']).absolute()
    temp = Path(env['RUNNER_TEMP']).absolute()
    need(not temp.is_symlink() and root != temp and root not in temp.parents, 'private-output-root')
    out = Path(tempfile.mkdtemp(prefix='cybercoach-trivy-', dir=temp))
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('evidence=' + str(out) + '\n')
    try:
        receipt = execute(root, out, env)
    except Exception as error:
        guarded = type(error) is _GuardFailure
        failure = dict(schema='ncdit-trivy-policy-receipt-v1', contract=CONTRACT,
            status='blocked', organization_policy_acceptance='not-established',
            error_type='ValueError' if guarded else type(error).__name__)
        # Emit only owned, constant labels and finding identities; never exception text.
        if guarded:
            failure['guard_code'] = error.args[0]
            print('::error::CyberCoach Trivy policy blocked: ' + error.args[0])
        if guarded and error.args == ('unaccepted-high-critical',):
            failure['unaccepted_high_critical_findings'] = error.details
            for b in error.details:
                print(annotation(b))
        (out / 'receipt.json').write_text(canonical(failure))
        print('::error::CyberCoach Trivy policy blocked; inspect retained evidence.')
        return 1
    (out / 'receipt.json').write_text(canonical(receipt))
    for entry in receipt['unused_accepted_entries']:
        print('::warning::Accepted entry ' + entry['rule'] + ' ' + entry['path'] + ' matched no finding; remove it.')
    print('CyberCoach Trivy policy passed; complete findings retained.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Owner-maintained CyberCoach Trivy contract, embedded in the required workflow.

No target-repository Python, configuration, ignore list or classifier is executed.
A receipt means this scanner contract passed, never AWS delivery/launch readiness.
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
from urllib.parse import quote

REPOSITORY = 'NC-DIT-Open-Source/CyberCoach-NC'
WORKFLOW_REF = 'NC-DIT-Open-Source/ncdit-required-workflows/.github/workflows/pr-security-gate.yml@refs/heads/main'
CONTRACT = 'ncdit-cybercoach-terminal-s3-receivers-v1'
VERSION = '0.70.0'
ACTION = 'ed142fd0673e97e23eac54620cfb913e5ce36c25'
SETUP = '3fb12ec12f41e471780db15c232d5dd185dcb514'
BINARY = '379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166'
ARCHIVE = '8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9'
# Exact R22 35b9612 source inventory, including every observed IaC resource/call site.
SOURCES = {'infra/aws/operator-foundations/access-logging.tf': 'c563039d82141b9fd97b83b9d6b901a7601f64dda6367865a61aa4ca75a0a3de', 'infra/aws/modules/audit-foundation/receivers.tf': '7bacfbc849b2e4b693a7b8cad9077560e07db492f2b3eb2d15fdffaf2c2a0c5f', 'infra/aws/modules/public-frontdoor/main.tf': '534cd982a373079a8f5a2e9b07eba55a25f622b52fe094b74ade610368f1b6d4', 'infra/aws/modules/records/operator-tests/composed/main.tf': 'af35d548780a3dcd2ff99c47f18d8ae3d8c0035dffc91e6e28f66a02b250bd4e', 'infra/aws/public-frontdoor/main.tf': '446d6e50a5ec169a710f6cd5a0ab33cc271a829168692fb912b1fa0138b10ff3', 'infra/aws/modules/origin-authentication/main.tf': '803c6f2408abab1ea28be4678c06041542c71b5e1ca62d5fa8428a6a471ad397', 'infra/aws/origin-authentication/main.tf': 'a89eae775ad381c7cfce465cf472c81dcc1508350f6a76882932fe7306c83e8a', 'infra/aws/operator-database/stores.tf': '629b0f83a2078dc7350d953f456ec233c74b884529301960b09b572ad4ca11e1'}
# LOW AWS-0066 is visible, not remediated: Lambda@Edge does not support X-Ray.
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-edge-function-restrictions.html
# MEDIUM AWS-0014 remains a visible single-region trail product improvement.
# These observations grant no additional HIGH/CRITICAL exception.
EXPECTED = [{'rule': 'AWS-0089', 'severity': 'LOW', 'target': 'modules/audit-foundation/receivers.tf', 'provider': 'AWS', 'service': 's3', 'resource': 'module.audit', 'start_line': 64, 'end_line': 78, 'occurrences': [{'resource': 'module.audit', 'filename': 'modules/records/operator-tests/composed/main.tf', 'start_line': 11, 'end_line': 43}]}, {'rule': 'AWS-0132', 'severity': 'HIGH', 'target': 'modules/audit-foundation/receivers.tf', 'provider': 'AWS', 'service': 's3', 'resource': 'module.audit', 'start_line': 100, 'end_line': 107, 'occurrences': [{'resource': 'module.audit', 'filename': 'modules/records/operator-tests/composed/main.tf', 'start_line': 11, 'end_line': 43}]}, {'rule': 'AWS-0066', 'severity': 'LOW', 'target': 'modules/origin-authentication/main.tf', 'provider': 'AWS', 'service': 'lambda', 'resource': 'module.origin_authentication', 'start_line': 65, 'end_line': 85, 'occurrences': [{'resource': 'module.origin_authentication', 'filename': 'origin-authentication/main.tf', 'start_line': 26, 'end_line': 37}]}, {'rule': 'AWS-0010', 'severity': 'MEDIUM', 'target': 'modules/public-frontdoor/main.tf', 'provider': 'AWS', 'service': 'cloudfront', 'resource': 'module.public_frontdoor', 'start_line': 70, 'end_line': 131, 'occurrences': [{'resource': 'module.public_frontdoor', 'filename': 'public-frontdoor/main.tf', 'start_line': 92, 'end_line': 107}]}, {'rule': 'AWS-0014', 'severity': 'MEDIUM', 'target': 'operator-database/stores.tf', 'provider': 'AWS', 'service': 'cloudtrail', 'resource': 'aws_cloudtrail.database', 'start_line': 160, 'end_line': 160, 'occurrences': [{'resource': 'aws_cloudtrail.database', 'filename': 'operator-database/stores.tf', 'start_line': 154, 'end_line': 172}]}, {'rule': 'AWS-0089', 'severity': 'LOW', 'target': 'operator-foundations/access-logging.tf', 'provider': 'AWS', 'service': 's3', 'resource': 'aws_s3_bucket.access_logs', 'start_line': 40, 'end_line': 47, 'occurrences': []}, {'rule': 'AWS-0132', 'severity': 'HIGH', 'target': 'operator-foundations/access-logging.tf', 'provider': 'AWS', 'service': 's3', 'resource': 'aws_s3_bucket_server_side_encryption_configuration.access_logs', 'start_line': 69, 'end_line': 80, 'occurrences': []}]
SEVERITIES = ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
KINDS = ('Vulnerabilities', 'Misconfigurations', 'Secrets', 'Licenses')
RESULT_KEYS = {'Target', 'Class', 'Type', 'Packages', 'MisconfSummary', *KINDS}


def need(value, code):
    if not value:
        raise ValueError(code)


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
    hashes = {}
    for name, expected in SOURCES.items():
        raw = regular(root / name, 1024 * 1024)
        need(sha(raw) == expected, 'reviewed-source-hash')
        entry = git('ls-files', '-s', '--', name).split()
        need(len(entry) == 4 and entry[0] == '100644' and entry[2] == '0' and entry[3] == name, 'source-git-mode')
        hashes[name] = sha(raw)
    return dict(commit=commit, tree=tree, clean=True, source_sha256=hashes)


def normalized(result, finding, prefix):
    need(result['Class'] == 'config' and result['Type'] == 'terraform', 'iac-result-type')
    need(finding.get('Status') == 'FAIL' and finding.get('Type') == 'Terraform Security Check', 'iac-status-type')
    cause = finding['CauseMetadata']
    need(isinstance(cause, dict) and set(cause) <= {'Provider', 'Service', 'Resource', 'StartLine', 'EndLine', 'Occurrences', 'Code'}, 'cause-schema')
    def path(value):
        value = relative(value)
        if prefix:
            need(value.startswith(prefix), 'iac-path-prefix')
            value = relative(value[len(prefix):])
        return value
    rule = finding['ID']
    service = cause['Service']
    need(finding.get('Namespace') == 'builtin.aws.' + service + '.' + rule.lower().replace('-', '') and
         finding.get('Query') == 'data.' + finding['Namespace'] + '.deny', 'iac-builtin-rule')
    occurrences = cause.get('Occurrences', [])
    need(isinstance(occurrences, list), 'occurrences-schema')
    result_occurrences = []
    for o in occurrences:
        need(set(o) == {'Resource', 'Filename', 'Location'} and set(o['Location']) == {'StartLine', 'EndLine'}, 'occurrence-schema')
        result_occurrences.append(dict(resource=o['Resource'], filename=path(o['Filename']),
            start_line=integer(o['Location']['StartLine'], 1), end_line=integer(o['Location']['EndLine'], 1)))
    return dict(rule=rule, severity=finding['Severity'], target=path(result['Target']),
        provider=cause['Provider'], service=service, resource=cause['Resource'],
        start_line=integer(cause['StartLine'], 1), end_line=integer(cause['EndLine'], 1), occurrences=result_occurrences)


def report(value, prefix, config_only=False):
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
    counts = Counter(); iac = []; blockers = []; successes = 0
    seen = set()
    for r in results:
        need(isinstance(r, dict) and set(r) <= RESULT_KEYS, 'result-schema')
        relative(r['Target'])
        identity = (r['Target'], r['Class'], r.get('Type'))
        need(identity not in seen, 'duplicate-result'); seen.add(identity)
        need(r['Class'] in ('config', 'lang-pkgs', 'os-pkgs', 'secret', 'license', 'license-file'), 'result-class')
        if config_only:
            need(r['Class'] == 'config', 'config-report-class')
        if r['Class'] == 'config':
            summary = r.get('MisconfSummary')
            need(isinstance(summary, dict) and set(summary) <= {'Successes', 'Failures', 'Exceptions'}, 'misconf-summary')
            successes += integer(summary['Successes'])
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
                if kind == 'Misconfigurations':
                    item = normalized(r, f, prefix); iac.append(item)
                    accepted = item in EXPECTED and item['rule'] == 'AWS-0132' and severity == 'HIGH'
                else:
                    accepted = False
                if severity in ('HIGH', 'CRITICAL') and not accepted:
                    # Do not copy secret contents into the receipt/log.
                    blockers.append(dict(kind=kind, severity=severity, target=r['Target']))
    need(successes > 0, 'no-evaluated-configuration-successes')
    need(Counter(map(canonical, iac)) == Counter(map(canonical, EXPECTED)), 'exact-iac-inventory')
    return dict(counts=dict(sorted(counts.items())), iac=iac, blockers=blockers, configuration_successes=successes)


def sarif_projection(fs, with_rules=False):
    """Semantic result multiset of the pinned Trivy 0.70 repository converter.

    One finding produces one result, possibly with several package locations.
    Keep repeated findings AND repeated locations; neither is a set. Rule
    descriptions are shared by ID, so per-result severity/message is authoritative.
    """
    result = Counter()
    rules = {}
    location_cache = {}
    levels = dict(CRITICAL='error', HIGH='error', MEDIUM='warning', LOW='note', UNKNOWN='note')
    scores = dict(CRITICAL='9.5', HIGH='8.0', MEDIUM='5.5', LOW='2.0')
    names = {'os-pkgs': 'OsPackageVulnerability', 'lang-pkgs': 'LanguageSpecificPackageVulnerability',
             'config': 'Misconfiguration', 'secret': 'Secret', 'license': 'License', 'license-file': 'License'}
    def string(obj, key, required=False):
        value = obj.get(key, '')
        need(isinstance(value, str) and (value or not required), 'sarif-json-string')
        return value
    def locations(path, spans, message):
        uri = quote(relative(path), safe="/:@!$&'()*+,;=-._~%?#")
        rows = []
        for span in spans or [dict(StartLine=1, EndLine=1)]:
            start, end = span.get('StartLine', 0), span.get('EndLine', 0)
            integer(start); integer(end)
            if start == end == 0:
                start = end = 1
            need(start >= 1 and end >= start, 'sarif-json-region')
            rows.append(dict(physicalLocation=dict(artifactLocation=dict(uri=uri, uriBaseId='ROOTPATH'),
                region=dict(startLine=start, endLine=end, startColumn=1, endColumn=1)),
                message=dict(text=message)))
        return sorted(map(canonical, rows))
    for r in fs['Results']:
        target = r['Target']
        # The admitted artifact is a repository, not an OCI image. OS package
        # targets may append a distro annotation; image-name rewriting is out
        # of this filesystem contract and must never guess an alternate path.
        path = re.sub(r'\s*\(.*?\).*$', '', target) if r['Class'] == 'os-pkgs' else target
        for kind in KINDS:
            for f in r.get(kind, []):
                severity = '' if kind == 'Licenses' and f.get('Severity') is None else string(f, 'Severity')
                level = levels.get(severity, 'none')
                score = scores.get(severity, '0.0')
                spans = []; location_message = ''; artifact = path
                if kind == 'Vulnerabilities':
                    rule = string(f, 'VulnerabilityID', True)
                    package = string(f, 'PkgName', True); version = string(f, 'InstalledVersion', True)
                    artifact = string(f, 'PkgPath') or path
                    if r['Class'] == 'os-pkgs':
                        artifact = re.sub(r'\s*\(.*?\).*$', '', artifact)
                    cache_key = (artifact, package, version)
                    if cache_key not in location_cache:
                        packages = r.get('Packages', [])
                        need(isinstance(packages, list), 'sarif-json-packages')
                        for p in packages:
                            need(isinstance(p, dict), 'sarif-json-package')
                            if p.get('Name') == package and p.get('Version') == version:
                                spans = p.get('Locations', [])
                                need(isinstance(spans, list) and all(isinstance(s, dict) for s in spans), 'sarif-json-locations')
                                location_cache[cache_key] = spans
                                break
                    spans = location_cache.get(cache_key, [])
                    location_message = f'{artifact}: {package}@{version}'
                    url = string(f, 'PrimaryURL')
                    cvss = f.get('CVSS', {}).get(f.get('SeveritySource', ''), {})
                    need(isinstance(cvss, dict), 'sarif-json-cvss')
                    v3 = cvss.get('V3Score', 0)
                    need(type(v3) in (int, float) and 0 <= v3 <= 10, 'sarif-json-cvss-score')
                    if v3:
                        score = f'{v3:.1f}'
                    message = (f'Package: {package}\nInstalled Version: {version}\nVulnerability {rule}\n'
                               f'Severity: {severity}\nFixed Version: {string(f, "FixedVersion")}\nLink: [{rule}]({url})')
                elif kind == 'Misconfigurations':
                    rule = string(f, 'ID', True); spans = [f['CauseMetadata']]
                    artifact = target; location_message = target
                    message = (f'Artifact: {target}\nType: {string(r, "Type")}\nVulnerability {rule}\n'
                               f'Severity: {severity}\nMessage: {string(f, "Message")}\nLink: [{rule}]({string(f, "PrimaryURL")})')
                elif kind == 'Secrets':
                    rule = string(f, 'RuleID', True); spans = [f]; location_message = path
                    message = (f'Artifact: {target}\nType: {string(r, "Type")}\nSecret {string(f, "Title")}\n'
                               f'Severity: {severity}\nMatch: {string(f, "Match")}')
                else:
                    package = string(f, 'PkgName'); name = string(f, 'Name', True)
                    rule = package + ':' + name
                    message = (f'Artifact: {target}\nLicense {name}\nPkgName: {package}\n'
                               f' Classification: {string(f, "Category")}\n Path: {string(f, "FilePath")}')
                result[canonical(dict(ruleId=rule, level=level, message=message,
                    locations=locations(artifact, spans, location_message)))] += 1
                # AddRule reuses an ID and updates its metadata on each visit:
                # the last finding wins, even when individual severities differ.
                rules[rule] = dict(name=names[r['Class']], level=level, score=score,
                    tags=[{'Vulnerabilities': 'vulnerability', 'Misconfigurations': 'misconfiguration',
                           'Secrets': 'secret', 'Licenses': 'license'}[kind], 'security', severity])
    return (result, rules) if with_rules else result


def sarif_correspondence(fs, sarif, conversion_input=None):
    need(isinstance(sarif, dict) and sarif.get('version') == '2.1.0' and
         isinstance(sarif.get('runs'), list) and len(sarif['runs']) == 1, 'sarif-schema')
    run = sarif['runs'][0]
    need(isinstance(run, dict), 'sarif-run')
    tool = run.get('tool')
    need(isinstance(tool, dict), 'sarif-tool')
    driver = tool.get('driver')
    need(isinstance(driver, dict) and driver.get('name') == 'Trivy' and
         driver.get('version') == VERSION, 'sarif-tool')
    rules = driver.get('rules')
    need(isinstance(rules, list) and all(isinstance(r, dict) and isinstance(r.get('id'), str) and r['id'] for r in rules), 'sarif-rules')
    need(len({r['id'] for r in rules}) == len(rules), 'sarif-duplicate-rule')
    expected, expected_rules = sarif_projection(fs, with_rules=True)
    need({r['id'] for r in rules} == set(expected_rules), 'sarif-rule-inventory')
    for rule in rules:
        want = expected_rules[rule['id']]
        props = rule.get('properties', {})
        need(rule.get('name') == want['name'] and
             rule.get('defaultConfiguration') == {'level': want['level']} and
             isinstance(props, dict) and props.get('security-severity') == want['score'] and
             props.get('tags') == want['tags'] and props.get('precision') == 'very-high', 'sarif-rule-severity')
    invocations = run.get('invocations', [])
    need(isinstance(invocations, list), 'sarif-invocations')
    for invocation in invocations:
        need(isinstance(invocation, dict) and invocation.get('executionSuccessful') is True,
             'sarif-failed-invocation')
        if 'exitCode' in invocation:
            need(type(invocation['exitCode']) is int and invocation['exitCode'] == 0, 'sarif-invocation-exit')
        for name in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            notes = invocation.get(name, [])
            need(isinstance(notes, list) and all(isinstance(n, dict) and n.get('level') != 'error' for n in notes),
                 'sarif-error-notification')
    # Trivy convert bases ROOTPATH on the input JSON filename, not ArtifactName.
    # Bind that representation to the actual convert argv at the live boundary.
    bases = run.get('originalUriBaseIds')
    need(isinstance(bases, dict) and set(bases) == {'ROOTPATH'} and
         isinstance(bases['ROOTPATH'], dict) and set(bases['ROOTPATH']) == {'uri'} and
         isinstance(bases['ROOTPATH']['uri'], str) and bases['ROOTPATH']['uri'].startswith('file:///') and
         bases['ROOTPATH']['uri'].endswith('/'), 'sarif-uri-base')
    if conversion_input is not None:
        need(Path(conversion_input).is_absolute() and run.get('originalUriBaseIds') ==
             {'ROOTPATH': {'uri': 'file://' + str(conversion_input) + '/'}}, 'sarif-conversion-input')
    results = run.get('results')
    need(isinstance(results, list) and len(results) >= len(EXPECTED), 'sarif-results')
    observed = Counter()
    for r in results:
        need(isinstance(r, dict) and set(r) == {'ruleId', 'ruleIndex', 'level', 'message', 'locations'}, 'sarif-result-structure')
        index = integer(r['ruleIndex'])
        need(index < len(rules) and r['ruleId'] == rules[index]['id'], 'sarif-rule-index')
        need(r['level'] in ('error', 'warning', 'note', 'none') and
             isinstance(r['message'], dict) and set(r['message']) == {'text'} and
             isinstance(r['message']['text'], str), 'sarif-result-message-level')
        locs = r['locations']
        need(isinstance(locs, list) and locs, 'sarif-result-locations')
        for loc in locs:
            need(isinstance(loc, dict) and set(loc) == {'physicalLocation', 'message'}, 'sarif-location')
            physical = loc['physicalLocation']
            need(isinstance(physical, dict) and set(physical) == {'artifactLocation', 'region'}, 'sarif-physical-location')
            region = physical['region']
            need(isinstance(region, dict) and set(region) == {'startLine', 'endLine', 'startColumn', 'endColumn'}, 'sarif-region')
            start = integer(region['startLine'], 1); end = integer(region['endLine'], 1)
            need(end >= start and type(region['startColumn']) is int and region['startColumn'] == 1 and
                 type(region['endColumn']) is int and region['endColumn'] == 1, 'sarif-region-bounds')
        observed[canonical(dict(ruleId=r['ruleId'], level=r['level'], message=r['message']['text'],
            locations=sorted(map(canonical, locs))))] += 1
    need(observed == expected, 'sarif-semantic-multiset')


def classify(fs, config, sarif, conversion_input=None):
    whole = report(fs, 'infra/aws/')
    scoped = report(config, '', config_only=True)
    need(Counter(map(canonical, whole['iac'])) == Counter(map(canonical, scoped['iac'])), 'paired-iac-projection')
    need(not whole['blockers'] and not scoped['blockers'], 'unaccepted-high-critical')
    sarif_correspondence(fs, sarif, conversion_input)
    # Conversion is from this exact raw JSON, never from filtered findings.
    return dict(finding_counts_by_kind_and_severity=whole['counts'],
                iac_findings=whole['iac'], configuration_successes=whole['configuration_successes'],
                accepted_high_findings=[x for x in whole['iac'] if x['severity'] == 'HIGH'],
                unaccepted_high_critical_findings=[])


def upload_view(fs, config, sarif, conversion_input=None):
    """Derive an upload view only after the complete, unchanged raw contract.

    Match each result through the native converter projection of its exact
    accepted JSON identity, including its source/caller contract. Keep every
    other result, its order, and all SARIF metadata verbatim as JSON values.
    """
    decision = classify(fs, config, sarif, conversion_input)
    accepted = decision['accepted_high_findings']
    need(len(accepted) == 2 and all(x['rule'] == 'AWS-0132' for x in accepted),
         'upload-exact-two-classifications')
    eligible = {}
    for result in fs['Results']:
        for finding in result.get('Misconfigurations', []):
            identity = normalized(result, finding, 'infra/aws/')
            if identity not in accepted:
                continue
            projection = sarif_projection({'Results': [{
                'Target': result['Target'], 'Class': result['Class'],
                'Type': result['Type'], 'Misconfigurations': [finding]}]})
            need(len(projection) == 1 and sum(projection.values()) == 1,
                 'upload-single-result-projection')
            key = next(iter(projection))
            need(key not in eligible, 'upload-duplicate-classification')
            eligible[key] = identity
    need(len(eligible) == 2, 'upload-complete-classification')
    derived = copy.deepcopy(sarif)
    retained = []
    removed = []
    for index, result in enumerate(sarif['runs'][0]['results']):
        key = canonical(dict(ruleId=result['ruleId'], level=result['level'],
            message=result['message']['text'], locations=sorted(map(canonical, result['locations']))))
        if key in eligible:
            identity = eligible.pop(key)
            paths = [identity['target'], *(o['filename'] for o in identity['occurrences'])]
            removed.append(dict(raw_result_index=index,
                result_sha256=sha(canonical(result).encode()), classification=identity,
                source_sha256={'infra/aws/' + p: SOURCES['infra/aws/' + p] for p in paths}))
        else:
            retained.append(copy.deepcopy(result))
    need(not eligible and len(removed) == 2, 'upload-exact-removal-inventory')
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
        [str(binary), 'config', *common, '--format', 'json', '--output', str(out / 'config.json'), str(root / 'infra/aws')],
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
        # A full scanner failure never becomes a passing classifier decision.
        need(result.returncode == 0, 'scanner-nonzero')
        no_policy(cache)
    need(source(root, identity['event_head'], env) == before, 'source-changed-during-scan')
    raw = {name: regular(out / name) for name in ('filesystem.json', 'config.json', 'trivy.sarif')}
    fs, config, sarif = (decode(raw[name]) for name in ('filesystem.json', 'config.json', 'trivy.sarif'))
    need(fs.get('Metadata', {}).get('Commit') == before['commit'], 'report-source-commit')
    need(fs.get('ArtifactName') == str(root) and config.get('ArtifactName') == str(root / 'infra/aws'),
         'report-source-root')
    decision, derived, removed = upload_view(fs, config, sarif, out / 'filesystem.json')
    upload = (canonical(derived) + '\n').encode()
    # Raw SARIF is immutable evidence; never overwrite it or filter JSON scans.
    with (out / 'trivy-upload.sarif').open('xb') as handle:
        handle.write(upload)
    upload_receipt = dict(raw_sha256=sha(raw['trivy.sarif']), upload_sha256=sha(upload),
        raw_result_count=len(sarif['runs'][0]['results']),
        upload_result_count=len(derived['runs'][0]['results']),
        removed_result_count=len(removed), removed_results=removed)
    return dict(schema='ncdit-trivy-contract-receipt-v2', contract=CONTRACT, status='passed',
        organization_policy_acceptance='established-for-this-contract', **identity, source=before, scanner=tool,
        private_cache_path=str(cache), external_policy_files=[], inherited_trivy_configuration='not-forwarded',
        secret_config_sha256=sha(regular(out / 'secret-config.yaml')),
        report_sha256={**{name: sha(data) for name, data in raw.items()}, 'trivy-upload.sarif': sha(upload)},
        sarif_upload=upload_receipt, scanner_exits=exits, **decision)


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
        (out / 'receipt.json').write_text(canonical(dict(schema='ncdit-trivy-contract-receipt-v2', contract=CONTRACT,
            status='blocked', organization_policy_acceptance='not-established', error_type=type(error).__name__)))
        print('::error::CyberCoach Trivy contract blocked; inspect retained evidence.')
        return 1
    (out / 'receipt.json').write_text(canonical(receipt))
    print('CyberCoach Trivy contract passed; complete findings retained.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

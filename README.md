# ncdit-required-workflows

The single source for NC DIT's organization-wide **required** GitHub Actions workflows, injected
into every repository in `NC-DIT-Open-Source` by an organization ruleset. Target repositories
need no workflow file of their own.

Built and maintained by NC DIT's Office of AI & Policy (OAIP).

## What runs on a pull request

`.github/workflows/pr-security-gate.yml` runs one job, `precheck`:

| Job | What | Cost | Blocks on |
|-----|------|------|-----------|
| `precheck` | **Trivy** — dependency CVEs, IaC/Dockerfile misconfiguration, secrets, licenses — plus an **errors-only** lint pass | ~2 min, deterministic, no tokens | CRITICAL/HIGH |

**CodeQL** runs in parallel as each repo's own required check.

The lint pass is intentionally lenient — syntax errors, undefined names, shell errors, workflow
expression errors. No style rules. A linter that fails on formatting teaches people to ignore
it.

The former Claude Security AI review (`scan`) and its findings comment (`report`) were removed
on 2026-10-21. Both depended on the org secret `CLAUDE_CODE_OAUTH_TOKEN`, which Anthropic
rejects (`401 authentication_failed`), so every human-authored pull request failed this required
gate without being reviewed. The `CLAUDE_*` organization variables and secret are no longer
read. Restoring an AI review is a separate decision.

## Why this repository is public

GitHub runs a required workflow only in repositories whose visibility is **at or below** the
source repository's:

> a public workflow can run on any repository in your organization, an internal workflow can run
> on internal and private repositories, and a private workflow can run on private repositories

The same restriction applies to reusable workflows:

> reusable workflows stored in internal repositories cannot be used in public repositories

The org contains public repositories. Covering them from a single source therefore requires that
source to be public — there is no internal arrangement that reaches a public repo. The
alternative is a byte-synced copy committed into every public repo, which publishes exactly the
same content while adding permanent drift risk and a fail-open (a copy living in the PR's own
repo can be edited by that PR, which makes the action self-skip).

Nothing secret lives here. Every credential is a `secrets.*` or `vars.*` indirection; the only
token-shaped strings are placeholders in a comment. Everything that must stay private stays in
the internal `.github` repo — in particular the findings dashboard, which reports per-repo open
finding counts.

## `security-router/`

Holds the owner-maintained CyberCoach Trivy contract and the embedder that inlines it into the
workflow YAML, because a required workflow cannot read a sibling file from its source repo.
CI fails on drift. See [`security-router/README.md`](security-router/README.md).

## Changing anything here

This file gates every pull request in the organization, so treat a change to it as a change to
the gate:

1. Edit `security-router/trivy_contract.py`, never the embedded block.
2. `python3 security-router/embed.py`
3. Run the suites in `.github/workflows/security-router-tests.yml`.
4. `actionlint .github/workflows/*.yml`
5. Keep every `uses:` pinned to a 40-character commit SHA with a version comment. CI enforces it.

## CyberCoach terminal S3 receiver contract

The CyberCoach-only precheck uses the owner-maintained
`security-router/trivy_contract.py`, generated into the required workflow by
`security-router/embed.py`. It never imports code or policy from the target PR.
Every other repository retains the existing Trivy action, parameters, exit
behavior and summary selection.

Contract `ncdit-cybercoach-terminal-s3-receivers-v1` accepts only two exact
AWS-0132 HIGH findings for terminal SSE-S3 server-access-log receivers. It
requires the paired AWS-0089 no-recursion findings, exact AWS-0010 CloudFront
adapter finding, LOW Lambda@Edge and audit-projection AWS-0066, and both MEDIUM CloudTrail
AWS-0014 observations. All nine remain in the raw results and SARIF.
A missing, additional, duplicated or changed IaC finding blocks, as does any
other HIGH/CRITICAL vulnerability, misconfiguration, secret or license finding.

The policy pins thirteen reviewed resource/caller files by SHA-256, including
DEV WAF membership and the exact projection and hosted-database callers. Current
source bodies are retained from `8348d5b451211f79284b3f9120320cf3ea8c5129`.
A genuine Trivy 0.70.0 configuration-only scan observes 2091 successful checks and
nine findings: the same two SSE-S3 HIGH classifications, four LOW and three MEDIUM.
The only changes from the 0fbcd contract are two exact source bindings and five
observed location fields. The optional common-store logging selector moves the
operator receiver's AWS-0089 location to lines 60–67 and AWS-0132 location to
lines 89–100. The retained database trail's optional data-event selectors move
its caller occurrence end from line 189 to 199. These changes do not alter either
HIGH receiver exception, any finding identity or severity, or scanner behavior.
Every field, source hash and caller occurrence remains bound exactly.

Historical full/R26, source467, f90/WAF, f701 and 0fbcd reports remain unchanged and
tested at their historical constants. `fixtures/8348-policy-source.json` retains
the actual current config report, all thirteen exact public bodies, scanner
identity and native terminal. Its repository JSON is an explicitly synthetic
projection used only for native converter and classifier controls, not a claimed
filesystem or vulnerability scan. A fresh complete hosted scan remains required.
No DB/download or new HIGH exception was introduced by this source correction.
This is provenance, **not** a permanent whole-repository commit restriction: each run must match the actual PR event
head, record its actual Git tree, and perform a complete fresh scan. Thus an
unrelated committed source fix can proceed; changes to reviewed IaC bytes,
call sites or the nine findings require an owner-reviewed contract revision.
Dirty, ignored/untracked, linked or submodule content is rejected.

The CyberCoach path installs SHA-pinned Trivy setup with caching disabled,
verifies the Linux AMD64 0.70.0 binary hash, and uses a new private cache with
embedded misconfiguration checks only. Inherited scanner configuration is not
forwarded. Target config/ignore/secret-rule files cannot govern the decision.
The trusted empty secret-rule YAML mapping keeps the built-in rules enabled.
The official archive checksum is recorded as a reviewed release reference;
the installed binary itself is measured at runtime.

All four scanners run with all severities and the existing ignore-unfixed
vulnerability policy. A separate config scan must match the filesystem IaC
projection one-for-one. SARIF is converted from that exact unfiltered full
JSON, keeping all severities and avoiding a second vulnerability-database
snapshot. The classifier compares semantic multisets: every rule identity,
per-result severity/message and exact physical location must correspond to the
full JSON, including package versions, repeated findings and repeated package
locations. Result order is immaterial; multiplicity is not. Rule indexes must
resolve to the stated rule ID. Null/malformed results, same-count substitution,
suppression fields and explicit unsuccessful invocation/error evidence block.
The runtime also binds Trivy convert's ROOTPATH to its exact JSON input path.
LOW/UNKNOWN licenses remain present; unranked licenses cannot disappear merely
because conversion omitted them. A new converter representation fails closed
until its contract is reviewed. Scanner, conversion, parser and artifact-upload
failures all block. Reports are written
outside the target checkout, never filtered or printed to the job log, and
retained for seven days with their hashes, scanner exits, actual workflow
ref/SHA, run identity, target head/tree and decision receipt.

A passing receipt establishes only this scanner policy decision after this
owner-maintained workflow is approved and merged. It does not establish live
S3/CloudFront delivery, privacy compliance, AWS permissions or launch readiness.
This proposal itself grants no exception. The security-policy owner must review
the exact semantic change and successful **Security router tests** before a
protected-main merge; the current ruleset's minimum required status is not a
substitute. A fresh required-workflow run on the published CyberCoach event
head, with complete retained evidence and no unaccepted HIGH/CRITICAL findings,
is required before hosted closure.

Run the embedder tests plus
`python3 -B security-router/test_trivy_contract.py`,
`python3 security-router/embed.py --check`, workflow parsing and actionlint.
Do not edit generated Python in the workflow; the embedder protects both
canonical source against every quoted heredoc delimiter and every reserved marker pair.

Retained467 local evidence uses the authenticated Darwin/ARM64 Trivy0.70 binary
for misconfiguration, secret and license scans plus its native SARIF converter.
No vulnerability database was available locally. The later WAF reports are
scoped config scans only. Neither establishes a current full vulnerability or
hosted pass. The hosted Linux binary pin and all four scanner commands are
unchanged. Historical full-scan/R26 and467 fixtures remain untouched and exercise
the same guard functions at their original policy constants. Separate tests bind
the current source bodies and authentic partial WAF reports; explicitly labelled
synthetic composition controls test the historical seven-finding contract without
claiming a new scan. Stale coordinates, other HIGH/CRITICAL findings and malformed
or suppressed results still block. Exactly two reviewed HIGH results are removed
only from the derived upload; raw reports remain intact.

The existing `test_trivy_contract.py` entry loads historical `test_trivy_f701.py`
and current `test_trivy_0fbcd.py`.
Current controls authenticate the real config report, all thirteen source bodies,
all nine findings and exact source lines; they reject every missing/duplicate/
changed identity, every source mutation and every other HIGH/CRITICAL category.
Only the original two HIGH receiver identities can leave the derived upload;
all raw findings remain intact. Historical tests are explicitly rebound to their
original constants and cannot pass as proof of a current scan.

CyberCoach source156dd refresh: the current contract binds fourteen public source bodies and the actual ten-finding Trivy 0.70.0 configuration scan. The two existing HIGH SSE-S3 receiver classifications are unchanged. The new MEDIUM AWS-0065 origin-bootstrap key-rotation finding remains visible in both raw and uploaded results; it is not remediated or a HIGH/CRITICAL exception. Historical 8348 fixtures/tests retain their original constants. Configuration-only and synthetic conversion tests do not establish a full dependency scan or hosted CI clearance.

CyberCoach PR226 refresh: two exact frontdoor source fingerprints now follow the reviewed disabled/associated PROD stages. The ten finding identities, severities, line coordinates, two HIGH receiver exceptions, scanner commands and every other repository's workflow remain unchanged. The new public source fixture and offline negative controls prove source association only; they do not claim a fresh scan or hosted success. Historical PR197 fixtures retain their original constants. A fresh complete required-workflow run is still required on the published CyberCoach head.

CyberCoach PR272 source association: two current public-frontdoor fingerprints and
the existing AWS-0010 caller coordinates (112–129) follow the reviewed PROD network
restriction and direct logging-metadata reader. Other source hashes, finding
identities/severities and receiver exceptions are unchanged. PR197/PR226 fixtures
retain their original source/coordinate bindings. The current public-source fixture
and explicitly synthetic inventory projection establish source/guard compatibility,
not a new scanner result. A fresh complete hosted gate is still required.

CyberCoach PR364 source association: two exact public-frontdoor fingerprints and
the existing AWS-0010 caller end line (129 to 131) follow the reviewed DEV-only
auth-rate rule removal and remaining-rule sampled requests. ACL-level sampling
remains false; PROD defaults and the existing finding identities, severities,
receiver exceptions, scanner commands and other repositories are unchanged.
PR272 and earlier fixtures retain their original constants. The new public-source
fixture and synthetic inventory controls prove source/guard compatibility only,
not a new scanner result. A fresh complete hosted gate remains required.

CyberCoach PR364 general-rate follow-up: two exact frontdoor fingerprints and
the AWS-0010 caller end line (131 to 132) follow the explicit DEV-only general-rate
flag. DEV retains its network restriction and rule sampling; PROD rate rules and
ACL-level sampling remain unchanged. Finding identities, severities, HIGH receiver
exceptions, scanner commands and all other repositories retain their behavior.
The auth-only PR364 fixture remains immutable with its historical bindings.
New public-source and synthetic projection controls establish compatibility only;
no fresh scanner result or hosted clearance is claimed.

CyberCoach PR453 records-trail follow-up: the audit projection module drops its
log subscription and Lambda invoke permission, so its reviewed source fingerprint
changes and the LOW AWS-0066 projection finding moves from lines 117–135 to
116–134. Finding identities, severities, HIGH receiver exceptions, scanner
commands and all other repositories keep their behavior. Earlier fixtures keep
their historical coordinates. The new public-source fixture and synthetic
projection controls establish compatibility only; no fresh scanner result or
hosted clearance is claimed.

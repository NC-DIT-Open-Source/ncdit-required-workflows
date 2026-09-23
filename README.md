# ncdit-required-workflows

The single source for NC DIT's organization-wide **required** GitHub Actions workflows, injected
into every repository in `NC-DIT-Open-Source` by an organization ruleset. Target repositories
need no workflow file of their own.

Built and maintained by NC DIT's Office of AI & Policy (OAIP).

## What runs on a pull request

`.github/workflows/pr-security-gate.yml` runs in two phases, and the order is deliberate:

| Phase | What | Cost | Blocks on |
|-------|------|------|-----------|
| 1. `precheck` | **Trivy** — dependency CVEs, IaC/Dockerfile misconfiguration, secrets, licenses — plus an **errors-only** lint pass | ~2 min, deterministic, no tokens | CRITICAL/HIGH |
| 2. `scan` | **Claude Security** — AI review of the filtered PR diff | 15–90 min, probabilistic | CRITICAL/HIGH into the default branch |

The AI scan explicitly uses **Claude Opus 5.5** (`claude-opus-5-5` for OAuth,
`us.anthropic.claude-opus-5-5` for Bedrock). Security researchers and verifiers inherit
that model; the plugin's Sonnet inventory helpers keep their existing model.

Phase 2 carries `needs: precheck`, so anything a scanner can decide is decided first. A known
CVE or a public storage bucket in the diff blocks in phase 1 and the expensive AI pass never
starts.

Blocking is safe in phase 1 in a way it is not in phase 2: Trivy and the linters cannot hang, so
there is no timeout to trade against. Phase 2's timeout policy is a deliberate trade-off — see
`CLAUDE_SECURITY_TIMEOUT_POLICY` below.

**CodeQL** runs in parallel as each repo's own required check. Actions cannot express ordering
across workflows, and CodeQL finishes in a minute or two, so it is not worth contorting for.

The lint pass is intentionally lenient — syntax errors, undefined names, shell errors, workflow
expression errors. No style rules. A linter that fails on formatting teaches people to ignore
it, and this one gates the scan.

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

## Configuration

Set once at the organization level, Settings → Secrets and variables → Actions.

| Kind | Name | Value | Mode |
|------|------|-------|------|
| Variable | `CLAUDE_AUTH_MODE` | `bedrock` or `oauth` | both |
| Secret | `AWS_ROLE_TO_ASSUME` | role ARN | bedrock |
| Variable | `AWS_REGION` | e.g. `us-east-1` | bedrock |
| Secret | `CLAUDE_CODE_OAUTH_TOKEN` | subscription token | oauth |

Optional, all with working defaults:

| Variable | Default | Effect |
|----------|---------|--------|
| `CLAUDE_SECURITY_TIMEOUT_POLICY` | `warn` | `warn`: a scan that trips its step timeout reports loudly and does not block. `block`: it fails closed. |
| `CLAUDE_SECURITY_MAX_FILES` | `20` | Filtered-diff file cap; above it, effort drops rather than coverage. |
| `CLAUDE_SECURITY_MAX_LINES` | `3000` | Same, on changed lines. |
| `CLAUDE_SECURITY_MAX_FILE_LINES` | `2000` | A file above this is still scanned, but pulls effort down to `low`. |
| `CLAUDE_SECURITY_DEBUG` | unset | `true` re-enables `show_full_output`. Off by default: it logs all tool results, which on a public repo means publicly. |
| `CLAUDE_SECURITY_MAX_BUDGET_USD` | unset | Optional per-invocation model-spending cap for the scan. Configure together with the report cap. |
| `CLAUDE_SECURITY_REPORT_MAX_BUDGET_USD` | unset | Optional per-invocation model-spending cap for the report-posting helper. Configure together with the scan cap. |

Set spending caps as **repository variables** to bound a particular project's
reviews without changing other repositories. Both must be positive USD amounts
below 1000, with at most two decimal places (for example, `18.00` and `0.50`).
Invalid or incomplete configuration fails before inference. Leaving both unset
preserves existing behavior. The caps apply to each invocation; callers still
need to budget repeated runs and any separate repository review workflows.

A configured scan that does not complete successfully fails closed, including
when a partial report exists or the failure occurs near the timeout window.
Exhausting a spending cap does not establish a clean security review or reduce
the scope being scanned. If the bounded report helper cannot post, the existing
deterministic comment fallback still publishes the findings.

## How long should a run take?

**A run over 30 minutes is normal. It is not hung. Do not cancel it.**

This is the single most common misreading of this workflow — the Actions UI shows *elapsed*
time and never *expected* time, so a healthy AI review looks identical to a stuck job.

| Diff shape | Expect |
|---|---|
| ≤5 files **and** ≤300 changed lines | 5–10 min (the scanner's fast path) |
| anything larger | 15–60 min, capped at 90 into the default branch, 30 elsewhere |
| `precheck` alone | 30–60 s |

The 300-line boundary is a **cliff**, not a slope — measured: 1 file / 4 lines took 6m07s, while
1 file / 387 lines took 40m39s, because the second one falls outside the fast path and runs the
full review. Runtime then scales with the number of top-level **areas** in scope rather than
line count: 1 area ran 16–41 min, 4 areas ran 57 min.

Every run tells you this itself, in three places, so you should not have to come here:

- the **run title** ("allow up to 90 min (not hung)");
- a **`::notice`** on the run page with the expected range for that specific diff;
- a **banner at the top of the job summary**, written seconds in and on screen for the whole run.

If a scan genuinely exceeds its budget the step is killed on its own and says
`scan infrastructure timeout … this is NOT a security finding`, which is deliberately worded to
be distinguishable from a real finding. With `CLAUDE_SECURITY_TIMEOUT_POLICY=warn` (the default)
that does not block the merge.

### Why the caps are 20 / 3000

Measured, not guessed. At `medium` the plugin runs its full component matrix for anything
outside its own fast path (≤5 files **and** ≤300 lines), and observed wall-clock tracks the
number of top-level areas in scope far more than the line count:

| PR | files | lines | areas in scope | scan |
|---|---|---|---|---|
| `Public-Comment-Analyzer` #193 | 1 | 404 | 1 | 16m20s |
| `mock-carolina` #63 (1st) | 1 | 387 | 1 | 40m39s |
| `mock-carolina` #63 (2nd) | 4 | 656 | 4 | **57m01s** |
| `mock-carolina` #56 (pre-filter) | 126 | 31,576 | 12 | 1h26m, then a 2h kill |

57 minutes on a **four-file** diff is 63% of the 90-minute step budget. A release-shaped diff
spans roughly ten areas and would exceed it. The earlier 80 / 12,000 defaults did **not** trip
on that shape — post-filter it is 65 files / 9,151 lines — so it would have run at `medium` and
probably timed out, which is the failure this router exists to prevent.

Raise these only with runtime evidence. Setting them too high does not fail loudly; it fails as
a timeout, and with `CLAUDE_SECURITY_TIMEOUT_POLICY=warn` that is a pass.

> A file/line cap is a proxy for what actually drives cost. The more predictive control would
> be a cap on the **number of top-level areas** in scope; that is a router change, tracked
> separately rather than guessed at here.

## Skipped by design

Each of these still satisfies the required check, so it cannot wedge a merge:

- **Fork pull requests.** GitHub withholds Actions secrets from fork runs, so the scan cannot
  authenticate. Flagged as needing human review. Never "fixed" with `pull_request_target` —
  that runs with secrets while checking out untrusted code.
- **Bot actors.** Bot-initiated runs get the Dependabot secret store, not Actions secrets.
  Dependency updates are covered by Dependabot advisories, CodeQL and Trivy.
- **Draft pull requests**, until marked ready for review.
- **Diffs with nothing reviewable** — every changed file binary or data.

## `security-router/`

Decides what phase 2 reads and how deep it goes. It is inlined into the workflow YAML because a
required workflow cannot read a sibling file from its source repo; `embed.py` regenerates the
embedded copy and CI fails on drift. See [`security-router/README.md`](security-router/README.md)
for the invariants — most of them exist because they were broken once.

```bash
python3 security-router/test_route.py
python3 security-router/test_embed.py
bash    security-router/test_gate.sh .github/workflows/pr-security-gate.yml
python3 security-router/embed.py --check
```

## Changing anything here

This file gates every pull request in the organization, so treat a change to it as a change to
the gate:

1. Edit `security-router/route_scan.py`, never an embedded block.
2. `python3 security-router/embed.py`
3. Run all three suites, **including under bash 5** — macOS ships bash 3.2 and the runner does
   not agree with it about `set -u`.
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
requires the paired AWS-0089 no-recursion findings and the exact AWS-0010
CloudFront adapter finding. All five remain in the raw results and SARIF.
A missing, additional, duplicated or changed IaC finding blocks, as does any
other HIGH/CRITICAL vulnerability, misconfiguration, secret or license finding.

The policy pins the three reviewed resource files and both occurrence call
sites by SHA-256. Those bytes were checked at CyberCoach source
`153a1aac7f3e4fd67f966f02a1fdcb3afce35180`. This is provenance, **not** a permanent
whole-repository commit restriction: each run must match the actual PR event
head, record its actual Git tree, and perform a complete fresh scan. Thus an
unrelated committed source fix can proceed; changes to reviewed IaC bytes,
call sites or the five findings require an owner-reviewed contract revision.
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

Run the existing router, gate, budget and embedder tests plus
`python3 -B security-router/test_trivy_contract.py`,
`python3 security-router/embed.py --check`, workflow parsing and actionlint.
Do not edit generated Python in the workflow; the embedder protects both
canonical sources against every quoted heredoc delimiter and both marker pairs.

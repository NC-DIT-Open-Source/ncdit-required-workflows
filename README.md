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

## CyberCoach Trivy policy

Only `NC-DIT-Open-Source/CyberCoach-NC` takes this path; every step is guarded by
`github.repository == 'NC-DIT-Open-Source/CyberCoach-NC'`. Every other repository keeps the
standard Trivy action, inputs, exit behavior and summary. The policy lives in
`security-router/trivy_contract.py` and is generated into the workflow by
`security-router/embed.py`. No code, config, ignore file or policy from the target PR is used.

**Rule.** Run a complete Trivy 0.70.0 scan of the PR head (vulnerabilities, misconfiguration,
secrets, licenses; all severities) plus a configuration scan of `infra/aws`. Block on every
HIGH or CRITICAL finding, except a misconfiguration whose **rule ID and repository path** are
listed in `ACCEPTED`. LOW, MEDIUM and UNKNOWN findings never block and stay visible in the
raw reports and in the Security tab.

**Accepted findings.** Each `ACCEPTED` entry is `rule`, `path` and a written `justification`
(at least 40 characters; a doc link is expected). No line numbers and no file hashes, so
editing or moving IaC does not need a change here. Only misconfigurations can be accepted;
HIGH/CRITICAL vulnerabilities, secrets and licenses always block. An entry covers every
finding of that rule in that file. An entry that matches nothing produces a warning so it can
be removed. Current entries:

| Rule | Path | Why |
|------|------|-----|
| `AWS-0132` | `infra/aws/modules/audit-foundation/receivers.tf` | Terminal S3 server-access-log receiver; AWS supports only SSE-S3 there |
| `AWS-0132` | `infra/aws/operator-foundations/access-logging.tf` | Same |

To accept a new finding, add an entry with its justification, run the tests below and get
security-policy owner review. To fix one instead, fix the Terraform; nothing here changes.

**What else is still enforced.** The run must be the GitHub `pull_request` event for
CyberCoach-NC from this workflow at `refs/heads/main`. The checkout must be the clean event
head (no untracked, ignored, linked or submodule content) with the canonical origin, and must
not change during the scan. The Trivy binary hash and version are measured; the cache is
private and empty, contains no external policy, and inherited `TRIVY_*` settings are not
forwarded. Trivy suppressions (`Exceptions`) block. The repository and configuration scans
must agree on which rules fire in which `infra/aws` files. Scanner, parser, SARIF and
artifact failures all block. The uploaded SARIF drops only the accepted results; the raw JSON,
raw SARIF, scanner output and receipt are retained for seven days.

A passing receipt is a scanner policy decision only. It does not establish live AWS delivery,
privacy compliance or launch readiness.

The `fixtures/r26-trivy-10716525352.zip` artifact is a real hosted CyberCoach scan used as the
positive control; every other case in the tests is a labelled mutation of it.

```bash
python3 -B security-router/test_trivy_contract.py
python3 security-router/test_embed.py
python3 security-router/embed.py --check
```

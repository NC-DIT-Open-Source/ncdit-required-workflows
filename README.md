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
| `CLAUDE_SECURITY_MAX_FILES` | `80` | Filtered-diff file cap; above it, effort drops rather than coverage. |
| `CLAUDE_SECURITY_MAX_LINES` | `12000` | Same, on changed lines. |
| `CLAUDE_SECURITY_MAX_FILE_LINES` | `2000` | A file above this is still scanned, but pulls effort down to `low`. |
| `CLAUDE_SECURITY_DEBUG` | unset | `true` re-enables `show_full_output`. Off by default: it logs all tool results, which on a public repo means publicly. |

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

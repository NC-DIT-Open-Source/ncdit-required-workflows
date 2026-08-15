# security-router

Decides **what** the Claude Security scan reads and **how deep** it goes, before any tokens
are spent. Owned by `.github/workflows/claude-security.yml`; see
[`../docs/claude-security-org-rollout.md`](../docs/claude-security-org-rollout.md) for the
operator view.

## Why it exists

The `claude-security` plugin only takes its cheap single-researcher path when it can read
**both** a changed-file count ≤ 5 **and** a changed-line count ≤ 300. Its own
`jobs/scan-changes.md` instructs the agent to pass **no line count at all** when any
`git diff --numstat` row is binary (`-`).

So a single `.parquet` or `.zip` anywhere in the diff makes that fast path *structurally
unreachable*, and the full component matrix plus three-lens verification panel runs no
matter how small the real code change was. On mock-carolina PR #56 that meant a 2-hour
runner kill on a change whose actual code content was modest:

| | files | lines | binary rows |
|---|---|---|---|
| Raw diff | 126 | 31,576 | 20 |
| After filtering | 65 | 9,151 | **0** |

Dropping generated paths removes the binary rows, which is what lets the plugin's own
proportionality logic work again. The filter is not a workaround for the scanner being
slow — it is what makes the scanner's own sizing correct.

## Files

| File | Role |
|---|---|
| `route_scan.py` | The router. Canonical source — **edit this**. |
| `test_route.py` | Filtering, tiering, caps, scope safety, hostile filenames, and every router regression from the OAIP-479 review. |
| `test_gate.sh` | Drives all 19 outcomes of the workflow's gate step, extracted from the YAML. Tests the timeout path in seconds instead of waiting out a 90-minute budget. |
| `embed.py` | Inlines `route_scan.py` into each workflow copy, and `--check`s for drift. |
| `test_embed.py` | Heredoc-escape and marker-collision refusals. |

```bash
python3 security-router/test_route.py
python3 security-router/test_embed.py
bash    security-router/test_gate.sh .github/workflows/claude-security.yml
python3 security-router/embed.py            # re-embed after editing route_scan.py
python3 security-router/embed.py --check    # what CI runs
```

**Run the gate tests under bash 5 before pushing.** macOS ships bash 3.2, the runner has 5.x,
and they disagree on `set -u`: `${VAR%%pattern}` on an unset variable is an unbound-variable
error in 4.4+ and silently empty in 3.2. That difference already turned a benign
validation-skip into a hard failure once, passing locally and failing in CI.

```bash
docker run --rm -v "$PWD":/w -w /w python:3.12-slim \
  bash -c "pip install -q pyyaml && bash security-router/test_gate.sh .github/workflows/claude-security.yml"
```

## Why the router is inlined into the YAML

The workflow runs as an org **required workflow**, injected into repos that hold no file of
their own — so it cannot read a sibling script from this repository. A cross-repo checkout
is not an option either: this repo is internal, and a public repo's job token cannot read
it. The router therefore has to travel inside the YAML.

`embed.py` is what keeps that honest. `route_scan.py` stays the single tested source; the
copies between the `BEGIN`/`END` markers are generated. Never edit a block in a workflow
file — CI (`.github/workflows/security-router-tests.yml`) fails on drift.

## Per-repo exclusions

A repo may add `.github/claude-security-ignore`, one gitignore-style glob per line, `#` for
comments. Patterns are **appended** to the built-in defaults; there is no way to remove a
default (a repo cannot opt out of being scanned).

```
# generated provenance records
receipts/**
catalog/*.jsonld
```

**The list is read from the base ref, never from the pull request head.** A PR must not be
able to widen its own exclusions and blank the gate it has to pass. Editing the file is
allowed; the change takes effect once merged, and the run warns that it applied the base
version.

What a repo pattern can and cannot do:

- It cannot match everything. Catch-alls are rejected by a functional test (matched against
  probe paths), not a list of spellings — `?*`, `*?` and `?**` all match every path and no
  enumeration of literals catches them. Patterns with more than two `**` are refused as a
  backtracking hazard.
- It cannot hide code. Anything a repo excludes is treated as *possibly code* regardless of
  extension, and if any possibly-code path was filtered, **no `--scope` is passed at all** —
  the whole range is scanned. So `*.py` in an ignore file costs you the precise scope; it does
  not cost you the scan.
- It therefore only ever saves cost on paths the built-in rules already consider inert.

## Invariants worth preserving

Every one of these has a test, and most of them have a test because the invariant was
already broken once. A filter on a security gate fails in one direction — quietly, toward
less coverage — so treat a change here as a change to the gate itself.

- **A scope entry can never readmit a filtered path.** A directory is emitted only when its
  *entire subtree* is clean; otherwise the surviving files are listed individually. An
  earlier version emitted clean immediate parents and then pruned descendants by prefix,
  which readmitted excluded paths when a sibling subtree was dirty.
- **No fallback may widen scope.** When the precise scope is too large to pass as one
  argument, the scope is *dropped* (scan everything, at reduced effort) rather than collapsed
  to top-level directories. Collapsing shortens the string by widening it, readmitting the
  binary rows the router exists to remove — the one fallback that is actively wrong.
- **Coverage never shrinks silently.** A path outside the safe shape (metacharacters,
  newlines, `..`, non-ASCII, leading `-`), or an unparseable `--numstat` record, disables
  scoping entirely so the whole range is scanned. That is the expensive direction on
  purpose; the step timeout bounds it.
- **Code, workflows, IaC, config and docs are never excluded — including large ones.** Size
  is a cost signal, so a file over `MAX_FILE_LINES` drops the run to `--effort low` but stays
  in scope. Skipping it outright let a 2,500-line source file out of review while the gate
  stayed green, and padding an existing file to 2,001 changed lines did the same.
- **If anything possibly-code was filtered, no `--scope` is passed — unconditionally.** Not
  "when nothing else survived": that version was bypassed by one unrelated file, and nearly
  every real PR has a CHANGELOG or README line in it, so `dist/bundle.js` and `*.py`-ignored
  sources dropped straight back out of scope behind a green check.
- **Possibly-code is a denylist, so an unrecognised extension counts as code.** An allowlist
  defaulted every format nobody enumerated to "data" — measured, 22 of 27 probes under `dist/`
  went unscanned, including `.htaccess`, `.svg`, `.ipynb`, `.jsp` and `pipeline.yml`. Dotfiles
  are code (`.htaccess` enables CGI; `.env` is secrets). Repo-supplied patterns skip the
  extension test entirely and always count as code.
- **"Nothing to scan" requires every dropped path to be inert.** Data and binaries qualify.
  Build output does not: `dist/policy.json` alone means the output moved without its input, so
  it is scanned. Published data and dependency trees changing alone *is* normal, which is what
  keeps a data-release PR skippable — and that distinction is per-pattern
  (`BUILD_OUTPUT_IGNORE`), not per-extension.
- **A repo cannot switch its own scanning off.** See the per-repo section above for exactly
  what is and is not enforced.
- **No source line may equal the heredoc sentinel.** `embed.py` refuses it. Such a line ends
  the heredoc and hands the remainder to bash in a step holding `pull-requests: write` and
  `id-token: write` — and it compiles, passes the router tests, and shows no drift, inside a
  block reviewers are told not to read.
- **Every skip is reported.** The step summary names the count and the paths, and
  `claude-security-route.json` ships in the run artifact, separating generated skips from
  oversized-but-scanned files. A filter nobody can see is indistinguishable from a scan that
  missed something.

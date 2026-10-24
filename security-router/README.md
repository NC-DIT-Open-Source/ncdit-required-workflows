# security-router

Owner-maintained sources inlined into `.github/workflows/pr-security-gate.yml`.

The Claude Security scan router (`route_scan.py`) and its gate, budget and receipt tests were
removed on 2026-10-21 together with the token-dependent `scan` and `report` jobs. The router's
markers stay reserved in `embed.py`, so that block cannot be re-spliced into another source.

## Files

| File | Role |
|---|---|
| `trivy_contract.py` | CyberCoach Trivy policy and its `ACCEPTED` list. Canonical source — **edit this**. |
| `embed.py` | Inlines `trivy_contract.py` into the workflow, and `--check`s for drift. |
| `test_embed.py` | Heredoc-escape and marker-collision refusals. |
| `test_trivy_contract.py` | Trivy policy, accepted-list, runtime and workflow-scope tests. |
| `fixtures/r26-trivy-10716525352.zip` | Real hosted CyberCoach Trivy artifact used as the positive control. |
| `test_lint.py` | Dockerfile lint discovery and failure tests. |

```bash
python3 -B security-router/test_trivy_contract.py
python3 security-router/test_embed.py
python3 security-router/embed.py            # re-embed after editing trivy_contract.py
python3 security-router/embed.py --check    # what CI runs
```

## Why the contract is inlined into the YAML

The workflow runs as an org **required workflow**, injected into repos that hold no file of
their own, so it cannot read a sibling script from this repository. The contract therefore has
to travel inside the YAML. Never edit the block between the `BEGIN`/`END` markers in a workflow
file; CI (`.github/workflows/security-router-tests.yml`) fails on drift.

**No source line may equal a heredoc sentinel.** `embed.py` refuses it. Such a line ends the
heredoc and hands the remainder to bash in a privileged step, and it would compile, pass the
contract tests and show no drift.

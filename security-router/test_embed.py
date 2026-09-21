"""Tests for embed.py, the thing that inlines the router into the workflow YAML.

The interesting property is not "does it splice correctly" but "can a source line escape the
heredoc it is spliced into". The embedded block sits inside `python3 - ... <<'CS_ROUTER_PY'`,
and YAML block-scalar de-indentation returns every rendered line to column zero -- so a
source line that is exactly the sentinel ends the heredoc and bash executes everything after
it, in a step holding `pull-requests: write`, `id-token: write` and a checkout credential.

A Python docstring or comment containing that word on its own line is enough. It compiles,
the router tests pass, and `embed.py --check` reports no drift -- while reviewers are
explicitly told not to read the generated block. Hence a generation-time refusal.

Run: python3 test_embed.py
"""
import importlib.util, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EMBED = os.path.join(HERE, "embed.py")
WORKFLOW = os.path.join(os.path.dirname(HERE), ".github", "workflows", "pr-security-gate.yml")

spec = importlib.util.spec_from_file_location("embed", EMBED)
embed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(embed)

fails = []


def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        fails.append(name)


def rendered_lines(source_text, sentinel="CS_ROUTER_PY"):
    return embed.render(source_text, 10, sentinel).split("\n")


def splice_with_prelude(prelude, source_text):
    """Build a minimal target that looks like the real workflow, optionally with an extra
    comment above the marker, and splice into it."""
    with tempfile.TemporaryDirectory() as td:
        wf = os.path.join(td, "wf.yml")
        with open(wf, "w", encoding="utf-8") as fh:
            fh.write("jobs:\n  scan:\n    steps:\n      - run: |\n")
            fh.write("          python3 - x <<'GATE_PY'\n          import sys\n          GATE_PY\n")
            fh.write("          python3 - y <<'CS_ROUTER_PY'\n")
            if prelude:
                fh.write("          %s\n" % prelude)
            fh.write("          %s\n          %s\n" % (embed.BEGIN, embed.END))
            fh.write("          CS_ROUTER_PY\n")
        return embed.splice(wf, source_text)


# --- the escape ---------------------------------------------------------------------------
polyglot = '\n'.join([
    'CS_ROUTER_PY = None',
    '_NOTES = """',
    'CS_ROUTER_PY',
    'echo PWNED',
    '"""',
])
try:
    rendered_lines(polyglot)
    check("a source line equal to the sentinel is refused", False)
except SystemExit as e:
    check("a source line equal to the sentinel is refused", "sentinel" in str(e))

# Indented occurrences are just as dangerous: YAML strips the block indent, so an indented
# sentinel line still lands at column zero.
try:
    rendered_lines('x = 1\n    CS_ROUTER_PY\ny = 2')
    check("an indented sentinel line is refused", False)
except SystemExit:
    check("an indented sentinel line is refused", True)

# The word inside a larger line cannot terminate a heredoc, so it must remain allowed --
# refusing it would make the guard unusable (the workflow's own comments mention it).
try:
    out = rendered_lines('# see CS_ROUTER_PY below\nx = "CS_ROUTER_PY plus more"\n')
    check("the sentinel inside a longer line is allowed", len(out) > 2)
except SystemExit:
    check("the sentinel inside a longer line is allowed", False)

# --- marker collisions -------------------------------------------------------------------
try:
    rendered_lines(embed.BEGIN + "\nx = 1")
    check("a duplicated BEGIN marker is refused", False)
except SystemExit as e:
    check("a duplicated BEGIN marker is refused", "marker" in str(e))

# --- indentation / fidelity ---------------------------------------------------------------
out = rendered_lines('import os\n\nif True:\n    pass\n')
check("markers wrap the block", out[0].strip() == embed.BEGIN and out[-1].strip() == embed.END)
check("body is padded to the block indent", out[1] == " " * 10 + "import os")
check("relative indentation is preserved", out[-2] == " " * 10 + "    pass")
check("blank lines carry no trailing whitespace", "" in out)

# --- the sentinel is read from the target, not assumed ------------------------------------
with open(WORKFLOW, encoding="utf-8") as fh:
    wf = fh.read()
check("workflow uses the sentinel these tests assume", "<<'CS_ROUTER_PY'" in wf)

_, updated = embed.splice(WORKFLOW, open(embed.SOURCE, encoding="utf-8").read())
check("splicing the real workflow is idempotent", updated == wf)

# The guard must not be redirectable. Scanning backwards for the nearest `<<'NAME'` meant one
# innocuous comment above the marker naming a DIFFERENT block's delimiter retargeted the check,
# so the real sentinel went unchecked and the escape reopened -- across two separately harmless
# diffs, which is worse than the single-diff version. Every delimiter in the file is checked now.
escape = "x = 1\nCS_ROUTER_PY\ny = 2"
try:
    splice_with_prelude("# (the gate step uses a similar <<'GATE_PY' block)", escape)
    check("sentinel guard is not redirectable by a decoy comment", False)
except SystemExit as e:
    check("sentinel guard is not redirectable by a decoy comment", "CS_ROUTER_PY" in str(e))
try:
    splice_with_prelude(None, escape)
    check("sentinel guard fires with no decoy present", False)
except SystemExit:
    check("sentinel guard fires with no decoy present", True)
# A line matching any OTHER block's delimiter is refused too -- cheap, and it means the router
# can never be spliced somewhere that would break a different heredoc.
try:
    splice_with_prelude(None, "x = 1\nGATE_PY\ny = 2")
    check("a line matching another block's delimiter is refused", False)
except SystemExit:
    check("a line matching another block's delimiter is refused", True)
# ...and an ordinary source file still splices cleanly into that shape.
try:
    _, out = splice_with_prelude(None, "import os\nprint(os.name)\n")
    check("an ordinary source still splices", "print(os.name)" in out)
except SystemExit:
    check("an ordinary source still splices", False)

# A target whose heredoc delimiter cannot be found must fail loudly rather than guess.
with tempfile.TemporaryDirectory() as td:
    broken = os.path.join(td, "wf.yml")
    with open(broken, "w", encoding="utf-8") as fh:
        fh.write("run: |\n  python3 - x\n  %s\n  %s\n" % (embed.BEGIN, embed.END))
    try:
        embed.splice(broken, "x = 1")
        check("a missing heredoc delimiter is refused", False)
    except SystemExit as e:
        check("a missing heredoc delimiter is refused", "delimiter" in str(e))

# --- drift detection actually detects drift -----------------------------------------------
rc = subprocess.run([sys.executable, EMBED, "--check"], capture_output=True, text=True).returncode
check("--check passes on a clean tree", rc == 0)


# Both canonical sources are checked against EVERY delimiter and marker.
for begin, end, label in ((embed.BEGIN, embed.END, 'router'),
                          (embed.TRIVY_BEGIN, embed.TRIVY_END, 'trivy')):
    for sentinel in ('CS_ROUTER_PY', 'CC_TRIVY_PY', 'GATE_PY'):
        try:
            embed.render('x = 1\n' + sentinel + '\ny = 2', 10,
                         {'CS_ROUTER_PY', 'CC_TRIVY_PY', 'GATE_PY'}, begin, end)
            check(label + ' refuses ' + sentinel, False)
        except SystemExit:
            check(label + ' refuses ' + sentinel, True)
    for marker in embed.MARKERS:
        try:
            embed.render(marker, 10, {'CC_TRIVY_PY'}, begin, end)
            check(label + ' refuses cross-source marker', False)
        except SystemExit:
            check(label + ' refuses cross-source marker', True)
_, updated = embed.splice(WORKFLOW, open(embed.TRIVY, encoding='utf-8').read(),
                          embed.TRIVY_BEGIN, embed.TRIVY_END)
check('splicing the trusted Trivy source is idempotent', updated == wf)
for begin, end in ((embed.BEGIN,embed.END),(embed.TRIVY_BEGIN,embed.TRIVY_END)):
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td,'wf.yml')
        for content in ("run: |\n  python3 - <<'X'\n  " + begin + '\n  X\n',
                        "run: |\n  python3 - <<'X'\n  " + begin + '\n  ' + begin + '\n  ' + end + '\n  X\n'):
            with open(path,'w',encoding='utf-8') as handle:
                handle.write(content)
            try:
                embed.splice(path,'x = 1',begin,end)
                check('missing/duplicate named markers rejected',False)
            except SystemExit:
                check('missing/duplicate named markers rejected',True)

print()
if fails:
    print("%d FAILURE(S): %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("all tests passed")

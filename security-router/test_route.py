"""Boundary, hostile-filename and scope-safety tests for the Claude Security router.

Run: python3 test_route.py
"""
import importlib.util, json, os, subprocess, sys, tempfile

spec = importlib.util.spec_from_file_location("rs", os.path.join(os.path.dirname(os.path.abspath(__file__)), "route_scan.py"))
# route_scan.py calls main() on import, so load it with a trivial argv/env sandbox.
_fails = []


def check(name, got, want):
    if got != want:
        _fails.append("%s\n    got : %r\n    want: %r" % (name, got, want))
        print("FAIL %s" % name)
    else:
        print("ok   %s" % name)


def covers(scope, path):
    """Is `path` inside the scope? An empty scope means unscoped, which covers everything.

    Asserting coverage rather than an exact scope string is deliberate: the scope is
    intentionally collapsed to the shortest safe form, so `src` and `src/auth.py` are the
    same answer. Pinning the string makes the tests fail when the collapse improves, and --
    worse -- says nothing about the invariant that actually matters.
    """
    if scope == "":
        return True
    return any(e == path or path.startswith(e + "/") for e in scope.split(","))


def run(rows, base="main", default="main", ignore="", **env):
    """rows: list of (added, deleted, path) with added='-' for binary."""
    blob = b"".join(
        ("%s\t%s\t%s" % (a, d, p)).encode("utf-8", "surrogateescape") + b"\x00"
        for a, d, p in rows
    )
    with tempfile.TemporaryDirectory() as td:
        ns = os.path.join(td, "ns.z")
        ig = os.path.join(td, "ig.txt")
        open(ns, "wb").write(blob)
        open(ig, "w", encoding="utf-8").write(ignore)
        e = dict(os.environ)
        e.update({"BASE_REF": base, "DEFAULT_BRANCH": default,
                  "GITHUB_OUTPUT": os.path.join(td, "out"),
                  "GITHUB_STEP_SUMMARY": os.path.join(td, "sum")})
        e.pop("MAX_FILE_LINES", None); e.pop("MAX_FILES", None); e.pop("MAX_LINES", None)
        for k, v in env.items():
            e[k] = str(v)
        subprocess.run([sys.executable, spec.origin, ns, ig], cwd=td, env=e,
                       check=True, capture_output=True)
        return json.load(open(os.path.join(td, "claude-security-route.json")))


# --- the regression this router exists for -------------------------------------------
r = run([("-", "-", "data/releases/demo/x.parquet"), ("3", "1", "src/app.py")])
check("binary row is dropped, code kept", (r["kept_files"], r["binary_rows"]), (2 - 1, 1))
check("no binary survives into the kept set", r["binary_rows"], 1)

# --- scope must never readmit a dropped path (the bug found in review) ---------------
r = run([("5", "0", "src/a.py"), ("2", "0", "src/sub/b.py"),
         ("9", "9", "src/sub/big.jsonl")])
drops = [s["path"] for s in r["skipped"]]
readmitted = [e for e in r["scope"].split(",")
              for d in drops if d == e or d.startswith(e + "/")]
check("sibling-dirty subtree does not readmit", readmitted, [])
check("dirty subtree emits files not dirs", r["scope"], "src/a.py,src/sub/b.py")

r = run([("1", "0", "docs/a.md"), ("1", "0", "docs/deep/nested/b.md")])
check("wholly clean subtree collapses to one dir", r["scope"], "docs")

r = run([("1", "0", "README.md"), ("1", "0", "docs/a.md")])
check("root file emitted as itself", r["scope"], "README.md,docs")

# --- tier selection -------------------------------------------------------------------
r = run([("1", "0", "src/a.py")], base="main", default="main")
check("into default branch -> medium/90/blocking",
      (r["effort"], r["step_timeout"], r["blocking"]), ("medium", 90, "true"))
r = run([("1", "0", "src/a.py")], base="feature/x", default="main")
check("into feature branch -> low/30/advisory",
      (r["effort"], r["step_timeout"], r["blocking"]), ("low", 30, "false"))

# --- caps -----------------------------------------------------------------------------
r = run([("1", "0", "src/f%d.py" % i) for i in range(90)], MAX_FILES=80)
check("file cap exceeded -> low + flagged", (r["effort"], r["caps_exceeded"]), ("low", True))
r = run([("9000", "9000", "src/big.py")], MAX_FILE_LINES=2000)
check("a huge source file is scanned, not skipped", (r["kept_files"], r["skipped_files"]), (1, 0))
check("a huge source file still yields a scan", r["should_scan"], "true")

# --- data-only PR ---------------------------------------------------------------------
r = run([("-", "-", "data/releases/a.parquet"), ("4", "4", "data/releases/b.jsonl")])
check("data-only PR does not scan", r["should_scan"], "false")
check("data-only PR passes empty scope", r["scope"], "")

# --- code/workflow/doc paths are never excluded ---------------------------------------
r = run([("1", "0", ".github/workflows/deploy.yml"), ("1", "0", "main.tf"),
         ("1", "0", "Dockerfile"), ("1", "0", "README.md"), ("1", "0", "app/x.py")])
check("code, workflow, IaC and docs all kept", r["kept_files"], 5)

# --- hostile filenames ----------------------------------------------------------------
r = run([("1", "0", "src/ok.py"), ("1", "0", "src/ev il$(whoami).py")])
check("space/metachar path disables scoping", r["scope"], "")
check("unsafe path is counted", r["unsafe_paths"], 1)
check("unsafe path still scans (no silent skip)", r["should_scan"], "true")

r = run([("1", "0", "src/ok.py"), ("1", "0", "src/we\nird.py")])
check("newline path disables scoping", (r["scope"], r["unsafe_paths"]), ("", 1))

r = run([("1", "0", "src/ok.py"), ("1", "0", "src/../../etc/passwd")])
check("traversal path disables scoping", r["unsafe_paths"], 1)

r = run([("1", "0", "src/café.py")])
check("non-ascii path disables scoping", (r["scope"], r["unsafe_paths"]), ("", 1))

# --- per-repo ignore file -------------------------------------------------------------
r = run([("1", "0", "receipts/x.txt"), ("1", "0", "src/a.py")],
        ignore="# generated receipts\nreceipts/**\n")
check("repo ignore pattern applies", (r["kept_files"], r["repo_ignore_patterns"]), (1, 1))
r = run([("1", "0", "src/a.py")], ignore="\n#only a comment\n\n")
check("comments/blank lines ignored", r["repo_ignore_patterns"], 0)

# --- malformed records ----------------------------------------------------------------
with tempfile.TemporaryDirectory() as td:
    ns = os.path.join(td, "ns.z")
    open(ns, "wb").write(b"garbage-no-tabs\x001\t0\tsrc/a.py\x00")
    e = dict(os.environ)
    e.update({"BASE_REF": "main", "DEFAULT_BRANCH": "main",
              "GITHUB_OUTPUT": os.path.join(td, "o"), "GITHUB_STEP_SUMMARY": os.path.join(td, "s")})
    subprocess.run([sys.executable, spec.origin, ns], cwd=td, env=e, check=True, capture_output=True)
    r = json.load(open(os.path.join(td, "claude-security-route.json")))
check("malformed record disables scoping, keeps scanning",
      (r["malformed_records"], r["scope"], r["should_scan"]), (1, "", "true"))

# --- empty diff -----------------------------------------------------------------------
r = run([])
check("empty range -> no scan", (r["should_scan"], r["kept_files"]), ("false", 0))

# --- glob semantics -------------------------------------------------------------------
r = run([("1", "0", "a/b/c/uv.lock"), ("1", "0", "pkg/thing.min.js"),
         ("1", "0", "x/node_modules/y/z.js"), ("1", "0", "keep.js")])
check("basename globs match at any depth; keep.js survives", r["kept_files"], 1)
check("keep.js is covered", covers(r["scope"], "keep.js"), True)
check("min.js/node_modules present -> unscoped, not a narrowed scope", r["scope"], "")
r = run([("1", "0", "src/notes.jsonld"), ("1", "0", "src/keep.py")])
check("*.jsonld dropped inside a code dir", r["scope"], "src/keep.py")

# --- regressions from the OAIP-479 security review ---------------------------------------

# A large source file must never fall out of scope. Excluding it let a 2,500-line file go
# unreviewed while the gate still went green.
r = run([("2", "0", "README.md"), ("2500", "0", "src/backdoor.py")], MAX_FILE_LINES=2000)
check("oversized file stays in scope", covers(r["scope"], "src/backdoor.py"), True)
check("oversized file is flagged", [o["path"] for o in r["oversized_scanned"]],
      ["src/backdoor.py"])
check("oversized file drops effort to low", r["effort"], "low")
check("oversized file produces a note", len(r["notes"]) > 0, True)
r = run([("2001", "0", "app/auth.py")], MAX_FILE_LINES=2000)
check("padding an existing file does not evade", covers(r["scope"], "app/auth.py"), True)

# A diff of nothing but build output is not "nothing to scan" -- that is the code that ships.
r = run([("40", "10", "dist/bundle.js")])
check("dist-only PR is still scanned", r["should_scan"], "true")
check("dist-only PR scans unscoped", r["scope"], "")
r = run([("5", "0", "assets/app.min.js")])
check("minified-only PR is still scanned", r["should_scan"], "true")
r = run([("-", "-", "a.parquet"), ("3", "3", "b.jsonl")])
check("inert-only PR is genuinely skipped", r["should_scan"], "false")

# ...but a data file that merely LIVES in a maybe-code directory is still just data, or every
# pure data-release PR would run an unscoped scan and drag the binaries back in.
r = run([("9", "9", "data/releases/demo/people.xml"),
         ("4", "0", "data/releases/demo/manifest.json"),
         ("-", "-", "data/releases/demo/x.parquet")])
check("pure data-release PR is still skipped", r["should_scan"], "false")
check("data under a releases/ dir is not treated as code", r["dropped_maybe_code"], [])
r = run([("9", "9", "data/releases/demo/people.xml"), ("2", "0", "dist/vendor/setup.py")])
check("one code file among release data forces a scan", r["should_scan"], "true")
r = run([("2", "0", "dist/run")])
check("extensionless file in build output counts as code", r["should_scan"], "true")

# A repo cannot switch its own scanning off.
r = run([("5", "0", "src/auth.py")], ignore="**\n")
check("catch-all ignore pattern is rejected", r["should_scan"], "true")
check("catch-all pattern does not apply", covers(r["scope"], "src/auth.py"), True)
check("rejection is recorded", len(r["rejected_ignore_patterns"]), 1)
for pat in ("*", "**/*", "*/**", ".", "./", "/"):
    r = run([("5", "0", "src/auth.py")], ignore=pat + "\n")
    check("catch-all %r rejected" % pat, covers(r["scope"], "src/auth.py"), True)
r = run([("5", "0", "src/auth.py")], ignore="*.py\n")
check("repo pattern hiding all source still scans", r["should_scan"], "true")
check("repo pattern hiding all source scans unscoped", r["scope"], "")

# Backtracking hazard: each '**' compiles to a backtrackable group, and nesting multiplies.
r = run([("1", "0", "src/a.py")], ignore="**/" * 20 + "x\n")
check("deeply nested '**' pattern refused", len(r["rejected_ignore_patterns"]), 1)

# The scope fallback must never WIDEN scope -- collapsing to top-level dirs readmitted the
# binary rows the router exists to remove.
rows = [("1", "0", "d%03d/f.py" % i) for i in range(260)] + [("-", "-", "d000/blob.bin")]
r = run(rows, MAX_FILES=1000, MAX_LINES=100000)
check("oversized scope falls back to no scope, not top-level dirs", r["scope"], "")
check("oversized scope reduces effort instead", r["effort"], "low")

# --- second review round: the maybe-code check must be unconditional --------------------
# One unrelated file used to bypass it entirely, because it only ran when nothing survived.
r = run([("40", "10", "dist/bundle.js"), ("1", "0", "README.md")])
check("dist + an unrelated file still unscopes", r["scope"], "")
check("dist + an unrelated file still scans", r["should_scan"], "true")
r = run([("400", "0", "src/evil.py"), ("1", "0", "README.md")], ignore="*.py\n")
check("repo-ignored source + unrelated file unscopes", r["scope"], "")
r = run([("9", "0", "node_modules/x/index.js"), ("3", "0", "src/a.py")])
check("vendored code alongside real code unscopes", r["scope"], "")
r = run([("9", "9", "data/releases/x.xml"), ("3", "0", "src/a.py")])
check("generated data alongside code keeps a precise scope", r["scope"], "src")
r = run([("9", "9", "data/releases/manifest.json"), ("3", "0", "src/a.py")])
check("generated json alongside code keeps a precise scope", r["scope"], "src")
# ...but a build-path change with no source beside it is scanned, not skipped.
r = run([("5", "0", "dist/policy.json")])
check("dist-only json is scanned, not skipped", r["should_scan"], "true")

# --- third review round: config-as-code under a build tree must not hide -----------------
# json and xml are the two commonest config-as-code formats. Each of these is live code:
# package.json runs postinstall, staticwebapp.config.json defines auth roles, web.xml sets
# security constraints, build.xml executes tasks. Paired with one kept file they used to leave
# scope silently.
for p in ("dist/package.json", "dist/manifest.json", "dist/staticwebapp.config.json",
          "dist/vercel.json", "build/build.xml", "dist/web.xml", "build/appsettings.json",
          "dist/template.json", "node_modules/pkg/package.json",
          "vendor/lib/config.xml", "site-packages/p/setup.json"):
    r = run([("5", "0", p), ("1", "0", "README.md")])
    check("%s is not hidden by a kept file" % p, r["scope"], "")
    r = run([("5", "0", p)])
    check("%s alone is not skipped" % p, r["should_scan"], "true")
# The bulk-data exemptions stay data, so a release PR keeps its precise scope.
for p in ("data/releases/demo/manifest.json", "data/releases/demo/people.xml",
          "coverage/lcov-report/data.json", "x/__snapshots__/s.json"):
    r = run([("9", "9", p), ("3", "0", "src/a.py")])
    check("%s stays exempt" % p, covers(r["scope"], "src/a.py") and r["scope"] != "", True)
# ...and when a scope IS passed, the exclusion is announced rather than silent.
r = run([("5", "0", "dist/report.csv"), ("3", "0", "src/a.py")])
check("generated-data exclusion is announced", len(r["notes"]) > 0, True)
check("generated-data exclusion keeps the precise scope", r["scope"], "src")
check("generated-data is recorded", r["dropped_generated_data"], ["dist/report.csv"])

# --- second review round: unknown extensions must default to code -----------------------
for p in (".htaccess", ".env", ".npmrc", "logo.svg", "policy.json", "index.jsp", "page.aspx",
          "pipeline.yml", "action.yaml", "notebook.ipynb", "tpl.erb", "tpl.hbs", "app.exs",
          "main.dart", "stack.hcl", "shim.phtml", "go.cgi", "x.pyw", "page.xhtml", "setup.cfg",
          "Jenkinsfile.groovy", "mod.wat"):
    r = run([("5", "0", "dist/" + p)])
    check("dist/%s is not skipped" % p, r["should_scan"], "true")
for p in ("people.xml", "rows.csv", "notes.txt", "README.md", "cal.ics"):
    r = run([("5", "0", "data/releases/" + p)])
    check("data/releases/%s stays data" % p, r["should_scan"], "false")

# --- second review round: catch-all detection is functional, not a spelling list ---------
for pat in ("?*", "**/?*", "?**", "*?", "*", "**"):
    r = run([("5", "0", "src/auth.py")], ignore=pat + "\n")
    check("catch-all %r rejected" % pat, len(r["rejected_ignore_patterns"]), 1)
    check("catch-all %r leaves the file scanned" % pat, covers(r["scope"], "src/auth.py"), True)
# `*.*` misses extensionless paths so it is not a true catch-all, but it is broad enough to
# hide almost everything -- the invariant is that the file still gets scanned either way.
for pat in ("*.*", "src/**", "*.py"):
    r = run([("5", "0", "src/auth.py")], ignore=pat + "\n")
    check("broad pattern %r cannot hide code" % pat, covers(r["scope"], "src/auth.py"), True)
    check("broad pattern %r still scans" % pat, r["should_scan"], "true")
# A legitimately broad-but-not-total pattern must still work.
r = run([("5", "0", "src/a.py"), ("5", "0", "docs/b.md")], ignore="docs/**\n")
check("a broad but partial pattern still applies", r["rejected_ignore_patterns"], [])

# --- second review round: quantifier collapse bounds the backtracking -------------------
import time
_t = time.time()
r = run([("1", "0", "x" * 200 + ".py")], ignore="**/**/**/x*\n")
check("collapsed quantifiers stay fast", time.time() - _t < 10, True)
r = run([("1", "0", "src/a.py")], ignore="**a**a**a**a\n")
check("pathological quantifier pattern refused", len(r["rejected_ignore_patterns"]), 1)

print()
if _fails:
    print("%d FAILURE(S):" % len(_fails))
    for f in _fails:
        print("  " + f)
    sys.exit(1)
print("all tests passed")

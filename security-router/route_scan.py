import json, os, re, sys

# Two classes, and the distinction is load-bearing.
#
# INERT: data and binaries. Nothing here can be code a reviewer needs to read, so a diff
# consisting only of these genuinely has nothing to scan.
INERT_IGNORE = [
    # bulk / serialized data
    "*.jsonl", "*.ndjson", "*.parquet", "*.avro", "*.arrow", "*.feather", "*.dat", "*.jsonld",
    # archives, databases, media, office documents
    "*.zip", "*.gz", "*.tgz", "*.tar", "*.bz2", "*.xz", "*.7z", "*.rar",
    "*.sqlite", "*.sqlite3", "*.db", "*.mdb",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.tiff", "*.ico", "*.icns",
    "*.pdf", "*.docx", "*.xlsx", "*.pptx", "*.doc", "*.xls", "*.ppt",
    "*.mp3", "*.mp4", "*.wav", "*.aiff", "*.mov", "*.avi",
    "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
    "*.pyc", "*.pyo", "*.so", "*.dylib", "*.dll", "*.exe", "*.wasm", "*.jar", "*.class",
    # lockfiles
    "uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "Pipfile.lock",
    # checksums and signatures
    "*.sha256", "*.sha512", "*.md5", "*.sig", "*.asc",
    # Bulk json/xml in the places that only ever hold published or generated records. Named
    # explicitly rather than by extension because json and xml are also the two commonest
    # configuration-as-code formats -- `package.json` runs postinstall, `staticwebapp.config.json`
    # defines auth roles, `web.xml` sets security constraints, `build.xml` executes tasks. So the
    # extensions themselves count as code (see DATA_EXT) and only these paths are exempt.
    "**/releases/**/*.json", "**/releases/**/*.xml",
    "**/coverage/**/*.json", "**/coverage/**/*.xml",
    "**/__snapshots__/**/*.json",
]

# MAYBE-CODE: build output and vendored trees. Skipping these on an ordinary PR is right --
# the source they were built from is in the same diff. But they can be the code that
# actually ships (a Pages site committing `dist/`), so a diff consisting ONLY of these is
# NOT "nothing to scan": it gets scanned unscoped instead. Same for anything a repo adds to
# its own ignore list, which is why repo patterns are always treated as maybe-code.
MAYBE_CODE_IGNORE = [
    "*.min.js", "*.min.css", "*.map",
    "**/node_modules/**", "**/dist/**", "**/build/**", "**/vendor/**", "**/.venv/**",
    "**/venv/**", "**/__pycache__/**", "**/__snapshots__/**", "**/coverage/**",
    "**/.terraform/**", "**/releases/**", "**/site-packages/**",
]

# Of those, the ones that are built FROM this repository's source. A change here with no source
# change beside it is anomalous -- the output moved without its input -- so such a diff is
# scanned even when every file in it is a data format. The rest of MAYBE_CODE_IGNORE is
# published artifacts and dependency trees, where changing alone is entirely normal: a data
# release is exactly that, and skipping it is the point.
# Dependency trees count here too: they are installed INTO the repository, so "the output moved
# without its input" applies to them just as it does to a build directory. Committing them is
# routine in Go and PHP, and a vendored `composer.json` postinstall or Spring XML is live.
BUILD_OUTPUT_IGNORE = {
    "*.min.js", "*.min.css", "*.map",
    "**/dist/**", "**/build/**", "**/coverage/**", "**/__snapshots__/**",
    "**/node_modules/**", "**/vendor/**", "**/site-packages/**",
    "**/.venv/**", "**/venv/**", "**/.terraform/**", "**/__pycache__/**",
}

DEFAULT_IGNORE = INERT_IGNORE + MAYBE_CODE_IGNORE

# Whether a filtered path could be code is decided by the file, not only by the directory it
# sits in: `data/releases/people.xml` matches a maybe-code directory pattern but is plainly
# data, while `dist/bundle.js` is the opposite case.
#
# This is a DENYLIST on purpose. An allowlist of "code extensions" defaults every extension
# nobody thought of to `data`, and the consequence of that default is a green check on
# unreviewed code -- measured, 22 of 27 probes under `dist/` went unscanned, including
# `.htaccess`, `.svg`, `.ipynb`, `.jsp`, `.aspx`, `policy.json` and `pipeline.yml`. So only
# formats that are unambiguously inert prose or tabular data are listed, and anything
# unrecognised is treated as code. Notably absent, and deliberately so: json, yaml/yml, toml,
# ini, cfg (configuration and policy), and html/svg (browser-rendered, script-bearing).
# json and xml are deliberately ABSENT: they are the two commonest configuration-as-code
# formats, and a `package.json` with a postinstall hook or a `web.xml` security-constraint under
# a committed build tree is live code. The bulk-data uses of both are exempted by explicit path
# patterns in INERT_IGNORE instead, which is narrow enough to be safe.
DATA_EXT = {
    "csv", "tsv", "txt", "rst", "log", "md", "markdown",
    "po", "pot", "srt", "vtt", "ics", "geojson", "rtf",
}


def maybe_code(path, from_repo_pattern):
    """Could this filtered path be code someone ships? Unknown means yes.

    A repo-supplied pattern gets no extension test at all. The built-in maybe-code patterns
    name contexts we chose and understand -- `dist/`, `build/`, `node_modules/`, `releases/` --
    so a `.json` there is a build or release manifest, and calling it data keeps pure
    data-release PRs cheap. A pattern the repo wrote is a different matter: it points anywhere,
    and trusting an extension there would let `config/**` in an ignore file hide
    `config/iam-policy.json` from review. So anything a repo excludes counts as possible code.
    """
    if from_repo_pattern:
        return True
    base = path.rsplit("/", 1)[-1]
    # lstrip so a dotfile is not read as "extension = htaccess". `.htaccess` can turn on CGI
    # and rewrites and `.env` is secrets; both were being classified as data.
    if "." not in base.lstrip("."):
        return True
    return base.rsplit(".", 1)[-1].lower() not in DATA_EXT

# Probes for detecting a pattern that excludes everything. A literal spelling set does not
# work -- `?*`, `*.*`, `?**` and `*?` all match every path and would sail through one.
CATCH_ALL_PROBES = [
    "a.py", "a/b/c.js", "README.md", "x/y", "Dockerfile",
    ".github/workflows/ci.yml", "src/main/App.java",
]

# Each `**` compiles to a backtrackable group and nesting them multiplies -- measured on a
# non-matching path, `**a**a**a**a` is clean O(n^4). Two is all a real pattern needs
# (`**/dist/**`). The router step's own `timeout-minutes` is the actual backstop; this just
# keeps ordinary mistakes from reaching it.
MAX_GLOB_STARSTAR = 2

# A path we are willing to hand to the scanner as a scope entry. Anything outside this
# shape (newlines, tabs, quotes, shell metacharacters, non-ASCII) is not excluded from the
# scan -- it disables scoping entirely, so coverage never silently shrinks.
SAFE_PATH = re.compile(r"^[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+-]+)*$")


def safe_path(path):
    """The character class alone is not enough: '.' and '/' are both legal, so '..' would
    slip through as a segment, and a leading '-' can read as an option. scan.js applies
    the same '..'-segment guard to scope entries."""
    if not SAFE_PATH.match(path):
        return False
    segs = path.split("/")
    return ".." not in segs and not any(s.startswith("-") for s in segs)

MAX_SCOPE_ENTRIES = 200
MAX_SCOPE_CHARS = 8000


def glob_to_re(pat):
    """Translate one gitignore-style pattern to a full-path regex.

    A pattern with no '/' matches any path's basename (so '*.zip' and 'uv.lock' work at
    any depth). A pattern containing '/' matches the whole path, with '**' spanning
    directory separators and '*' stopping at them.
    """
    anchored = "/" in pat.strip("/")
    if not anchored:
        body, prefix = pat, r"(?:.*/)?"
    else:
        body, prefix = pat, ""

    out, i = [], 0
    while i < len(body):
        c = body[i]
        if body.startswith("**/", i):
            out.append(r"(?:.*/)?")
            i += 3
        elif body.startswith("/**", i):
            out.append(r"(?:/.*)?")
            i += 3
        elif body.startswith("**", i):
            out.append(r".*")
            i += 2
        elif c == "*":
            out.append(r"[^/]*")
            i += 1
        elif c == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1

    # Collapse adjacent greedy quantifiers before compiling. `**/**/**` and `****` otherwise
    # emit several interchangeable backtrackable groups in a row, which is where the
    # multiplicative blowup comes from; one of them matches exactly the same language.
    collapsed = []
    for tok in out:
        if tok in (r"(?:.*/)?", r".*", r"[^/]*") and collapsed:
            if collapsed[-1] == tok:
                continue
            if tok == r".*" and collapsed[-1] in (r"(?:.*/)?", r"[^/]*"):
                collapsed[-1] = r".*"
                continue
            if tok in (r"(?:.*/)?", r"[^/]*") and collapsed[-1] == r".*":
                continue
        collapsed.append(tok)
    return re.compile("^" + prefix + "".join(collapsed) + "$")


def load_patterns(extra_text):
    """Built-in patterns first, then the repo's own. Repo patterns are always classed
    maybe-code: whatever a repo chooses to exclude, we will not conclude from it that a diff
    has nothing worth scanning."""
    pats = [(p, glob_to_re(p), "default", p in INERT_IGNORE) for p in DEFAULT_IGNORE]
    rejected = []
    for raw in (extra_text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("**") > MAX_GLOB_STARSTAR:
            rejected.append((line, "more than %d '**' segments -- refused as a regex-backtracking hazard" % MAX_GLOB_STARSTAR))
            continue
        try:
            rx = glob_to_re(line)
        except re.error as exc:
            rejected.append((line, "not a usable pattern (%s)" % exc))
            continue
        # Functional catch-all test rather than a spelling list: `?*`, `*.*` and `*?` all
        # match every path, and no enumeration of literals catches them.
        if all(rx.match(p) for p in CATCH_ALL_PROBES):
            rejected.append((line, "matches every path -- a repo cannot switch off its own scan"))
            continue
        pats.append((line, rx, "repo", False))
    return pats, rejected


def parse_numstat(blob):
    """Records are 'added\\tdeleted\\tpath' separated by NUL (git diff --numstat -z
    --no-renames). NUL separation means no quoting and no rename brace-compaction, so
    paths arrive verbatim."""
    rows = []
    for rec in blob.split(b"\x00"):
        if not rec:
            continue
        parts = rec.split(b"\t", 2)
        if len(parts) != 3:
            rows.append((None, None, rec.decode("utf-8", "surrogateescape"), True))
            continue
        a, d, p = parts
        path = p.decode("utf-8", "surrogateescape")
        if a == b"-" or d == b"-":
            rows.append((None, None, path, False))  # binary: unmeasurable
            continue
        try:
            rows.append((int(a), int(d), path, False))
        except ValueError:
            rows.append((None, None, path, True))
    return rows


def collapse_scope(kept, dropped):
    """Reduce the kept paths to the shortest scope that cannot readmit a dropped path.

    A directory is 'tainted' if anything under it -- at any depth -- was filtered out.
    Each kept file is represented by its highest untainted ancestor directory, or by
    itself when its own parent is tainted. Taint is inherited by ancestors, so an entry
    is either a wholly-clean subtree or a single file; that makes the result safe by
    construction rather than by a follow-up pruning pass. (An earlier version emitted
    clean immediate parents and then pruned descendants by ancestor prefix, which could
    readmit an excluded path when a *sibling* subtree was dirty.)
    """
    def parent(p):
        return p.rsplit("/", 1)[0] if "/" in p else ""

    tainted = set()
    for p in dropped:
        d = parent(p)
        while d:
            tainted.add(d)
            d = parent(d)

    entries = set()
    for p in kept:
        d = parent(p)
        if not d or d in tainted:
            entries.add(p)
            continue
        best = d
        while True:
            up = parent(best)
            if not up or up in tainted:
                break
            best = up
        entries.add(best)
    return sorted(entries)


def main():
    numstat = open(sys.argv[1], "rb").read()
    extra = ""
    if len(sys.argv) > 2 and os.path.exists(sys.argv[2]):
        extra = open(sys.argv[2], encoding="utf-8", errors="replace").read()

    max_file_lines = int(os.environ.get("MAX_FILE_LINES") or 2000)
    # Calibrated against measured runtime rather than guessed. At `medium` the plugin runs its
    # full component matrix for anything outside its own fast path (<=5 files AND <=300 lines),
    # and observed wall-clock tracks the number of top-level areas in scope far more than the
    # line count: 1 area took 16-41 min, 4 areas took 57 min -- 63% of the 90-minute step
    # budget. A release-shaped diff spans ~10 areas and would blow past it. 20/3000 routes those
    # to `low` before they can time out, and leaves genuinely small changes at `medium`.
    # Raise them only with runtime evidence; the failure mode of setting them too high is the
    # 2-hour wedge this router exists to prevent.
    max_files = int(os.environ.get("MAX_FILES") or 20)
    max_lines = int(os.environ.get("MAX_LINES") or 3000)
    base_ref = os.environ.get("BASE_REF") or ""
    default_branch = os.environ.get("DEFAULT_BRANCH") or ""

    pats, rejected_patterns = load_patterns(extra)
    rows = parse_numstat(numstat)

    kept, kept_lines, skipped, unsafe, malformed = [], 0, [], [], []
    oversized, dropped_maybe_code, dropped_generated_data = [], [], []
    for a, d, path, bad in rows:
        if bad:
            malformed.append(path)
            continue
        if a is None:
            skipped.append((path, "binary (unmeasurable diff)"))
            continue
        hit = next(((p, src, inert) for p, rx, src, inert in pats if rx.match(path)), None)
        if hit:
            skipped.append((path, "%s pattern %s" % (hit[1], hit[0])))
            # Three outcomes, because "could this be code" and "is this definitely nothing"
            # are different questions. hit[2] is True for the inert built-ins; hit[1] is
            # "default" or "repo".
            if not hit[2]:
                if maybe_code(path, hit[1] == "repo"):
                    dropped_maybe_code.append(path)      # forces an unscoped scan
                elif hit[0] in BUILD_OUTPUT_IGNORE:
                    dropped_generated_data.append(path)  # only blocks the "nothing to scan" skip
            continue
        # A big file is KEPT, not skipped. Size is a cost signal, never grounds to leave
        # code unreviewed: excluding here let a 2,500-line source file drop silently out of
        # scope while the gate still went green. Its lines count toward the caps below, which
        # is what pulls effort down to `low`.
        if a + d > max_file_lines:
            oversized.append((path, a + d))
        if not safe_path(path):
            unsafe.append(path)
        kept.append(path)
        kept_lines += a + d

    # Tier: depth follows where the change is going, not how it was authored.
    into_default = bool(default_branch) and base_ref == default_branch
    effort = "medium" if into_default else "low"
    step_timeout = 90 if into_default else 30
    blocking = "true" if into_default else "false"

    notes = []
    for pat, why in rejected_patterns:
        notes.append("ignored .github/claude-security-ignore pattern %r: %s" % (pat, why))

    caps_exceeded = len(kept) > max_files or kept_lines > max_lines
    if caps_exceeded and effort == "medium":
        effort = "low"
        notes.append(
            "filtered diff still exceeds the caps (%d files / %d lines vs %d / %d) -- "
            "dropped to --effort low rather than truncating coverage"
            % (len(kept), kept_lines, max_files, max_lines)
        )
    if oversized:
        if effort == "medium":
            effort = "low"
        notes.append(
            "%d file(s) exceed the %d-line per-file cap and are still scanned (size is a "
            "cost signal, not grounds to skip code) -- effort dropped to low: %s"
            % (len(oversized), max_file_lines,
               ", ".join("%s (%d lines)" % (p, n) for p, n in oversized[:5]))
        )

    scope, scope_reason = "", ""
    if unsafe:
        scope_reason = (
            "%d changed path(s) fall outside the safe scope shape, so no --scope is passed "
            "and the whole range is scanned (coverage is never silently reduced): %s"
            % (len(unsafe), ", ".join(repr(p) for p in unsafe[:5]))
        )
        notes.append(scope_reason)
    elif malformed:
        scope_reason = (
            "%d unparseable --numstat record(s), so no --scope is passed and the whole "
            "range is scanned" % len(malformed)
        )
        notes.append(scope_reason)
    elif kept:
        entries = collapse_scope(kept, [p for p, _ in skipped])
        candidate = ",".join(entries)
        if len(entries) > MAX_SCOPE_ENTRIES or len(candidate) > MAX_SCOPE_CHARS:
            # Deliberately NOT collapsed to top-level directories. That shortens the string
            # by WIDENING it, readmitting the very binary rows the router exists to remove --
            # the one fallback that is actively wrong. Drop the scope instead: more gets
            # scanned, never less, and the step timeout bounds the cost.
            notes.append(
                "precise scope too large for one argument (%d entries / %d chars, caps %d / "
                "%d) -- no --scope is passed and the whole range is scanned at reduced effort"
                % (len(entries), len(candidate), MAX_SCOPE_ENTRIES, MAX_SCOPE_CHARS)
            )
            effort = "low"
        else:
            scope = candidate

    # THE INVARIANT: if anything that might be shipped code was filtered out, no --scope is
    # passed at all. Build output, vendored trees and anything a repo put in its own ignore
    # list can be the code that actually runs, and no scope string can honestly exclude it.
    #
    # This is deliberately unconditional. Checking it only when the kept set was empty left
    # the hole wide open: one unrelated file -- a CHANGELOG line, a README touch, which nearly
    # every real PR has -- meant `kept` was non-empty, the check never ran, and `dist/bundle.js`
    # or an `*.py`-ignored source file dropped straight back out of scope behind a green check.
    if dropped_maybe_code:
        scope = ""
        if effort == "medium":
            effort = "low"
        notes.append(
            "%d filtered path(s) may be shipped code rather than inert data (build output, "
            "vendored trees, minified assets, or a repo ignore pattern), so no --scope is "
            "passed and the whole range is scanned at reduced effort: %s"
            % (len(dropped_maybe_code), ", ".join(dropped_maybe_code[:5]))
        )

    # Generated data dropped from a build or dependency tree stays out of scope, but it must not
    # do so silently: this was the one filtered class that produced no annotation at all, which
    # contradicts the rule the whole design rests on -- a filter nobody can see is
    # indistinguishable from a scan that missed something.
    if dropped_generated_data and scope:
        notes.append(
            "%d data file(s) under a build or dependency tree are excluded from the scan scope "
            "(json/xml there are exempt only under releases/, coverage/ and __snapshots__): %s"
            % (len(dropped_generated_data), ", ".join(dropped_generated_data[:5]))
        )

    # "Nothing to scan" requires every dropped path to have been INERT -- a built-in data or
    # binary pattern. Generated data under a build/release directory does not qualify: a diff
    # of nothing but `dist/policy.json` is suspicious precisely because its source did not
    # change, so it is scanned rather than skipped. It does not force an unscoped scan though,
    # which is what keeps a release PR's precise scope (and with it the plugin's own diff
    # sizing) intact.
    should_scan = "true" if (kept or dropped_maybe_code or dropped_generated_data) else "false"
    if not kept and not dropped_maybe_code and dropped_generated_data:
        notes.append(
            "the whole diff is generated data under a build or release path (%d file(s)) with "
            "no source change beside it -- scanning rather than skipping: %s"
            % (len(dropped_generated_data), ", ".join(dropped_generated_data[:5]))
        )
    elif not kept and not dropped_maybe_code:
        notes.append(
            "every changed file is binary or data -- there is no code, workflow or "
            "documentation change to scan"
        )

    route = {
        "should_scan": should_scan, "effort": effort, "step_timeout": step_timeout,
        "blocking": blocking, "into_default_branch": into_default,
        "base_ref": base_ref, "default_branch": default_branch,
        "changed_files": len([r for r in rows if not r[3]]),
        "kept_files": len(kept), "kept_lines": kept_lines,
        "skipped_files": len(skipped), "binary_rows": sum(1 for _, r in skipped if r.startswith("binary")),
        "unsafe_paths": len(unsafe), "malformed_records": len(malformed),
        "caps_exceeded": caps_exceeded, "scope_entries": len(scope.split(",")) if scope else 0,
        "scope": scope, "notes": notes,
        "oversized_scanned": [{"path": p, "lines": n} for p, n in oversized],
        "dropped_maybe_code": dropped_maybe_code,
        "dropped_generated_data": dropped_generated_data,
        "rejected_ignore_patterns": [{"pattern": p, "reason": r} for p, r in rejected_patterns],
        "repo_ignore_patterns": sum(1 for _, _, s, _ in pats if s == "repo"),
        "skipped": [{"path": p, "reason": r} for p, r in skipped],
    }
    # Route evidence: uploaded alongside the report so a reviewer can see exactly what was
    # filtered and why, long after the run log has expired.
    with open(os.environ.get("ROUTE_JSON") or "claude-security-route.json", "w",
              encoding="utf-8") as fh:
        json.dump(route, fh, indent=2, sort_keys=True)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for k in ("should_scan", "effort", "step_timeout", "blocking",
                      "kept_files", "kept_lines", "skipped_files", "scope"):
                # Heredoc form: a scope string can be long, and this is the only
                # GITHUB_OUTPUT shape that cannot be broken by its contents.
                fh.write("%s<<CS_EOF_%s\n%s\nCS_EOF_%s\n" % (k, k, route[k], k))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["### Claude Security — scan route", ""]
    if kept:
        # Lead with the expected duration. This step finishes in seconds, so the banner is on
        # screen for the whole scan -- and the Actions UI shows elapsed time but never expected
        # time, which is how a long-but-healthy AI review gets mistaken for a hung job and
        # cancelled. Measured runs are the basis for the range, not a guess.
        fast_path = len(kept) <= 5 and kept_lines <= 300 and effort == "medium"
        if fast_path:
            headline = "**Expect roughly 5-10 minutes.**"
            because = (
                "This diff is inside the scanner's fast path (at most 5 files and 300 changed"
                " lines), so it takes the short route."
            )
        else:
            headline = "**Expect 15-60 minutes, up to a %d-minute cap.**" % step_timeout
            because = (
                "This diff is outside the scanner's fast path (over 5 files or 300 changed"
                " lines), so the full review runs. Runtime scales with how many top-level areas"
                " are in scope rather than with line count."
            )
        lines += [
            "> [!NOTE]",
            "> %s %s" % (headline, because),
            ">",
            "> A long run is normal and is *not* a hang — please do not cancel it. If the scan"
            " genuinely",
            "> exceeds its %d-minute budget the step is killed on its own and reports an"
            % step_timeout,
            "> infrastructure timeout, worded to be distinguishable from a security finding.",
            "",
        ]
        lines.append(
            "Scanning **%d of %d** changed files (%d lines) at `--effort %s`, "
            "%s gate, %d-minute step cap."
            % (len(kept), route["changed_files"], kept_lines, effort,
               "blocking" if blocking == "true" else "advisory", step_timeout)
        )
    else:
        lines.append("**Nothing to scan** — no code, workflow or documentation changed.")
    lines.append("")
    lines.append("Skipped **%d** generated files (%d binary)."
                 % (len(skipped), route["binary_rows"]))
    if skipped:
        lines += ["", "<details><summary>Skipped paths</summary>", "", "```"]
        lines += ["%s  —  %s" % (p, r) for p, r in skipped[:60]]
        if len(skipped) > 60:
            lines.append("... and %d more (see the claude-security-route.json artifact)" % (len(skipped) - 60))
        lines += ["```", "", "</details>"]
    for n in notes:
        lines += ["", "> [!NOTE]", "> %s" % n]
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    # A ::notice surfaces on the run page itself, next to the elapsed-time display that is
    # otherwise the only timing information anyone sees. Emitted before the route JSON so it is
    # the first thing in the log too, for anything tailing output rather than reading the UI.
    if kept:
        print(
            "::notice title=Claude Security — expected duration::The AI review step that follows "
            "usually takes %s and is capped at %d minutes. A long run is normal and is NOT a "
            "hang — do not cancel it. If it exceeds the cap the step is killed on its own and "
            "reports an infrastructure timeout rather than a finding."
            % ("5-10 minutes (fast path)"
               if (len(kept) <= 5 and kept_lines <= 300 and effort == "medium")
               else "15-60 minutes", step_timeout)
        )

    print("route: %s" % json.dumps({k: v for k, v in route.items() if k != "skipped"}))
    for n in notes:
        print("::warning title=Claude Security route::%s" % n.replace("\n", " "))


main()

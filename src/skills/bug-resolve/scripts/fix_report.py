#!/usr/bin/env python3
"""fix_report - build the final bug-fix report and a ready-to-paste work item / PR comment.

It only prints or writes markdown/JSON. It never calls an API, never posts anything and never
touches the repository: you (or the user) paste the comment where it belongs.

It is also a proof checker. The test outputs you give it are read, and the report will not say
"PASSED" unless the after-fix output really shows a pass:
  - before-fix output must show a failure (and not just a compile/import/collection error);
  - after-fix output must show a pass indicator and no failure;
  - the suite output must show a pass indicator and no failure;
  - before and after outputs must not be identical.
Anything that fails these checks is listed under "Proof check" and the report says NOT VERIFIED.

Inputs: a JSON file (--input) and/or command-line options (options win). JSON keys:
  bug, root_cause, fix, branch, work_item, files_changed [list], test_name, test_command,
  before_output, after_output, suite_command, suite_output, follow_ups [list], guardrail,
  similar (find_similar JSON object, or a path to it)

Usage:
  python fix_report.py --input fix.json [--out-dir report] [--json]
  python fix_report.py --bug "..." --root-cause "..." --file src/a.py --test-name test_x \\
      --before before.txt --after after.txt --suite suite.txt --suite-command "pytest -q" \\
      --similar similar.json
Exit code: 0 when the proof checks pass, 3 when something is unverified (the report is still produced).
Standard library only; Python 3.8+.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

SNIPPET_LINES = 20
SIMILAR_ROWS = 15

FAIL_SIGNALS = [
    ("n failed", re.compile(r"\b[1-9]\d* failed\b", re.I)),
    ("FAILED", re.compile(r"\bFAILED\b")),
    ("n errors", re.compile(r"\b[1-9]\d* errors?\b", re.I)),
    ("Failed!", re.compile(r"^\s*Failed!", re.M)),
    ("Failed <test>", re.compile(r"^\s*Failed\s+[\w.]+", re.M)),
    ("Failed: n", re.compile(r"\bFailed:\s*[1-9]")),
    ("Failures: n", re.compile(r"\bFailures:\s*[1-9]")),
    ("Errors: n", re.compile(r"\bErrors:\s*[1-9]")),
    ("FAIL", re.compile(r"^\s*(?:---\s+)?FAIL\b", re.M)),
    ("BUILD FAILURE", re.compile(r"\bBUILD FAILURE\b|\bBUILD FAILED\b|\bBuild FAILED\b")),
    ("Overall result: Failed", re.compile(r"Overall result:\s*Failed", re.I)),
    ("Traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("AssertionError", re.compile(r"\bAssertionError\b|\bAssertionFailedError\b")),
    ("Assert failure", re.compile(r"\bAssert\.\w+\(\)\s+Failure\b")),
    ("failure mark", re.compile("[\u2715\u2717\u2718]|^\\s*\u00d7\\s", re.M)),
]
PASS_SIGNALS = [
    ("n passed", re.compile(r"\b[1-9]\d* passed\b", re.I)),
    ("Passed!", re.compile(r"^\s*Passed!", re.M)),
    ("Passed: n", re.compile(r"\bPassed:\s*[1-9]")),
    ("Tests run, 0 failures", re.compile(r"Tests run:\s*[1-9]\d*,\s*Failures:\s*0,\s*Errors:\s*0")),
    ("OK", re.compile(r"^OK\b", re.M)),
    ("ok <package>", re.compile(r"^ok\s+\S", re.M)),
    ("PASS", re.compile(r"^(?:---\s+)?PASS\b", re.M)),
    ("BUILD SUCCESS", re.compile(r"\bBUILD SUCCESS(?:FUL)?\b")),
    ("Overall result: Passed", re.compile(r"Overall result:\s*Passed", re.I)),
]
NO_TESTS = re.compile(
    r"\bno tests ran\b|\bcollected 0 items\b|\bRan 0 tests\b|No test is available|No tests found"
    r"|\bno test files\b|Tests run:\s*0,", re.I)
SETUP_ERRORS = [
    ("compile error (C#)", re.compile(r"\berror CS\d{4}\b")),
    ("compile error (TypeScript)", re.compile(r"\berror TS\d{4}\b")),
    ("compile error (Java)", re.compile(r"cannot find symbol|COMPILATION ERROR|error: package \S+ does not exist")),
    ("syntax error", re.compile(r"\bSyntaxError\b")),
    ("import error", re.compile(r"\bModuleNotFoundError\b|\bImportError\b|Cannot find module")),
    ("test collection error", re.compile(r"\bERROR collecting\b|errors? during collection")),
    ("missing fixture", re.compile(r"fixture '\w+' not found")),
]
SUMMARY_LINE = re.compile(
    r"\b\d+ (?:passed|failed)\b|Tests run:|Passed!|Failed!|^ok\s|^FAIL\b|^OK\b|^FAILED\b|BUILD \w+"
    r"|Total tests:|Overall result|^(?:Tests|Test Files)\s", re.I)


def classify(text):
    """What a test output actually shows. Never guesses a pass."""
    if text is None or not str(text).strip():
        return {"present": False, "fail_signals": [], "pass_signals": [], "setup_errors": [], "no_tests": False,
                "summary_line": None, "first_failure_line": None}
    text = str(text)
    fails = [label for label, rx in FAIL_SIGNALS if rx.search(text)]
    passes = [label for label, rx in PASS_SIGNALS if rx.search(text)]
    setup = [label for label, rx in SETUP_ERRORS if rx.search(text)]
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    summary = None
    for ln in reversed(lines):
        if SUMMARY_LINE.search(ln.strip()):
            summary = ln.strip().strip("= ").strip()
            break
    # the most telling failure line: an exception / assertion message first, else a failure summary line
    first_fail = None
    for ln in lines:
        s = ln.strip()
        if re.search(r"\b\w*(?:Error|Exception|Failure)\b", s) and not s.endswith(":"):
            first_fail = re.sub(r"^E\s+", "", s)
            break
    if first_fail is None:
        for ln in lines:
            if any(rx.search(ln) for _, rx in FAIL_SIGNALS):
                first_fail = ln.strip()
                break
    return {"present": True, "fail_signals": fails, "pass_signals": passes, "setup_errors": setup,
            "no_tests": bool(NO_TESTS.search(text)), "summary_line": summary,
            "first_failure_line": first_fail[:200] if first_fail else None}


def check_proof(data):
    before = classify(data.get("before_output"))
    after = classify(data.get("after_output"))
    suite = classify(data.get("suite_output"))
    problems = []

    def add(pid, severity, msg):
        problems.append({"id": pid, "severity": severity, "message": msg})

    if not before["present"]:
        add("before-missing", "blocking", "No before-fix output was given, so there is no evidence the new test "
            "failed before the fix.")
    elif not before["fail_signals"] and not before["setup_errors"]:
        add("before-no-failure", "blocking", "The before-fix output does not show a failing test. If the test "
            "passed before the fix, it does not reproduce the bug.")
    if before["setup_errors"]:
        add("before-setup-error", "blocking", "The before-fix run failed with a " + ", ".join(before["setup_errors"])
            + ", not with the bug itself. Make the test compile/import and fail on the wrong behaviour.")
    name = (data.get("test_name") or "").strip()
    if before["present"] and name and name not in str(data.get("before_output")):
        add("before-test-not-named", "warning", f"The before-fix output does not mention the test `{name}`; "
            "check it is the run of the new test.")

    if not after["present"]:
        add("after-missing", "blocking", "No after-fix output was given, so the new test cannot be claimed as "
            "passing.")
    elif after["fail_signals"]:
        add("after-failed", "blocking", "The after-fix output still shows a failure (" +
            ", ".join(after["fail_signals"]) + ").")
    elif after["no_tests"]:
        add("after-no-tests", "blocking", "The after-fix output says no tests ran.")
    elif not after["pass_signals"]:
        add("after-no-pass-indicator", "blocking", "The after-fix output has no recognisable pass line "
            "(for example '1 passed', 'Passed!', 'Tests run: 1, Failures: 0, Errors: 0', 'ok', 'OK').")
    if (before["present"] and after["present"]
            and str(data.get("before_output")).strip() == str(data.get("after_output")).strip()):
        add("identical-output", "blocking", "The before-fix and after-fix outputs are identical.")

    if not suite["present"]:
        add("suite-missing", "warning", "No test-suite output was given; the report says the suite was not run.")
    elif suite["fail_signals"]:
        add("suite-failed", "blocking", "The suite output shows failures (" + ", ".join(suite["fail_signals"]) + ").")
    elif suite["no_tests"]:
        add("suite-no-tests", "blocking", "The suite output says no tests ran.")
    elif not suite["pass_signals"]:
        add("suite-no-pass-indicator", "blocking", "The suite output has no recognisable pass line.")

    blocking = [p for p in problems if p["severity"] == "blocking"]
    test_ok = not any(p["id"].startswith(("before-", "after-", "identical")) and p["severity"] == "blocking"
                      for p in problems)
    if blocking:
        status = "unverified"
    elif not suite["present"]:
        status = "partial"
    else:
        status = "verified"
    return {"status": status, "test_verified": test_ok, "problems": problems,
            "before": before, "after": after, "suite": suite}


# ---------------------------------------------------------------------------------------------

def _fence(text):
    fence = "~~~" if "```" in text else "```"
    return fence + "text\n" + text + "\n" + fence


def _snippet(text):
    lines = str(text).rstrip().splitlines()
    tail = lines[-SNIPPET_LINES:]
    note = f"(last {len(tail)} of {len(lines)} lines)\n" if len(lines) > len(tail) else ""
    return note, "\n".join(tail)


def _similar_rows(similar, files_changed):
    if not similar:
        return None
    changed = {re.sub(r"^(?:\./)+", "", str(f).replace("\\", "/")) for f in files_changed}
    rows = []
    for f in similar.get("files", []):
        for m in f.get("matches", []):
            if m.get("origin"):
                continue
            rows.append({"path": f["path"], "line": m["line"], "text": m.get("text", ""),
                         "in_changed_file": f["path"] in changed})
    s = similar.get("summary", {})
    q = similar.get("query", {})
    label = (similar.get("like") or {}).get("bug_class") or q.get("preset") or "custom pattern"
    return {"label": label, "elsewhere": s.get("elsewhere_count", len(rows)),
            "files": s.get("files_with_matches", 0), "rows": rows,
            "in_changed": sum(1 for r in rows if r["in_changed_file"])}


def build(data):
    proof = check_proof(data)
    files = list(data.get("files_changed") or [])
    sim = _similar_rows(data.get("similar"), files)
    bug = (data.get("bug") or "(bug summary missing)").strip()
    name = (data.get("test_name") or "(new test name missing)").strip()
    before, after, suite = proof["before"], proof["after"], proof["suite"]
    ids = {p["id"] for p in proof["problems"]}

    if proof["test_verified"]:
        why = before["first_failure_line"] or ", ".join(before["fail_signals"])
        test_line = f"New test {name}: FAILED before ({why}) -> PASSED after"
    else:
        reasons = [p["message"] for p in proof["problems"] if p["severity"] == "blocking"
                   and p["id"].startswith(("before-", "after-", "identical"))]
        test_line = f"New test {name}: NOT VERIFIED ({reasons[0]})"
    cmd = data.get("suite_command")
    if not suite["present"]:
        suite_line = "Suite: not run (no output provided)"
    elif "suite-failed" in ids:
        suite_line = f"Suite: FAILING: {suite['summary_line'] or 'see output'}" + (f" ({cmd})" if cmd else "")
    elif proof["problems"] and any(i.startswith("suite-") for i in ids):
        suite_line = "Suite: NOT VERIFIED (see the proof check)" + (f" ({cmd})" if cmd else "")
    else:
        suite_line = f"Suite: {suite['summary_line'] or 'passed'}" + (f" ({cmd})" if cmd else "")

    fix = (data.get("fix") or "").strip()
    fix_line = "Fix: " + (fix + "; " if fix else "") + ("files: " + ", ".join(files) if files else "files: (none listed)")
    if data.get("branch"):
        fix_line += f"  (branch {data['branch']})"
    follow = list(data.get("follow_ups") or [])
    R = [f"Bug: {bug}", f"Root cause: {(data.get('root_cause') or '(missing)').strip()}", fix_line, "Proof:",
         f"  - {test_line}", f"  - {suite_line}"]
    if sim is not None:
        R.append(f"Same pattern elsewhere: {sim['elsewhere']} other match(es) of {sim['label']} in "
                 f"{sim['files']} file(s); {sim['in_changed']} in files changed by this fix")
    if data.get("guardrail"):
        R.append(f"Prevention: {data['guardrail'].strip()}")
    R.append("Risk / follow-ups: " + ("; ".join(follow) if follow else "none recorded"))
    report = "\n".join(R)

    C = []
    if proof["status"] == "unverified":
        C += ["> **Proof incomplete.** This fix is not verified yet; see the proof check at the end.", ""]
    title = f"fix: {bug}"
    C += [f"## {title}", ""]
    if data.get("work_item"):
        C += [f"Work item: {data['work_item']}", ""]
    C += [f"**Root cause:** {(data.get('root_cause') or '(missing)').strip()}", ""]
    if fix:
        C += [f"**Change:** {fix}", ""]
    if files:
        C += ["**Files changed:**", ""] + [f"- `{f}`" for f in files] + [""]
    if data.get("branch"):
        C += [f"**Branch:** `{data['branch']}`", ""]
    C += [f"**Regression test:** `{name}`" + (f" (`{data['test_command']}`)" if data.get("test_command") else ""),
          ""]
    for key, label, cls in (("before_output", "Before the fix", before), ("after_output", "After the fix", after)):
        if cls["present"]:
            note, text = _snippet(data[key])
            C += ["<details>", f"<summary>{label}</summary>", "", note + _fence(text), "", "</details>", ""]
    suite_label, suite_rest = suite_line.split(":", 1)
    C += [f"**Result:** {test_line}", "", f"**{suite_label}:**{suite_rest}", ""]
    if sim is not None:
        C += [f"**Same pattern elsewhere ({sim['label']}):** {sim['elsewhere']} other match(es) in "
              f"{sim['files']} file(s).", ""]
        if sim["rows"]:
            C += ["| Location | Code | Status |", "|---|---|---|"]
            for r in sim["rows"][:SIMILAR_ROWS]:
                code = r["text"].replace("|", "\\|").replace("`", "'")
                status = "in a file changed here" if r["in_changed_file"] else "not changed, review"
                C.append(f"| `{r['path']}:{r['line']}` | `{code}` | {status} |")
            if len(sim["rows"]) > SIMILAR_ROWS:
                C.append(f"| ... | {len(sim['rows']) - SIMILAR_ROWS} more | |")
            C.append("")
    if data.get("guardrail"):
        C += [f"**Prevention:** {data['guardrail'].strip()}", ""]
    if follow:
        C += ["**Follow-ups:**", ""] + [f"- {x}" for x in follow] + [""]
    C += ["**Proof check:** " + {"verified": "verified (fail before, pass after, suite passing).",
                                  "partial": "new test verified; suite output not provided.",
                                  "unverified": "NOT VERIFIED."}[proof["status"]]]
    for p in proof["problems"]:
        C.append(f"- {p['severity']}: {p['message']}")
    comment = "\n".join(C).rstrip() + "\n"
    return {"tool": "fix_report", "pr_title": title, "proof": proof, "report_text": report,
            "comment_markdown": comment}


def to_markdown(r):
    return ("# Bug fix report\n\n" + _fence(r["report_text"]) + "\n\n# Work item / PR comment\n\n"
            + r["comment_markdown"])


def load_inputs(a):
    data = {}
    if a.input:
        data = json.loads(Path(a.input).read_text(encoding="utf-8"))
    for key in ("bug", "root_cause", "fix", "branch", "work_item", "test_name", "test_command", "suite_command",
                "guardrail"):
        val = getattr(a, key)
        if val is not None:
            data[key] = val
    if a.file:
        data["files_changed"] = a.file
    if a.follow_up:
        data["follow_ups"] = a.follow_up
    for key, path in (("before_output", a.before), ("after_output", a.after), ("suite_output", a.suite)):
        if path:
            data[key] = Path(path).read_text(encoding="utf-8", errors="replace")
    sim = a.similar if a.similar else data.get("similar")
    if isinstance(sim, str):
        data["similar"] = json.loads(Path(sim).read_text(encoding="utf-8"))
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description="Draft the bug-fix report and work item comment (prints only).")
    ap.add_argument("--input", help="JSON file with the fields listed in the module docstring")
    ap.add_argument("--bug")
    ap.add_argument("--root-cause", dest="root_cause")
    ap.add_argument("--fix")
    ap.add_argument("--branch")
    ap.add_argument("--work-item", dest="work_item")
    ap.add_argument("--file", action="append", help="file changed by the fix (repeatable)")
    ap.add_argument("--test-name", dest="test_name")
    ap.add_argument("--test-command", dest="test_command")
    ap.add_argument("--before", help="file with the new test's output BEFORE the fix")
    ap.add_argument("--after", help="file with the new test's output AFTER the fix")
    ap.add_argument("--suite", help="file with the relevant suite's output after the fix")
    ap.add_argument("--suite-command", dest="suite_command")
    ap.add_argument("--follow-up", action="append", dest="follow_up")
    ap.add_argument("--guardrail", help="the prevention guardrail proposed (see references/prevention-catalog.md)")
    ap.add_argument("--similar", help="find_similar.py --json output file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-dir")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        data = load_inputs(a)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"fix_report: {e}\n")
        return 2
    r = build(data)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "fix-report.json").write_text(json.dumps(r, indent=2) + "\n", encoding="utf-8")
        Path(a.out_dir, "fix-report.md").write_text(to_markdown(r), encoding="utf-8")
        print(f"wrote {a.out_dir}/fix-report.md and .json (proof: {r['proof']['status']})")
    else:
        sys.stdout.write(json.dumps(r, indent=2) + "\n" if a.json else to_markdown(r))
    return 3 if r["proof"]["status"] == "unverified" else 0


if __name__ == "__main__":
    sys.exit(main())

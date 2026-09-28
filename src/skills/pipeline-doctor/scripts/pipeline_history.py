#!/usr/bin/env python3
"""pipeline_history - flaky vs regression vs recurring, from a window of CI runs.

Reads a runs list plus the logs of the failed runs and answers the questions that decide
what to do with a red build:
  * is this failing test FLAKY (it also passed on the same commit)?
  * is it a REGRESSION (it started at one commit and fails on every later run of the branch)?
    -> first bad commit and last good commit
  * is this failure RECURRING (the same signature in 3+ runs of the window)?
  * failure rate, mean time between failures (MTBF) and mean time to green (MTTG).

Inputs (read-only commands):
  Azure Pipelines  az pipelines runs list --pipeline-ids <id> --top 30 -o json > runs.json
  GitHub Actions   gh run list --workflow <wf> -L 30 --json databaseId,conclusion,status,headSha,headBranch,createdAt,updatedAt,name > runs.json
  Logs folder      one log per failed run, named by run id: run-1234.log, 1234.log, build_1234.txt,
                   or a subfolder named by id (e.g. the unzipped "Download logs" folder 1234/).

Usage:
  python pipeline_history.py runs.json --logs <folder> [--json] [--recurring-min 3] [--signatures lib.json]
Output is deterministic and redacted. Standard library only; Python 3.8+.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pipeline_triage as pt  # noqa: E402
from pipeline_common import human, iso, load_json, mean, parse_ts  # noqa: E402
from redact import Redactor  # noqa: E402

LOG_NAME = re.compile(r"^(?:run|build|job)?[-_ ]?(?P<id>\d+)(?:$|[-_. ])", re.I)
LOG_SUFFIXES = (".log", ".txt")
# A summary line proves the test step actually ran (so a test missing from the failures passed).
TEST_SUMMARY = re.compile(r"(Passed|Failed)!\s+-\s+Failed:|Total tests:|^=+ .*\b(passed|failed)\b.* in [\d.]+s|"
                          r"^Tests:\s+\d+|Tests run: \d+, Failures:", re.I)
GREEN, RED, PARTIAL, CANCELLED, OTHER, RUNNING = "success", "failure", "partial", "cancelled", "other", "in_progress"

DEFINITIONS = {
    "failure_rate": "failed runs / completed runs (cancelled, skipped and in-progress runs excluded; partially succeeded counts as not failed).",
    "incident": "a red streak on one branch: starts at the first failed run after a green (or first) run, ends at the next successful run.",
    "mtbf": "mean time between the starts of consecutive incidents on the same branch (finish times).",
    "mttg": "mean time to green: from the finish of the first failed run of an incident to the finish of the run that turned the branch green again.",
    "flaky": "the test failed on a commit that also has a successful run, or a run of the same commit that ran the tests without this test failing.",
    "regression": "the test fails on every run of the branch from one commit onwards; the run before it was green on another commit.",
    "intermittent": "failed, recovered and failed again on different commits with no same-commit proof: probably flaky, confirm locally.",
    "recurring": "the same diagnosis id is the root cause in at least --recurring-min runs of the window.",
}

ADVICE = {
    "flaky": "Do not change product code for this first. Look for timing, ordering, shared state, real network or clock use in the test; fix or quarantine it with a tracked ticket. Re-runs only hide it.",
    "regression": "Real regression: diff the suspect range (`git log --oneline {last_good}..{first_bad}`), reproduce at both commits, and hand the test name to bug-resolve. Use git bisect if the range has several commits.",
    "persistent": "Failing on every run in the window, so the start is outside it: fetch a longer runs list (--top 100) to find the first bad commit.",
    "intermittent": "Fails on and off across different commits: very likely flaky. Run it in a loop locally (e.g. 20 times) and in random order to confirm before touching product code.",
    "fixed": "Passing again since {fixed_commit}; no action unless it returns.",
}


def normalize_outcome(raw, status):
    raw = (raw or "").strip().lower()
    status = (status or "").strip().lower()
    if raw in ("succeeded", "success"):
        return GREEN
    if raw in ("failed", "failure", "timed_out", "startup_failure"):
        return RED
    if raw in ("canceled", "cancelled"):
        return CANCELLED
    if raw in ("partiallysucceeded", "partially_succeeded"):
        return PARTIAL
    if not raw and status and status != "completed":
        return RUNNING
    return OTHER


def normalize_runs(data):
    """Azure runs list, `az devops invoke` {"value": [...]}, gh run list, or REST workflow_runs."""
    if isinstance(data, dict):
        data = data.get("value") or data.get("workflow_runs") or data.get("runs") or []
    runs = []
    for r in data:
        if not isinstance(r, dict):
            continue
        rid = r.get("id") if r.get("databaseId") is None else r.get("databaseId")
        if rid is None:
            continue
        github = any(k in r for k in ("databaseId", "conclusion", "headSha", "head_sha"))
        raw = r.get("conclusion") if github else r.get("result")
        branch = r.get("sourceBranch") or r.get("headBranch") or r.get("head_branch") or ""
        definition = r.get("definition") if isinstance(r.get("definition"), dict) else {}
        start = parse_ts(r.get("startTime") or r.get("startedAt") or r.get("run_started_at")
                         or r.get("createdAt") or r.get("created_at") or r.get("queueTime"))
        finish = parse_ts(r.get("finishTime") or r.get("updatedAt") or r.get("updated_at"))
        runs.append({
            "id": str(rid), "platform": "github" if github else "azure",
            "outcome": normalize_outcome(raw, r.get("status")), "raw_result": raw or r.get("status"),
            "commit": r.get("sourceVersion") or r.get("headSha") or r.get("head_sha"),
            "branch": re.sub(r"^refs/heads/", "", branch),
            "pipeline": definition.get("name") or r.get("workflowName") or r.get("name"),
            "start": start, "finish": finish,
        })

    def key(r):
        t = r["start"] if r["start"] is not None else (r["finish"] if r["finish"] is not None else 0.0)
        return (t, int(r["id"]) if r["id"].isdigit() else 0, r["id"])
    return sorted(runs, key=key)


def find_logs(folder, run_ids):
    """{run_id: [files]} plus the names of files/folders that match no run in the list."""
    found, unmatched = {}, []
    if not folder:
        return found, unmatched
    for p in sorted(Path(folder).iterdir(), key=lambda x: x.name):
        if p.is_dir():
            files = sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in LOG_SUFFIXES)
            m = LOG_NAME.match(p.name)
        elif p.suffix.lower() in LOG_SUFFIXES:
            files = [p]
            m = LOG_NAME.match(p.stem)
        else:
            continue
        if m and m.group("id") in run_ids and files:
            found.setdefault(m.group("id"), []).extend(files)
        else:
            unmatched.append(p.name)
    return found, unmatched


def collect_tests(lines, sigs):
    """Failing test names from every test signature present in the log (not just the primary one)."""
    clean = [t for _, _, t in lines]
    blob = "\n".join(clean)
    tests = set()
    for s in sigs:
        if s.get("collect_rx") and any(s["rx"].search(t) for t in clean):
            tests |= {m.group("test").strip() for m in s["collect_rx"].finditer(blob)}
    ran = bool(tests) or any(TEST_SUMMARY.search(t) for t in clean)
    return sorted(tests), ran


def analyse_run_logs(files, sigs, red):
    diagnoses, tests, ran = {}, set(), False
    for f in files:
        text = f.read_text(encoding="utf-8-sig", errors="replace")
        r = pt.triage(text, sigs, red)
        d = r["diagnosis"]
        if d["id"] != "unknown" or r["error_lines"]:
            weight = next((s["weight"] for s in sigs if s["id"] == d["id"]), 0)
            if d["id"] not in diagnoses or diagnoses[d["id"]]["weight"] < weight:
                diagnoses[d["id"]] = {"id": d["id"], "title": d["title"], "owner": d["owner"],
                                      "category": d["category"], "weight": weight}
        t, ran_here = collect_tests(pt.parse_lines(text), sigs)
        tests |= set(t)
        ran = ran or ran_here
    known = [d for d in diagnoses.values() if d["id"] != "unknown"] or list(diagnoses.values())
    known.sort(key=lambda d: (-d["weight"], d["id"]))
    return known, sorted(tests), ran


def test_state(run, test):
    if run["outcome"] == GREEN:
        return "pass"
    if run["outcome"] in (RED, PARTIAL) and run["has_logs"]:
        if test in run["failing_tests"]:
            return "fail"
        return "pass" if run["tests_ran"] else "unknown"
    return "unknown"


def classify_test(test, runs):
    failed = [r for r in runs if test in r["failing_tests"]]
    # 1. flaky: same commit both failed and passed
    proof = []
    for commit in sorted({r["commit"] for r in failed if r["commit"]}):
        same = [r for r in runs if r["commit"] == commit]
        passed = [r["id"] for r in same if test_state(r, test) == "pass"]
        if passed:
            proof.append({"commit": commit, "failed_runs": [r["id"] for r in same if test_state(r, test) == "fail"],
                          "passed_runs": passed})
    latest = failed[-1]
    branch_runs = [r for r in runs if r["branch"] == latest["branch"]]
    seq = [(r, test_state(r, test)) for r in branch_runs]
    seq = [(r, s) for r, s in seq if s != "unknown"]
    out = {"branch": latest["branch"], "failed_runs": [r["id"] for r in failed], "fail_count": len(failed),
           "first_bad_commit": None, "last_good_commit": None, "first_bad_run": None, "last_good_run": None}
    if proof:
        out.update(status="flaky", confidence="high", evidence=proof)
        return out
    # streaks of consecutive "fail" among the known states on this branch
    streaks, cur = [], []
    for r, s in seq:
        if s == "fail":
            cur.append(r)
        elif cur:
            streaks.append(cur)
            cur = []
    last_is_fail = seq and seq[-1][1] == "fail"
    if cur:
        streaks.append(cur)
    if last_is_fail:
        final = streaks[-1]
        idx = [r["id"] for r, _ in seq].index(final[0]["id"])
        if len(streaks) > 1:
            out.update(status="intermittent", confidence="medium")
        elif idx == 0:
            out.update(status="persistent", confidence="medium",
                       first_bad_commit=None, first_bad_run=final[0]["id"])
        else:
            good = seq[idx - 1][0]
            # (a green run on the same commit would already have been caught as flaky above)
            out.update(status="regression", confidence="high" if len(final) >= 2 else "medium",
                       first_bad_commit=final[0]["commit"], first_bad_run=final[0]["id"],
                       last_good_commit=good["commit"], last_good_run=good["id"])
        return out
    if len(streaks) > 1:
        out.update(status="intermittent", confidence="medium")
        return out
    ids = [r["id"] for r, _ in seq]
    end = ids.index(streaks[0][-1]["id"])
    fixed = seq[end + 1][0]  # the last known state is "pass", so a run follows the streak
    out.update(status="fixed", confidence="medium", first_bad_commit=streaks[0][0]["commit"],
               first_bad_run=streaks[0][0]["id"], fixed_commit=fixed["commit"], fixed_run=fixed["id"])
    return out


def branch_view(branch, runs):
    done = [r for r in runs if r["branch"] == branch and r["outcome"] in (GREEN, RED, PARTIAL)]
    view = {"branch": branch, "runs": len(done), "latest": done[-1]["outcome"] if done else None,
            "latest_run": done[-1]["id"] if done else None, "status": "green" if done else "no-completed-runs"}
    if not done or done[-1]["outcome"] != RED:
        return view
    i = len(done) - 1
    while i > 0 and done[i - 1]["outcome"] == RED:
        i -= 1
    streak = done[i:]
    good = next((r for r in reversed(done[:i]) if r["outcome"] == GREEN), None)
    ids = []
    for r in streak:
        for d in r["diagnoses"]:
            if d["id"] not in ids:
                ids.append(d["id"])
    view.update(red_runs=[r["id"] for r in streak], red_since_run=streak[0]["id"], first_bad_commit=streak[0]["commit"],
                last_good_run=good["id"] if good else None, last_good_commit=good["commit"] if good else None,
                diagnoses=ids)
    if not good:
        view["status"] = "red-throughout-window"
    elif good["commit"] and good["commit"] == streak[0]["commit"]:
        view["status"] = "broke-without-code-change"
    else:
        view["status"] = "regression"
    return view


def incidents(runs):
    """Red streaks per branch -> [{branch, start_run, start, end_run, end}]."""
    out = []
    for branch in sorted({r["branch"] for r in runs}):
        current = None
        for r in runs:
            if r["branch"] != branch or r["outcome"] not in (GREEN, RED):
                continue
            t = r["finish"] if r["finish"] is not None else r["start"]
            if r["outcome"] == RED and current is None:
                current = {"branch": branch, "start_run": r["id"], "start": t, "end_run": None, "end": None}
                out.append(current)
            elif r["outcome"] == GREEN and current is not None:
                current.update(end_run=r["id"], end=t)
                current = None
    return out


def metrics(runs):
    completed = [r for r in runs if r["outcome"] in (GREEN, RED, PARTIAL)]
    failed = [r for r in completed if r["outcome"] == RED]
    inc = incidents(runs)
    gaps = []
    for branch in sorted({i["branch"] for i in inc}):
        starts = [i["start"] for i in inc if i["branch"] == branch and i["start"] is not None]
        gaps += [b - a for a, b in zip(starts, starts[1:])]
    ttg = [i["end"] - i["start"] for i in inc if i["end"] is not None and i["start"] is not None]
    latest = max((r["finish"] for r in completed if r["finish"] is not None), default=None)
    mtbf, mttg = mean(gaps), mean(ttg)
    return {
        "runs_total": len(runs), "completed": len(completed), "failed": len(failed),
        "succeeded": sum(1 for r in completed if r["outcome"] == GREEN),
        "partially_succeeded": sum(1 for r in completed if r["outcome"] == PARTIAL),
        "cancelled": sum(1 for r in runs if r["outcome"] == CANCELLED),
        "in_progress_or_other": sum(1 for r in runs if r["outcome"] in (RUNNING, OTHER)),
        "failure_rate": round(len(failed) / len(completed), 3) if completed else None,
        "incidents": len(inc),
        "mtbf_seconds": mtbf, "mtbf": human(mtbf), "mtbf_samples": len(gaps),
        "mttg_seconds": mttg, "mttg": human(mttg), "mttg_samples": len(ttg),
        "open_incidents": [{"branch": i["branch"], "since_run": i["start_run"], "since": iso(i["start"]),
                            "open_for_seconds": round(latest - i["start"], 1) if latest is not None and i["start"] is not None else None,
                            "open_for": human(latest - i["start"]) if latest is not None and i["start"] is not None else "n/a"}
                           for i in inc if i["end"] is None],
    }


def analyse(runs_data, logs_folder=None, sigs=None, recurring_min=3, redactor=None):
    sigs = sigs if sigs is not None else pt.load_library()
    red = redactor or Redactor()
    runs = normalize_runs(runs_data)
    by_id = {r["id"]: r for r in runs}
    logs, unmatched = find_logs(logs_folder, set(by_id))
    for r in runs:
        files = logs.get(r["id"], [])
        r["has_logs"] = bool(files)
        r["log_files"] = [f.relative_to(Path(logs_folder)).as_posix() for f in files] if files else []
        r["diagnoses"], r["failing_tests"], r["tests_ran"] = (analyse_run_logs(files, sigs, red) if files else ([], [], False))

    tests = []
    for name in sorted({t for r in runs for t in r["failing_tests"]}):
        c = classify_test(name, runs)
        c["test"] = red.redact(name)
        fmt = {"last_good": (c.get("last_good_commit") or "?")[:10], "first_bad": (c.get("first_bad_commit") or "?")[:10],
               "fixed_commit": (c.get("fixed_commit") or "a later commit")[:10]}
        c["advice"] = ADVICE[c["status"]].format(**fmt)
        tests.append(c)
    order = {"regression": 0, "flaky": 1, "intermittent": 2, "persistent": 3, "fixed": 4}
    tests.sort(key=lambda c: (order[c["status"]], -c["fail_count"], c["test"]))

    counts = {}
    for r in runs:
        for d in r["diagnoses"]:
            if d["id"] != "unknown":
                v = counts.setdefault(d["id"], {"id": d["id"], "owner": d["owner"], "category": d["category"],
                                                "runs": [], "titles": []})
                v["runs"].append(r["id"])
                v["title"] = d["title"]  # latest occurrence
                if d["title"] not in v["titles"]:
                    v["titles"].append(d["title"])
    recurring = sorted((dict(v, count=len(v["runs"])) for v in counts.values() if len(v["runs"]) >= recurring_min),
                       key=lambda v: (-v["count"], v["id"]))
    for v in recurring:
        hits = [by_id[i] for i in v["runs"]]
        v["first_seen"] = iso(hits[0]["finish"])
        v["last_seen"] = iso(hits[-1]["finish"])
        v["branches"] = sorted({h["branch"] for h in hits})

    branches = [branch_view(b, runs) for b in sorted({r["branch"] for r in runs})]
    times = [t for r in runs for t in (r["start"], r["finish"]) if t is not None]
    return {
        "pipeline": ", ".join(sorted({r["pipeline"] for r in runs if r["pipeline"]})) or None,
        "platform": ", ".join(sorted({r["platform"] for r in runs})) or None,
        "window": {"runs": len(runs), "from": iso(min(times)) if times else None, "to": iso(max(times)) if times else None,
                   "branches": sorted({r["branch"] for r in runs})},
        "metrics": metrics(runs),
        "branches": branches,
        "tests": tests,
        "recurring": recurring,
        "recurring_min": recurring_min,
        "missing_logs": [r["id"] for r in runs if r["outcome"] == RED and not r["has_logs"]],
        "unmatched_logs": unmatched,
        "runs": [{"id": r["id"], "outcome": r["outcome"], "branch": r["branch"], "commit": r["commit"],
                  "start": iso(r["start"]), "finish": iso(r["finish"]), "log_files": r["log_files"],
                  "diagnoses": [d["id"] for d in r["diagnoses"]], "failing_tests": [red.redact(t) for t in r["failing_tests"]]}
                 for r in runs],
        "definitions": DEFINITIONS,
    }


def short(sha):
    return f"`{sha[:10]}`" if sha else "n/a"


def to_markdown(res):
    m = res["metrics"]
    L = ["# Pipeline Doctor - run history", "",
         f"Pipeline: **{res['pipeline'] or 'unknown'}** ({res['platform'] or '?'}), {res['window']['runs']} runs "
         f"from {res['window']['from'] or '?'} to {res['window']['to'] or '?'}", "",
         "| Metric | Value |", "|---|---|",
         f"| Failure rate | {'n/a' if m['failure_rate'] is None else format(m['failure_rate'] * 100, '.1f') + '%'} "
         f"({m['failed']} of {m['completed']} completed runs) |",
         f"| Mean time between failures | {m['mtbf']} ({m['mtbf_samples']} intervals) |",
         f"| Mean time to green | {m['mttg']} ({m['mttg_samples']} recoveries) |",
         f"| Cancelled / in progress | {m['cancelled']} / {m['in_progress_or_other']} |", ""]
    for o in m["open_incidents"]:
        L.append(f"- Still red: **{o['branch']}** since run {o['since_run']} ({o['since']}), open for {o['open_for']}")
    L += ["", "## Branches", ""]
    for b in res["branches"]:
        if b["status"] in ("green", "no-completed-runs"):
            L.append(f"- **{b['branch']}**: {b['status']} (latest run {b['latest_run']})")
        else:
            L.append(f"- **{b['branch']}**: {b['status']} - red since run {b['red_since_run']} (commit {short(b['first_bad_commit'])}), "
                     f"last green run {b['last_good_run'] or 'none in window'} (commit {short(b['last_good_commit'])}); "
                     f"causes: {', '.join(b['diagnoses']) or 'no logs'}")
    if res["tests"]:
        L += ["", "## Failing tests", "", "| Test | Verdict | Failed in runs | Commits | Next step |", "|---|---|---|---|---|"]
        for t in res["tests"]:
            if t["status"] == "regression":
                commits = f"good {short(t['last_good_commit'])} -> bad {short(t['first_bad_commit'])}"
            elif t["status"] == "flaky":
                commits = "; ".join(f"{short(e['commit'])} failed {','.join(e['failed_runs'])} passed {','.join(e['passed_runs'])}"
                                    for e in t.get("evidence", []))
            else:
                commits = ""
            L.append(f"| `{t['test']}` | **{t['status']}** ({t['confidence']}) | {', '.join(t['failed_runs'])} | {commits} | {t['advice']} |")
    if res["recurring"]:
        L += ["", f"## Recurring causes (>= {res['recurring_min']} runs)", ""]
        for v in res["recurring"]:
            L.append(f"- **{v['title']}** (`{v['id']}`, owner {v['owner']}): {v['count']} runs ({', '.join(v['runs'])}), "
                     f"{v['first_seen']} to {v['last_seen']}. Fix the cause once instead of re-running.")
    if res["missing_logs"]:
        L += ["", f"Failed runs without logs (not classified): {', '.join(res['missing_logs'])}"]
    if res["unmatched_logs"]:
        L += [f"Log files that match no run in the list: {', '.join(res['unmatched_logs'])}"]
    L += ["", "---", "Definitions: flaky = failed and passed on the same commit; regression = fails on every run since one commit; "
          "recurring = same cause in several runs. Times come from run finish times. "
          "Log content redacted. No pipeline or run was changed."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Classify CI failures across a window of runs: flaky, regression, recurring.")
    ap.add_argument("runs", help="runs list JSON (az pipelines runs list -o json / gh run list --json ...)")
    ap.add_argument("--logs", help="folder with failed-run logs named by run id")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--recurring-min", type=int, default=3)
    ap.add_argument("--signatures", help="alternative failure library JSON")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    res = analyse(load_json(a.runs), a.logs, pt.load_library(a.signatures), a.recurring_min)
    sys.stdout.write(json.dumps(res, indent=2) + "\n" if a.json else to_markdown(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())

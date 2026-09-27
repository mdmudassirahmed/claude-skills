#!/usr/bin/env python3
"""pipeline_triage - find the root cause in a failed CI/CD log (Azure Pipelines or GitHub Actions).

Strips timestamps/ANSI codes, tracks the step each line belongs to, matches lines against
the failure library (../references/failure-signatures.json), and picks
the ROOT error rather than the cascade ("exit code 1") that follows it. Output is redacted.

Inputs:
  Azure Pipelines  log text downloaded from the run ("Download logs" zip, or
                   az devops invoke --area build --resource logs ... ) - one or many files
  GitHub Actions   gh run view <run-id> --log-failed > run.log

Usage:
  python pipeline_triage.py run.log [more.log ...] [--json] [--signatures custom.json]
Standard library only; Python 3.8+.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from redact import Redactor  # noqa: E402

DEFAULT_LIB = HERE.parent / "references" / "failure-signatures.json"

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
ADO_TS = re.compile(r"^﻿?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z ")
GHA_PREFIX = re.compile(r"^(?P<job>[^\t]+)\t(?P<step>[^\t]+)\t(﻿)?\d{4}-\d{2}-\d{2}T[\d:.]+Z ?")
ADO_STEP = re.compile(r"^##\[section\]Starting: (?P<step>.+)$")
GHA_GROUP = re.compile(r"^##\[group\](?P<step>.+)$")
GENERIC_ERROR = re.compile(r"##\[error\]|\berror\b[:\s]|\bERR!|\bFAILED\b|\bfatal:|Exception\b|Traceback", re.I)
CASCADE = re.compile(r"Process completed with exit code|exited with code|Bash exited with|PowerShell exited with|"
                     r"Build FAILED|The process '.*' failed with exit code|npm (ERR!|error) A complete log|"
                     r"Error: Process completed|##\[error\]Script failed with error|Command exited with code|"
                     r"error Command failed with exit code", re.I)


def load_library(path=None):
    data = json.loads(Path(path or DEFAULT_LIB).read_text(encoding="utf-8"))
    sigs = []
    for s in data["signatures"]:
        pat = s["pattern"]
        flags = 0 if pat.startswith("(?-i)") else re.I
        s = dict(s, rx=re.compile(pat.replace("(?-i)", "", 1), flags))
        if s.get("collect"):
            s["collect_rx"] = re.compile(s["collect"], re.M)
        sigs.append(s)
    return sigs


def parse_lines(text):
    """Return [(line_no, step, clean_text)]."""
    out, step = [], None
    for i, raw in enumerate(text.splitlines(), 1):
        line = ANSI.sub("", raw).rstrip("\r")
        m = GHA_PREFIX.match(line)
        if m:
            # `gh run view --log-failed`: the step column is authoritative.
            step = m.group("step").strip()
            line = line[m.end():]
        else:
            line = ADO_TS.sub("", line)
            s = ADO_STEP.match(line)
            g = GHA_GROUP.match(line)
            if s:
                step = s.group("step").strip()
            elif g:  # raw GitHub log without the job/step columns: "##[group]Run npm ci"
                step = re.sub(r"^Run ", "", g.group("step").strip())
        out.append((i, step, line))
    return out


def fmt(template, groups):
    class Safe(dict):
        def __missing__(self, key):
            return "?"
    merged = {}
    for k, v in groups.items():
        base = re.sub(r"\d+$", "", k)
        if v is not None and base not in merged:
            merged[base] = v.strip()
    return template.format_map(Safe(merged))


def triage(text, sigs, redactor):
    lines = parse_lines(text)
    matches, error_lines = [], []
    for no, step, line in lines:
        for s in sigs:
            m = s["rx"].search(line)
            if m:
                matches.append({"sig": s, "line": no, "step": step, "text": line, "groups": m.groupdict()})
                break
        if GENERIC_ERROR.search(line) and not CASCADE.search(line):
            error_lines.append((no, step, line))

    primary = None
    if matches:
        primary = sorted(matches, key=lambda x: (-x["sig"]["weight"], x["line"]))[0]
    first_error = error_lines[0] if error_lines else None

    def excerpt(center, radius=6):
        lo, hi = max(1, center - radius), center + radius
        return [f"{n:>5}  {redactor.redact(t)}" for n, _, t in lines if lo <= n <= hi]

    result = {
        "lines": len(lines),
        "failing_steps": sorted({st for _, st, _ in error_lines if st}) or None,
        "error_lines": [{"line": n, "step": st, "text": redactor.redact(t)[:300]} for n, st, t in error_lines[:25]],
    }
    if primary:
        s = primary["sig"]
        collected = []
        if s.get("collect_rx"):
            collected = sorted({m.group("test").strip() for m in s["collect_rx"].finditer("\n".join(l for _, _, l in lines))})[:20]
        result["diagnosis"] = {
            "id": s["id"], "category": s["category"], "confidence": s["confidence"], "owner": s["owner"],
            "title": fmt(s["title"], primary["groups"]), "why": fmt(s["why"], primary["groups"]),
            "fix": [fmt(f, primary["groups"]) for f in s["fix"]],
            "line": primary["line"], "step": primary["step"], "evidence": redactor.redact(primary["text"])[:400],
            "details": {k: v for k, v in primary["groups"].items() if v},
            "failing_tests": collected,
        }
        result["excerpt"] = excerpt(primary["line"])
        others = []
        seen = {s["id"]}
        for m in sorted(matches, key=lambda x: x["line"]):
            if m["sig"]["id"] not in seen:
                seen.add(m["sig"]["id"])
                others.append({"id": m["sig"]["id"], "title": fmt(m["sig"]["title"], m["groups"]),
                               "line": m["line"], "weight": m["sig"]["weight"]})
        result["other_signals"] = others
    else:
        result["diagnosis"] = {
            "id": "unknown", "category": "unknown", "confidence": "low", "owner": "developer",
            "title": "No known failure pattern matched",
            "why": "Read the first real error line below; the library has no pattern for it yet.",
            "fix": ["Investigate the first error line and the step it belongs to.",
                    "If this turns out to be a recurring cause, add a pattern to failure-signatures.json."],
            "line": first_error[0] if first_error else None, "step": first_error[1] if first_error else None,
            "evidence": redactor.redact(first_error[2])[:400] if first_error else None,
            "details": {}, "failing_tests": [],
        }
        result["excerpt"] = excerpt(first_error[0]) if first_error else []
        result["other_signals"] = []
    return result


def to_markdown(results):
    L = ["# Pipeline Doctor - diagnosis", ""]
    for r in results:
        d = r["diagnosis"]
        L += [f"## `{r['file']}`", "",
              f"**{d['title']}** - {d['category']}, confidence {d['confidence']}, fix owner: {d['owner']}", "",
              f"- Where: step **{d.get('step') or 'unknown'}**, log line {d.get('line')}",
              f"- Why: {d['why']}"]
        if d.get("evidence"):
            L.append(f"- Evidence: `{d['evidence'][:200]}`")
        if d.get("failing_tests"):
            L.append("- Failing tests: " + ", ".join(f"`{t}`" for t in d["failing_tests"]))
        L += ["", "**Fix:**"] + [f"{i}. {s}" for i, s in enumerate(d["fix"], 1)]
        if r.get("other_signals"):
            L += ["", "Other signals in the log: " + "; ".join(f"{o['title']} (line {o['line']})" for o in r["other_signals"])]
        if r.get("excerpt"):
            L += ["", "```", *r["excerpt"], "```"]
        L.append("")
    L += ["---", "Log content redacted. No pipeline, service connection or resource was changed."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Diagnose failed CI/CD logs.")
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--signatures", help="alternative failure library JSON")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sigs = load_library(a.signatures)
    red = Redactor()
    results = []
    for p in a.logs:
        text = Path(p).read_text(encoding="utf-8-sig", errors="replace")
        r = triage(text, sigs, red)
        r["file"] = str(p)
        results.append(r)
    sys.stdout.write(json.dumps(results, indent=2) + "\n" if a.json else to_markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""log_detective - turn exported logs into incident evidence: when it started, what is new,
what got slower, what changed just before, and which code lines are implicated.

It produces EVIDENCE, not a verdict. The skill (Claude) reasons over this output together
with the code; timing correlation with a deployment is a lead, not proof.

Inputs (auto-detected; any mix, files or folders):
  App Insights     az monitor app-insights query --app <app> --analytics-query "<kql>" -o json
  Log Analytics    az monitor log-analytics query -w <workspace> --analytics-query "<kql>" -o json
  CloudWatch       aws logs get-query-results --query-id <id>        (Logs Insights)
  CloudWatch       aws logs filter-log-events --log-group-name <g> ...
  GCP              gcloud logging read "<filter>" --format=json
  Plain text       any .log/.txt (multi-line stack traces are joined to their line)

All message text is redacted (scripts/redact.py) before analysis and output.

Usage:
  python log_detective.py incident-logs/ [--deploys deploys.txt] [--out-dir report] [--json]
  --deploys: `git log --since=... --format="%H|%cI|%s"` output, or JSON [{"time","id","description"}]
Standard library only; Python 3.8+.
"""
import argparse
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import Redactor  # noqa: E402

# ------------------------------------------------------------------ field mapping
F_TIME = ["timestamp", "timegenerated", "@timestamp", "time", "receivetimestamp", "eventtime", "date"]
F_MSG = ["message", "@message", "outermessage", "innermostmessage", "textpayload", "msg", "renderedmessage",
         "log", "details", "outerMessage"]
F_TYPE = ["exceptiontype", "outertype", "innermosttype", "problemid", "exception_type", "dependencytype", "type"]
F_OP = ["operation_name", "operationname", "name", "path", "url", "route", "request_path", "@logstream"]
F_STATUS = ["resultcode", "status", "statuscode", "status_code", "httpstatus", "httpresponsestatus"]
F_DUR = ["duration", "durationms", "latency_ms", "duration_ms", "elapsed_ms", "latency", "responsetime"]
F_SUCCESS = ["success"]
F_LEVEL = ["severitylevel", "severity", "level", "loglevel", "levelname"]
F_ITEM = ["itemtype", "kind"]
# Table names that arrive in a "Type"/"TableName" column (Log Analytics) - they describe the
# record kind, not an exception type.
TABLE_NAMES = {"apprequests": "request", "requests": "request", "appdependencies": "dependency",
               "dependencies": "dependency", "appexceptions": "exception", "exceptions": "exception",
               "apptraces": "log", "traces": "log", "customevents": "log", "appevents": "log"}
F_TARGET = ["target", "dependency", "host"]
F_OPID = ["operation_id", "operationid", "traceid", "trace", "correlation_id", "requestid", "@requestid"]
F_ROLE = ["cloud_rolename", "approlename", "service", "logname", "@log"]
F_STACK = ["details", "stack", "stacktrace", "exception", "@stack"]

TS_PREFIX = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?")
LEVEL_WORD = re.compile(r"\b(CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b", re.I)
LEVEL_MAP = {"critical": "error", "fatal": "error", "error": "error", "err": "error", "warn": "warn",
             "warning": "warn", "info": "info", "debug": "info", "trace": "info",
             "4": "error", "3": "error", "2": "warn", "1": "info", "0": "info"}

# In-app stack frames (library frames filtered out below).
FRAME_PATTERNS = [
    re.compile(r"at (?P<func>[\w.<>`+]+)\([^)]*\) in (?P<file>[^\s:]+(?::\\[^\s:]+)?):line (?P<line>\d+)"),  # .NET
    re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<func>[\w<>.]+)'),                       # Python
    re.compile(r"at (?P<func>[\w.$<>]+) \((?P<file>[^():]+):(?P<line>\d+):\d+\)"),                          # Node
    re.compile(r"at (?P<func>[\w.$<>]+)\((?P<file>[\w$]+\.(?:java|kt|scala)):(?P<line>\d+)\)"),            # JVM
]
LIBRARY_FRAME = re.compile(r"(^|[\\/.])(System|Microsoft|node_modules|site-packages|dist-packages|java\.|"
                           r"javax\.|sun\.|jdk\.|kotlin\.|org\.springframework|internal/|<frozen|lib/python)",
                           re.I)


def lower_map(d):
    return {str(k).lower(): v for k, v in d.items()}


def pick(d, names):
    for n in names:
        v = d.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def parse_ts(v):
    if v is None:
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        n = float(v)
        return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
    s = str(v).strip().replace(",", ".")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)             # trim 7-digit fractions (Azure)
    s = s.replace("Z", "+00:00")
    if re.match(r"^\d{4}-\d{2}-\d{2} \d", s):
        s = s.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        if isinstance(v, str):  # "00:00:01.5320000" timespan
            m = re.match(r"^(\d+):(\d+):(\d+(?:\.\d+)?)$", v.strip())
            if m:
                return (int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))) * 1000
        return None


def to_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    return str(v).strip().lower() in ("true", "1", "yes")


# ------------------------------------------------------------------ loaders
def rows_from_json(data):
    """Yield dict rows from any supported JSON shape, plus a source label."""
    if isinstance(data, dict) and isinstance(data.get("tables"), list):          # App Insights
        for t in data["tables"]:
            cols = [c.get("name") for c in t.get("columns", [])]
            for r in t.get("rows", []):
                yield dict(zip(cols, r)), "app-insights"
        return
    if isinstance(data, dict) and isinstance(data.get("results"), list):         # CW Logs Insights
        for r in data["results"]:
            yield {x.get("field"): x.get("value") for x in r if isinstance(x, dict)}, "cloudwatch-insights"
        return
    if isinstance(data, dict) and isinstance(data.get("events"), list):          # CW filter-log-events
        for e in data["events"]:
            yield {"timestamp": e.get("timestamp"), "message": e.get("message"),
                   "@logStream": e.get("logStreamName")}, "cloudwatch-events"
        return
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]
    if isinstance(data, list):
        for r in data:
            if not isinstance(r, dict):
                continue
            if "jsonPayload" in r or "textPayload" in r or "logName" in r:            # GCP
                flat = dict(r)
                jp = r.get("jsonPayload") or {}
                if isinstance(jp, dict):
                    flat.update(jp)
                yield flat, "gcp-logging"
            else:
                yield r, "log-analytics"


def load_text(text):
    """Plain-text logs; lines without a leading timestamp continue the previous record."""
    records, cur = [], None
    for line in text.splitlines():
        m = TS_PREFIX.match(line)
        if m:
            if cur:
                records.append(cur)
            cur = {"timestamp": m.group(1), "message": line[m.end():].strip()}
        elif cur is not None and line.strip():
            cur["message"] += "\n" + line.rstrip()
    if cur:
        records.append(cur)
    return records


def normalise(row, source, redactor):
    d = lower_map(row)
    msg = pick(d, F_MSG)
    # Structured JSON inside the message (common in CloudWatch / container logs)
    if isinstance(msg, str) and msg.strip().startswith("{"):
        try:
            inner = lower_map(json.loads(msg))
            d = {**inner, **{k: v for k, v in d.items() if k not in ("message", "@message")}}
            msg = pick(inner, F_MSG) or msg
        except ValueError:
            pass
    ts = parse_ts(pick(d, F_TIME))
    level_raw = pick(d, F_LEVEL)
    level = LEVEL_MAP.get(str(level_raw).lower()) if level_raw is not None else None
    if level is None and isinstance(msg, str):
        m = LEVEL_WORD.search(msg[:80])
        level = LEVEL_MAP.get(m.group(1).lower()) if m else None
    item = str(pick(d, F_ITEM) or "").lower()
    for col in ("type", "tablename"):
        v = str(d.get(col) or "").lower()
        if v in TABLE_NAMES and not item:
            item = TABLE_NAMES[v]
    etype = pick(d, F_TYPE)
    if etype and str(etype).lower() in TABLE_NAMES:
        etype = pick({k: v for k, v in d.items() if k != "type"}, F_TYPE)
    stack = pick(d, F_STACK)
    if not isinstance(stack, str):
        stack = json.dumps(stack) if stack else ""
    text = msg if isinstance(msg, str) else (json.dumps(msg) if msg is not None else "")
    if not etype:
        m = re.search(r"\b([A-Za-z_][\w.]*(?:Exception|Error))\b", text)
        etype = m.group(1) if m else None
    status = pick(d, F_STATUS)
    success = to_bool(pick(d, F_SUCCESS))
    kind = ("exception" if "exception" in item or (etype and not item and ("exception" in text.lower()
                                                                             or "traceback" in text.lower()))
            else "dependency" if "dependenc" in item
            else "request" if "request" in item or (status is not None and pick(d, F_OP) and item == "")
            else "log")
    rec = {
        "ts": ts, "source": source, "kind": kind, "level": level,
        "type": str(etype) if etype else None,
        "op": str(pick(d, F_OP) or "") or None,
        "status": str(status) if status is not None else None,
        "duration_ms": to_num(pick(d, F_DUR)),
        "success": success,
        "target": pick(d, F_TARGET),
        "op_id": pick(d, F_OPID),
        "role": pick(d, F_ROLE),
        "message": redactor.redact(text)[:4000],
        "stack": redactor.redact(stack)[:8000],
    }
    rec["problem"] = is_problem(rec)
    return rec


def is_problem(r):
    if r["kind"] == "exception":
        return True
    if r["success"] is False:
        return True
    try:
        code = int(float(r["status"])) if r["status"] not in (None, "") else None
    except ValueError:
        code = None
    if code is not None and (code >= 500 or code in (408, 429)):
        return True
    if code is not None and code < 0:        # SQL client error codes e.g. -2 timeout
        return True
    return r["level"] == "error"


# ------------------------------------------------------------------ analysis
NORMALISERS = [
    (re.compile(r"<[a-z0-9-]+-\d+>"), "<redacted>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<guid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"https?://[^\s\"']+"), "<url>"),
    (re.compile(r"'[^']{1,80}'|\"[^\"]{1,80}\""), "<str>"),
    (re.compile(r"\b\d+(\.\d+)?\b"), "<n>"),
]


def headline(r):
    """The line that names the problem: for a Python traceback it is the last line
    ("KeyError: 'currency'"); otherwise the first line."""
    lines = [l for l in (r["message"] or "").strip().splitlines() if l.strip()]
    if not lines:
        return ""
    if any(l.startswith("Traceback (most recent call last)") for l in lines):
        return lines[-1].strip()
    return lines[0]


def signature(r):
    first_line = headline(r)
    if r["type"] and first_line.startswith(r["type"]):
        first_line = first_line[len(r["type"]):].lstrip(": ")
    for rx, rep in NORMALISERS:
        first_line = rx.sub(rep, first_line)
    first_line = re.sub(r"^\W*(CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?)\W*", "", first_line, flags=re.I)[:140]
    if r["kind"] == "exception":
        return f"{r['type'] or 'Exception'}: {first_line}"
    if r["kind"] == "dependency":
        return f"dependency {r['target'] or '?'} failed ({r['type'] or ''} {r['status'] or ''})".replace("  ", " ")
    if r["kind"] == "request":
        return f"{r['op'] or 'request'} -> {r['status']}"
    return first_line or "(empty message)"


def pick_bucket(span):
    for minutes in (1, 5, 10, 15, 30, 60, 180, 360, 720, 1440):
        if span / timedelta(minutes=minutes) <= 48:
            return timedelta(minutes=minutes)
    return timedelta(days=1)


def floor_to(dt, step):
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return epoch + ((dt - epoch) // step) * step


def find_onset(problems, start, end, step):
    """First bucket where problems jump to >= max(5, 3x the median of the earlier buckets)."""
    if not problems:
        return None, []
    n = int((floor_to(end, step) - floor_to(start, step)) / step) + 1
    counts = [0] * n
    base = floor_to(start, step)
    for r in problems:
        counts[int((floor_to(r["ts"], step) - base) / step)] += 1
    for i, c in enumerate(counts):
        prev = counts[:i]
        baseline = statistics.median(prev) if prev else 0
        if i >= 2 and c >= max(5, 3 * max(baseline, 1)):
            return base + i * step, counts
    return None, counts


def frames_from(text):
    out = []
    for rx in FRAME_PATTERNS:
        for m in rx.finditer(text or ""):
            file, func = m.group("file"), m.group("func")
            if LIBRARY_FRAME.search(file) or LIBRARY_FRAME.search(func):
                continue
            out.append({"file": file.replace("\\", "/"), "line": int(m.group("line")), "function": func})
    return out


def percentile(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    k = max(0, min(len(vals) - 1, int(round(p / 100 * (len(vals) - 1)))))
    return vals[k]


def latency_changes(records, split_at):
    by_op = {}
    for r in records:
        if r["duration_ms"] is None or r["kind"] == "dependency" and not r["op"]:
            continue
        key = r["op"] or r["target"] or "(unnamed)"
        side = "after" if r["ts"] >= split_at else "before"
        by_op.setdefault(key, {"before": [], "after": []})[side].append(r["duration_ms"])
    out = []
    for op, v in by_op.items():
        if len(v["before"]) < 5 or len(v["after"]) < 5:
            continue
        b, a = percentile(v["before"], 95), percentile(v["after"], 95)
        if b and a and a >= 1.5 * b and a - b >= 200:
            out.append({"operation": op, "p95_before_ms": round(b), "p95_after_ms": round(a),
                        "factor": round(a / b, 1), "samples_before": len(v["before"]),
                        "samples_after": len(v["after"])})
    return sorted(out, key=lambda x: -x["factor"])


def load_deploys(path):
    if not path:
        return []
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    out = []
    try:
        for d in json.loads(text):
            t = parse_ts(d.get("time") or d.get("finishTime") or d.get("completedOn") or d.get("date"))
            if t:
                out.append({"time": t, "id": str(d.get("id", ""))[:12], "description": d.get("description") or d.get("name", "")})
    except ValueError:
        for line in text.splitlines():
            parts = line.strip().split("|", 2)
            if len(parts) >= 2 and parse_ts(parts[1]):
                out.append({"time": parse_ts(parts[1]), "id": parts[0][:12],
                            "description": parts[2] if len(parts) > 2 else ""})
    return sorted(out, key=lambda d: d["time"])


def iter_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".json", ".log", ".txt", ".jsonl"))
        elif p.exists():
            yield p


def analyse(paths, deploys_path=None):
    red = Redactor()
    records, inputs, skipped = [], [], []
    exclude = {Path(deploys_path).resolve()} if deploys_path else set()
    for f in iter_files(paths):
        if f.resolve() in exclude:
            continue
        raw = f.read_text(encoding="utf-8-sig", errors="replace")
        before = len(records)
        if f.suffix.lower() == ".json":
            try:
                data = json.loads(raw)
            except ValueError as e:
                skipped.append({"file": str(f), "reason": f"invalid JSON ({e})"})
                continue
            for row, src in rows_from_json(data):
                records.append(normalise(row, src, red))
        elif f.suffix.lower() == ".jsonl":
            for line in raw.splitlines():
                try:
                    records.append(normalise(json.loads(line), "jsonl", red))
                except ValueError:
                    continue
        else:
            for row in load_text(raw):
                records.append(normalise(row, "text", red))
        added = len(records) - before
        (inputs if added else skipped).append({"file": str(f), "records": added} if added
                                              else {"file": str(f), "reason": "no log records recognised"})
    no_ts = sum(1 for r in records if r["ts"] is None)
    records = [r for r in records if r["ts"] is not None]
    records.sort(key=lambda r: r["ts"])
    report = {"inputs": inputs, "skipped": skipped, "records": len(records), "records_without_time": no_ts,
              "redactions": dict(sorted(red.counts.items()))}
    if not records:
        report.update({"verdict_hint": "no-data", "problems": 0, "signatures": []})
        return report

    start, end = records[0]["ts"], records[-1]["ts"]
    step = pick_bucket(end - start)
    problems = [r for r in records if r["problem"]]
    onset, counts = find_onset(problems, start, end, step)

    sigs = {}
    for r in problems:
        s = sigs.setdefault(signature(r), {"count": 0, "first_seen": r["ts"], "last_seen": r["ts"], "kinds": set(),
                                           "operations": {}, "roles": set(), "sample": r["message"][:600],
                                           "headline": headline(r)[:300],
                                           "op_ids": [], "frames": [], "type": r["type"]})
        s["count"] += 1
        s["last_seen"] = r["ts"]
        s["kinds"].add(r["kind"])
        if r["op"]:
            s["operations"][r["op"]] = s["operations"].get(r["op"], 0) + 1
        if r["role"]:
            s["roles"].add(str(r["role"]))
        if r["op_id"] and len(s["op_ids"]) < 3:
            s["op_ids"].append(str(r["op_id"]))
        if not s["frames"]:
            s["frames"] = frames_from(r["stack"] + "\n" + r["message"])[:5]
    sig_list = []
    for text, s in sorted(sigs.items(), key=lambda kv: -kv[1]["count"]):
        sig_list.append({
            "signature": text, "count": s["count"], "first_seen": s["first_seen"].isoformat(),
            "last_seen": s["last_seen"].isoformat(), "kinds": sorted(s["kinds"]),
            "top_operations": sorted(s["operations"].items(), key=lambda kv: -kv[1])[:3],
            "roles": sorted(s["roles"]), "headline": s["headline"], "sample": s["sample"], "example_operation_ids": s["op_ids"],
            "code_frames": s["frames"],
            "new_at_onset": bool(onset and s["first_seen"] >= onset - step),
        })

    split = onset or (start + (end - start) / 2)
    lat = latency_changes(records, split)
    if not onset and lat:
        # Pure slowdown (no error spike): find where the slowest operation degraded.
        op = lat[0]["operation"]
        thr = (lat[0]["p95_before_ms"] + lat[0]["p95_after_ms"]) / 2
        slow = [r for r in records if (r["op"] or r["target"]) == op and (r["duration_ms"] or 0) >= thr]
        onset_latency = slow[0]["ts"] if slow else None
    else:
        onset_latency = None

    new_sigs = [s for s in sig_list if s["new_at_onset"]]
    first_new = min((s["first_seen"] for s in new_sigs), default=None)
    deploys = load_deploys(deploys_path)
    anchor = parse_ts(first_new) if first_new else (onset or onset_latency)
    correlated = None
    if anchor and deploys:
        prior = [d for d in deploys if d["time"] <= anchor + timedelta(minutes=1)]
        if prior:
            d = prior[-1]
            gap = anchor - d["time"]
            if gap <= timedelta(hours=24):
                correlated = {"id": d["id"], "time": d["time"].isoformat(), "description": d["description"],
                              "minutes_before_onset": round(gap.total_seconds() / 60),
                              "strength": "strong" if gap <= timedelta(hours=2) else "weak"}

    all_frames = {}
    for s in sig_list[:5]:
        for fr in s["code_frames"]:
            key = (fr["file"], fr["line"])
            all_frames[key] = {**fr, "signature": s["signature"][:80]}

    report.update({
        "window": {"start": start.isoformat(), "end": end.isoformat(), "bucket_minutes": int(step.total_seconds() // 60)},
        "problems": len(problems),
        "problem_rate": round(len(problems) / len(records), 4),
        "onset": onset.isoformat() if onset else None,
        "first_new_error": first_new,
        "latency_onset": onset_latency.isoformat() if onset_latency else None,
        "timeline_counts": counts,
        "signatures": sig_list[:15],
        "latency_regressions": lat[:10],
        "deploy_correlation": correlated,
        "deploys_considered": len(deploys),
        "code_candidates": list(all_frames.values())[:10],
        "verdict_hint": ("error-spike" if onset else "latency-regression" if lat
                         else "steady-errors" if problems else "no-problem-signal"),
    })
    return report


def to_markdown(r):
    L = ["# Log Detective - evidence summary", ""]
    if r.get("verdict_hint") == "no-data":
        L += ["**No timestamped log records could be read from the inputs.**", ""]
    else:
        w = r["window"]
        L += [f"_Window {w['start']} → {w['end']} · {r['records']} records · {r['problems']} problem records "
              f"({r['problem_rate']:.1%}) · bucket {w['bucket_minutes']} min_", ""]
        hint = {"error-spike": "An error spike starts in the bucket at **{onset}** (first new error: **{first}**).",
                "latency-regression": "No error spike, but latency regressed (from about **{lat}**).",
                "steady-errors": "Errors are present but steady - no clear start point in this window.",
                "no-problem-signal": "**No error or failure signal found** in the supplied logs. Widen the time "
                                     "window or add request/dependency tables before concluding."}[r["verdict_hint"]]
        L += [hint.format(onset=r.get("onset"), lat=r.get("latency_onset"), first=r.get("first_new_error")), ""]
        if r.get("deploy_correlation"):
            d = r["deploy_correlation"]
            L += [f"**Change just before:** `{d['id']}` at {d['time']} - {d['description']} "
                  f"({d['minutes_before_onset']} min before onset; {d['strength']} timing correlation, not proof).", ""]
        elif r.get("deploys_considered"):
            L += ["No deployment in the 24 h before the onset - consider infrastructure, dependencies, data or traffic.", ""]
        if r["signatures"]:
            L += ["## Top problem signatures", "", "| # | Count | First seen | New at onset | Signature |",
                  "|---|---:|---|---|---|"]
            for i, s in enumerate(r["signatures"][:10], 1):
                L.append(f"| {i} | {s['count']} | {s['first_seen']} | {'yes' if s['new_at_onset'] else ''} | "
                         f"`{s['signature'][:110]}` |")
        if r.get("latency_regressions"):
            L += ["", "## Latency regressions (p95)", "", "| Operation | Before | After | × |", "|---|---:|---:|---:|"]
            L += [f"| `{x['operation']}` | {x['p95_before_ms']} ms | {x['p95_after_ms']} ms | {x['factor']} |"
                  for x in r["latency_regressions"]]
        if r.get("code_candidates"):
            L += ["", "## Code locations from stack traces", ""]
            L += [f"- `{c['file']}:{c['line']}` in `{c['function']}`" for c in r["code_candidates"]]
    if r.get("redactions"):
        L += ["", "_Redacted before analysis: " + ", ".join(f"{k} ×{v}" for k, v in r["redactions"].items()) + "._"]
    if r.get("skipped"):
        L += ["", "## Files not used", ""] + [f"- `{s['file']}`: {s['reason']}" for s in r["skipped"]]
    L += ["", "---", "Evidence only. Confirm the cause against the code before fixing."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarise exported logs into incident evidence.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--deploys", help="git log --format='%%H|%%cI|%%s' output, or JSON list of deployments")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-dir")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    rep = analyse(a.paths, a.deploys)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "log-detective.json").write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
        Path(a.out_dir, "log-detective.md").write_text(to_markdown(rep), encoding="utf-8")
        print(f"wrote {a.out_dir}/log-detective.md and .json ({rep.get('verdict_hint')})")
    else:
        sys.stdout.write(json.dumps(rep, indent=2, default=str) + "\n" if a.json else to_markdown(rep))
    return 0 if rep["records"] else 1


if __name__ == "__main__":
    sys.exit(main())

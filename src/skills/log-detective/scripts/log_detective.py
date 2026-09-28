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
  Portal CSV       Azure portal Logs blade > Export > CSV (App Insights / Log Analytics)
  Plain text       any .log/.txt (multi-line stack traces are joined to their line)

What changed in the cloud (auto-detected among the inputs, never counted as log records):
  Azure Activity Log   az monitor activity-log list --offset 24h -o json   (incl. Service Health)
  AWS CloudTrail       aws cloudtrail lookup-events ... -o json
  AWS Health           aws health describe-events ... -o json

All message text is redacted (scripts/redact.py) before analysis and output. Caller identities
in change records are pseudonymised; user / client ids are only ever counted, never output.

Usage:
  python log_detective.py incident-logs/ [--deploys deploys.txt] [--out-dir report] [--json]
         [--baseline last-week/ ...] [--changes activity-log.json ...] [--change-window-hours 24]
         [--postmortem]
  --deploys: `git log --since=... --format="%H|%cI|%s"` output, or JSON [{"time","id","description"}]
  --baseline: the same kinds of exports for a comparable earlier window (e.g. same hours last week)
  --postmortem: also write postmortem-draft.md next to the report (see postmortem.py)
Nothing is ever changed in the cloud: alert rules are proposed as text for a human to apply.
Standard library only; Python 3.8+.
"""
import argparse
import csv
import io
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import Redactor  # noqa: E402
import alert_rules  # noqa: E402
import infra_changes  # noqa: E402
import postmortem  # noqa: E402

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
# Identity columns for blast radius. Values are hashed in memory and only COUNTED, never output.
F_USER = ["user_authenticatedid", "userauthenticatedid", "authenticateduserid", "user_id", "userid",
          "user_accountid", "enduserid", "customer_id", "customerid", "account_id", "accountid"]
F_CLIENT = ["client_ip", "clientip", "client_address", "sourceipaddress", "remote_addr", "remoteaddr",
            "remoteip", "x_forwarded_for", "ip"]
F_TENANT = ["tenant_id", "tenantid", "tenant", "org_id", "orgid", "organization_id", "organizationid"]
NESTED_DIMS = ("customdimensions", "properties", "labels", "httprequest")
# The same identity fields written inside message text (JSON lines, key=value logs) are masked
# before the text is kept, so samples and headlines never carry user / client / tenant ids.
ID_IN_TEXT = re.compile(r"(?i)\b(user_?authenticated_?id|authenticated_?user_?id|end_?user_?id|user_?id|"
                        r"customer_?id|account_?id|tenant_?id|org_?id|client_?ip|remote_?addr|source_?ip(?:_?address)?)"
                        r"(\\?[\"']?\s*[:=]\s*\\?[\"']?)(?!<)([^\s\"',;&}\\]+)")
MASKED_IPS = {"0.0.0.0", "", "::"}

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
        dt = None
        raw = re.sub(r"(\.\d{6})\d+", r"\1", str(v).strip())
        for fmt in ("%m/%d/%Y, %I:%M:%S.%f %p", "%m/%d/%Y, %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p",
                    "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        if dt is None:
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


def identity_keys(d):
    """(user, client, tenant) as in-memory hashes, from top-level columns or customDimensions /
    Properties. Only distinct counts are ever reported; the values themselves are dropped here."""
    look = {}
    for key in NESTED_DIMS:
        v = d.get(key)
        if isinstance(v, str) and v.strip().startswith("{"):
            try:
                v = json.loads(v)
            except ValueError:
                v = None
        if isinstance(v, dict):
            for k2, v2 in v.items():
                look.setdefault(str(k2).lower(), v2)
    look.update(d)

    def first(names, tag, skip=()):
        for n in names:
            v = look.get(n)
            if v not in (None, "") and not isinstance(v, (dict, list)) and str(v).strip() not in skip:
                return hash((tag, str(v).strip().lower()))
        return None
    return first(F_USER, "u"), first(F_CLIENT, "c", MASKED_IPS), first(F_TENANT, "t")


def mask_ids(text, redactor):
    def repl(m):
        redactor.counts["identifier"] = redactor.counts.get("identifier", 0) + 1
        return m.group(1) + m.group(2) + "<id>"
    return ID_IN_TEXT.sub(repl, text)


def normalise(row, source, redactor):
    d = lower_map(row)
    msg = pick(d, F_MSG)
    json_keys = None
    # Structured JSON inside the message (common in CloudWatch / container logs)
    if isinstance(msg, str) and msg.strip().startswith("{"):
        try:
            raw_inner = json.loads(msg)
            inner = lower_map(raw_inner)
            json_keys = {str(k).lower(): str(k) for k in raw_inner}
            d = {**inner, **{k: v for k, v in d.items() if k not in ("message", "@message")}}
            msg = pick(inner, F_MSG) or msg
        except (ValueError, AttributeError):
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
        "message": redactor.redact(mask_ids(text, redactor))[:4000],
        "stack": redactor.redact(mask_ids(stack, redactor))[:8000],
        "schema": "workspace" if "timegenerated" in d else "classic",
        "json_keys": json_keys,
    }
    rec["_user"], rec["_client"], rec["_tenant"] = identity_keys(d)
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
            yield from sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".json", ".log", ".txt", ".jsonl", ".csv"))
        elif p.exists():
            yield p


def load_inputs(paths, red, exclude):
    """Read every supported file. Control-plane exports (Activity Log, CloudTrail, Health) are
    recognised by shape and set aside: they describe changes, not application behaviour."""
    records, inputs, skipped, change_files = [], [], [], []
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
            kind = infra_changes.detect(data)
            if kind:
                change_files.append({"file": str(f), "kind": kind, "data": data})
                continue
            for row, src in rows_from_json(data):
                records.append(normalise(row, src, red))
        elif f.suffix.lower() == ".csv":
            # Azure portal exports label columns like "timestamp [UTC]"; drop the bracketed suffix.
            for row in csv.DictReader(io.StringIO(raw)):
                clean = {re.sub(r"\s*\[[^\]]*\]\s*$", "", k or "").strip(): v for k, v in row.items()}
                records.append(normalise(clean, "csv-export", red))
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
    return records, inputs, skipped, change_files


# ------------------------------------------------------------------ change records (infrastructure)
STRONG = timedelta(hours=2)


def _change_out(c, anchor):
    o = {"time": c["time"].isoformat(), "platform": c["platform"], "operation": c["operation"],
         "description": c["description"], "category": c.get("category"), "resource": c["resource"]}
    if c["platform"] == "azure":
        o.update({"resource_type": c.get("resource_type"), "resource_group": c.get("resource_group")})
    else:
        o.update({"service": c.get("service"), "region": c.get("region")})
    o["caller"] = c["caller"]
    o["minutes_before_onset"] = round((anchor - c["time"]).total_seconds() / 60) if anchor else None
    return o


def change_section(changes, reads, health, anchor, window_hours):
    win = timedelta(hours=window_hours)
    if anchor:
        before = [c for c in changes if anchor - win <= c["time"] <= anchor + timedelta(minutes=1)]
        after = [c for c in changes if c["time"] > anchor + timedelta(minutes=1)]
        reads_in = [c for c in reads if anchor - win <= c["time"] <= anchor + timedelta(minutes=1)]
    else:
        before, after, reads_in = list(changes), [], list(reads)
    correlation = None
    if anchor and before:
        strong = [c for c in before if anchor - c["time"] <= STRONG]
        pool = strong or before
        # Most relevant: highest-impact kind of change, then the one closest to the onset.
        best = max(pool, key=lambda c: (c["priority"], c["time"]))
        correlation = _change_out(best, anchor)
        correlation["strength"] = "strong" if anchor - best["time"] <= STRONG else "weak"
        correlation["other_changes_in_window"] = len(before) - 1
    after_out = []
    for c in after[:20]:
        o = _change_out(c, anchor)
        o["minutes_after_onset"] = -o.pop("minutes_before_onset")
        after_out.append(o)
    hl, seen = [], set()
    for h in health:
        key = (h["provider"], h.get("tracking_id") or h["title"], h.get("resource"))
        if key in seen:
            continue
        seen.add(key)
        hl.append({"time": h["time"].isoformat(), "provider": h["provider"], "title": h["title"],
                   "service": h.get("service"), "regions": h.get("regions") or [], "type": h.get("type"),
                   "stage": h.get("stage"), "tracking_id": h.get("tracking_id"), "resource": h.get("resource"),
                   "minutes_before_onset": round((anchor - h["time"]).total_seconds() / 60) if anchor else None,
                   "summary": infra_changes.health_summary(h)})
    return {
        "infra_changes": [_change_out(c, anchor) for c in before][-50:],
        "infra_changes_after_onset": after_out,
        "infra_correlation": correlation,
        "secret_reads_noted": [{k: v for k, v in _change_out(c, anchor).items() if k != "category"}
                               for c in reads_in][-20:],
        "service_health": hl,
        "change_window_hours": window_hours,
    }


# ------------------------------------------------------------------ blast radius
def blast_radius(records, problems, scope_start):
    """Who and what is affected, as COUNTS. Identifiers were hashed at load time and are never output."""
    probs = [r for r in problems if r["ts"] >= scope_start]
    if not probs:
        return None
    scope = [r for r in records if r["ts"] >= scope_start]
    ops = {}
    for r in probs:
        if r["op"]:
            ops[r["op"]] = ops.get(r["op"], 0) + 1
    total, failed = {}, {}
    for r in scope:
        if r["kind"] == "request" and r["op"]:
            total[r["op"]] = total.get(r["op"], 0) + 1
            if r["problem"]:
                failed[r["op"]] = failed.get(r["op"], 0) + 1
    items = []
    for op, n in sorted(ops.items(), key=lambda kv: (-kv[1], kv[0])):
        t = total.get(op, 0)
        items.append({"operation": op, "problem_records": n, "failed_requests": failed.get(op, 0),
                      "total_requests": t, "failure_share": round(failed.get(op, 0) / t, 4) if t else None})
    roles = sorted({str(r["role"]) for r in probs if r["role"]})

    def distinct(key):
        seen = {r[key] for r in scope if r[key] is not None}
        if not seen:
            return None
        hit = {r[key] for r in probs if r[key] is not None}
        return {"affected": len(hit), "seen": len(seen), "share": round(len(hit) / len(seen), 4)}

    req_scope = sum(total.values())
    return {
        "scope_start": scope_start.isoformat(),
        "problem_records": len(probs),
        "operations": {"count": len(ops), "items": items[:10]},
        "roles": {"count": len(roles), "names": roles[:10]},
        "users": distinct("_user"),
        "clients": distinct("_client"),
        "tenants": distinct("_tenant"),
        "requests_in_scope": req_scope,
        "failed_request_share": round(sum(failed.values()) / req_scope, 4) if req_scope else None,
        "identifiers_output": False,
        "note": "Distinct counts only; user, client and tenant identifiers are never written out.",
    }


# ------------------------------------------------------------------ baseline
def hours_between(a, b):
    return max((b - a).total_seconds() / 3600, 1 / 60)


def baseline_section(bl, sig_list, records, problems, onset, start, end, step):
    base = {"inputs": bl["inputs"], "skipped": bl["skipped"], "ignored_change_exports": bl["ignored"]}
    recs = bl["records"]
    if not recs:
        base.update({"records": 0, "assessment": "no-baseline-data",
                     "assessment_text": "No timestamped records in the baseline exports; no comparison made."})
        return base
    b_start, b_end = recs[0]["ts"], recs[-1]["ts"]
    b_probs = [r for r in recs if r["problem"]]
    b_hours, c_hours = hours_between(b_start, b_end), hours_between(start, end)
    b_counts = {}
    for r in b_probs:
        k = signature(r)
        b_counts[k] = b_counts.get(k, 0) + 1
    b_rate = len(b_probs) / len(recs)
    c_rate = len(problems) / len(records)
    ratio = round(c_rate / b_rate, 2) if b_rate else None
    b_onset, _ = find_onset(b_probs, b_start, b_end, step)
    same_pattern = bool(onset and b_onset and abs((b_onset - floor_to(b_start, step)) - (onset - floor_to(start, step)))
                        <= 2 * step)
    rows = []
    for s in sig_list:
        bc = b_counts.get(s["signature"], 0)
        cur_h, base_h = round(s["count"] / c_hours, 2), round(bc / b_hours, 2)
        s["in_baseline"] = bc > 0
        s["baseline_count"] = bc
        s["baseline_per_hour"] = base_h
        s["current_per_hour"] = cur_h
        s["rate_vs_baseline"] = round(cur_h / base_h, 2) if base_h else None
        rows.append({"signature": s["signature"], "current_count": s["count"], "baseline_count": bc,
                     "current_per_hour": cur_h, "baseline_per_hour": base_h, "in_baseline": bc > 0,
                     "rate_vs_baseline": s["rate_vs_baseline"], "new_at_onset": s["new_at_onset"]})
    new_not_in_base = [s for s in sig_list if s["new_at_onset"] and not s["in_baseline"] and s["count"] >= 5]
    elevated = [s for s in sig_list if s["new_at_onset"] and s["in_baseline"] and (s["rate_vs_baseline"] or 0) >= 3]
    top = sig_list[:5]
    similar = all(s["in_baseline"] and (s["rate_vs_baseline"] or 0) <= 2 for s in top)
    pct = lambda x: "%.1f%%" % (100 * x)  # noqa: E731
    rate_txt = "problem rate %s now vs %s in the baseline window" % (pct(c_rate), pct(b_rate))
    if not problems:
        assessment, text = "no-problems", "No problem records in the current window."
    elif new_not_in_base:
        assessment = "new-problem"
        text = ("%d signature(s) that start at the onset never appear in the baseline window (e.g. `%s`); "
                "this is not normal noise. %s." % (len(new_not_in_base), new_not_in_base[0]["signature"][:90],
                                                   rate_txt[0].upper() + rate_txt[1:]))
    elif ratio is None:
        assessment, text = "new-problem", "The baseline window had no problem records at all; %s." % rate_txt
    elif ratio >= 3 or elevated:
        assessment = "above-baseline"
        text = "Problems are well above the baseline: %s (x%s)." % (rate_txt, ratio)
    elif ratio <= 1.5 and similar:
        assessment = "matches-baseline"
        text = ("Likely normal noise, not an incident: %s (x%s) and the top signatures also appear there at a "
                "similar rate%s." % (rate_txt, ratio, ", with the same spike at the same point in the window"
                                     if same_pattern else ""))
    else:
        assessment = "somewhat-elevated"
        text = "Somewhat above the baseline: %s (x%s); check the signatures that grew." % (rate_txt, ratio)
    base.update({
        "window": {"start": b_start.isoformat(), "end": b_end.isoformat()},
        "records": len(recs), "problems": len(b_probs),
        "problem_rate": round(b_rate, 4), "current_problem_rate": round(c_rate, 4), "rate_ratio": ratio,
        "problems_per_hour": round(len(b_probs) / b_hours, 2),
        "current_problems_per_hour": round(len(problems) / c_hours, 2),
        "onset_in_baseline": b_onset.isoformat() if b_onset else None,
        "same_pattern_in_baseline": same_pattern,
        "signatures": rows[:10],
        "assessment": assessment, "assessment_text": text,
    })
    return base


# ------------------------------------------------------------------ alert suggestion
FIVE = timedelta(minutes=5)


def five_minute_counts(recs, pred, a, b, inclusive=True):
    base = floor_to(a, FIVE)
    stop = floor_to(b, FIVE)
    n = int((stop - base) / FIVE) + (1 if inclusive else 0)
    if n <= 0:
        return base, []
    counts = [0] * n
    for r in recs:
        if r["ts"] < base or not pred(r):
            continue
        i = int((floor_to(r["ts"], FIVE) - base) / FIVE)
        if 0 <= i < n:
            counts[i] += 1
    return base, counts


def alert_section(sig_list, samples, records, onset, start, end, bl_records):
    cands = [s for s in sig_list if s["new_at_onset"]
             and (not s.get("in_baseline") or (s.get("rate_vs_baseline") or 0) >= 3)]
    if not cands:
        reason = ("no signature is new at the onset" if not any(s["new_at_onset"] for s in sig_list)
                  else "the signatures new at the onset also occur in the baseline at a similar rate (normal noise)")
        return {"status": "not-suggested", "reason": reason}
    s = cands[0]
    rec = samples[s["signature"]]
    sample = {k: rec.get(k) for k in ("kind", "type", "op", "status", "target", "source", "schema", "json_keys")}
    sample["headline"] = s["headline"]
    sample["role"] = s["roles"][0] if len(s["roles"]) == 1 else None
    # The predicate mirrors what the proposed query counts, so the threshold is computed on the same thing.
    pred = alert_rules.matcher(dict(rec, headline=s["headline"]), signature)
    if bl_records:
        _, normal = five_minute_counts(bl_records, pred, bl_records[0]["ts"], bl_records[-1]["ts"])
        source = "baseline"
    else:
        _, normal = five_minute_counts(records, pred, start, onset, inclusive=False)
        source = "pre-onset"
    p95 = percentile(normal, 95) or 0
    thr = alert_rules.threshold(p95)
    inc_base, inc = five_minute_counts(records, pred, onset, end)
    fire = next((i for i, c in enumerate(inc) if c > thr), None)
    fire_at = inc_base + (fire + 1) * FIVE if fire is not None else None
    basis = {"source": source, "rule": "max(5, 3 x p95 of the 5-minute counts)", "p95_5min_count": p95,
             "normal_buckets": len(normal), "threshold": thr, "incident_peak_5min_count": max(inc) if inc else 0,
             "would_have_fired_at": fire_at.isoformat() if fire_at else None,
             "minutes_after_onset": round((fire_at - onset).total_seconds() / 60) if fire_at else None}
    out = alert_rules.build(s, sample, sample.get("schema") or "classic", basis)
    if fire_at is None:
        # Never present a rule as useful if it would have stayed silent through this very incident.
        out["warning"] = ("With this threshold the rule would NOT have fired during this incident (peak %d per "
                          "5 minutes, threshold %d). Narrow the query or lower the threshold before using it."
                          % (basis["incident_peak_5min_count"], thr))
    return out


# ------------------------------------------------------------------ timeline
def build_timeline(r, deploys, changes, anchor, window_hours, step, counts, start, end, last_problem):
    ev = []

    def add(t, order, text):
        if t is not None:
            ev.append((t, order, text))

    win = timedelta(hours=window_hours)
    if anchor:
        in_win = [(d["time"], "Code deployment `%s` (%s)" % (d["id"], d["description"]))
                  for d in deploys if anchor - win <= d["time"] <= anchor + timedelta(minutes=1)]
        in_win += [(c["time"], "%s on `%s` (`%s`)" % (c["description"], c["resource"], c["operation"]))
                   for c in changes if anchor - win <= c["time"] <= anchor + timedelta(minutes=1)]
        in_win.sort(key=lambda x: (x[0], x[1]))
        if in_win:
            add(in_win[0][0], 0, "Earliest recorded change in the %g h before onset: %s" % (window_hours, in_win[0][1]))
    d = r.get("deploy_correlation")
    if d:
        add(parse_ts(d["time"]), 1, "Code deployment `%s` (%s), correlated by timing" % (d["id"], d["description"]))
    ic = r.get("infra_correlation")
    if ic:
        add(parse_ts(ic["time"]), 1, "%s on `%s` (`%s`), correlated by timing" % (ic["description"], ic["resource"],
                                                                              ic["operation"]))
    for h in r.get("service_health") or []:
        add(parse_ts(h["time"]), 2, "Platform event: %s" % h["summary"])
    if r.get("onset"):
        add(parse_ts(r["onset"]), 3, "Problem rate jumps (start of the onset bucket, %d-min buckets)"
            % int(step.total_seconds() // 60))
    if r.get("latency_onset"):
        op = r["latency_regressions"][0]["operation"] if r.get("latency_regressions") else "?"
        add(parse_ts(r["latency_onset"]), 3, "Latency regression starts on `%s`" % op)
    new = [s for s in r["signatures"] if s["new_at_onset"]]
    if new:
        add(parse_ts(new[0]["first_seen"]), 4, "First new error: `%s`" % new[0]["signature"][:120])
    al = r.get("alert_suggestion") or {}
    if al.get("status") == "suggested" and al["threshold_basis"].get("would_have_fired_at"):
        add(parse_ts(al["threshold_basis"]["would_have_fired_at"]), 5,
            "The proposed alert `%s` would have fired (%s)" % (al["name"], al["condition"]))
    if counts and max(counts) > 0:
        i = counts.index(max(counts))
        add(floor_to(start, step) + i * step, 6, "Peak: %d problem records in one %d-min bucket"
            % (counts[i], int(step.total_seconds() // 60)))
    for c in (r.get("infra_changes_after_onset") or [])[:5]:
        add(parse_ts(c["time"]), 7, "%s on `%s` (`%s`) after the onset (possibly a mitigation step)"
            % (c["description"], c["resource"], c["operation"]))
    if new:
        add(parse_ts(new[0]["last_seen"]), 8, "Last occurrence of `%s` in the data" % new[0]["signature"][:120])
    elif last_problem:
        add(last_problem, 8, "Last problem record in the data")
    add(end, 9, "End of the log data window")
    seen, out = set(), []
    for t, o, text in sorted(ev, key=lambda x: (x[0], x[1], x[2])):
        if (t, text) in seen:
            continue
        seen.add((t, text))
        out.append({"time": t.isoformat(), "event": text})
    return out


# ------------------------------------------------------------------ main analysis
def _read_changes(paths, exclude, change_files, skipped):
    known = {Path(c["file"]).resolve() for c in change_files}
    for f in iter_files(paths):
        if f.resolve() in exclude or f.resolve() in known:
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig", errors="replace"))
        except ValueError as e:
            skipped.append({"file": str(f), "reason": f"invalid JSON ({e})"})
            continue
        kind = infra_changes.detect(data)
        if kind:
            change_files.append({"file": str(f), "kind": kind, "data": data})
            known.add(f.resolve())
        else:
            skipped.append({"file": str(f), "reason": "not a recognised Activity Log / CloudTrail / Health export"})


def analyse(paths, deploys_path=None, baseline_paths=None, change_paths=None, change_window_hours=24):
    red = Redactor()
    exclude = {Path(deploys_path).resolve()} if deploys_path else set()
    baseline_paths = list(baseline_paths or [])
    baseline_files = {f.resolve() for f in iter_files(baseline_paths)}
    records, inputs, skipped, change_files = load_inputs(paths, red, exclude | baseline_files)
    _read_changes(change_paths or [], exclude | baseline_files, change_files, skipped)
    deploys = []
    if deploys_path:
        try:
            ddata = json.loads(Path(deploys_path).read_text(encoding="utf-8-sig", errors="replace"))
        except ValueError:
            ddata = None
        dkind = infra_changes.detect(ddata) if ddata is not None else None
        if dkind:
            change_files.append({"file": str(deploys_path), "kind": dkind, "data": ddata})
        else:
            deploys = load_deploys(deploys_path)

    no_ts = sum(1 for r in records if r["ts"] is None)
    records = [r for r in records if r["ts"] is not None]
    records.sort(key=lambda r: r["ts"])

    changes, reads, health, change_inputs = [], [], [], []
    for c in change_files:
        ch, rd, hl, st = infra_changes.parse(c["data"], c["kind"], red, parse_ts)
        change_inputs.append({"file": c["file"], "kind": c["kind"], "events": st["events"], "changes": len(ch),
                              "secret_reads": len(rd), "platform_events": len(hl)})
        changes += ch
        reads += rd
        health += hl
    order = lambda x: (x["time"], str(x.get("operation") or x.get("title")), str(x.get("resource")))  # noqa: E731
    changes.sort(key=order)
    reads.sort(key=order)
    health.sort(key=order)

    bl = None
    if baseline_paths:
        b_recs, b_inputs, b_skipped, b_changes = load_inputs(baseline_paths, red, exclude)
        b_recs = sorted((r for r in b_recs if r["ts"] is not None), key=lambda r: r["ts"])
        bl = {"records": b_recs, "inputs": b_inputs, "skipped": b_skipped, "ignored": len(b_changes)}

    report = {"inputs": inputs, "skipped": skipped, "records": len(records), "records_without_time": no_ts,
              "redactions": {}}
    if not records:
        report.update({"verdict_hint": "no-data", "problems": 0, "signatures": []})
        report.update(change_section(changes, reads, health, None, change_window_hours))
        report.update({"change_inputs": change_inputs, "baseline": None, "blast_radius": None,
                       "alert_suggestion": None, "peak": None, "timeline_events": []})
        report["redactions"] = dict(sorted(red.counts.items()))
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
                                           "op_ids": [], "frames": [], "type": r["type"], "sample_rec": r})
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
    samples = {text: s["sample_rec"] for text, s in sigs.items()}

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

    top_sigs = sig_list[:15]
    baseline = baseline_section(bl, top_sigs, records, problems, onset, start, end, step) if bl is not None else None
    peak = None
    if counts and max(counts) > 0:
        i = counts.index(max(counts))
        peak = {"time": (floor_to(start, step) + i * step).isoformat(), "count": counts[i],
                "bucket_minutes": int(step.total_seconds() // 60)}
    scope_start = (onset - step) if onset else start

    report.update({
        "window": {"start": start.isoformat(), "end": end.isoformat(), "bucket_minutes": int(step.total_seconds() // 60)},
        "problems": len(problems),
        "problem_rate": round(len(problems) / len(records), 4),
        "onset": onset.isoformat() if onset else None,
        "first_new_error": first_new,
        "latency_onset": onset_latency.isoformat() if onset_latency else None,
        "timeline_counts": counts,
        "signatures": top_sigs,
        "latency_regressions": lat[:10],
        "deploy_correlation": correlated,
        "deploys_considered": len(deploys),
        "code_candidates": list(all_frames.values())[:10],
        "verdict_hint": ("error-spike" if onset else "latency-regression" if lat
                         else "steady-errors" if problems else "no-problem-signal"),
    })
    report.update(change_section(changes, reads, health, anchor, change_window_hours))
    report["change_inputs"] = change_inputs
    report["baseline"] = baseline
    report["blast_radius"] = blast_radius(records, problems, scope_start)
    report["alert_suggestion"] = (alert_section(top_sigs, samples, records, onset, start, end,
                                                bl["records"] if bl else None) if onset else
                                  {"status": "not-suggested", "reason": "no error spike with a clear onset"})
    report["peak"] = peak
    report["timeline_events"] = build_timeline(report, deploys, changes, anchor, change_window_hours, step, counts,
                                               start, end, problems[-1]["ts"] if problems else None)
    report["redactions"] = dict(sorted(red.counts.items()))
    return report


# ------------------------------------------------------------------ markdown
def _md_change_line(c):
    who = " by %s" % c["caller"] if c.get("caller") else ""
    return "%s on `%s` (`%s`) at %s%s" % (c["description"], c["resource"], c["operation"], c["time"], who)


def to_markdown(r):
    L = ["# Log Detective - evidence summary", ""]
    for h in r.get("service_health") or []:
        L += ["**Platform event reported (%s, %s):** %s. Check this before debugging code." % (
            h["provider"], h["time"], h["summary"]), ""]
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
        b = r.get("baseline")
        if b and b.get("assessment"):
            L += ["**Baseline:** " + b["assessment_text"], ""]
        if r.get("deploy_correlation"):
            d = r["deploy_correlation"]
            L += [f"**Change just before:** `{d['id']}` at {d['time']} - {d['description']} "
                  f"({d['minutes_before_onset']} min before onset; {d['strength']} timing correlation, not proof).", ""]
        elif r.get("deploys_considered"):
            if r.get("infra_correlation"):
                L += ["No deployment in the 24 h before the onset, but an infrastructure change was recorded (below).", ""]
            else:
                L += ["No deployment in the 24 h before the onset - consider infrastructure, dependencies, data or traffic.", ""]
        if r.get("infra_correlation"):
            c = r["infra_correlation"]
            L += ["**Infrastructure change just before:** %s (%d min before onset; %s timing correlation, not proof)."
                  % (_md_change_line(c), c["minutes_before_onset"], c["strength"]), ""]
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
    L += _md_extras(r)
    if r.get("redactions"):
        L += ["", "_Redacted before analysis: " + ", ".join(f"{k} ×{v}" for k, v in r["redactions"].items()) + "._"]
    if r.get("skipped"):
        L += ["", "## Files not used", ""] + [f"- `{s['file']}`: {s['reason']}" for s in r["skipped"]]
    L += ["", "---", "Evidence only. Confirm the cause against the code before fixing."]
    return "\n".join(L) + "\n"


def _md_extras(r):
    L = []
    if r.get("infra_changes") or r.get("infra_changes_after_onset") or r.get("change_inputs"):
        L += ["", "## Infrastructure changes (%g h before the onset)" % r.get("change_window_hours", 24), ""]
        if r.get("infra_changes"):
            L += ["| Time | Min before | Change | Resource | Operation | Caller |", "|---|---:|---|---|---|---|"]
            for c in r["infra_changes"][-15:]:
                mb = "" if c["minutes_before_onset"] is None else c["minutes_before_onset"]
                L.append("| %s | %s | %s | `%s` | `%s` | %s |" % (c["time"], mb, c["description"], c["resource"],
                                                                  c["operation"], c["caller"] or ""))
        else:
            L.append("No successful infrastructure change recorded in this window.")
        for c in r.get("infra_changes_after_onset") or []:
            L.append("- After the onset (+%d min): %s" % (c["minutes_after_onset"], _md_change_line(c)))
        if r.get("secret_reads_noted"):
            L += ["", "_Not changes, noted only: %d key / secret listing operation(s) in the window._"
                  % len(r["secret_reads_noted"])]
    b = r.get("baseline")
    if b and b.get("signatures"):
        L += ["", "## Compared with baseline", "",
              "Baseline window %s → %s: %d records, %d problems (%.1f%%); now %.1f%% (ratio %s)."
              % (b["window"]["start"], b["window"]["end"], b["records"], b["problems"], 100 * b["problem_rate"],
                 100 * b["current_problem_rate"], b["rate_ratio"] if b["rate_ratio"] is not None else "n/a"), "",
              "| Signature | Now /h | Baseline /h | Also in baseline |", "|---|---:|---:|---|"]
        for s in b["signatures"][:8]:
            L.append("| `%s` | %s | %s | %s |" % (s["signature"][:90], s["current_per_hour"], s["baseline_per_hour"],
                                                 "yes" if s["in_baseline"] else "**no**"))
    br = r.get("blast_radius")
    if br:
        L += ["", "## Blast radius (since %s)" % br["scope_start"], ""]
        L.append("- %d problem records across %d operation(s) and %d service(s)/role(s)"
                 % (br["problem_records"], br["operations"]["count"], br["roles"]["count"]))
        for o in br["operations"]["items"][:5]:
            share = ("%.1f%% of %d requests failed" % (100 * o["failure_share"], o["total_requests"])
                     if o["total_requests"] else "%d problem records" % o["problem_records"])
            L.append("  - `%s`: %s" % (o["operation"], share))
        for key, noun in (("users", "users"), ("clients", "client addresses"), ("tenants", "tenants")):
            v = br.get(key)
            if v:
                L.append("- %d of %d %s seen in this period were affected (%.1f%%)"
                         % (v["affected"], v["seen"], noun, 100 * v["share"]))
        L.append("- _Counts only; identifiers are never written out._")
    a = r.get("alert_suggestion")
    if a and a.get("status") == "suggested":
        tb = a["threshold_basis"]
        L += ["", "## Proposed alert (not applied - a human reviews and applies it)", "",
              "For `%s`: fire when %s. Threshold %d = max(5, 3 x %s), where %s is the p95 of 5-minute counts in "
              "the %s data%s." % (a["signature"][:100], a["condition"], a["threshold"], tb["p95_5min_count"],
                                   tb["p95_5min_count"], tb["source"],
                                   "; during this incident it would have fired at %s" % tb["would_have_fired_at"]
                                   if tb.get("would_have_fired_at") else "")]
        if a.get("warning"):
            L += ["", "**Warning:** " + a["warning"]]
        for key, lang in (("kql", "kusto"), ("az_cli", "bash"), ("bicep", "bicep"), ("aws_cli", "bash"),
                          ("gcloud_cli", "bash")):
            if a.get(key):
                L += ["", "```" + lang, a[key], "```"]
        if a.get("pattern"):
            L += ["", "Pattern: `%s`. %s" % (a["pattern"], a["note"])]
    elif a and a.get("status") == "not-suggested" and r.get("onset"):
        L += ["", "_No alert proposed: %s._" % a["reason"]]
    return L


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarise exported logs into incident evidence.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--deploys", help="git log --format='%%H|%%cI|%%s' output, or JSON list of deployments")
    ap.add_argument("--baseline", nargs="+", help="exports for a comparable earlier window (e.g. same hours last week)")
    ap.add_argument("--changes", nargs="+", help="Activity Log / CloudTrail / Health exports kept outside the log folder")
    ap.add_argument("--change-window-hours", type=float, default=24.0,
                    help="how far before the onset to look for infrastructure changes (default 24)")
    ap.add_argument("--postmortem", action="store_true", help="also write postmortem-draft.md next to the report")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-dir")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    rep = analyse(a.paths, a.deploys, a.baseline, a.changes, a.change_window_hours)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "log-detective.json").write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
        Path(a.out_dir, "log-detective.md").write_text(to_markdown(rep), encoding="utf-8")
        print(f"wrote {a.out_dir}/log-detective.md and .json ({rep.get('verdict_hint')})")
    else:
        sys.stdout.write(json.dumps(rep, indent=2, default=str) + "\n" if a.json else to_markdown(rep))
    if a.postmortem:
        target = Path(a.out_dir or ".", "postmortem-draft.md")
        target.write_text(postmortem.render(json.loads(json.dumps(rep, default=str))), encoding="utf-8")
        sys.stderr.write(f"wrote {target}\n")
    return 0 if rep["records"] else 1


if __name__ == "__main__":
    sys.exit(main())

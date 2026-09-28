#!/usr/bin/env python3
"""alert_rules - turn the top NEW problem signature into a ready-to-review alert rule, as TEXT.

Nothing here talks to a cloud. The output is a proposal a human reviews and applies:
  Azure (App Insights / Log Analytics)  KQL + `az monitor scheduled-query create` + Bicep
  AWS CloudWatch                        metric filter + alarm (aws CLI)
  GCP Cloud Logging                     log-based metric (gcloud) + where to add the policy
  Anything else                         the pattern and threshold to use

log_detective.py decides the threshold from the data (baseline or pre-onset rate, see
threshold()) and calls build(). Standard library only; Python 3.8+.
"""
import re

FREQUENCY_MIN = 5

# Columns per table flavour: classic App Insights vs workspace-based (Log Analytics).
KQL = {
    "classic": {"exception": ("exceptions", "type", "outerMessage"),
                "request": ("requests", "success", "name", "resultCode"),
                "dependency": ("dependencies", "success", "target", "resultCode"),
                "log": ("traces", "severityLevel", "message"),
                "role": "cloud_RoleName"},
    "workspace": {"exception": ("AppExceptions", "ExceptionType", "OuterMessage"),
                  "request": ("AppRequests", "Success", "Name", "ResultCode"),
                  "dependency": ("AppDependencies", "Success", "Target", "ResultCode"),
                  "log": ("AppTraces", "SeverityLevel", "Message"),
                  "role": "AppRoleName"},
}
GENERIC_TYPES = {"exception", "system.exception", "error", "runtimeerror", "java.lang.exception",
                 "java.lang.runtimeexception"}
AZURE_SOURCES = {"app-insights", "log-analytics", "csv-export"}
CW_LOG_GROUP = re.compile(r"^\d{12}:(/?[\w./#-]+)$")


def ceil_int(x):
    n = int(x)
    return n if n == x else n + 1


def threshold(p95_count):
    """Fire when more than max(5, 3x the normal 5-minute p95) matching records arrive."""
    return max(5, ceil_int(3 * (p95_count or 0)))


def platform_of(sample):
    src = sample.get("source")
    if src in AZURE_SOURCES:
        return "azure"
    if src and src.startswith("cloudwatch"):
        return "aws-cloudwatch"
    if src == "gcp-logging":
        return "gcp"
    return "unknown"


def stable_term(headline, etype=None):
    """The constant part of a message, safe to search for: text up to the first variable
    part (number, quote, placeholder), without a dangling key= fragment."""
    s = (headline or "").strip()
    s = re.sub(r"^\W*(CRITICAL|FATAL|ERROR|ERR|WARN(?:ING)?)\W+", "", s, flags=re.I)
    if etype and s.startswith(etype):
        s = s[len(etype):].lstrip(": ")
    m = re.search(r"[0-9\"'<{\[(\\`]", s)
    if m:
        s = s[:m.start()]
    words = s.split()
    while words and ("=" in words[-1] or words[-1].endswith(":")):
        words.pop()
    s = " ".join(words).rstrip(" ,;:=(-")
    if len(s) > 80:
        s = s[:80].rsplit(" ", 1)[0]
    return s if len(s) >= 6 else None


def matcher(sample, signature_of):
    """Predicate over normalised records that mirrors what the proposed query counts,
    so the threshold is computed on the same thing the alert will count."""
    k = sample["kind"]
    if k == "exception" and sample.get("type") and sample["type"].lower() not in GENERIC_TYPES:
        t = sample["type"]
        # Narrow to the stable message text as well as the type, exactly like kql_for(): other
        # errors of the same type (background noise) must not inflate the threshold.
        term = stable_term(sample.get("headline"), t)
        if term:
            low = term.lower()
            return lambda r: (r["kind"] == "exception" and r["type"] == t
                              and low in ((r.get("message") or "") + " " + (r.get("headline") or "")).lower())
        return lambda r: r["kind"] == "exception" and r["type"] == t
    if k == "request" and sample.get("op"):
        op, st = sample["op"], sample.get("status")
        return lambda r: r["kind"] == "request" and r["problem"] and r["op"] == op and r["status"] == st
    if k == "dependency" and sample.get("target"):
        tg = sample["target"]
        return lambda r: r["kind"] == "dependency" and r["problem"] and r["target"] == tg
    sig = signature_of(sample)
    return lambda r: r["problem"] and signature_of(r) == sig


def _kq(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sh(s):
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def slug(text, n=40):
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:n].rstrip("-")) or "signature"


def kql_for(sample, schema):
    c = KQL[schema]
    k = sample["kind"]
    role = sample.get("role")
    lines = []
    if k == "exception":
        table, tcol, mcol = c["exception"]
        lines.append(table)
        if sample.get("type") and sample["type"].lower() not in GENERIC_TYPES:
            lines.append("| where %s == %s" % (tcol, _kq(sample["type"])))
            term = stable_term(sample.get("headline"), sample.get("type"))
            if term:
                lines.append("| where %s contains %s" % (mcol, _kq(term)))
        else:
            term = stable_term(sample.get("headline"), sample.get("type")) or sample.get("type") or "Exception"
            lines.append("| where %s contains %s" % (mcol, _kq(term)))
    elif k == "request":
        table, scol, ncol, rcol = c["request"]
        lines.append(table)
        cond = "%s == false and %s == %s" % (scol, ncol, _kq(sample["op"]))
        if sample.get("status"):
            cond += " and %s == %s" % (rcol, _kq(sample["status"]))
        lines.append("| where " + cond)
    elif k == "dependency":
        table, scol, tcol, _ = c["dependency"]
        lines.append(table)
        lines.append("| where %s == false and %s == %s" % (scol, tcol, _kq(sample.get("target") or "")))
    else:
        table, lcol, mcol = c["log"]
        lines.append(table)
        term = stable_term(sample.get("headline"), sample.get("type")) or "error"
        lines.append("| where %s >= 3 and %s contains %s" % (lcol, mcol, _kq(term)))
    if role:
        lines.append("| where %s == %s" % (c["role"], _kq(role)))
    return lines


def azure_texts(sample, schema, name, thr, sig_text):
    lines = kql_for(sample, schema)
    one_line = " ".join(lines)
    desc = "Proposed by log-detective after an incident: %s. Review before applying." % sig_text[:120]
    cli = "\n".join([
        "az monitor scheduled-query create \\",
        "  --name %s \\" % name,
        "  --resource-group <resource-group> \\",
        "  --scopes <app-insights-or-workspace-resource-id> \\",
        "  --condition \"count 'Failures' > %d\" \\" % thr,
        "  --condition-query Failures=%s \\" % _sh(one_line),
        "  --window-size %dm --evaluation-frequency %dm \\" % (FREQUENCY_MIN, FREQUENCY_MIN),
        "  --severity 2 \\",
        "  --action-groups <action-group-resource-id> \\",
        "  --description %s" % _sh(desc),
    ])
    bicep = "\n".join([
        "param appInsightsOrWorkspaceId string",
        "param actionGroupId string",
        "param location string = resourceGroup().location",
        "",
        "resource alert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {",
        "  name: '%s'" % name,
        "  location: location",
        "  properties: {",
        "    displayName: '%s'" % name,
        "    description: '%s'" % desc.replace("\\", "\\\\").replace("'", "\\'"),
        "    severity: 2",
        "    enabled: true",
        "    scopes: [ appInsightsOrWorkspaceId ]",
        "    evaluationFrequency: 'PT%dM'" % FREQUENCY_MIN,
        "    windowSize: 'PT%dM'" % FREQUENCY_MIN,
        "    criteria: {",
        "      allOf: [",
        "        {",
        "          query: '''",
    ] + ["            " + l for l in lines] + [
        "            '''",
        "          timeAggregation: 'Count'",
        "          operator: 'GreaterThan'",
        "          threshold: %d" % thr,
        "          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }",
        "        }",
        "      ]",
        "    }",
        "    actions: { actionGroups: [ actionGroupId ] }",
        "  }",
        "}",
    ])
    return {"kql": "\n".join(lines), "az_cli": cli, "bicep": bicep, "table": lines[0]}


def cloudwatch_texts(sample, name, thr):
    k = sample["kind"]
    keys = sample.get("json_keys") or {}
    pattern = None
    if k == "request" and keys:
        opk = next((keys[x] for x in ("path", "route", "url", "request_path", "operation_name", "name") if x in keys), None)
        stk = next((keys[x] for x in ("status", "statuscode", "status_code", "httpstatus") if x in keys), None)
        if opk and stk and sample.get("status") and str(sample["status"]).lstrip("-").isdigit():
            pattern = '{ ($.%s = %s) && ($.%s = "%s") }' % (stk, sample["status"], opk, sample["op"])
    if pattern is None:
        terms = []
        if sample.get("type") and sample["type"].lower() not in GENERIC_TYPES:
            terms.append(sample["type"])
        else:
            t = stable_term(sample.get("headline"), sample.get("type"))
            if t:
                terms.append(t)
        pattern = " ".join('"%s"' % t.replace('"', "") for t in terms) or '"ERROR"'
    m = CW_LOG_GROUP.match(str(sample.get("role") or ""))
    group = m.group(1) if m else "<log-group-name>"
    metric = re.sub(r"(^|-)(\w)", lambda x: x.group(2).upper(), name)
    cli = "\n".join([
        "aws logs put-metric-filter \\",
        "  --log-group-name %s \\" % group,
        "  --filter-name %s \\" % name,
        "  --filter-pattern %s \\" % _sh(pattern),
        "  --metric-transformations metricName=%s,metricNamespace=LogDetective,metricValue=1,defaultValue=0" % metric,
        "",
        "aws cloudwatch put-metric-alarm \\",
        "  --alarm-name %s \\" % name,
        "  --namespace LogDetective --metric-name %s \\" % metric,
        "  --statistic Sum --period %d --evaluation-periods 1 \\" % (FREQUENCY_MIN * 60),
        "  --threshold %d --comparison-operator GreaterThanThreshold \\" % thr,
        "  --treat-missing-data notBreaching \\",
        "  --alarm-actions <sns-topic-arn>",
    ])
    return {"filter_pattern": pattern, "log_group": group, "metric": "LogDetective/" + metric, "aws_cli": cli}


def gcp_texts(sample, name, thr):
    term = (sample.get("type") if sample.get("type") and sample["type"].lower() not in GENERIC_TYPES
            else stable_term(sample.get("headline"), sample.get("type"))) or "ERROR"
    filt = 'severity>=ERROR AND "%s"' % term.replace('"', "")
    cli = "\n".join([
        "gcloud logging metrics create %s \\" % name,
        "  --description=%s \\" % _sh("Proposed by log-detective; review before applying"),
        "  --log-filter=%s" % _sh(filt),
        "# Then add an alerting policy on logging.googleapis.com/user/%s:" % name,
        "#   aligner ALIGN_DELTA, period %d s, condition: above %d" % (FREQUENCY_MIN * 60, thr),
    ])
    return {"log_filter": filt, "gcloud_cli": cli}


def build(sig, sample, schema, basis):
    """sig: signature entry; sample: first normalised record of it; basis: threshold facts."""
    thr = basis["threshold"]
    name = "ld-" + slug(sig["signature"])
    platform = platform_of(sample)
    out = {"status": "suggested", "signature": sig["signature"], "platform": platform, "name": name,
           "frequency_minutes": FREQUENCY_MIN, "window_minutes": FREQUENCY_MIN, "threshold": thr,
           "condition": "more than %d matching records in %d minutes" % (thr, FREQUENCY_MIN),
           "threshold_basis": basis,
           "apply_note": "Proposal only. log-detective never creates alerts; a human reviews and applies it "
                         "(fill in the <placeholders>)."}
    if platform == "azure":
        out["schema"] = schema
        out.update(azure_texts(sample, schema, name, thr, sig["signature"]))
    elif platform == "aws-cloudwatch":
        out.update(cloudwatch_texts(sample, name, thr))
    elif platform == "gcp":
        out.update(gcp_texts(sample, name, thr))
    else:
        term = stable_term(sample.get("headline"), sample.get("type")) or sig["signature"][:80]
        out["pattern"] = term
        out["note"] = ("The log platform could not be identified from a plain file; create a log-based alert on "
                       "this pattern in the platform that stores these logs.")
    return out

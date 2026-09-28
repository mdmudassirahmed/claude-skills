#!/usr/bin/env python3
"""postmortem - draft a blameless postmortem from a log-detective report.

Facts (timeline, impact, evidence, the proposed alert) come from the report; everything
that needs judgement is left as an explicit [to be confirmed] placeholder for Claude or a
human. No personal data: the report is already redacted, and callers of infrastructure
changes are left out entirely (blameless: systems and decisions, not people).
Output is deterministic (no "generated at" time).

Usage:
  python postmortem.py incident-report/log-detective.json [--out incident-report/postmortem-draft.md]
  (or: python log_detective.py ./incident-logs --out-dir ./incident-report --postmortem)
Standard library only; Python 3.8+.
"""
import argparse
import json
import sys
from pathlib import Path

TBC = "**[to be confirmed]**"


def _t(iso):
    """2026-09-27T08:15:00+00:00 -> 2026-09-27 08:15:00 UTC (report times are UTC)."""
    if not iso:
        return "?"
    s = str(iso).replace("T", " ")
    for suffix in ("+00:00", "Z"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
    if "." in s:
        s = s.split(".")[0]
    return s + " UTC"


def _pct(x):
    return "n/a" if x is None else "%.1f%%" % (100 * x)


def render(r):
    L = ["# Postmortem draft: <incident title> " + TBC, ""]
    L += ["> Draft assembled by log-detective from redacted log evidence. Blameless by design: it describes "
          "systems, signals and decisions, not people. Every " + TBC + " item needs a human or further evidence "
          "before this is shared.", ""]
    hint = r.get("verdict_hint")
    sigs = r.get("signatures") or []
    new = [s for s in sigs if s.get("new_at_onset")]
    top = new[0] if new else (sigs[0] if sigs else None)
    base = r.get("baseline") or {}
    blast = r.get("blast_radius") or {}
    alert = r.get("alert_suggestion") or {}

    # ------------------------------------------------------------ summary
    L += ["## Summary", ""]
    L.append("- **What happened:** <one or two sentences in plain language> " + TBC)
    signal = {"error-spike": "error spike starting in the bucket at %s" % _t(r.get("onset")),
              "latency-regression": "latency regression from about %s" % _t(r.get("latency_onset")),
              "steady-errors": "errors present but steady (no clear start in the data window)",
              "no-problem-signal": "no error or failure signal in the supplied logs",
              "no-data": "no readable log records"}.get(hint, hint or "unknown")
    L.append("- **Signal in the logs:** " + signal)
    if top:
        L.append("- **Main error:** `%s` (%d occurrences, first %s)" % (top["signature"][:140], top["count"],
                                                                      _t(top["first_seen"])))
    start = r.get("first_new_error") or r.get("onset") or r.get("latency_onset")
    end = top["last_seen"] if top else None
    if start:
        L.append("- **Duration (from logs):** %s to %s (last occurrence in the data); resolution time %s"
                 % (_t(start), _t(end), TBC))
    if base.get("assessment"):
        L.append("- **Compared with baseline:** " + base.get("assessment_text", base["assessment"]))
    for h in (r.get("service_health") or [])[:3]:
        L.append("- **Platform event:** " + h["summary"])
    L.append("- **Severity:** <Sev 1-4> " + TBC)
    L.append("")

    # ------------------------------------------------------------ impact
    L += ["## Impact", ""]
    if blast:
        ops = blast.get("operations") or {}
        L.append("- Problem records since %s: %d" % (_t(blast.get("scope_start")), blast.get("problem_records", 0)))
        L.append("- Affected operations: %d" % ops.get("count", 0))
        for o in (ops.get("items") or [])[:5]:
            share = ("%s of %d requests failed" % (_pct(o["failure_share"]), o["total_requests"])
                     if o.get("total_requests") else "%d problem records" % o["problem_records"])
            L.append("  - `%s`: %s" % (o["operation"], share))
        roles = blast.get("roles") or {}
        if roles.get("count"):
            L.append("- Affected services / roles: %d (%s)" % (roles["count"], ", ".join(roles.get("names") or [])))
        for key, noun in (("users", "users"), ("clients", "client addresses"), ("tenants", "tenants")):
            v = blast.get(key)
            if v:
                L.append("- Distinct %s affected: %d of %d seen in the same period (%s); counts only, "
                         "identifiers not recorded" % (noun, v["affected"], v["seen"], _pct(v["share"])))
        if not any(blast.get(k) for k in ("users", "clients", "tenants")):
            L.append("- Users affected: not measurable from these exports (no user or client id column) " + TBC)
    else:
        L.append("- <operations, users and share of traffic affected> " + TBC)
    L.append("- Business impact (orders, revenue, SLA): " + TBC)
    L.append("")

    # ------------------------------------------------------------ timeline
    L += ["## Timeline (UTC, from logs and change records)", "", "| Time | Event |", "|---|---|"]
    for e in r.get("timeline_events") or []:
        L.append("| %s | %s |" % (_t(e["time"]), e["event"].replace("|", "/")))
    L.append("| %s | Detection: how and when the team noticed %s |" % ("?", TBC))
    L.append("| %s | Mitigation applied and service restored %s |" % ("?", TBC))
    L.append("")

    # ------------------------------------------------------------ evidence
    L += ["## Evidence", ""]
    for s in new[:3]:
        L.append("- New at onset: `%s`, %d times, first %s, last %s" % (s["signature"][:140], s["count"],
                                                                        _t(s["first_seen"]), _t(s["last_seen"])))
        if "in_baseline" in s:
            L.append("  - in the baseline window: %s" % ("yes, %s per hour" % s["baseline_per_hour"]
                                                          if s["in_baseline"] else "no"))
    old = [s for s in sigs if not s.get("new_at_onset")][:2]
    for s in old:
        L.append("- Background (present before onset): `%s`, %d times" % (s["signature"][:120], s["count"]))
    for x in (r.get("latency_regressions") or [])[:3]:
        L.append("- Latency: `%s` p95 %d ms -> %d ms (x%s)" % (x["operation"], x["p95_before_ms"],
                                                               x["p95_after_ms"], x["factor"]))
    d = r.get("deploy_correlation")
    if d:
        L.append("- Code deployment `%s` at %s, %d min before the first new error (%s timing correlation, "
                 "not proof)" % (d["id"], _t(d["time"]), d["minutes_before_onset"], d["strength"]))
    ic = r.get("infra_correlation")
    if ic:
        L.append("- Infrastructure change: %s on `%s` (`%s`) at %s, %d min before the first new error "
                 "(%s timing correlation, not proof)" % (ic["description"], ic["resource"], ic["operation"],
                                                         _t(ic["time"]), ic["minutes_before_onset"], ic["strength"]))
    if not d and not ic and (r.get("deploys_considered") or r.get("change_inputs")):
        L.append("- No code deployment or infrastructure change recorded shortly before the onset")
    if base.get("assessment"):
        L.append("- Baseline: problem rate %s now vs %s in the baseline window (ratio %s)"
                 % (_pct(base.get("current_problem_rate")), _pct(base.get("problem_rate")),
                    base.get("rate_ratio") if base.get("rate_ratio") is not None else "n/a"))
    for c in (r.get("code_candidates") or [])[:3]:
        L.append("- Stack frame: `%s:%s` in `%s`" % (c["file"], c["line"], c["function"]))
    L.append("")

    # ------------------------------------------------------------ root cause
    L += ["## Root cause " + TBC, ""]
    L.append("- Confidence: <Confirmed | Likely | Hypothesis> " + TBC)
    lead = None
    if ic and (not d or ic["minutes_before_onset"] <= d["minutes_before_onset"]):
        lead = "the %s on `%s` shortly before the onset" % (ic["description"].lower(), ic["resource"])
    elif d:
        lead = "code deployment `%s` (%s)" % (d["id"], d.get("description") or "")
    if lead:
        L.append("- Leading hypothesis from timing: %s. Timing is a lead, not proof: confirm against the diff, "
                 "the configuration values and the code frames above. %s" % (lead, TBC))
    else:
        L.append("- No change correlates in time. Consider dependency outage, expiry of a secret or certificate, "
                 "data change, traffic or resource exhaustion. " + TBC)
    L.append("- Why it was not caught earlier (tests, review, monitoring): " + TBC)
    L.append("")

    # ------------------------------------------------------------ actions
    L += ["## Action items", "", "| # | Type | Action | Owner | Status |", "|---|---|---|---|---|"]
    n = 1
    frames = r.get("code_candidates") or []
    if top:
        where = " at `%s:%s`" % (frames[0]["file"], frames[0]["line"]) if frames else ""
        L.append("| %d | Fix | Fix the cause of `%s`%s (hand to bug-resolve with a failing test first) | %s | open |"
                 % (n, top["signature"][:90].replace("|", "/"), where, TBC))
        n += 1
    if alert.get("status") == "suggested":
        L.append("| %d | Prevent | Review and apply the proposed alert `%s` (%s; %s) | %s | open |"
                 % (n, alert["name"], alert["condition"], alert["platform"], TBC))
        n += 1
    if top:
        L.append("| %d | Test | Add a regression test that reproduces `%s` | %s | open |"
                 % (n, (top.get("headline") or top["signature"])[:90].replace("|", "/"), TBC))
        n += 1
    if ic:
        L.append("| %d | Prevent | Put %s on `%s` through the same review and staged rollout as code "
                 "(e.g. validate in a slot or staging first) | %s | open |"
                 % (n, ic["category"].replace("-", " ") + " changes", ic["resource"], TBC))
        n += 1
    if r.get("service_health"):
        L.append("| %d | Resilience | Review behaviour during the platform event (retries, failover region) | %s | open |"
                 % (n, TBC))
        n += 1
    L.append("| %d | Process | <anything else the team agrees on> | %s | open |" % (n, TBC))
    L += ["", "---", "Evidence only. Timing correlation is a lead, not proof; confirm the cause against the code "
                     "and change records before publishing."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Draft a blameless postmortem from log-detective.json.")
    ap.add_argument("report", help="log-detective.json written by log_detective.py --out-dir")
    ap.add_argument("--out", help="output file (default: postmortem-draft.md next to the report)")
    a = ap.parse_args(argv)
    rep = json.loads(Path(a.report).read_text(encoding="utf-8"))
    out = Path(a.out) if a.out else Path(a.report).resolve().parent / "postmortem-draft.md"
    out.write_text(render(rep), encoding="utf-8")
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

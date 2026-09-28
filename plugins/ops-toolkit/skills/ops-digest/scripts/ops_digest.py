#!/usr/bin/env python3
"""ops_digest - turn the JSON reports from the other skills into one short summary a manager can read.

Reads any mix of (files or folders, auto-detected by content):
  cost-scout-report.json      from cloud-cost-scout
  log-detective.json          from log-detective (one per incident)
  pipeline triage / history / YAML review JSON from pipeline-doctor
  fix report JSON             from bug-resolve
Anything unrecognised is listed, not guessed at.

Writes ops-digest.md and ops-digest.html (self-contained, no external assets).
It never invents numbers: every figure comes from a report, and each section says which file.

Usage:
  python ops_digest.py reports/ --title "Orders platform" --period "22-28 Sep 2026" --out-dir digest
  python ops_digest.py a.json b.json --json
Standard library only; Python 3.8+.
"""
import argparse
import html
import json
import os
import sys
from pathlib import Path


# ------------------------------------------------------------------ detection
def kind_of(data):
    if isinstance(data, dict):
        if "totals_monthly" in data and "findings" in data:
            return "cost"
        if "verdict_hint" in data:
            return "incident"
        if data.get("tool") == "fix_report" or ("proof" in data and "pr_title" in data):
            return "bugfix"
        if "metrics" in data and "runs" in data and "tests" in data:
            return "pipeline-history"
        if "wall_clock_seconds" in data and "tips" in data:
            return "pipeline-speed"
        if "findings" in data and "files" in data and isinstance(data.get("summary"), dict)                 and set(data["summary"]) <= {"high", "medium", "low"}:
            return "pipeline-yaml"
    if isinstance(data, list) and data and isinstance(data[0], dict) and "diagnosis" in data[0]:
        return "pipeline-triage"
    return None


def iter_json(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*.json") if x.is_file())
        elif p.suffix.lower() == ".json" and p.exists():
            yield p


def money(v, cur="USD"):
    return f"{cur} {v:,.0f}" if v is not None else "n/a"


# ------------------------------------------------------------------ summarisers
def summarise_cost(d, src):
    totals = d.get("totals_monthly") or {}
    lanes = []
    for cur, t in sorted(totals.items()):
        act = (t.get("actionable") or {}) if isinstance(t, dict) else {}
        own = (t.get("needs_owner_decision") or {}) if isinstance(t, dict) else {}
        lanes.append({"currency": cur,
                      "actionable_confirmed": round(act.get("confirmed", 0.0), 2),
                      "actionable_estimated": round(act.get("estimated", 0.0), 2),
                      "owner_decision": round(own.get("confirmed", 0.0) + own.get("estimated", 0.0), 2)})
    findings = [f for f in d.get("findings", []) if f.get("risk") != "high" and f.get("monthly_savings")]
    top = sorted(findings, key=lambda f: -(f.get("monthly_savings") or 0))[:3]
    out = {"source": src, "as_of": d.get("generated_for"), "lanes": lanes,
           "finding_count": d.get("finding_count", len(d.get("findings", []))),
           "top": [{"name": f.get("name"), "title": f.get("title"), "saving": f.get("monthly_savings"),
                    "currency": f.get("currency"), "owner": (f.get("evidence") or {}).get("owner"),
                    "estimated": f.get("basis") not in ("advisor", "compute-optimizer", "actual-cost"),
                    "action": f.get("action")} for f in top]}
    # bill_change / tagging from cloud-cost-scout 1.1: figures are per currency.
    bc = d.get("bill_change") or {}
    if bc.get("status") == "compared":
        for cur, v in sorted((bc.get("by_currency") or {}).items()):
            inc = (v.get("top_increases_by_resource") or [{}])[0]
            out.setdefault("bill_change", []).append({
                "currency": cur, "previous_month": bc.get("previous_month"), "latest_month": bc.get("latest_month"),
                "previous_monthly": v.get("previous_monthly"), "latest_monthly": v.get("latest_monthly"),
                "change": v.get("change"), "change_pct": v.get("change_pct"),
                "latest_days": bc.get("latest_days"),
                "top_mover": ({"name": inc.get("name"), "change": inc.get("change")} if inc.get("name") else None)})
    tg = d.get("tagging") or {}
    if tg.get("status") == "ok":
        for cur, v in sorted((tg.get("by_currency") or {}).items()):
            if v.get("untagged_pct") is not None:
                out.setdefault("untagged", []).append({"currency": cur, "pct": v.get("untagged_pct"),
                                                       "monthly": v.get("untagged_monthly")})
    return out


def summarise_incident(d, src):
    sigs = d.get("signatures") or []
    top = next((s for s in sigs if s.get("new_at_onset")), sigs[0] if sigs else None)
    corr = d.get("deploy_correlation")
    infra = d.get("infra_changes") or []
    ic = d.get("infra_correlation")
    return {"source": src, "verdict": d.get("verdict_hint"),
            "started": d.get("first_new_error") or d.get("onset") or d.get("latency_onset"),
            "last_seen": top.get("last_seen") if top else None,
            "problems": d.get("problems"), "problem_rate": d.get("problem_rate"),
            "headline": (top.get("headline") or top.get("signature")) if top else None,
            "deploy": ({"id": corr.get("id"), "description": corr.get("description"),
                        "minutes_before": corr.get("minutes_before_onset")} if corr else None),
            "infra_change": ({"operation": ic.get("description") or ic.get("operation"),
                              "resource": ic.get("resource"), "minutes_before": ic.get("minutes_before_onset"),
                              "strength": ic.get("strength")} if isinstance(ic, dict) else None),
            "blast_radius": _blast(d.get("blast_radius")),
            "service_health": bool(d.get("service_health")),
            "code": [f"{c.get('file')}:{c.get('line')}" for c in (d.get("code_candidates") or [])[:2]],
            "alert_suggested": bool(d.get("alert_suggestion"))}


def _blast(b):
    """Counts only (log-detective never outputs identifiers). Shape: {"operations": {"count": n},
    "users": {"affected": n, "seen": m, "share": x}, ...}."""
    if not isinstance(b, dict):
        return None
    keep = {}
    ops = b.get("operations")
    if isinstance(ops, dict) and ops.get("count"):
        keep["operations"] = ops["count"]
    for k in ("users", "clients", "tenants"):
        v = b.get(k)
        if isinstance(v, dict) and v.get("affected"):
            keep[k] = v["affected"]
    if isinstance(b.get("failed_request_share"), (int, float)):
        keep["failed_request_share"] = b["failed_request_share"]
    return keep or None


def summarise_triage(d, src):
    items = []
    for r in d:
        g = r.get("diagnosis") or {}
        items.append({"file": Path(str(r.get("file", src))).name, "title": g.get("title"), "owner": g.get("owner"),
                      "confidence": g.get("confidence"), "step": g.get("step")})
    return {"source": src, "items": items}


def summarise_history(d, src):
    m = d.get("metrics") or {}
    tests = d.get("tests") or []
    return {"source": src, "kind": "pipeline-history", "pipeline": d.get("pipeline"),
            "facts": {"runs": m.get("completed"), "failure_rate": m.get("failure_rate"),
                      "time_to_green": m.get("mttg"), "time_between_failures": m.get("mtbf"),
                      "flaky_tests": sum(1 for x in tests if x.get("status") == "flaky"),
                      "regressed_tests": sum(1 for x in tests if x.get("status") == "regression"),
                      "recurring_causes": [r.get("title") for r in (d.get("recurring") or [])][:3],
                      "open_red_branches": [o.get("branch") for o in (m.get("open_incidents") or [])][:3]}}


def summarise_speed(d, src):
    tips = d.get("tips") or []
    return {"source": src, "kind": "pipeline-speed",
            "facts": {"run_time": d.get("wall_clock"), "estimated_saving_per_run": d.get("estimated_saving"),
                      "tips": len(tips),
                      "top_tip": (f"{tips[0].get('rule', '').replace('-', ' ')} on '{tips[0].get('step')}' "
                                  f"(saves about {tips[0].get('estimate')})") if tips else None}}


def summarise_yaml(d, src):
    s = d.get("summary") or {}
    return {"source": src, "kind": "pipeline-yaml",
            "facts": {"files_reviewed": len(d.get("files") or []), "high": s.get("high", 0),
                      "medium": s.get("medium", 0), "low": s.get("low", 0)}}


def summarise_bugfix(d, src):
    proof = d.get("proof") or {}
    return {"source": src, "summary": d.get("pr_title"), "proof_status": proof.get("status"),
            "proof_ok": proof.get("status") == "verified", "problems": len(proof.get("problems") or [])}


def build(paths):
    digest = {"cost": [], "incidents": [], "pipelines": [], "bugfixes": [], "unrecognised": [], "invalid": []}
    for f in iter_json(paths):
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except ValueError:
            digest["invalid"].append(str(f.name))
            continue
        k = kind_of(data)
        name = f.name
        if k == "cost":
            digest["cost"].append(summarise_cost(data, name))
        elif k == "incident":
            digest["incidents"].append(summarise_incident(data, name))
        elif k == "pipeline-triage":
            digest["pipelines"].append(summarise_triage(data, name))
        elif k == "pipeline-history":
            digest["pipelines"].append(summarise_history(data, name))
        elif k == "pipeline-speed":
            digest["pipelines"].append(summarise_speed(data, name))
        elif k == "pipeline-yaml":
            digest["pipelines"].append(summarise_yaml(data, name))
        elif k == "bugfix":
            digest["bugfixes"].append(summarise_bugfix(data, name))
        else:
            digest["unrecognised"].append(name)
    digest["actions"] = actions(digest)
    return digest


def short(text, limit=70):
    """Cut at a word boundary so placeholders like <email-1> are never split."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:")
    return cut + "..."


def actions(d):
    acts = []
    for c in d["cost"]:
        for t in c["top"]:
            acts.append(f"Cost: {t['title']} on {t['name']} saves {money(t['saving'], t['currency'])}/month"
                        + (" (estimated)" if t.get("estimated") else "")
                        + (f" (owner: {t['owner']})" if t.get("owner") else ""))
    for i in d["incidents"]:
        if i["verdict"] in ("error-spike", "latency-regression", "steady-errors"):
            where = f" at {i['code'][0]}" if i["code"] else ""
            acts.append(f"Incident: fix and verify '{short(i['headline'] or 'problem')}'{where}"
                        + ("; add the suggested alert" if i["alert_suggested"] else ""))
    for p in d["pipelines"]:
        for it in p.get("items", []):
            if it.get("owner") in ("pipeline-admin", "platform-team"):
                acts.append(f"Pipeline: ask {it['owner']} to fix '{it['title']}'")
        f = p.get("facts") or {}
        if p.get("kind") == "pipeline-history":
            if f.get("regressed_tests"):
                acts.append(f"Pipeline: {f['regressed_tests']} test(s) regressed; fix before new work lands")
            if f.get("flaky_tests"):
                acts.append(f"Pipeline: quarantine or fix {f['flaky_tests']} flaky test(s)")
        if p.get("kind") == "pipeline-yaml" and f.get("high"):
            acts.append(f"Pipeline: {f['high']} high-severity issue(s) in pipeline YAML (see the review)")
    for b in d["bugfixes"]:
        if not b.get("proof_ok"):
            acts.append(f"Bug fix '{b.get('summary')}' is NOT proven yet; finish the before/after test evidence")
    return acts[:10]


# ------------------------------------------------------------------ rendering
def to_markdown(d, title, period):
    L = [f"# {title}", ""]
    if period:
        L += [f"_{period}_", ""]
    kp = []
    for c in d["cost"]:
        for l in c["lanes"]:
            kp.append(f"**{money(l['actionable_confirmed'], l['currency'])}/month** confirmed savings ready to act on")
        for bc in c.get("bill_change") or []:
            if isinstance(bc.get("change"), (int, float)) and isinstance(bc.get("change_pct"), (int, float)):
                kp.append(f"Cloud run rate {'up' if bc['change'] >= 0 else 'down'} "
                          f"**{money(abs(bc['change']), bc['currency'])}/month** ({bc['change_pct']:+.1f}%) "
                          f"from {bc['previous_month']} to {bc['latest_month']}")
    if d["incidents"]:
        kp.append(f"**{len(d['incidents'])}** incident(s) analysed")
    fails = sum(len(p.get("items", [])) for p in d["pipelines"])
    if fails:
        kp.append(f"**{fails}** pipeline failure(s) diagnosed")
    for p in d["pipelines"]:
        f = p.get("facts") or {}
        if p.get("kind") == "pipeline-history" and isinstance(f.get("failure_rate"), (int, float)):
            kp.append(f"Build failure rate **{f['failure_rate']:.0%}** over {f.get('runs')} runs"
                      + (f" ({p['pipeline']})" if p.get("pipeline") else ""))
    proven = sum(1 for b in d["bugfixes"] if b.get("proof_ok"))
    unproven = len(d["bugfixes"]) - proven
    if proven:
        kp.append(f"**{proven}** bug fix(es) with test proof")
    if unproven:
        kp.append(f"**{unproven}** bug fix(es) NOT yet proven")
    L += (["## At a glance", ""] + [f"- {k}" for k in kp] + [""]) if kp else ["No recognised reports were supplied.", ""]
    if d["actions"]:
        L += ["## What needs doing", ""] + [f"{n}. {a}" for n, a in enumerate(d["actions"], 1)] + [""]
    for c in d["cost"]:
        L += [f"## Cloud cost ({c['source']})", ""]
        for l in c["lanes"]:
            L.append(f"- Actionable now: {money(l['actionable_confirmed'], l['currency'])} confirmed, "
                     f"{money(l['actionable_estimated'], l['currency'])} estimated per month; "
                     f"{money(l['owner_decision'], l['currency'])} waiting on owners")
        for bc in c.get("bill_change") or []:
            ch = bc.get("change")
            sign = "+" if (ch or 0) >= 0 else "-"
            pct = f" ({bc['change_pct']:+.1f}%)" if isinstance(bc.get("change_pct"), (int, float)) else ""
            partial = (f"; {bc['latest_month']} has {bc['latest_days']} days of data, scaled to a month"
                       if bc.get("latest_days") and bc["latest_days"] < 28 else "")
            L.append(f"- Monthly run rate {bc['previous_month']} to {bc['latest_month']}: "
                     f"{money(bc.get('previous_monthly'), bc['currency'])} to {money(bc.get('latest_monthly'), bc['currency'])}, "
                     f"{sign}{money(abs(ch) if ch is not None else None, bc['currency'])}{pct}{partial}"
                     + (f"; biggest increase {bc['top_mover']['name']} "
                        f"(+{money(bc['top_mover']['change'], bc['currency'])})" if bc.get("top_mover") else ""))
        for u in c.get("untagged") or []:
            L.append(f"- Spend with no owner tag: {money(u['monthly'], u['currency'])}/month ({u['pct']:.1f}%)")
        L.append("")
    for i in d["incidents"]:
        L += [f"## Incident ({i['source']})", "",
              f"- Status: {i['verdict']}; started {i['started'] or 'n/a'}, last seen {i['last_seen'] or 'n/a'}",
              f"- Main error: {i['headline'] or 'n/a'}"]
        if i["deploy"]:
            L.append(f"- Change just before: deploy {i['deploy']['id']} ({i['deploy']['description']}), "
                     f"{i['deploy']['minutes_before']} min earlier")
        if i["infra_change"]:
            ic = i["infra_change"]
            L.append(f"- Infrastructure change before it: {ic['operation']} on {ic['resource']}, "
                     f"{ic['minutes_before']} min earlier ({ic['strength']} timing link)")
        if i.get("blast_radius"):
            br = i["blast_radius"]
            parts = [f"{v} {k[:-1] if v == 1 else k}" for k, v in br.items() if k != "failed_request_share"]
            if "failed_request_share" in br:
                parts.append(f"{br['failed_request_share']:.1%} of requests failing")
            L.append(f"- Affected: {', '.join(parts)}")
        if i["service_health"]:
            L.append("- A platform (Service Health) event overlaps this incident")
        if i["code"]:
            L.append(f"- Code involved: {', '.join(i['code'])}")
        L.append("")
    for p in d["pipelines"]:
        L += [f"## Pipelines ({p['source']})", ""]
        for it in p.get("items", []):
            L.append(f"- {it['file']}: {it['title']} (fix owner: {it['owner']}, confidence {it['confidence']})")
        for k, v in (p.get("facts") or {}).items():
            if v in (None, [], 0) and k not in ("high",):
                continue
            if k == "failure_rate" and isinstance(v, (int, float)):
                v = f"{v:.0%}"
            if isinstance(v, list):
                v = "; ".join(str(x) for x in v)
            L.append(f"- {k.replace('_', ' ')}: {v}")
        L.append("")
    for b in d["bugfixes"]:
        L += [f"## Bug fix ({b['source']})", "", f"- {b['summary'] or 'n/a'}",
              f"- Proof: {'verified (test failed before the fix and passes after)' if b['proof_ok'] else 'NOT verified: ' + str(b['proof_status'])}",
              ""]
    if d["unrecognised"] or d["invalid"]:
        L += ["## Files not used", ""] + [f"- {n} (not a recognised report)" for n in d["unrecognised"]] \
             + [f"- {n} (invalid JSON)" for n in d["invalid"]] + [""]
    L += ["---", "Every figure above comes from the listed report files. Nothing was changed in any system."]
    return "\n".join(L) + "\n"


def to_html(md_text, title):
    """Small, dependency-free markdown-to-HTML for the subset to_markdown produces."""
    out, in_list, in_olist = [], False, False

    def close():
        nonlocal in_list, in_olist
        if in_list:
            out.append("</ul>")
        if in_olist:
            out.append("</ol>")
        in_list = in_olist = False

    def inline(s):
        s = html.escape(s)
        while "**" in s:
            s = s.replace("**", "<b>", 1).replace("**", "</b>", 1)
        return s

    for line in md_text.splitlines():
        if line.startswith("# "):
            close(); out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("## "):
            close(); out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("- "):
            if not in_list:
                close(); out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(line[2:])}</li>")
        elif line[:1].isdigit() and ". " in line[:4]:
            if not in_olist:
                close(); out.append("<ol>"); in_olist = True
            out.append(f"<li>{inline(line.split('. ', 1)[1])}</li>")
        elif line.startswith("_") and line.endswith("_") and len(line) > 2:
            close(); out.append(f"<p class='sub'>{inline(line[1:-1])}</p>")
        elif line == "---":
            close(); out.append("<hr>")
        elif line.strip():
            close(); out.append(f"<p>{inline(line)}</p>")
    close()
    css = ("body{font:16px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:860px;margin:32px auto;"
           "padding:0 20px;color:#1d2129}h1{margin-bottom:0}h2{margin-top:28px;border-top:1px solid #e3e5ea;"
           "padding-top:12px}.sub{color:#5d6675;margin-top:4px}li{margin:4px 0}hr{border:0;border-top:1px solid #e3e5ea}")
    return (f"<!DOCTYPE html>\n<html lang='en'><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<style>{css}</style></head><body>\n" + "\n".join(out) + "\n</body></html>\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarise skill reports into one ops digest.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--title", default="Ops digest")
    ap.add_argument("--period", default="")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-dir")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    d = build(a.paths)
    md = to_markdown(d, a.title, a.period)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "ops-digest.md").write_text(md, encoding="utf-8")
        Path(a.out_dir, "ops-digest.html").write_text(to_html(md, a.title), encoding="utf-8")
        Path(a.out_dir, "ops-digest.json").write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")
        print(f"wrote {a.out_dir}/ops-digest.md, .html and .json")
    else:
        sys.stdout.write(json.dumps(d, indent=2, default=str) + "\n" if a.json else md)
    found = d["cost"] or d["incidents"] or d["pipelines"] or d["bugfixes"]
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())

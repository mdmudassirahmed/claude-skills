#!/usr/bin/env python3
"""cost_scout - turn read-only cloud cost exports into a ranked, evidence-backed savings list.

Reads any mix of these files (format auto-detected, never needs cloud access itself):
  Azure  advisor.json      az advisor recommendation list --category Cost -o json
  Azure  *.json (ARG)      az graph query -q "<query from references/azure-idle-resources.kql>" --first 1000 -o json
  Azure  cost export .csv  Cost Management > Cost analysis / Exports (resource-level, daily or monthly)
  AWS    ce.json           aws ce get-cost-and-usage ... --group-by Type=DIMENSION,Key=SERVICE
  AWS    volumes.json      aws ec2 describe-volumes --filters Name=status,Values=available
  AWS    addresses.json    aws ec2 describe-addresses
  AWS    optimizer.json    aws compute-optimizer get-ec2-instance-recommendations

Every $ figure carries its basis:
  advisor / compute-optimizer / actual-cost  -> "confirmed" (from the provider or the real bill)
  list-price-estimate                        -> "estimated" (../references/aws-approx-prices.json)
  unknown                                    -> listed, but not totalled

Usage:
  python cost_scout.py exports/                      # markdown report to stdout
  python cost_scout.py exports/ --json               # JSON to stdout
  python cost_scout.py a.json b.csv --out-dir report # writes cost-scout-report.md + .json
  python cost_scout.py exports/ --as-of 2026-09-27   # fix "today" for age calculations (tests)
Standard library only; Python 3.8+.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRICES_FILE = HERE.parent / "references" / "aws-approx-prices.json"

CONFIRMED_BASES = {"advisor", "compute-optimizer", "actual-cost"}
BASIS_RANK = {"advisor": 4, "compute-optimizer": 4, "actual-cost": 3, "list-price-estimate": 2, "unknown": 0}
PROD_VALUES = {"prod", "production", "prd", "live"}
KEEP_TAGS = {"do-not-delete", "donotdelete", "keep", "retain", "legal-hold"}
HOURS_PER_MONTH = 730


# ------------------------------------------------------------------ helpers
def parse_date(s):
    """Dates as they appear in Azure/AWS exports: ISO (with or without time/7-digit
    fractions), MM/DD/YYYY (Azure cost exports), YYYYMMDD, DD/MM/YYYY."""
    if s is None or str(s).strip() == "":
        return None
    s = str(s).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    for fmt, n in (("%Y-%m-%d", 10), ("%m/%d/%Y", 10), ("%Y%m%d", 8), ("%d/%m/%Y", 10)):
        try:
            return datetime.strptime(s[:n], fmt).date()
        except ValueError:
            continue
    return None


def to_float(v):
    try:
        return float(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def norm_id(rid):
    return (rid or "").strip().lower().rstrip("/")


def tags_of(obj):
    t = obj.get("tags") or obj.get("Tags") or {}
    if isinstance(t, list):  # AWS style [{"Key":..,"Value":..}]
        return {str(x.get("Key", "")): str(x.get("Value", "")) for x in t if isinstance(x, dict)}
    return {str(k): str(v) for k, v in t.items()} if isinstance(t, dict) else {}


def get(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        # case-insensitive key match (ARG property casing varies)
        if p in d:
            d = d[p]
        else:
            m = next((k for k in d if k.lower() == p.lower()), None)
            if m is None:
                return default
            d = d[m]
    return d


def resource_group_of(rid):
    m = re.search(r"/resourcegroups/([^/]+)", rid or "", re.I)
    return m.group(1) if m else ""


def new_finding(**kw):
    f = {
        "resource_id": "", "name": "", "provider": "", "resource_type": "", "scope": "",
        "category": "other", "title": "", "action": "", "monthly_savings": None,
        "currency": None, "basis": "unknown", "risk": "low", "risk_notes": [],
        "tags": {}, "sources": [], "evidence": {},
    }
    f.update(kw)
    return f


# ------------------------------------------------------------------ detection
def detect(path, data):
    if path.suffix.lower() == ".csv":
        return "azure-cost-csv"
    if isinstance(data, dict):
        if "ResultsByTime" in data:
            return "aws-ce"
        if "Volumes" in data:
            return "aws-volumes"
        if "Addresses" in data:
            return "aws-addresses"
        if "instanceRecommendations" in data:
            return "aws-compute-optimizer"
        if isinstance(data.get("data"), list):
            return "azure-arg"
        if isinstance(data.get("value"), list):
            data = data["value"]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        first = data[0]
        if "shortDescription" in first and "category" in first:
            return "azure-advisor"
        if "type" in first and str(first.get("id", "")).lower().startswith("/subscriptions/"):
            return "azure-arg"
    return None


# ------------------------------------------------------------------ Azure
def advisor_findings(items):
    out = []
    if isinstance(items, dict):
        items = items.get("value", [])
    for r in items:
        if str(r.get("category", "")).lower() != "cost":
            continue
        ext = r.get("extendedProperties") or {}
        rid = get(r, "resourceMetadata", "resourceId") or re.sub(
            r"/providers/microsoft\.advisor/recommendations/.*$", "", r.get("id", ""), flags=re.I)
        problem = get(r, "shortDescription", "problem") or ""
        solution = get(r, "shortDescription", "solution") or problem
        annual, monthly = to_float(ext.get("annualSavingsAmount")), to_float(ext.get("savingsAmount"))
        savings = annual / 12 if annual else monthly
        low = problem.lower()
        cat = ("rightsize" if "right-size" in low or "rightsize" in low or "underutilized" in low
               else "commitment" if "reserv" in low or "savings plan" in low
               else "idle" if any(w in low for w in ("unattached", "idle", "unused", "delete", "shutdown")) else "other")
        cur_sku, tgt_sku = ext.get("currentSku"), ext.get("targetSku")
        if cat == "rightsize" and cur_sku and tgt_sku:
            problem = f"Underutilised: right-size {cur_sku} -> {tgt_sku}"
            solution = f"Change the SKU to {tgt_sku} in IaC and redeploy in a maintenance window"
        elif cat == "commitment":
            solution = f"Buy a {ext.get('term', '1-3 year')} reservation / savings plan after finance approval"
        out.append(new_finding(
            resource_id=rid, name=r.get("impactedValue") or rid.split("/")[-1], provider="azure",
            resource_type=r.get("impactedField", ""), scope=resource_group_of(rid),
            category=cat, title=problem, action=solution,
            monthly_savings=round(savings, 2) if savings else None,
            currency=ext.get("savingsCurrency") or ("USD" if savings else None),
            basis="advisor" if savings else "unknown",
            sources=["azure-advisor"],
            evidence={k: ext[k] for k in ("currentSku", "targetSku", "recommendationType", "term",
                                          "lookbackPeriod", "annualSavingsAmount", "savingsAmount") if k in ext},
        ))
    return out


def arg_rows(data):
    if isinstance(data, dict):
        return data.get("data") or data.get("value") or []
    return data


def arg_findings(data, as_of):
    out = []
    for row in arg_rows(data):
        rtype = str(row.get("type", "")).lower()
        props = row.get("properties") or {}
        rid = row.get("id", "")
        base = dict(resource_id=rid, name=row.get("name") or rid.split("/")[-1], provider="azure",
                    resource_type=rtype, scope=row.get("resourceGroup", ""), tags=tags_of(row),
                    sources=["azure-resource-graph"])
        if rtype == "microsoft.compute/disks" and str(get(props, "diskState", default="")).lower() == "unattached":
            f = new_finding(category="idle", title="Unattached managed disk",
                            action="Snapshot if the data may be needed, then delete the disk",
                            evidence={"sizeGB": get(props, "diskSizeGB"), "sku": get(row, "sku", "name"),
                                      "timeCreated": get(props, "timeCreated"),
                                      "lastOwnershipUpdateTime": get(props, "LastOwnershipUpdateTime")}, **base)
            changed = parse_date(get(props, "LastOwnershipUpdateTime"))
            if changed and (as_of - changed).days < 7:
                f["risk"] = "medium"
                f["risk_notes"].append(f"detached only {(as_of - changed).days} day(s) ago - may be mid-migration")
            out.append(f)
        elif rtype == "microsoft.network/publicipaddresses" and not get(props, "ipConfiguration") \
                and not get(props, "natGateway"):
            out.append(new_finding(category="idle", title="Public IP not associated with any resource",
                                   action="Delete the public IP (confirm it is not reserved for DNS/allow-lists)",
                                   evidence={"sku": get(row, "sku", "name"),
                                             "allocation": get(props, "publicIPAllocationMethod"),
                                             "ipAddress": "<redacted>"}, **base))
        elif rtype == "microsoft.compute/virtualmachines":
            state = str(get(props, "extended", "instanceView", "powerState", "code", default="")).lower()
            if state == "powerstate/stopped":
                out.append(new_finding(category="idle", title="VM stopped but not deallocated (compute still billed)",
                                       action="Deallocate the VM (az vm deallocate) - or delete if no longer needed",
                                       evidence={"powerState": state, "vmSize": get(props, "hardwareProfile", "vmSize")},
                                       **base))
        elif rtype == "microsoft.web/serverfarms":
            sites = get(props, "numberOfSites")
            tier = str(get(row, "sku", "tier", default="")).lower()
            if sites == 0 and tier not in ("free", "dynamic", "flexconsumption"):
                out.append(new_finding(category="idle", title="App Service plan with no apps",
                                       action="Delete the empty plan (or move apps onto it before buying another)",
                                       evidence={"sku": get(row, "sku", "name"), "tier": tier, "numberOfSites": sites},
                                       **base))
        elif rtype == "microsoft.compute/snapshots":
            created = parse_date(get(props, "timeCreated"))
            if created and (as_of - created).days > 90:
                out.append(new_finding(category="idle", title=f"Snapshot older than 90 days ({(as_of - created).days} days)",
                                       action="Confirm retention policy, then delete or move to archive tier",
                                       evidence={"timeCreated": str(created), "sizeGB": get(props, "diskSizeGB")},
                                       **base))
        elif rtype == "microsoft.network/loadbalancers":
            pools = get(props, "backendAddressPools") or []
            empty = all(not (get(p, "properties", "backendIPConfigurations") or get(p, "properties", "loadBalancerBackendAddresses"))
                        for p in pools) if pools else True
            if empty and str(get(row, "sku", "name", default="")).lower() == "standard":
                out.append(new_finding(category="idle", title="Standard load balancer with empty backend pools",
                                       action="Delete the load balancer if unused",
                                       evidence={"backendPools": len(pools)}, **base))
    return out


COST_COLS = ["costinbillingcurrency", "cost", "pretaxcost", "costinusd", "unblendedcost", "billedcost", "effectivecost"]
ID_COLS = ["resourceid", "instanceid", "resource id", "resourceuri"]
CUR_COLS = ["billingcurrency", "billingcurrencycode", "currency", "currencycode"]
DATE_COLS = ["date", "usagedate", "usagedatetime", "chargeperiodstart", "billingperiodstartdate"]


def pick(header, candidates):
    low = {h.lower().strip(): h for h in header}
    for c in candidates:
        if c in low:
            return low[c]
    return None


def cost_csv(path):
    """Return {resource_id: {"monthly": float, "currency": str, "total": float, "days": int}}."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    header = reader.fieldnames or []
    c_id, c_cost, c_cur, c_date = (pick(header, ID_COLS), pick(header, COST_COLS),
                                   pick(header, CUR_COLS), pick(header, DATE_COLS))
    if not c_id or not c_cost:
        raise ValueError(f"{path}: cost CSV needs a resource-id column and a cost column; found {header}")
    totals, currency, dates = {}, {}, set()
    for row in reader:
        rid = norm_id(row.get(c_id))
        amt = to_float(row.get(c_cost))
        if not rid or amt is None:
            continue
        totals[rid] = totals.get(rid, 0.0) + amt
        currency[rid] = (row.get(c_cur) or "USD").strip() if c_cur else "USD"
        d = parse_date(row.get(c_date)) if c_date else None
        if d:
            dates.add(d)
    days = ((max(dates) - min(dates)).days + 1) if dates else 30
    factor = 30.4 / days
    return {rid: {"monthly": round(t * factor, 2), "total": round(t, 2), "currency": currency[rid], "days": days}
            for rid, t in totals.items()}


# ------------------------------------------------------------------ AWS
def load_prices():
    try:
        return json.loads(PRICES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def aws_volume_findings(data, prices, as_of):
    out = []
    ebs = (prices.get("ebs_gb_month") or {})
    for v in data.get("Volumes", []):
        if str(v.get("State", "")).lower() != "available":
            continue
        vtype, size = v.get("VolumeType", "gp2"), to_float(v.get("Size")) or 0
        rate = ebs.get(vtype)
        est = round(size * rate, 2) if rate else None
        created = parse_date(v.get("CreateTime"))
        f = new_finding(resource_id=v.get("VolumeId", ""), name=tags_of(v).get("Name") or v.get("VolumeId", ""),
                        provider="aws", resource_type="ec2/volume", scope=v.get("AvailabilityZone", ""),
                        category="idle", title=f"Unattached EBS volume ({vtype}, {int(size)} GiB)",
                        action="Snapshot if needed, then delete the volume",
                        monthly_savings=est, currency="USD" if est else None,
                        basis="list-price-estimate" if est else "unknown",
                        tags=tags_of(v), sources=["aws-ec2-volumes"],
                        evidence={"volumeType": vtype, "sizeGiB": size, "createTime": v.get("CreateTime"),
                                  "priceNote": prices.get("_note")})
        if created and (as_of - created).days < 7:
            f["risk"] = "medium"
            f["risk_notes"].append("created in the last 7 days - may be in use by a pending workflow")
        out.append(f)
    return out


def aws_address_findings(data, prices):
    out = []
    hourly = prices.get("eip_idle_hour")
    for a in data.get("Addresses", []):
        if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
            continue
        est = round(hourly * HOURS_PER_MONTH, 2) if hourly else None
        out.append(new_finding(resource_id=a.get("AllocationId", a.get("PublicIp", "")),
                               name=tags_of(a).get("Name") or a.get("AllocationId", ""), provider="aws",
                               resource_type="ec2/elastic-ip", scope=a.get("NetworkBorderGroup", ""),
                               category="idle", title="Elastic IP not associated with anything",
                               action="Release the Elastic IP (confirm it is not allow-listed by a partner)",
                               monthly_savings=est, currency="USD" if est else None,
                               basis="list-price-estimate" if est else "unknown",
                               tags=tags_of(a), sources=["aws-ec2-addresses"],
                               evidence={"domain": a.get("Domain"), "priceNote": prices.get("_note")}))
    return out


def aws_optimizer_findings(data):
    out = []
    for r in data.get("instanceRecommendations", []):
        finding = str(r.get("finding", "")).lower().replace("_", "")
        if finding not in ("overprovisioned",):
            continue
        opts = r.get("recommendationOptions") or []
        best = max(opts, key=lambda o: to_float(get(o, "savingsOpportunity", "estimatedMonthlySavings", "value")) or 0,
                   default={})
        sav = to_float(get(best, "savingsOpportunity", "estimatedMonthlySavings", "value"))
        cur = get(best, "savingsOpportunity", "estimatedMonthlySavings", "currency") or "USD"
        f = new_finding(resource_id=r.get("instanceArn", ""), name=r.get("instanceName") or r.get("instanceArn", "").split("/")[-1],
                        provider="aws", resource_type="ec2/instance", scope=r.get("accountId", ""),
                        category="rightsize",
                        title=f"Over-provisioned EC2 instance ({r.get('currentInstanceType')} -> {best.get('instanceType')})",
                        action=f"Resize to {best.get('instanceType')} via IaC and redeploy in a maintenance window",
                        monthly_savings=round(sav, 2) if sav else None, currency=cur if sav else None,
                        basis="compute-optimizer" if sav else "unknown",
                        tags=tags_of(r), sources=["aws-compute-optimizer"],
                        evidence={"currentType": r.get("currentInstanceType"), "recommendedType": best.get("instanceType"),
                                  "performanceRisk": best.get("performanceRisk"),
                                  "lookbackDays": r.get("lookBackPeriodInDays")})
        out.append(f)
    return out


def aws_ce_summary(data):
    by_service = {}
    for period in data.get("ResultsByTime", []):
        for g in period.get("Groups", []):
            key = (g.get("Keys") or ["?"])[0]
            m = get(g, "Metrics", "UnblendedCost") or get(g, "Metrics", "AmortizedCost") or {}
            amt = to_float(m.get("Amount")) or 0
            by_service[key] = by_service.get(key, 0) + amt
        total = get(period, "Total", "UnblendedCost", "Amount")
        if not period.get("Groups") and total:
            by_service["Total"] = by_service.get("Total", 0) + (to_float(total) or 0)
    return sorted(({"service": k, "cost": round(v, 2)} for k, v in by_service.items()), key=lambda x: -x["cost"])


# ------------------------------------------------------------------ merge / risk
def merge(findings):
    merged = {}
    for f in findings:
        key = norm_id(f["resource_id"]) or f"{f['provider']}:{f['name']}:{f['title']}"
        if key not in merged:
            merged[key] = f
            continue
        m = merged[key]
        m["sources"] = sorted(set(m["sources"]) | set(f["sources"]))
        m["evidence"].update({k: v for k, v in f["evidence"].items() if k not in m["evidence"]})
        m["tags"] = m["tags"] or f["tags"]
        m["risk_notes"] = sorted(set(m["risk_notes"]) | set(f["risk_notes"]))
        if BASIS_RANK[f["basis"]] > BASIS_RANK[m["basis"]]:
            for k in ("monthly_savings", "currency", "basis"):
                m[k] = f[k]
        if m["category"] == "other" and f["category"] != "other":
            m["category"], m["title"], m["action"] = f["category"], f["title"], f["action"]
    return list(merged.values())


def enrich_with_cost(findings, costs):
    for f in findings:
        c = costs.get(norm_id(f["resource_id"]))
        if not c:
            continue
        f["evidence"]["actualMonthlyCost"] = c["monthly"]
        f["evidence"]["actualCostCurrency"] = c["currency"]
        f["sources"] = sorted(set(f["sources"]) | {"cost-export"})
        # Removing an idle resource saves its whole run-rate; right-sizing needs a provider estimate.
        if f["category"] == "idle" and BASIS_RANK[f["basis"]] < BASIS_RANK["actual-cost"]:
            f["monthly_savings"], f["currency"], f["basis"] = c["monthly"], c["currency"], "actual-cost"


def assess_risk(f):
    tags_low = {k.lower(): str(v).lower() for k, v in f["tags"].items()}
    env = tags_low.get("environment") or tags_low.get("env") or tags_low.get("stage")
    if env in PROD_VALUES or re.search(r"(^|[-_/])(prod|prd)([-_/]|$)", (f["scope"] or "").lower()):
        f["risk"] = "high"
        f["risk_notes"].append("production resource - confirm with the owner before any change")
    if any(k in KEEP_TAGS or v in KEEP_TAGS for k, v in tags_low.items()):
        f["risk"] = "high"
        f["risk_notes"].append("tagged to be kept (do-not-delete / retain / legal-hold)")
    if f["category"] == "commitment":
        f["risk"] = "medium" if f["risk"] == "low" else f["risk"]
        f["risk_notes"].append("a 1-3 year purchase commitment - needs finance approval and a usage forecast")
    if f["category"] == "rightsize" and f["risk"] == "low":
        f["risk"] = "medium"
        f["risk_notes"].append("resizing can affect performance - load-test or watch metrics after the change")
    owner = tags_low.get("owner") or tags_low.get("createdby") or tags_low.get("costcenter")
    if owner:
        f["evidence"]["owner"] = owner
    f["risk_notes"] = sorted(set(f["risk_notes"]))


# ------------------------------------------------------------------ run
def iter_files(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(x for x in p.rglob("*") if x.suffix.lower() in (".json", ".csv"))
        elif p.exists():
            yield p


def analyse(paths, as_of=None):
    as_of = as_of or datetime.now(timezone.utc).date()
    prices = load_prices()
    findings, costs, spend, inputs, skipped = [], {}, [], [], []
    for path in iter_files(paths):
        try:
            data = None if path.suffix.lower() == ".csv" else json.loads(path.read_text(encoding="utf-8-sig"))
        except ValueError as e:
            skipped.append({"file": str(path), "reason": f"invalid JSON ({e})"})
            continue
        kind = detect(path, data)
        if kind is None:
            skipped.append({"file": str(path), "reason": "unrecognised format"})
            continue
        try:
            if kind == "azure-advisor":
                findings += advisor_findings(data)
            elif kind == "azure-arg":
                findings += arg_findings(data, as_of)
            elif kind == "azure-cost-csv":
                for rid, c in cost_csv(path).items():
                    costs[rid] = c
            elif kind == "aws-volumes":
                findings += aws_volume_findings(data, prices, as_of)
            elif kind == "aws-addresses":
                findings += aws_address_findings(data, prices)
            elif kind == "aws-compute-optimizer":
                findings += aws_optimizer_findings(data)
            elif kind == "aws-ce":
                spend += aws_ce_summary(data)
        except ValueError as e:
            skipped.append({"file": str(path), "reason": str(e)})
            continue
        inputs.append({"file": str(path), "type": kind})

    findings = merge(findings)
    enrich_with_cost(findings, costs)
    for f in findings:
        assess_risk(f)
    findings.sort(key=lambda f: (f["monthly_savings"] is None, -(f["monthly_savings"] or 0)))

    totals = {}
    for f in findings:
        if f["monthly_savings"] is None:
            continue
        bucket = "confirmed" if f["basis"] in CONFIRMED_BASES else "estimated"
        lane = "needs_owner_decision" if f["risk"] == "high" else "actionable"
        cur = totals.setdefault(f["currency"] or "USD", {
            "actionable": {"confirmed": 0.0, "estimated": 0.0},
            "needs_owner_decision": {"confirmed": 0.0, "estimated": 0.0}})
        cur[lane][bucket] = round(cur[lane][bucket] + f["monthly_savings"], 2)
    top_spend = sorted(({"resource_id": k, **v} for k, v in costs.items()), key=lambda x: -x["monthly"])[:10]
    return {
        "generated_for": str(as_of), "inputs": inputs, "skipped": skipped,
        "totals_monthly": totals, "finding_count": len(findings),
        "unpriced_count": sum(1 for f in findings if f["monthly_savings"] is None),
        "findings": findings, "top_spend": top_spend, "aws_spend_by_service": spend,
    }


def money(v, cur):
    return "unknown" if v is None else f"{cur or ''} {v:,.2f}".strip()


def to_markdown(r):
    lines = ["# Cloud Cost Scout report", "",
             f"_As of {r['generated_for']} · {len(r['inputs'])} input file(s) · {r['finding_count']} finding(s)_", ""]
    if not r["findings"]:
        lines += ["**No savings opportunities found in the supplied data.**",
                  "This means none of the checks matched - not that the estate is optimal. "
                  "Check that the exports cover the right subscription/account and period.", ""]
    else:
        lines += ["## Potential monthly savings", "",
                  "| Currency | Lane | Confirmed | Estimated |", "|---|---|---:|---:|"]
        for cur, t in r["totals_monthly"].items():
            for lane, label in (("actionable", "**Actionable now** (low/medium risk)"),
                                ("needs_owner_decision", "Needs owner decision (high risk)")):
                lines.append(f"| {cur} | {label} | {t[lane]['confirmed']:,.2f} | {t[lane]['estimated']:,.2f} |")
        lines += ["", "_Quote the **Actionable now + Confirmed** figure as the headline. "
                      "Confirmed = from Azure Advisor / AWS Compute Optimizer / your actual bill. "
                      "Estimated = from list prices; verify before quoting. "
                      "High-risk items (production, retention tags) need their owner's decision first._", "",
                  "## Findings (highest saving first)", "",
                  "| # | Resource | Finding | Saving / month | Basis | Risk | Action |",
                  "|---|---|---|---:|---|---|---|"]
        for i, f in enumerate(r["findings"], 1):
            risk = f["risk"] + (f" - {'; '.join(f['risk_notes'])}" if f["risk_notes"] else "")
            lines.append(f"| {i} | `{f['name']}` ({f['provider']}, {f['scope'] or '-'}) | {f['title']} | "
                         f"{money(f['monthly_savings'], f['currency'])} | {f['basis']} | {risk} | {f['action']} |")
        if r["unpriced_count"]:
            lines += ["", f"{r['unpriced_count']} finding(s) have no price: add a resource-level cost export "
                          "to price them from your actual bill."]
    if r["top_spend"]:
        lines += ["", "## Top spend (from cost export, monthly run-rate)", "", "| Resource | Monthly |", "|---|---:|"]
        lines += [f"| `{x['resource_id'].split('/')[-1]}` | {money(x['monthly'], x['currency'])} |" for x in r["top_spend"]]
    if r["aws_spend_by_service"]:
        lines += ["", "## AWS spend by service (period in export)", "", "| Service | Cost (USD) |", "|---|---:|"]
        lines += [f"| {x['service']} | {x['cost']:,.2f} |" for x in r["aws_spend_by_service"][:10]]
    if r["skipped"]:
        lines += ["", "## Files not used", ""] + [f"- `{s['file']}`: {s['reason']}" for s in r["skipped"]]
    lines += ["", "---", "Read-only analysis. No resource was changed. Apply fixes through a pull request "
                  "(IaC) or the owning team's change process."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Rank cloud cost savings from exported, read-only data.")
    ap.add_argument("paths", nargs="+", help="files or folders with exports")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--out-dir", help="write cost-scout-report.md and cost-scout-report.json here")
    ap.add_argument("--as-of", help="reference date YYYY-MM-DD for age checks (default: today, UTC)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    report = analyse(a.paths, parse_date(a.as_of) if a.as_of else None)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "cost-scout-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        Path(a.out_dir, "cost-scout-report.md").write_text(to_markdown(report), encoding="utf-8")
        print(f"wrote {a.out_dir}/cost-scout-report.md and .json "
              f"({report['finding_count']} findings)")
    else:
        sys.stdout.write(json.dumps(report, indent=2) + "\n" if a.json else to_markdown(report))
    return 0 if report["inputs"] else 1


if __name__ == "__main__":
    sys.exit(main())

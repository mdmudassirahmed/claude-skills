#!/usr/bin/env python3
"""cost_scout - turn read-only cloud cost exports into a ranked, evidence-backed savings list.

Reads any mix of these files (format auto-detected, never needs cloud access itself):
  Azure  advisor.json      az advisor recommendation list --category Cost -o json
  Azure  *.json (ARG)      az graph query -q "<query from references/azure-idle-resources.kql>" --first 1000 -o json
  Azure  *.json (ARG)      same, with references/azure-optimisation-candidates.kql (schedules, rate,
                           storage tiering, workspace settings; rows carry scoutQuery=optimisation-candidates)
  Azure  cost export .csv  Cost Management > Cost analysis / Exports (resource-level, daily or monthly)
  Azure  usage.json        Log Analytics Usage query (az monitor log-analytics query, or {"tables": [...]})
  AWS    CUR .csv          Cost and Usage Report (lineItem/ResourceId, lineItem/UnblendedCost, ...)
  AWS    ce.json           aws ce get-cost-and-usage ... --group-by Type=DIMENSION,Key=SERVICE
  AWS    volumes.json      aws ec2 describe-volumes --filters Name=status,Values=available
  AWS    addresses.json    aws ec2 describe-addresses
  AWS    instances.json    aws ec2 describe-instances
  AWS    optimizer.json    aws compute-optimizer get-ec2-instance-recommendations

Every $ figure carries its basis:
  advisor / compute-optimizer / actual-cost  -> "confirmed" (from the provider or the real bill)
  list-price-estimate                        -> "estimated" (../references/aws-approx-prices.json)
  *-estimate (schedule, tiering, logs)       -> "estimated" (../references/optimisation-assumptions.json)
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
ASSUMPTIONS_FILE = HERE.parent / "references" / "optimisation-assumptions.json"

CONFIRMED_BASES = {"advisor", "compute-optimizer", "actual-cost"}
BASIS_RANK = {"advisor": 4, "compute-optimizer": 4, "actual-cost": 3, "list-price-estimate": 2, "unknown": 0}
PROD_VALUES = {"prod", "production", "prd", "live"}
KEEP_TAGS = {"do-not-delete", "donotdelete", "keep", "retain", "legal-hold"}
HOURS_PER_MONTH = 730
DAYS_PER_MONTH = 30.4

NONPROD_VALUES = {"dev", "development", "test", "testing", "qa", "uat", "sandbox", "sbx", "nonprod", "non-prod", "demo"}
EXEMPT_MARKERS = {"schedule-exempt", "scheduleexempt", "always-on", "alwayson", "24x7", "24/7"}
OWNER_TAG_KEYS = ["owner", "createdby", "costcenter", "cost-center", "team", "app-owner"]
_OWNER_NORM = {"owner", "createdby", "created-by", "costcenter", "cost-center", "costcentre", "cost-centre",
               "team", "app-owner", "appowner"}
BATCH_TOKENS = {"batch", "worker", "workers", "build", "builds", "builder", "render", "renderer", "rendering"}
LOG_METER_WORDS = ("log analytics", "azure monitor", "application insights", "insight and analytics")
OPT_QUERY_MARKERS = {"optimisation-candidates", "optimization-candidates"}
USAGE_WINDOW_DAYS = 31  # the documented Usage query looks back 31 days
NEW_CATEGORIES = ("schedule", "storage", "logging")  # estimated opportunities
RATE = "rate"


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


def short_name(rid):
    """Last meaningful part of an Azure id or an AWS ARN / id."""
    last = (rid or "").rstrip("/").split("/")[-1]
    if last.startswith("arn:"):
        last = last.split(":")[-1]
    return last


def month_key(d):
    return "%04d-%02d" % (d.year, d.month) if d else None


def new_finding(**kw):
    f = {
        "resource_id": "", "name": "", "provider": "", "resource_type": "", "scope": "",
        "category": "other", "title": "", "action": "", "monthly_savings": None,
        "currency": None, "basis": "unknown", "risk": "low", "risk_notes": [],
        "tags": {}, "sources": [], "evidence": {}, "check": None,
    }
    f.update(kw)
    return f


def name_tokens(*texts):
    """Word tokens of resource / group names ("rg-web-dev01" -> {rg, web, dev}) plus whether
    the text says non-prod ("non-prod", "nonprod", "non_prod")."""
    toks, nonprod = set(), False
    for t in texts:
        s = str(t or "").lower()
        if re.search(r"(^|[^a-z0-9])non[-_]?prod", s):
            nonprod = True
        s = re.sub(r"non[-_]?prod(uction)?", " ", s)
        for tok in re.split(r"[^a-z0-9]+", s):
            tok = re.sub(r"\d+$", "", tok)
            if tok:
                toks.add(tok)
    return toks, nonprod


def environment_class(tags, *texts):
    """'prod', 'nonprod' or None. An environment/env/stage tag wins; otherwise name tokens decide,
    and any production token beats a non-production one (safer to leave prod alone)."""
    tl = {str(k).strip().lower(): str(v).strip().lower() for k, v in (tags or {}).items()}
    env = tl.get("environment") or tl.get("env") or tl.get("stage")
    if env:
        if env in PROD_VALUES:
            return "prod"
        if env in NONPROD_VALUES:
            return "nonprod"
    toks, nonprod = name_tokens(*texts)
    if toks & PROD_VALUES:
        return "prod"
    if nonprod or toks & NONPROD_VALUES:
        return "nonprod"
    return None


def schedule_exempt(tags):
    for k, v in (tags or {}).items():
        kn = str(k).strip().lower().replace("_", "-")
        vn = str(v).strip().lower().replace("_", "-")
        if kn in EXEMPT_MARKERS and vn not in ("false", "no", "0", "off"):
            return True
        if vn in EXEMPT_MARKERS:
            return True
    return False


def is_owner_key(k):
    kn = str(k).strip().lower()
    for p in ("user:", "user_", "aws:"):
        if kn.startswith(p):
            kn = kn[len(p):]
    return kn.replace("_", "-").replace(" ", "-") in _OWNER_NORM


def parse_tag_text(s):
    """Tags cell from a cost export. Azure writes '"env": "dev","owner": "a"' (no braces);
    FOCUS / some exports write proper JSON; older ones key=value;key=value."""
    s = (s or "").strip()
    if not s:
        return {}
    for cand in (s, "{" + s + "}"):
        try:
            v = json.loads(cand)
        except ValueError:
            continue
        if isinstance(v, dict):
            return {str(k): "" if x is None else str(x) for k, x in v.items()}
    pairs = re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', s)
    if pairs:
        return dict(pairs)
    out = {}
    for part in re.split(r"[;,]", s):
        if "=" in part:
            k, v = part.split("=", 1)
        elif ":" in part:
            k, v = part.split(":", 1)
        else:
            continue
        k = k.strip().strip('"{} ')
        if k:
            out[k] = v.strip().strip('"{} ')
    return out


def load_json_reference(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------ detection
def csv_flavour(path):
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            head = fh.readline().lower()
    except OSError:
        return "azure-cost-csv"
    return "aws-cur-csv" if ("lineitem/" in head or "line_item_" in head) else "azure-cost-csv"


def _has_usage_columns(names):
    low = {str(n).lower() for n in names}
    return "datatype" in low and bool(low & {"ingestedgb", "billablegb", "quantity"})


def detect(path, data):
    if path.suffix.lower() == ".csv":
        return csv_flavour(path)
    if isinstance(data, dict):
        if "ResultsByTime" in data:
            return "aws-ce"
        if "Volumes" in data:
            return "aws-volumes"
        if "Addresses" in data:
            return "aws-addresses"
        if "Reservations" in data:
            return "aws-ec2-instances"
        if "instanceRecommendations" in data:
            return "aws-compute-optimizer"
        tables = data.get("tables")
        if isinstance(tables, list) and tables and isinstance(tables[0], dict) and _has_usage_columns(
                [c.get("name", "") for c in (tables[0].get("columns") or []) if isinstance(c, dict)]):
            return "azure-log-usage"
        if isinstance(data.get("data"), list):
            return "azure-arg"
        if isinstance(data.get("value"), list):
            data = data["value"]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        first = data[0]
        if "shortDescription" in first and "category" in first:
            return "azure-advisor"
        if _has_usage_columns(first.keys()):
            return "azure-log-usage"
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
        rows = data.get("data") or data.get("value") or []
    else:
        rows = data
    return [r for r in rows if isinstance(r, dict)]


def is_optimisation_row(row):
    return str(get(row, "scoutQuery", default="")).strip().lower() in OPT_QUERY_MARKERS


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


# ------------------------------------------------------------------ cost exports (Azure + AWS CUR)
COST_COLS = ["costinbillingcurrency", "cost", "pretaxcost", "costinusd", "unblendedcost", "billedcost", "effectivecost",
             "lineitem/unblendedcost", "line_item_unblended_cost"]
ID_COLS = ["resourceid", "instanceid", "resource id", "resourceuri", "lineitem/resourceid", "line_item_resource_id"]
CUR_COLS = ["billingcurrency", "billingcurrencycode", "currency", "currencycode",
            "lineitem/currencycode", "line_item_currency_code"]
DATE_COLS = ["date", "usagedate", "usagedatetime", "chargeperiodstart", "billingperiodstartdate",
             "lineitem/usagestartdate", "line_item_usage_start_date"]
SERVICE_COLS = ["metercategory", "servicename", "product/productname", "product_product_name", "product/servicename",
                "lineitem/productcode", "line_item_product_code", "consumedservice", "productname"]
RG_COLS = ["resourcegroup", "resourcegroupname", "x_resourcegroupname"]
TAG_COLS = ["tags", "resource_tags"]


def pick(header, candidates):
    low = {h.lower().strip(): h for h in header}
    for c in candidates:
        if c in low:
            return low[c]
    return None


def cur_tag_columns(header):
    """AWS CUR tag columns: resourceTags/user:owner, resourceTags/aws:createdBy, resource_tags_user_owner."""
    out = []
    for h in header:
        hs = h.strip()
        hl = hs.lower()
        for pre in ("resourcetags/", "resource_tags_"):
            if hl.startswith(pre) and len(hl) > len(pre):
                key = hs[len(pre):]
                for p in ("user:", "aws:", "user_"):
                    if key.lower().startswith(p):
                        key = key[len(p):]
                        break
                out.append((h, key))
                break
    return out


def read_cost_file(path):
    """Parse one cost CSV (Azure cost export, FOCUS or AWS CUR) into
    {"rows": {(rid, date, currency, service, rg): amount}, "tags": {(rid, month): {..}}, ...}."""
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    header = reader.fieldnames or []
    c_id, c_cost, c_cur, c_date = (pick(header, ID_COLS), pick(header, COST_COLS),
                                   pick(header, CUR_COLS), pick(header, DATE_COLS))
    if not c_id or not c_cost:
        raise ValueError(f"{path}: cost CSV needs a resource-id column and a cost column; found {header}")
    c_svc, c_rg, c_tags = pick(header, SERVICE_COLS), pick(header, RG_COLS), pick(header, TAG_COLS)
    cur_tags = cur_tag_columns(header)
    has_tags = bool(c_tags or cur_tags)
    rows, tags, bad, undated = {}, {}, 0, 0
    for row in reader:
        amt = to_float(row.get(c_cost))
        if amt is None:
            bad += 1
            continue
        rid = norm_id(row.get(c_id))
        d = parse_date(row.get(c_date)) if c_date else None
        if c_date and d is None:
            undated += 1
        cur = ((row.get(c_cur) or "").strip() or "USD") if c_cur else "USD"
        svc = (row.get(c_svc) or "").strip() if c_svc else ""
        rg = ((row.get(c_rg) or "").strip() if c_rg else "") or resource_group_of(rid)
        key = (rid, d, cur, svc, rg.lower())
        rows[key] = rows.get(key, 0.0) + amt
        if has_tags and rid:
            t = parse_tag_text(row.get(c_tags)) if c_tags else {}
            for col, k in cur_tags:
                v = (row.get(col) or "").strip()
                if v:
                    t[k] = v
            slot = tags.setdefault((rid, month_key(d)), {})
            for k, v in t.items():
                if k not in slot or not slot[k]:
                    slot[k] = v
    return {"rows": rows, "tags": tags, "has_tags": has_tags, "bad_rows": bad, "undated_rows": undated,
            "has_service": bool(c_svc)}


def combine_cost_files(parsed):
    """Merge several cost files. If two files cover the same resource on the same day (overlapping
    exports), the first file (sorted by path) wins so the day is not counted twice."""
    owner, entries, tags = {}, {}, {}
    info = {"has_tags": False, "bad_rows": 0, "undated_rows": 0, "has_service": False, "files": len(parsed)}
    for i, p in enumerate(parsed):
        for key, amt in p["rows"].items():
            if owner.setdefault((key[0], key[1]), i) != i:
                continue
            entries[key] = entries.get(key, 0.0) + amt
        for k, v in p["tags"].items():
            slot = tags.setdefault(k, {})
            for tk, tv in v.items():
                if tk not in slot or not slot[tk]:
                    slot[tk] = tv
        for k in ("has_tags", "has_service"):
            info[k] = info[k] or p[k]
        for k in ("bad_rows", "undated_rows"):
            info[k] += p[k]
    return entries, tags, info


def days_by_month(entries):
    span = {}
    for (rid, d, cur, svc, rg) in entries:
        if d:
            m = month_key(d)
            lo, hi = span.get(m, (d, d))
            span[m] = (min(lo, d), max(hi, d))
    return {m: (hi - lo).days + 1 for m, (lo, hi) in span.items()}


def _main_currency(by_cur):
    return sorted(by_cur.items(), key=lambda kv: (-abs(kv[1]), kv[0]))[0][0]


def resource_costs(entries, days_of):
    """{rid: {"monthly", "total", "currency", "days"}} from the LATEST month's per-day run rate
    (x 30.4). Resources seen only in undated rows fall back to a 30-day period."""
    months = sorted(days_of)
    latest = months[-1] if months else None
    per, undated, dated_rids = {}, {}, set()
    for (rid, d, cur, svc, rg), amt in entries.items():
        if not rid:
            continue
        if d is None:
            slot = undated.setdefault(rid, {})
            slot[cur] = slot.get(cur, 0.0) + amt
            continue
        dated_rids.add(rid)
        if month_key(d) == latest:
            slot = per.setdefault(rid, {})
            slot[cur] = slot.get(cur, 0.0) + amt
    out = {}
    for rid, by_cur in per.items():
        cur = _main_currency(by_cur)
        days = days_of[latest]
        out[rid] = {"monthly": round(by_cur[cur] * DAYS_PER_MONTH / days, 2), "total": round(by_cur[cur], 2),
                    "currency": cur, "days": days}
    for rid, by_cur in undated.items():
        if rid in dated_rids:
            continue
        cur = _main_currency(by_cur)
        out[rid] = {"monthly": round(by_cur[cur] * DAYS_PER_MONTH / 30, 2), "total": round(by_cur[cur], 2),
                    "currency": cur, "days": 30}
    return out


def service_costs(entries, days_of):
    """{rid: {service: monthly run rate}} for the latest month (unrounded)."""
    months = sorted(days_of)
    if not months:
        return {}
    latest, out = months[-1], {}
    factor = DAYS_PER_MONTH / days_of[latest]
    for (rid, d, cur, svc, rg), amt in entries.items():
        if rid and d and month_key(d) == latest:
            slot = out.setdefault(rid, {})
            slot[svc] = slot.get(svc, 0.0) + amt * factor
    return out


def cost_csv(path):
    """Return {resource_id: {"monthly": float, "currency": str, "total": float, "days": int}}
    for one file (kept for callers of the original single-file API)."""
    entries, _, _ = combine_cost_files([read_cost_file(path)])
    return resource_costs(entries, days_by_month(entries))


def _diff_rows(prev, latest, fp, fl, label, extra=None):
    items = []
    for k in sorted(set(prev) | set(latest)):
        p, l = prev.get(k, 0.0) * fp, latest.get(k, 0.0) * fl
        item = {label: k}
        if extra:
            item.update(extra(k))
        item.update({"previous_monthly": round(p, 2), "latest_monthly": round(l, 2), "change": round(l - p, 2),
                     "change_pct": round(100.0 * (l - p) / p, 1) if abs(p) > 0.005 else None})
        items.append(item)
    ups = sorted((x for x in items if x["change"] > 0), key=lambda x: (-x["change"], x[label]))
    downs = sorted((x for x in items if x["change"] < 0), key=lambda x: (x["change"], x[label]))
    return ups, downs


def bill_change(entries, days_of, info=None):
    """Latest calendar month vs the previous one in the data, per-day run rate x 30.4 so a
    partial month compares fairly with a full one."""
    months = sorted(days_of)
    if not entries:
        return {"status": "no-cost-data", "months": [],
                "message": "No cost export was supplied, so the bill change cannot be shown."}
    if not months:
        return {"status": "no-dates", "months": [],
                "message": "The cost export has no usable date column, so months cannot be compared."}
    if len(months) == 1:
        return {"status": "single-month", "months": months,
                "message": f"The cost data covers one calendar month ({months[0]}), so there is nothing to "
                           "compare it with. Add the previous month's cost export to see what changed."}
    lm, pm = months[-1], months[-2]
    fl, fp = DAYS_PER_MONTH / days_of[lm], DAYS_PER_MONTH / days_of[pm]
    by_cur = {}
    for (rid, d, cur, svc, rg), amt in entries.items():
        m = month_key(d)
        if m not in (lm, pm):
            continue
        slot = by_cur.setdefault(cur, {"total": {lm: 0.0, pm: 0.0}, "res": ({}, {}), "svc": ({}, {}), "rg": ({}, {})})
        slot["total"][m] += amt
        i = 1 if m == lm else 0
        if rid:
            slot["res"][i][rid] = slot["res"][i].get(rid, 0.0) + amt
        s = svc or "(unknown service)"
        slot["svc"][i][s] = slot["svc"][i].get(s, 0.0) + amt
        g = rg or "(no resource group)"
        slot["rg"][i][g] = slot["rg"][i].get(g, 0.0) + amt
    y, mo = int(lm[:4]), int(lm[5:])
    expected_prev = "%04d-%02d" % ((y, mo - 1) if mo > 1 else (y - 1, 12))
    notes = []
    if pm != expected_prev:
        notes.append(f"{pm} is the latest earlier month in the data; the months in between are missing.")
    if len(months) > 2:
        notes.append(f"Older months in the data ({', '.join(months[:-2])}) are not part of this comparison.")
    if info and info.get("undated_rows"):
        notes.append(f"{info['undated_rows']} row(s) had no usable date and are left out of the comparison.")
    out_cur = {}
    for cur in sorted(by_cur):
        s = by_cur[cur]
        p_total, l_total = s["total"][pm] * fp, s["total"][lm] * fl
        ups, downs = _diff_rows(s["res"][0], s["res"][1], fp, fl, "resource_id", lambda k: {"name": short_name(k)})
        sups, sdowns = _diff_rows(s["svc"][0], s["svc"][1], fp, fl, "service")
        gups, gdowns = _diff_rows(s["rg"][0], s["rg"][1], fp, fl, "resource_group")
        new = sorted(({"resource_id": k, "name": short_name(k), "latest_monthly": round(v * fl, 2)}
                      for k, v in s["res"][1].items() if abs(v) > 0.005 and abs(s["res"][0].get(k, 0.0)) <= 0.005),
                     key=lambda x: (-x["latest_monthly"], x["resource_id"]))
        gone = sorted(({"resource_id": k, "name": short_name(k), "previous_monthly": round(v * fp, 2)}
                       for k, v in s["res"][0].items() if abs(v) > 0.005 and abs(s["res"][1].get(k, 0.0)) <= 0.005),
                      key=lambda x: (-x["previous_monthly"], x["resource_id"]))
        out_cur[cur] = {
            "previous_monthly": round(p_total, 2), "latest_monthly": round(l_total, 2),
            "change": round(l_total - p_total, 2),
            "change_pct": round(100.0 * (l_total - p_total) / p_total, 1) if abs(p_total) > 0.005 else None,
            "top_increases_by_resource": ups[:10], "top_decreases_by_resource": downs[:5],
            "top_increases_by_service": sups[:10], "top_decreases_by_service": sdowns[:5],
            "top_increases_by_resource_group": gups[:10], "top_decreases_by_resource_group": gdowns[:5],
            "new_resources": new[:10], "new_resource_count": len(new),
            "gone_resources": gone[:10], "gone_resource_count": len(gone),
        }
    return {"status": "compared", "months": months, "latest_month": lm, "previous_month": pm,
            "latest_days": days_of[lm], "previous_days": days_of[pm], "normalised_days": DAYS_PER_MONTH,
            "method": "per-day run rate of each month x 30.4, so partial months compare fairly",
            "notes": notes, "by_currency": out_cur}


def tagging_summary(entries, tags, days_of, info):
    """Share of the latest month's spend on resources without an owner-type tag."""
    if not entries:
        return {"status": "no-cost-data", "owner_tag_keys": OWNER_TAG_KEYS,
                "message": "No cost export was supplied, so tag coverage of spend cannot be measured."}
    if not info.get("has_tags"):
        return {"status": "no-tag-column", "owner_tag_keys": OWNER_TAG_KEYS,
                "message": "The cost export has no Tags column (Azure) or resourceTags/* columns (AWS CUR). "
                           "Include tags in the export to measure how much spend has no owner."}
    months = sorted(days_of)
    period = months[-1] if months else None
    factor = DAYS_PER_MONTH / days_of[period] if period else DAYS_PER_MONTH / 30
    per, unattributed = {}, {}
    for (rid, d, cur, svc, rg), amt in entries.items():
        if month_key(d) != period:
            continue
        if not rid:
            unattributed[cur] = unattributed.get(cur, 0.0) + amt
            continue
        if (rid, period) not in tags:
            continue  # came from a file without tag columns
        slot = per.setdefault(cur, {})
        slot[rid] = slot.get(rid, 0.0) + amt
    by_cur = {}
    for cur in sorted(per):
        total = untagged = 0.0
        tagged_n = untagged_n = 0
        rows = []
        for rid, amt in per[cur].items():
            monthly = amt * factor
            total += monthly
            t = tags.get((rid, period), {})
            owned = any(is_owner_key(k) and str(v).strip() for k, v in t.items())
            if owned:
                tagged_n += 1
            else:
                untagged_n += 1
                untagged += monthly
                rows.append({"resource_id": rid, "name": short_name(rid), "monthly": round(monthly, 2),
                             "tags": {k: t[k] for k in sorted(t)}})
        rows.sort(key=lambda x: (-x["monthly"], x["resource_id"]))
        by_cur[cur] = {"total_monthly": round(total, 2), "untagged_monthly": round(untagged, 2),
                       "untagged_pct": round(100.0 * untagged / total, 1) if abs(total) > 0.005 else 0.0,
                       "tagged_resources": tagged_n, "untagged_resources": untagged_n,
                       "top_untagged": rows[:10],
                       "unattributed_monthly": round(unattributed.get(cur, 0.0) * factor, 2)}
    return {"status": "ok", "period": period, "owner_tag_keys": OWNER_TAG_KEYS,
            "method": "latest month's run rate; a resource counts as owned if any owner-type tag has a value",
            "by_currency": by_cur}


# ------------------------------------------------------------------ optimisation checks (Azure ARG rows)
def _power_state(row):
    v = get(row, "powerState")
    if isinstance(v, dict):
        v = get(v, "code")
    if not v:
        props = row.get("properties") or {}
        v = get(props, "extended", "instanceView", "powerState", "code") or get(props, "powerState", "code")
    return str(v or "").strip().lower()


def _first(*vals):
    for v in vals:
        if v not in (None, ""):
            return v
    return None


def _aks_managed(row):
    return any(str(k).lower().startswith("aks-managed") for k in tags_of(row)) or \
        str(row.get("resourceGroup", "")).lower().startswith("mc_")


def _vm_facts(row):
    props = row.get("properties") or {}
    vmp = get(props, "virtualMachineProfile") or {}
    return {
        "os": str(_first(get(row, "osType"), get(props, "storageProfile", "osDisk", "osType"),
                         get(vmp, "storageProfile", "osDisk", "osType")) or "").lower(),
        "publisher": str(_first(get(props, "storageProfile", "imageReference", "publisher"),
                                get(vmp, "storageProfile", "imageReference", "publisher")) or "").lower(),
        "license": str(_first(get(row, "licenseType"), get(props, "licenseType"), get(vmp, "licenseType")) or ""),
        "priority": str(_first(get(row, "priority"), get(props, "priority"), get(vmp, "priority")) or "Regular"),
        "size": _first(get(props, "hardwareProfile", "vmSize"), get(row, "sku", "name")),
    }


def _base(row, provider="azure"):
    rid = row.get("id", "")
    return dict(resource_id=rid, name=row.get("name") or rid.split("/")[-1], provider=provider,
                resource_type=str(row.get("type", "")).lower(), scope=row.get("resourceGroup", ""),
                tags=tags_of(row), sources=["azure-resource-graph"])


def _schedule_saving(cost, currency, a):
    office, week = a.get("office_hours_per_week"), a.get("hours_per_week") or 168
    if cost is None or office is None:
        return None, None, "unknown"
    return round(cost * (1 - float(office) / float(week)), 2), currency, "schedule-estimate"


SCHEDULE_NOTE = "confirm nobody works off-hours or runs overnight jobs on it"
RESERVATION_NOTE = "if it is covered by a reservation or savings plan, switching it off saves nothing"


def _schedule_finding(base, kind, cost, currency, a, extra_evidence):
    saving, cur, basis = _schedule_saving(cost, currency, a)
    office = a.get("office_hours_per_week")
    actions = {
        "vm": "Add a weekday office-hours schedule in IaC or automation (Azure VM auto-shutdown plus a start "
              "schedule, or Start/Stop VMs v2). Done by the owning team's IaC or pipeline, not by this skill.",
        "vmss": "Scale the scale set to 0 outside office hours with an autoscale schedule profile in IaC "
                "(or Start/Stop VMs v2). Done by the owning team's IaC or pipeline, not by this skill.",
        "aks": "Stop the cluster outside office hours with `az aks stop` / `az aks start`, run by a person or a "
               "scheduled pipeline owned by the team. Not run by this skill.",
        "ec2": "Schedule it with AWS Instance Scheduler (or EventBridge Scheduler) defined in IaC; for Auto "
               "Scaling groups use scheduled scaling actions. Done by the owning team, not by this skill.",
    }
    label = {"vm": "VM", "vmss": "VM scale set", "aks": "AKS cluster", "ec2": "EC2 instance"}[kind]
    ev = {"monthlyComputeCost": cost, "officeHoursPerWeek": office,
          "scheduleAssumption": (f"weekdays only, {office} of {a.get('hours_per_week') or 168} hours a week"
                                 if office is not None else "no office-hours assumption found"),
          "assumptionsNote": a.get("_note")}
    ev.update(extra_evidence)
    return new_finding(category="schedule", check="schedule",
                       title=f"Non-production {label} runs around the clock: switch it off outside office hours",
                       action=actions[kind], monthly_savings=saving, currency=cur, basis=basis,
                       risk="medium", risk_notes=[SCHEDULE_NOTE, RESERVATION_NOTE], evidence=ev, **base)


def _sql_ahb(base, lic):
    return new_finding(
        category=RATE, check="ahb-sql",
        title=f"SQL pays the SQL Server licence in the rate (license type {lic}): Azure Hybrid Benefit candidate",
        action="If the organisation has SQL Server core licences with Software Assurance, set the license type "
               "to BasePrice (databases / managed instances) or AHUB (SQL VMs) in IaC.",
        risk="medium", risk_notes=["licensing: only with eligible SQL Server licences; "
                                   "check with whoever manages licences"],
        evidence={"licenseType": lic,
                  "condition": "Needs SQL Server Enterprise or Standard core licences with active Software "
                               "Assurance (or subscription licences) covering the vCores",
                  "typical_effect": "removes the SQL Server licence part of the price; biggest on vCore "
                                    "General Purpose and Business Critical"},
        **base)


def _is_batchy(name, tags):
    toks, _ = name_tokens(name)
    return bool(toks & BATCH_TOKENS) or any(
        str(k).lower() in ("workload", "workload-type", "workloadtype") and str(v).lower() == "batch"
        for k, v in tags.items())


def azure_optimisation_findings(rows, costs, a):
    """Schedules, rate optimisations and storage tiering from rows of azure-optimisation-candidates.kql."""
    out = []
    shutdown_targets = set()
    for row in rows:
        if str(row.get("type", "")).lower() == "microsoft.devtestlab/schedules":
            props = row.get("properties") or {}
            if str(get(props, "status", default="")).lower() == "enabled" and \
                    str(get(props, "taskType", default="")).lower() == "computevmshutdowntask":
                shutdown_targets.add(norm_id(get(props, "targetResourceId")))
    tier_ratio = a.get("standard_ssd_price_ratio_vs_premium")
    tier_by_size = a.get("standard_ssd_price_ratio_by_size_gb") or {}

    def ratio_for(size_gb):
        """Smallest listed size that fits the disk; else the flat fallback ratio."""
        try:
            size = float(size_gb)
        except (TypeError, ValueError):
            return tier_ratio
        fits = sorted((float(k), v) for k, v in tier_by_size.items() if float(k) >= size)
        return fits[0][1] if fits else tier_ratio

    hot_min = a.get("hot_storage_account_min_monthly_cost")
    for row in rows:
        rtype = str(row.get("type", "")).lower()
        props = row.get("properties") or {}
        rid, name, rg, tags = row.get("id", ""), row.get("name") or "", row.get("resourceGroup", ""), tags_of(row)
        env = environment_class(tags, rg, name)
        cost = costs.get(norm_id(rid))
        state = _power_state(row)
        base = _base(row)

        if rtype in ("microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets"):
            vm = _vm_facts(row)
            is_vmss = rtype.endswith("scalesets")
            if is_vmss:
                capacity = to_float(get(row, "sku", "capacity"))
                running = bool(capacity and capacity > 0)
            else:
                running = "running" in state
            stopped = (not running) and (is_vmss or "deallocat" in state or "stopped" in state)
            aks_pool = is_vmss and _aks_managed(row)
            if running and env == "nonprod" and not aks_pool and not schedule_exempt(tags) \
                    and norm_id(rid) not in shutdown_targets:
                out.append(_schedule_finding(base, "vmss" if is_vmss else "vm",
                                             cost["monthly"] if cost else None, cost["currency"] if cost else None, a,
                                             {"vmSize": vm["size"], "powerState": state or None,
                                              "capacity": get(row, "sku", "capacity") if is_vmss else None}))
            if not stopped and vm["os"] == "windows" and "desktop" not in vm["publisher"] \
                    and vm["license"].lower() not in ("windows_server", "windows_client"):
                out.append(new_finding(
                    category=RATE, check="ahb-windows",
                    title="Windows Server pays the Windows licence in the hourly rate (no Azure Hybrid Benefit)",
                    action="If the organisation has eligible Windows Server licences with Software Assurance or "
                           "subscriptions, set licenseType: Windows_Server in IaC (no redeploy needed).",
                    risk="medium", risk_notes=["licensing: only with eligible Windows Server licences; "
                                               "check with whoever manages licences"],
                    evidence={"licenseType": vm["license"] or None, "osType": vm["os"],
                              "condition": "Needs Windows Server licences with active Software Assurance or "
                                           "subscriptions, enough cores to cover the VM",
                              "typical_effect": "removes the Windows licence part of the compute price; the "
                                                "size of that part depends on the VM size (see the pricing page)"},
                    **base))
            if env == "nonprod" and _is_batchy(name, tags) and not stopped and not aks_pool \
                    and vm["priority"].lower() != "spot":
                out.append(new_finding(
                    category=RATE, check="spot",
                    title="Non-production batch / build / worker compute on regular pricing: Spot candidate",
                    action="If the work can be retried, move it to Spot priority (with an eviction policy) in IaC.",
                    risk="medium", risk_notes=["Spot capacity can be taken back at short notice; "
                                               "only for interruptible, retryable work"],
                    evidence={"priority": vm["priority"],
                              "condition": "Workload must tolerate eviction (about 30 seconds notice) and restart "
                                           "cleanly; capacity is not guaranteed",
                              "typical_effect": "Spot prices are usually well below pay-as-you-go but vary by "
                                                "region and size and can change"},
                    **base))

        elif rtype == "microsoft.containerservice/managedclusters":
            if state == "running" and env == "nonprod" and not schedule_exempt(tags):
                node_rg = str(_first(get(props, "nodeResourceGroup"), get(row, "nodeResourceGroup")) or "").lower()
                pool_cost, cur, pools = 0.0, None, []
                if node_rg:
                    marker = f"/resourcegroups/{node_rg}/providers/microsoft.compute/virtualmachinescalesets/"
                    for crid in sorted(costs):
                        if marker in crid:
                            pool_cost += costs[crid]["monthly"]
                            cur = cur or costs[crid]["currency"]
                            pools.append(short_name(crid))
                out.append(_schedule_finding(base, "aks", round(pool_cost, 2) if pools else None, cur, a,
                                             {"nodeResourceGroup": node_rg or None, "nodePoolScaleSets": pools}))

        elif rtype in ("microsoft.sql/servers/databases", "microsoft.sql/servers/elasticpools",
                       "microsoft.sql/managedinstances"):
            lic = str(_first(get(row, "licenseType"), get(props, "licenseType")) or "")
            if lic.lower() == "licenseincluded" and name.lower() != "master":
                out.append(_sql_ahb(base, lic))
        elif rtype == "microsoft.sqlvirtualmachine/sqlvirtualmachines":
            lic = str(_first(get(row, "licenseType"), get(props, "sqlServerLicenseType")) or "")
            edition = str(get(props, "sqlImageSku", default="") or "").lower()
            if lic.lower() == "payg" and edition not in ("developer", "express"):
                out.append(_sql_ahb(base, lic))

        elif rtype == "microsoft.resources/subscriptions":
            quota = str(_first(get(row, "quotaId"), get(props, "subscriptionPolicies", "quotaId")) or "")
            q = quota.lower()
            if environment_class(tags, name) == "nonprod" and "devtest" not in q \
                    and ("payasyougo" in q or "enterpriseagreement" in q):
                b = dict(base, scope=row.get("subscriptionId") or "")
                out.append(new_finding(
                    category=RATE, check="devtest-offer",
                    title="Non-production subscription on a standard offer: Dev/Test pricing candidate",
                    action="Ask the billing owner to move this workload to an Azure Dev/Test subscription "
                           "(Pay-As-You-Go Dev/Test or Enterprise Dev/Test).",
                    risk="medium", risk_notes=["only for non-production work; no production workloads may run in it"],
                    evidence={"quotaId": quota,
                              "condition": "Only for development and testing; everyone using the subscription "
                                           "needs an active Visual Studio subscription; no financially backed SLA",
                              "typical_effect": "no Windows or SQL Server licence charges on VMs and discounted "
                                                "rates on some services"},
                    **b))

        elif rtype == "microsoft.compute/disks":
            sku = str(get(row, "sku", "name", default="") or "").lower()
            disk_state = str(get(props, "diskState", default="") or "").lower()
            if sku in ("premium_lrs", "premium_zrs") and disk_state in ("attached", "reserved") and env == "nonprod":
                c = cost["monthly"] if cost else None
                disk_ratio = ratio_for(get(props, "diskSizeGB"))
                if c is not None and disk_ratio is not None:
                    saving, cur, basis = round(c * (1 - float(disk_ratio)), 2), cost["currency"], "tier-change-estimate"
                else:
                    saving, cur, basis = None, None, "unknown"
                out.append(new_finding(
                    category="storage", check="premium-disk",
                    title=f"Premium SSD in non-production ({get(row, 'sku', 'name')}, {get(props, 'diskSizeGB')} GB): "
                          "Standard SSD is usually enough",
                    action="Change the disk sku to StandardSSD_LRS (or _ZRS) in IaC; the VM must be deallocated "
                           "for the change, so do it in a quiet window. Check IOPS/throughput needs first.",
                    monthly_savings=saving, currency=cur, basis=basis, risk="medium",
                    risk_notes=["lower IOPS and throughput than Premium SSD - check the workload's disk metrics"],
                    evidence={"sku": get(row, "sku", "name"), "sizeGB": get(props, "diskSizeGB"),
                              "diskMonthlyCost": c, "priceRatioStandardVsPremium": disk_ratio,
                              "assumptionsNote": a.get("_note")},
                    **base))

        elif rtype == "microsoft.storage/storageaccounts":
            tier = str(_first(get(row, "accessTier"), get(props, "accessTier")) or "").lower()
            if tier == "hot" and cost and hot_min is not None and cost["monthly"] > float(hot_min):
                out.append(new_finding(
                    category="storage", check="blob-lifecycle",
                    title=f"Hot storage account costing {cost['currency']} {cost['monthly']:,.2f}/month: "
                          "add a lifecycle rule",
                    action="If it does not have one yet, add a lifecycle management policy in IaC: move blobs to "
                           "Cool after 30 days without change and to Archive after 180 (or delete if not needed).",
                    risk="medium", risk_notes=["cool/archive tiers charge for reads, early deletion and "
                                               "rehydration - check how the data is read first"],
                    evidence={"accessTier": "Hot", "kind": row.get("kind") or get(props, "kind"),
                              "accountMonthlyCost": cost["monthly"], "threshold": hot_min,
                              "typical_effect": "cool and archive storage cost less per GB than hot; the saving "
                                                "depends on how much data is old and rarely read"},
                    **base))
    return out


# ------------------------------------------------------------------ logging (Log Analytics / App Insights)
def usage_rows(data):
    """Rows of the Usage query from `az monitor log-analytics query` (list of dicts) or the
    REST / App Insights shape {"tables": [{"columns": [...], "rows": [[...]]}]}."""
    if isinstance(data, dict) and isinstance(data.get("tables"), list):
        rows = []
        for t in data["tables"]:
            if not isinstance(t, dict):
                continue
            cols = [c.get("name", "") if isinstance(c, dict) else str(c) for c in (t.get("columns") or [])]
            for r in t.get("rows") or []:
                if isinstance(r, list):
                    rows.append(dict(zip(cols, r)))
    elif isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    else:
        rows = []
    clean = []
    for r in rows:
        table = str(get(r, "DataType", default="") or "").strip()
        gb = to_float(_first(get(r, "IngestedGB"), get(r, "BillableGB")))
        if gb is None and get(r, "Quantity") is not None:
            q = to_float(get(r, "Quantity"))
            gb = q / 1024 if q is not None else None
        if not table or gb is None or gb < 0:
            continue
        clean.append({"table": table, "solution": str(get(r, "Solution", default="") or ""), "gb": gb,
                      "workspace": str(_first(get(r, "Workspace"), get(r, "WorkspaceName")) or "").strip()})
    if not clean:
        raise ValueError("Log Analytics usage export has no rows with DataType and IngestedGB")
    return clean


def _token_in(needle, hay):
    return re.search(r"(^|[^a-z0-9])" + re.escape(needle) + r"([^a-z0-9]|$)", hay) is not None


def _assign_usage(usage_files, registry):
    groups = {}
    for path, rows in usage_files:
        stem = Path(path).stem.lower()
        by_label = {}
        for r in rows:
            if r["workspace"]:
                label, how = r["workspace"].lower(), "workspace column"
            else:
                hits = sorted((n for n in registry if n and _token_in(n, stem)), key=lambda n: (-len(n), n))
                if hits:
                    label, how = hits[0], "file name"
                elif len(registry) == 1:
                    label, how = next(iter(registry)), "only workspace in the data"
                else:
                    label, how = "unmatched:" + stem, None
            by_label.setdefault((label, how), []).append(r)
        for (label, how), rs in sorted(by_label.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
            if label in groups:
                groups[label]["notes"].append(f"ignored a second usage export for this workspace ({Path(path).name})")
                continue
            groups[label] = {"rows": rs, "matched_by": how, "file": str(path), "notes": []}
    return groups


def _table_finding(check, table, gb, share, ws_name, ws_rid, share_cost, ws_cost, ws_cur, a, f_base):
    if check == "basic-logs":
        ratio = a.get("basic_logs_price_ratio")
        ratio_saving = (1 - float(ratio)) if ratio is not None else None
        basis_name = "basic-logs-estimate"
        title = (f"Table {table} ingests {gb:,.1f} GB a month ({100.0 * share:.0f}% of the workspace): "
                 "candidate for the Basic or Auxiliary logs plan")
        action = ("If the table is used for troubleshooting rather than alerts or dashboards, set its plan to "
                  "Basic (or Auxiliary) in IaC (the table resource's plan property). Check the table supports it "
                  "in your region.")
        if table.lower() == "apptraces":
            action += " Also lower the logging level or add sampling in the app."
        notes = ["Basic/Auxiliary tables have limited query features and do not support most alert rules - "
                 "check what queries the table first"]
    else:
        ratio = a.get("sampling_volume_reduction")
        ratio_saving = float(ratio) if ratio is not None else None
        basis_name = "sampling-estimate"
        title = (f"Table {table} ingests {gb:,.1f} GB a month ({100.0 * share:.0f}% of the workspace): "
                 "turn on sampling or lower verbosity")
        action = ("Enable or tighten Application Insights sampling (or lower the log level) in the app "
                  "configuration, deployed through the normal pipeline.")
        notes = ["sampling drops a share of telemetry - keep enough for incident investigation"]
    if share_cost is not None and ratio_saving is not None:
        saving, cur, basis = round(share_cost * ratio_saving, 2), ws_cur, basis_name
    else:
        saving, cur, basis = None, None, "unknown"
    return new_finding(
        resource_id=(ws_rid or f"log-analytics:{ws_name}") + "/tables/" + table,
        name=f"{ws_name}/{table}", category="logging", check=check, title=title, action=action,
        monthly_savings=saving, currency=cur, basis=basis, risk="medium", risk_notes=notes,
        evidence={"workspace": ws_name, "table": table, "billableGB": round(gb, 2),
                  "sharePct": round(100.0 * share, 1), "tableMonthlyCost": share_cost,
                  "tableMonthlyCostBasis": "actual-cost" if share_cost is not None else None,
                  "workspaceMonthlyCost": ws_cost, "savingRatio": ratio_saving,
                  "assumptionsNote": a.get("_note")},
        **f_base)


def logging_analysis(usage_files, ws_rows, costs, svc_costs, a):
    """Returns (findings, per-workspace logging section)."""
    registry = {}
    for row in ws_rows:
        registry[str(row.get("name", "")).lower()] = {"resource_id": row.get("id", ""), "row": row}
    for rid in sorted(costs):
        if "/providers/microsoft.operationalinsights/workspaces/" in rid:
            registry.setdefault(short_name(rid), {"resource_id": rid, "row": None})
    groups = _assign_usage(usage_files, registry)

    basic_tables = {t.lower() for t in a.get("basic_logs_candidate_tables") or []}
    sampling_tables = {t.lower() for t in a.get("sampling_candidate_tables") or []}
    min_gb = a.get("logging_min_table_gb_month")
    max_ret, commit_gb = a.get("interactive_retention_days_max"), a.get("commitment_tier_min_gb_per_day")

    findings, sections = [], []
    labels = sorted(set(groups) | set(n for n in registry if registry[n]["row"] is not None))
    for label in labels:
        reg = registry.get(label) or {}
        row = reg.get("row")
        ws_rid = reg.get("resource_id") or ""
        ws_name = label[len("unmatched:"):] if label.startswith("unmatched:") else label
        if row is not None:
            ws_name = row.get("name") or ws_name
        props = (row or {}).get("properties") or {}
        retention = to_float(_first(get(row or {}, "retentionInDays"), get(props, "retentionInDays")))
        sku = _first(get(props, "sku", "name"), get(row or {}, "sku", "name"))
        cap = to_float(get(props, "workspaceCapping", "dailyQuotaGb"))
        tags = tags_of(row) if row else {}
        rg = (row or {}).get("resourceGroup", "") or resource_group_of(ws_rid)
        env = environment_class(tags, rg, ws_name)
        ws_cost, ws_cur = None, None
        c = costs.get(norm_id(ws_rid)) if ws_rid else None
        if c:
            ws_cur = c["currency"]
            by_svc = svc_costs.get(norm_id(ws_rid))
            if by_svc:
                logging_part = sum(v for s, v in by_svc.items()
                                   if not s or any(w in s.lower() for w in LOG_METER_WORDS))
                ws_cost = round(logging_part, 2) if logging_part > 0 else None
            else:
                ws_cost = c["monthly"]
        g = groups.get(label)
        sec = {"workspace": ws_name, "resource_id": ws_rid or None, "matched_by": g["matched_by"] if g else None,
               "usage_file": g["file"] if g else None, "monthly_cost": ws_cost, "currency": ws_cur,
               "cost_basis": "actual-cost" if ws_cost is not None else None,
               "retention_days": retention, "sku": sku, "daily_cap_gb": cap, "billable_gb": None,
               "gb_per_day": None, "tables": [], "notes": list(g["notes"]) if g else []}
        if g and g["matched_by"] is None:
            sec["notes"].append("could not tell which workspace this usage export belongs to; name the file after "
                                "the workspace (e.g. usage-<workspace>.json) to price it")
        elif g and ws_cost is None:
            sec["notes"].append("no logging cost for this workspace in the cost export, so tables are unpriced")
        f_base = dict(provider="azure", resource_type="microsoft.operationalinsights/workspaces", scope=rg,
                      tags=tags, sources=["azure-log-usage"] if g else ["azure-resource-graph"])
        if g:
            agg = {}
            for r in g["rows"]:
                slot = agg.setdefault(r["table"], {"gb": 0.0, "solutions": set()})
                slot["gb"] += r["gb"]
                if r["solution"]:
                    slot["solutions"].add(r["solution"])
            total = sum(v["gb"] for v in agg.values())
            sec["billable_gb"] = round(total, 2)
            sec["gb_per_day"] = round(total / USAGE_WINDOW_DAYS, 2)
            for table, v in sorted(agg.items(), key=lambda kv: (-kv[1]["gb"], kv[0])):
                share = v["gb"] / total if total > 0 else 0.0
                share_cost = round(ws_cost * share, 2) if ws_cost is not None else None
                tl = table.lower()
                big = min_gb is None or v["gb"] >= float(min_gb)
                check = ("basic-logs" if tl in basic_tables and big
                         else "sampling" if tl in sampling_tables and big else None)
                suggestion = {"basic-logs": "Basic or Auxiliary logs plan",
                              "sampling": "sampling / lower verbosity"}.get(check) or (
                    "small table" if not big else
                    "review who uses it; trim diagnostic settings or drop unused columns with a transformation")
                sec["tables"].append({"table": table, "solutions": sorted(v["solutions"]), "gb": round(v["gb"], 2),
                                      "share_pct": round(100.0 * share, 1), "monthly_cost_share": share_cost,
                                      "cost_share_basis": "actual-cost (apportioned by GB share)"
                                      if share_cost is not None else None, "suggestion": suggestion})
                if check:
                    findings.append(_table_finding(check, table, v["gb"], share, ws_name, ws_rid, share_cost,
                                                   ws_cost, ws_cur, a, f_base))
            per_day = total / USAGE_WINDOW_DAYS
            if commit_gb is not None and sku and str(sku).lower() == "pergb2018" and per_day >= float(commit_gb):
                findings.append(new_finding(
                    resource_id=ws_rid or f"log-analytics:{ws_name}", name=ws_name, category=RATE,
                    check="commitment-tier",
                    title=f"Workspace ingests about {per_day:,.0f} GB a day on pay-as-you-go: commitment tier candidate",
                    action="Ask the owner to compare commitment tiers with the current per-GB price and set the "
                           "chosen tier in IaC.",
                    risk="medium", risk_notes=["a commitment tier bills the committed volume even on quiet days"],
                    evidence={"gbPerDay": round(per_day, 2), "sku": sku,
                              "condition": "Daily ingestion must stay at or above the tier on most days; the "
                                           "tier is committed for at least 31 days",
                              "typical_effect": "a lower price per GB than pay-as-you-go at that volume"},
                    **f_base))
            sec["tables"] = sec["tables"][:10]
        if row is not None and retention is not None and max_ret is not None and retention > float(max_ret):
            findings.append(new_finding(
                resource_id=ws_rid, name=ws_name, category="logging", check="retention",
                title=f"Interactive retention is {int(retention)} days (more than {int(float(max_ret))})",
                action=f"Keep {int(float(max_ret))} days or less interactive and move older data to long-term "
                       "(archive) retention per table in IaC, if nobody needs to query it quickly.",
                risk="medium", risk_notes=["archived data must be restored or searched before use - "
                                           "check audit and compliance needs"],
                evidence={"retentionInDays": retention, "sku": sku,
                          "typical_effect": "long-term retention costs much less per GB than interactive"},
                **f_base))
        if row is not None and env == "nonprod" and (cap is None or cap < 0):
            findings.append(new_finding(
                resource_id=ws_rid, name=ws_name, category="logging", check="daily-cap",
                title="Non-production workspace has no daily cap",
                action="Set a daily cap (workspaceCapping.dailyQuotaGb) in IaC so a noisy deployment "
                       "cannot run up the bill.",
                risk="medium", risk_notes=["when the cap is hit, ingestion stops until the next day and log "
                                           "alerts go quiet"],
                evidence={"dailyQuotaGb": cap}, **f_base))
        sections.append(sec)
    sections.sort(key=lambda s: (s["workspace"].lower(), s["usage_file"] or ""))
    return findings, sections


# ------------------------------------------------------------------ AWS
def load_prices():
    return load_json_reference(PRICES_FILE)


def load_assumptions():
    return load_json_reference(ASSUMPTIONS_FILE)


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


def aws_instances(data):
    out = []
    for res in data.get("Reservations") or []:
        if isinstance(res, dict):
            out += [i for i in (res.get("Instances") or []) if isinstance(i, dict)]
    return out


def aws_instance_findings(instances, costs, a):
    out = []
    for inst in instances:
        iid = str(inst.get("InstanceId") or "")
        if not iid or str(get(inst, "State", "Name", default="")).lower() != "running":
            continue
        tags = tags_of(inst)
        name = tags.get("Name") or iid
        if environment_class(tags, name) != "nonprod":
            continue
        base = dict(resource_id=iid, name=name, provider="aws", resource_type="ec2/instance",
                    scope=get(inst, "Placement", "AvailabilityZone", default="") or "", tags=tags,
                    sources=["aws-ec2-instances"])
        cost = costs.get(norm_id(iid))
        if not schedule_exempt(tags):
            asg = next((v for k, v in tags.items() if k.lower() == "aws:autoscaling:groupname"), None)
            out.append(_schedule_finding(base, "ec2", cost["monthly"] if cost else None,
                                         cost["currency"] if cost else None, a,
                                         {"instanceType": inst.get("InstanceType"), "autoScalingGroup": asg}))
        if _is_batchy(name, tags) and str(inst.get("InstanceLifecycle") or "").lower() != "spot":
            out.append(new_finding(
                category=RATE, check="spot",
                title="Non-production batch / build / worker instance on On-Demand pricing: Spot candidate",
                action="If the work can be retried, run it on Spot Instances (for example a Spot-backed Auto "
                       "Scaling group) defined in IaC.",
                risk="medium", risk_notes=["Spot capacity can be taken back with a 2-minute warning; "
                                           "only for interruptible, retryable work"],
                evidence={"instanceType": inst.get("InstanceType"),
                          "condition": "Workload must tolerate interruption (2-minute notice) and restart cleanly",
                          "typical_effect": "Spot prices are usually well below On-Demand but vary by type, "
                                            "zone and time"},
                **base))
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
def merge_key(f):
    key = norm_id(f["resource_id"]) or f"{f['provider']}:{f['name']}:{f['title']}"
    return key + ("#" + f["check"] if f.get("check") else "")


def merge(findings):
    merged = {}
    for f in findings:
        key = merge_key(f)
        if key not in merged:
            merged[key] = f
            continue
        m = merged[key]
        m["sources"] = sorted(set(m["sources"]) | set(f["sources"]))
        m["evidence"].update({k: v for k, v in f["evidence"].items() if k not in m["evidence"]})
        m["tags"] = m["tags"] or f["tags"]
        m["risk_notes"] = sorted(set(m["risk_notes"]) | set(f["risk_notes"]))
        if BASIS_RANK.get(f["basis"], 1) > BASIS_RANK.get(m["basis"], 1):
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
        if f["category"] == "idle" and BASIS_RANK.get(f["basis"], 1) < BASIS_RANK["actual-cost"]:
            f["monthly_savings"], f["currency"], f["basis"] = c["monthly"], c["currency"], "actual-cost"


def note_overlaps(findings):
    """Savings on the same resource do not simply add up (a right-sized VM that is also
    switched off at night saves less than both figures together)."""
    by_res = {}
    for f in findings:
        if f["monthly_savings"] is not None and f["resource_id"]:
            by_res.setdefault(norm_id(f["resource_id"]), []).append(f)
    for fs in by_res.values():
        if len(fs) < 2:
            continue
        for f in fs:
            others = sorted({o["category"] for o in fs if o is not f})
            f["risk_notes"] = sorted(set(f["risk_notes"]) | {
                f"overlaps with the {', '.join(others)} finding for the same resource - "
                "doing both saves less than the sum"})


def assess_risk(f):
    tags_low = {k.lower(): str(v).lower() for k, v in f["tags"].items()}
    env = tags_low.get("environment") or tags_low.get("env") or tags_low.get("stage")
    scope = re.sub(r"non[-_]?prod", "", (f["scope"] or "").lower())
    if env in PROD_VALUES or re.search(r"(^|[-_/])(prod|prd)([-_/]|$)", scope):
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


def compute_totals(findings):
    totals = {}
    for f in findings:
        if f["monthly_savings"] is None or f["category"] == RATE:
            continue
        bucket = "confirmed" if f["basis"] in CONFIRMED_BASES else "estimated"
        lane = "needs_owner_decision" if f["risk"] == "high" else "actionable"
        cur = totals.setdefault(f["currency"] or "USD", {
            "actionable": {"confirmed": 0.0, "estimated": 0.0},
            "needs_owner_decision": {"confirmed": 0.0, "estimated": 0.0}})
        cur[lane][bucket] = round(cur[lane][bucket] + f["monthly_savings"], 2)
    return totals


def analyse(paths, as_of=None):
    as_of = as_of or datetime.now(timezone.utc).date()
    prices, assumptions = load_prices(), load_assumptions()
    findings, spend, inputs, skipped = [], [], [], []
    cost_files, opt_rows, instances, usage_files = [], [], [], []
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
                opt_rows += [r for r in arg_rows(data) if is_optimisation_row(r)]
            elif kind in ("azure-cost-csv", "aws-cur-csv"):
                cost_files.append(read_cost_file(path))
            elif kind == "azure-log-usage":
                usage_files.append((path, usage_rows(data)))
            elif kind == "aws-volumes":
                findings += aws_volume_findings(data, prices, as_of)
            elif kind == "aws-addresses":
                findings += aws_address_findings(data, prices)
            elif kind == "aws-ec2-instances":
                instances += aws_instances(data)
            elif kind == "aws-compute-optimizer":
                findings += aws_optimizer_findings(data)
            elif kind == "aws-ce":
                spend += aws_ce_summary(data)
        except ValueError as e:
            skipped.append({"file": str(path), "reason": str(e)})
            continue
        inputs.append({"file": str(path), "type": kind})

    entries, cost_tags, cost_info = combine_cost_files(cost_files)
    days_of = days_by_month(entries)
    costs = resource_costs(entries, days_of)
    svc_costs = service_costs(entries, days_of)

    findings += azure_optimisation_findings(opt_rows, costs, assumptions)
    findings += aws_instance_findings(instances, costs, assumptions)
    ws_rows = [r for r in opt_rows if str(r.get("type", "")).lower() == "microsoft.operationalinsights/workspaces"]
    logging_section = []
    if usage_files or ws_rows:
        log_findings, logging_section = logging_analysis(usage_files, ws_rows, costs, svc_costs, assumptions)
        findings += log_findings

    findings = merge(findings)
    enrich_with_cost(findings, costs)
    for f in findings:
        assess_risk(f)
    note_overlaps(findings)
    findings.sort(key=lambda f: (f["monthly_savings"] is None, -(f["monthly_savings"] or 0)))

    top_spend = sorted(({"resource_id": k, **v} for k, v in costs.items()), key=lambda x: -x["monthly"])[:10]
    return {
        "generated_for": str(as_of), "inputs": inputs, "skipped": skipped,
        "totals_monthly": compute_totals(findings), "finding_count": len(findings),
        "unpriced_count": sum(1 for f in findings if f["monthly_savings"] is None),
        "findings": findings, "top_spend": top_spend, "aws_spend_by_service": spend,
        "bill_change": bill_change(entries, days_of, cost_info),
        "tagging": tagging_summary(entries, cost_tags, days_of, cost_info),
        "logging": {"workspaces": logging_section,
                    "message": None if logging_section else
                    "No Log Analytics usage export or workspace settings were supplied "
                    "(see references/export-commands.md)."},
        "assumptions": {"file": "references/optimisation-assumptions.json", "loaded": bool(assumptions),
                        "values": {k: assumptions[k] for k in sorted(assumptions) if not k.startswith("_")},
                        "note": assumptions.get("_note")},
    }


def money(v, cur):
    return "unknown" if v is None else f"{cur or ''} {v:,.2f}".strip()


def _pct(v):
    return "n/a" if v is None else f"{v:+.1f}%"


def _finding_rows(fs):
    rows = []
    for i, f in enumerate(fs, 1):
        risk = f["risk"] + (f" - {'; '.join(f['risk_notes'])}" if f["risk_notes"] else "")
        rows.append(f"| {i} | `{f['name']}` ({f['provider']}, {f['scope'] or '-'}) | {f['title']} | "
                    f"{money(f['monthly_savings'], f['currency'])} | {f['basis']} | {risk} | {f['action']} |")
    return rows


def _bill_change_md(bc):
    lines = ["", "## Bill change (latest month vs the one before)", ""]
    if bc["status"] != "compared":
        return lines + [bc["message"]]
    lines.append(f"{bc['latest_month']} ({bc['latest_days']} day(s) of data) compared with {bc['previous_month']} "
                 f"({bc['previous_days']} day(s)), each as a per-day run rate x 30.4 so partial months compare fairly.")
    for n in bc["notes"]:
        lines.append(f"- {n}")
    for cur, c in bc["by_currency"].items():
        lines += ["", f"**{cur}: {c['previous_monthly']:,.2f} -> {c['latest_monthly']:,.2f} per month, "
                      f"{c['change']:+,.2f} ({_pct(c['change_pct'])})**"]
        for key, label, col in (("top_increases_by_resource", "Biggest increases by resource", "resource_id"),
                                ("top_decreases_by_resource", "Biggest decreases by resource", "resource_id"),
                                ("top_increases_by_service", "Increases by service", "service"),
                                ("top_decreases_by_service", "Decreases by service", "service"),
                                ("top_increases_by_resource_group", "Increases by resource group", "resource_group"),
                                ("top_decreases_by_resource_group", "Decreases by resource group", "resource_group")):
            if not c[key]:
                continue
            head = {"resource_id": "Resource", "service": "Service", "resource_group": "Resource group"}[col]
            lines += ["", f"{label}:", "", f"| {head} | Before | Now | Change | % |", "|---|---:|---:|---:|---:|"]
            for x in c[key]:
                label_v = f"`{x['name']}`" if col == "resource_id" else x[col]
                lines.append(f"| {label_v} | {x['previous_monthly']:,.2f} | {x['latest_monthly']:,.2f} | "
                             f"{x['change']:+,.2f} | {_pct(x['change_pct'])} |")
        if c["new_resources"]:
            lines += ["", f"New this month ({c['new_resource_count']}): " + ", ".join(
                f"`{x['name']}` {x['latest_monthly']:,.2f}" for x in c["new_resources"])]
        if c["gone_resources"]:
            lines += ["", f"Gone this month ({c['gone_resource_count']}): " + ", ".join(
                f"`{x['name']}` {x['previous_monthly']:,.2f}" for x in c["gone_resources"])]
    return lines


def _tagging_md(t):
    lines = ["", "## Tagging hygiene (spend with no owner)", ""]
    if t["status"] != "ok":
        return lines + [t["message"]]
    keys = ", ".join(t["owner_tag_keys"])
    for cur, c in t["by_currency"].items():
        lines.append(f"{cur} {c['untagged_monthly']:,.2f} of {c['total_monthly']:,.2f} per month "
                     f"({c['untagged_pct']:.1f}%) in {t['period'] or 'the export'} is on {c['untagged_resources']} "
                     f"resource(s) with no owner-type tag ({keys}).")
        if c["unattributed_monthly"]:
            lines.append(f"A further {cur} {c['unattributed_monthly']:,.2f} per month has no resource id "
                         "(tax, support, marketplace) and is not counted.")
        if c["top_untagged"]:
            lines += ["", "| Untagged resource | Monthly |", "|---|---:|"]
            lines += [f"| `{x['name']}` | {x['monthly']:,.2f} |" for x in c["top_untagged"]]
    return lines


def _logging_md(lg):
    lines = ["", "## Logging (Log Analytics / Application Insights)", ""]
    if not lg["workspaces"]:
        return lines + [lg["message"]]
    for w in lg["workspaces"]:
        cost = (money(w["monthly_cost"], w["currency"]) + " per month (actual cost)"
                if w["monthly_cost"] is not None else "cost not in the export")
        gb = (f"{w['billable_gb']:,.1f} GB billable in {USAGE_WINDOW_DAYS} days" if w["billable_gb"] is not None
              else "no usage export")
        ret = f"retention {int(w['retention_days'])} days" if w["retention_days"] is not None else "retention unknown"
        lines.append(f"- `{w['workspace']}`: {gb}, {cost}, {ret}, sku {w['sku'] or 'unknown'}")
        for n in w["notes"]:
            lines.append(f"  - {n}")
        if w["tables"]:
            lines += ["", "| Table | GB | Share | Cost share / month | Suggestion |", "|---|---:|---:|---:|---|"]
            lines += [f"| {x['table']} | {x['gb']:,.1f} | {x['share_pct']:.1f}% | "
                      f"{money(x['monthly_cost_share'], w['currency'])} | {x['suggestion']} |" for x in w["tables"]]
            lines.append("")
    lines.append("_Cost share = the workspace's actual logging cost split by each table's share of billable GB. "
                 "Savings on these tables are estimates from references/optimisation-assumptions.json._")
    return lines


def to_markdown(r):
    lines = ["# Cloud Cost Scout report", "",
             f"_As of {r['generated_for']} · {len(r['inputs'])} input file(s) · {r['finding_count']} finding(s)_", ""]
    core = [f for f in r["findings"] if f["category"] not in NEW_CATEGORIES + (RATE,)]
    opps = [f for f in r["findings"] if f["category"] in NEW_CATEGORIES]
    rate = [f for f in r["findings"] if f["category"] == RATE]
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
                      "Estimated = from list prices or stated assumptions (schedules, disk tiers, log plans); "
                      "verify before quoting. "
                      "High-risk items (production, retention tags) need their owner's decision first. "
                      "Rate optimisations have no price and are never in these totals._", ""]
        if core:
            lines += ["## Findings (highest saving first)", "",
                      "| # | Resource | Finding | Saving / month | Basis | Risk | Action |",
                      "|---|---|---|---:|---|---|---|"]
            lines += _finding_rows(core)
            unpriced = sum(1 for f in core if f["monthly_savings"] is None)
            if unpriced:
                lines += ["", f"{unpriced} finding(s) have no price: add a resource-level cost export "
                              "to price them from your actual bill."]
        if opps:
            lines += ["", "## Estimated opportunities (schedules, storage, logging)", "",
                      "| # | Resource | Opportunity | Saving / month | Basis | Risk | Action |",
                      "|---|---|---|---:|---|---|---|"]
            lines += _finding_rows(opps)
            lines += ["", "_Estimated from your actual cost and the ratios in references/optimisation-assumptions.json "
                          "(schedule = weekdays, 12 hours a day). \"unknown\" = no cost data for the resource, or a "
                          "setting change with no reliable price; not in the totals._"]
        if rate:
            lines += ["", "## Rate optimisations (no price; check the condition first)", "",
                      "| Resource | Opportunity | Condition | Typical effect | Risk | Action |",
                      "|---|---|---|---|---|---|"]
            for f in rate:
                ev = f["evidence"]
                lines.append(f"| `{f['name']}` ({f['provider']}, {f['scope'] or '-'}) | {f['title']} | "
                             f"{ev.get('condition', '-')} | {ev.get('typical_effect', '-')} | {f['risk']} | "
                             f"{f['action']} |")
    lines += _bill_change_md(r["bill_change"])
    lines += _tagging_md(r["tagging"])
    lines += _logging_md(r["logging"])
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

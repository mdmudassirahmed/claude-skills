#!/usr/bin/env python3
"""infra_changes - read control-plane exports (what changed in the cloud, not in the code)
and keep only the real changes, for log_detective.py.

Recognised exports (auto-detected by shape, never counted as log records):
  Azure Activity Log   az monitor activity-log list --offset 24h -o json
                       (also the Log Analytics AzureActivity table as JSON)
  AWS CloudTrail       aws cloudtrail lookup-events ... -o json   ({"Events": [...]})
                       (also raw CloudTrail files from S3: {"Records": [...]})
  AWS Health           aws health describe-events ... -o json      ({"events": [...eventTypeCode...]})

Kept: write / delete / action operations that succeeded and change behaviour (config and
app settings writes, slot swaps, restarts, scale operations, network rules, Key Vault and
identity changes, deployments). Dropped: reads, failed attempts and noise. Secret or key
listing is not a change but is noted separately. Service Health / Resource Health / AWS
Health entries are returned as platform events.

Caller identities are pseudonymised through the shared Redactor (emails become <email-N>,
other user names <user-N>, GUID principals <principal-N>); only platform service callers
(e.g. autoscaling.amazonaws.com) are kept as they are. Request bodies, properties, ARNs
with account numbers and subscription ids are never returned.
Standard library only; Python 3.8+.
"""
import json
import re

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# ------------------------------------------------------------------ classification tables
# (regex on the lower-cased Azure operation / resource id, category, priority)
AZ_RULES = [
    (re.compile(r"microsoft\.resources/deployments/write|/sites(/slots)?/(deployments|publish|extensions|"
                r"sourcecontrols|onedeploy|zipdeploy)|microsoft\.app/containerapps/write|"
                r"microsoft\.containerinstance/containergroups/write"), "deployment", 3),
    (re.compile(r"slotsswap|applyslotconfig"), "slot-swap", 3),
    (re.compile(r"/(stop|poweroff|deallocate)/action"), "restart", 3),
    (re.compile(r"/(restart|reboot|start|redeploy)/action"), "restart", 2),
    (re.compile(r"/sites(/slots)?/config/(write|delete)|/appsettings|/connectionstrings|"
                r"microsoft\.appconfiguration/"), "app-config", 3),
    (re.compile(r"autoscale|/serverfarms/write|virtualmachinescalesets/(write|scale)|/agentpools/write|"
                r"microsoft\.sql/servers/databases/write|microsoft\.cache/redis/write|/scale"), "scale", 2),
    (re.compile(r"microsoft\.network/|/firewallrules/|/virtualnetworkrules/|/networkrulesets|microsoft\.cdn/"),
     "network", 3),
    (re.compile(r"microsoft\.keyvault/|/regeneratekey|/rotatekey|microsoft\.authorization/roleassignments|"
                r"microsoft\.managedidentity/|/certificates/"), "secrets-identity", 3),
    (re.compile(r"microsoft\.web/sites(/slots)?/write"), "app-config", 2),
]
AZ_NOISE_VERBS = {"audit", "auditifnotexists", "deployifnotexists", "validate", "checknameavailability",
                  "checkpolicycompliance", "register"}
# Writes that never change runtime behaviour (tags, locks, diagnostic/alert wiring, advisor).
AZ_NOISE_OPS = re.compile(r"microsoft\.resources/tags/|/providers/microsoft\.resources/tags|microsoft\.authorization/locks/|"
                          r"microsoft\.insights/(diagnosticsettings|alertrules|activitylogalerts|metricalerts|"
                          r"scheduledqueryrules|actiongroups)/|microsoft\.advisor/|microsoft\.security/")
AZ_CHANGE_CATEGORIES = {"administrative", "autoscale", ""}

# CloudTrail: ordered (regex on EventName, category, priority)
CT_RULES = [
    (re.compile(r"^(UpdateAutoScalingGroup|SetDesiredCapacity|PutScalingPolicy|ModifyDBInstance|ModifyDBCluster|"
                r"ModifyCacheCluster|ModifyReplicationGroup|UpdateTable|PutProvisionedConcurrencyConfig|"
                r"PutFunctionConcurrency|ModifyInstanceAttribute|UpdateCapacityProvider|"
                r"RegisterScalableTarget)$"), "scale", 2),
    (re.compile(r"^(UpdateFunctionCode\w*|PublishVersion\w*|UpdateAlias\w*|UpdateService|RegisterTaskDefinition|"
                r"CreateDeployment|UpdateStack|CreateStack|ExecuteChangeSet|UpdateEnvironment|"
                r"UpdateDeploymentGroup)$"), "deployment", 3),
    (re.compile(r"^(UpdateFunctionConfiguration\w*|PutParameter|DeleteParameters?|UpdateConfigurationProfile|"
                r"StartDeployment|ModifyDBParameterGroup|ModifyDBClusterParameterGroup|"
                r"UpdateApplicationSettings)$"), "app-config", 3),
    (re.compile(r"^(StopInstances|TerminateInstances|StopDBInstance|StopDBCluster|StopTask)$"), "restart", 3),
    (re.compile(r"^(RebootInstances|StartInstances|RebootDBInstance|StartDBInstance|RestartAppServer|"
                r"RebootCacheCluster|RebootBroker)$"), "restart", 2),
    (re.compile(r"SecurityGroup|NetworkAcl|Route(Table)?$|^(Create|Delete|Replace|Associate|Disassociate)Route|"
                r"VpcEndpoint|NatGateway|Subnet|^(ModifyListener|ModifyRule|CreateRule|DeleteRule|RegisterTargets|"
                r"DeregisterTargets|ModifyTargetGroup\w*)$|WebACL|^ChangeResourceRecordSets$"), "network", 3),
    (re.compile(r"^(PutSecretValue|UpdateSecret|RotateSecret|DeleteSecret|UpdateAssumeRolePolicy|CreateAccessKey|"
                r"DeleteAccessKey|UpdateAccessKey|ScheduleKeyDeletion|DisableKey|CreatePolicyVersion|"
                r"SetDefaultPolicyVersion|ImportCertificate|DeleteCertificate)$|"
                r"^(Put|Attach|Detach|Delete)\w*Policy$"), "secrets-identity", 3),
]
CT_READ = re.compile(r"^(Describe|Get|List|Lookup|Head|Search|BatchGet|Scan|Query|Select|Filter|Test|Check|"
                     r"Validate|Preview|View|Estimate|Simulate|Poll)")
CT_SECRET_READS = {"GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters",
                   "GetParametersByPath", "GetPasswordData", "Decrypt", "GetAuthorizationToken",
                   "GetClusterCredentials", "GetFederationToken"}
CT_NOISE = {"ConsoleLogin", "AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML", "GetSessionToken",
            "StartQuery", "StopQuery", "CreateLogStream", "PutLogEvents", "Encrypt", "GenerateDataKey",
            "GenerateDataKeyWithoutPlaintext", "PutMetricData", "SendMessage", "ReceiveMessage", "DeleteMessage",
            "Invoke", "InvokeFunction", "StartSession", "ResumeSession", "TerminateSession", "CheckMfa",
            "SwitchRole", "RenewRole", "Federate", "CredentialVerification", "CredentialChallenge"}

CATEGORY_LABEL = {"deployment": "Deployment", "slot-swap": "Slot swap", "restart": "Restart / stop / start",
                  "app-config": "Configuration change", "scale": "Scale change", "network": "Network rule change",
                  "secrets-identity": "Secret / identity change", "other": "Resource change"}


# ------------------------------------------------------------------ detection
def _rows(data):
    """Row dicts from list / {"value": [...]} / App Insights tables shapes."""
    if isinstance(data, dict) and isinstance(data.get("tables"), list):
        out = []
        for t in data["tables"]:
            cols = [c.get("name") for c in t.get("columns", [])]
            out.extend(dict(zip(cols, r)) for r in t.get("rows", []))
        return out
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def detect(data):
    """Return 'azure-activity-log', 'aws-cloudtrail', 'aws-health' or None."""
    if isinstance(data, dict):
        ev = data.get("Events")
        if isinstance(ev, list) and ev and isinstance(ev[0], dict) and "EventName" in ev[0]:
            return "aws-cloudtrail"
        rec = data.get("Records")
        if isinstance(rec, list) and rec and isinstance(rec[0], dict) and "eventName" in rec[0]:
            return "aws-cloudtrail"
        ev = data.get("events")
        if isinstance(ev, list) and ev and isinstance(ev[0], dict) and "eventTypeCode" in ev[0]:
            return "aws-health"
    rows = _rows(data)
    if rows:
        keys = set(rows[0].keys())
        if "operationName" in keys and ("eventTimestamp" in keys or "submissionTimestamp" in keys):
            return "azure-activity-log"
        if "OperationNameValue" in keys and ("ActivityStatusValue" in keys or "CategoryValue" in keys):
            return "azure-activity-log"
    return None


# ------------------------------------------------------------------ helpers
def _val(v):
    """Activity Log fields are either plain strings or {"value", "localizedValue"}."""
    if isinstance(v, dict):
        return v.get("value") or v.get("localizedValue") or ""
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _label(v):
    if isinstance(v, dict):
        return v.get("localizedValue") or v.get("value") or ""
    return ""


def short_azure_resource(resource_id):
    """/subscriptions/../resourceGroups/rg/providers/Microsoft.Web/sites/app/config/appsettings
    -> ('app/appsettings', 'Microsoft.Web/sites/config', 'rg'). Subscription ids are dropped."""
    rid = (resource_id or "").strip("/")
    parts = rid.split("/")
    low = [p.lower() for p in parts]
    rg = parts[low.index("resourcegroups") + 1] if "resourcegroups" in low and low.index("resourcegroups") + 1 < len(parts) else None
    if "providers" not in low:
        return (parts[-1] if parts and parts[-1] and not GUID.match(parts[-1]) else "(subscription)"), None, rg
    i = len(low) - 1 - low[::-1].index("providers")
    rest = parts[i + 1:]
    if not rest:
        return "(unknown)", None, rg
    ns, pairs = rest[0], rest[1:]
    types, names = pairs[0::2], pairs[1::2]
    return "/".join(names) or ns, "/".join([ns] + types), rg


def short_aws_resource(name):
    """Drop ARN prefixes (and with them the account number): keep the resource name."""
    s = str(name or "")
    if s.startswith("arn:"):
        s = s.split(":", 5)[-1]
        s = s.split("/")[-1] if "/" in s else s.split(":")[-1]
    return s or "(unknown)"


def pseudonymise_caller(caller, redactor):
    """Emails via the shared redactor (same pseudonym as in the logs); anything else that
    names a person or principal gets its own consistent pseudonym. Platform services stay."""
    c = str(caller or "").strip()
    if not c:
        return None
    if re.search(r"\.amazonaws\.com$", c) or c.lower().startswith("microsoft.") or c.lower() in (
            "azure autoscale", "windows azure service management api", "aws internal", "awsservice"):
        return c
    if "@" in c:
        out = redactor.redact(c)
        if out != c:
            return out
    if GUID.match(c):
        return redactor._token("principal", c.lower())
    return redactor._token("user", c)


# ------------------------------------------------------------------ Azure
def classify_azure(op, resource_id, category):
    """-> ('change'|'secret-read'|'drop', change_category, priority)."""
    o = (op or "").lower()
    cat = (category or "").lower()
    last = o.rsplit("/", 1)[-1]
    verb = o.split("/")[-2] if o.count("/") >= 2 else ""
    if last == "read":
        return "drop", None, 0
    if last == "action" and (verb.startswith("list") or verb.startswith("get") or verb in ("publishxml",)):
        return "secret-read", None, 0
    if last not in ("write", "delete", "action") and "scale" not in o:
        return "drop", None, 0
    if last == "action" and verb in AZ_NOISE_VERBS:
        return "drop", None, 0
    if AZ_NOISE_OPS.search(o):
        return "drop", None, 0
    if cat not in AZ_CHANGE_CATEGORIES:
        return "drop", None, 0
    haystack = o + " " + (resource_id or "").lower()
    for rx, c, prio in AZ_RULES:
        if rx.search(haystack):
            return "change", c, prio
    return "change", "other", 1


def _az_describe(category, op_label, resource_short, resource_id):
    rid = (resource_id or "").lower()
    if category == "app-config" and rid.endswith("/appsettings"):
        return "App settings changed"
    if category == "app-config" and rid.endswith("/connectionstrings"):
        return "Connection strings changed"
    return op_label or CATEGORY_LABEL.get(category, "Resource change")


def _impacted_regions(props):
    regions = []
    raw = props.get("impactedServices")
    try:
        items = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except ValueError:
        items = []
    for it in items if isinstance(items, list) else []:
        for r in (it or {}).get("ImpactedRegions", []) or []:
            name = (r or {}).get("RegionName")
            if name and name not in regions:
                regions.append(name)
    if not regions and props.get("region"):
        regions = [x.strip() for x in str(props["region"]).split(",") if x.strip()]
    return regions


def parse_azure(data, redactor, parse_ts):
    changes, reads, health, stats = [], [], [], {"events": 0, "dropped": 0}
    seen, health_by_key = set(), {}
    for row in _rows(data):
        stats["events"] += 1
        la = "OperationNameValue" in row
        ts = parse_ts(row.get("TimeGenerated") if la else (row.get("eventTimestamp") or row.get("submissionTimestamp")))
        op = row.get("OperationNameValue") if la else _val(row.get("operationName"))
        op_label = row.get("OperationName") if la else _label(row.get("operationName"))
        status = (row.get("ActivityStatusValue") if la else _val(row.get("status"))) or ""
        category = (row.get("CategoryValue") if la else _val(row.get("category"))) or ""
        rid = (row.get("_ResourceId") or row.get("ResourceId")) if la else row.get("resourceId")
        props = row.get("Properties_d") or row.get("Properties") if la else row.get("properties")
        if isinstance(props, str):
            try:
                props = json.loads(props)
            except ValueError:
                props = {}
        props = props if isinstance(props, dict) else {}
        if ts is None:
            stats["dropped"] += 1
            continue
        cat_l = category.lower()
        if cat_l in ("servicehealth", "resourcehealth"):
            title = props.get("title") or props.get("defaultLanguageTitle") or op_label or op or ""
            regions = _impacted_regions(props) if cat_l == "servicehealth" else []
            res_short = short_azure_resource(rid)[0] if cat_l == "resourcehealth" else None
            key = ("sh", props.get("trackingId") or title, cat_l, res_short)
            # One entry per incident: time = impact start (else first notice), stage = latest update.
            start = parse_ts(props.get("impactStartTime")) or ts
            stage = props.get("stage") or props.get("currentHealthStatus") or status or None
            if key in health_by_key:
                h = health_by_key[key]
                stats["dropped"] += 1
                h["time"] = min(h["time"], start)
                if ts >= h["_updated"]:
                    h["_updated"], h["stage"] = ts, stage
                continue
            h = {
                "time": start, "provider": "azure-service-health" if cat_l == "servicehealth" else "azure-resource-health",
                "title": redactor.redact(str(title))[:200],
                "service": props.get("service") or (res_short if res_short else None),
                "regions": regions, "type": props.get("incidentType") or props.get("currentHealthStatus"),
                "stage": stage, "tracking_id": props.get("trackingId"), "resource": res_short, "_updated": ts,
            }
            health_by_key[key] = h
            health.append(h)
            continue
        if status.lower() not in ("succeeded", "success"):
            stats["dropped"] += 1
            continue
        kind, ccat, prio = classify_azure(op, rid, category)
        if kind == "drop":
            stats["dropped"] += 1
            continue
        corr = row.get("CorrelationId") if la else row.get("correlationId")
        key = (corr or ts.isoformat(), (op or "").lower(), (rid or "").lower())
        if key in seen:
            stats["dropped"] += 1
            continue
        seen.add(key)
        res_short, res_type, rg = short_azure_resource(rid)
        item = {"time": ts, "platform": "azure", "operation": op, "resource": res_short, "resource_type": res_type,
                "resource_group": rg, "caller": pseudonymise_caller(row.get("Caller") if la else row.get("caller"),
                                                                     redactor)}
        if kind == "secret-read":
            item["description"] = op_label or "Keys / secrets listed"
            reads.append(item)
        else:
            item.update({"category": ccat, "priority": prio,
                         "description": _az_describe(ccat, op_label, res_short, rid)})
            changes.append(item)
    for h in health:
        h.pop("_updated", None)
    return changes, reads, health, stats


# ------------------------------------------------------------------ AWS
def classify_cloudtrail(name, read_only):
    n = name or ""
    if n in CT_SECRET_READS:
        return "secret-read", None, 0
    if n in CT_NOISE:
        return "drop", None, 0
    if str(read_only).lower() == "true" or CT_READ.match(n):
        return "drop", None, 0
    for rx, c, prio in CT_RULES:
        if rx.search(n):
            return "change", c, prio
    return "change", "other", 1


def parse_cloudtrail(data, redactor, parse_ts):
    changes, reads, stats = [], [], {"events": 0, "dropped": 0}
    raw_records = data.get("Records") if isinstance(data.get("Records"), list) else None
    events = data.get("Events") if raw_records is None else raw_records
    seen = set()
    for e in events or []:
        if not isinstance(e, dict):
            continue
        stats["events"] += 1
        if raw_records is not None:          # raw S3 CloudTrail file
            inner = e
            name, t, source = e.get("eventName"), e.get("eventTime"), e.get("eventSource")
            read_only, resources = e.get("readOnly"), e.get("resources") or []
            ident = e.get("userIdentity") or {}
            username = (ident.get("userName") or (ident.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName")
                        or ident.get("invokedBy") or ident.get("principalId"))
        else:
            try:
                inner = json.loads(e.get("CloudTrailEvent") or "{}")
            except ValueError:
                inner = {}
            name, t, source = e.get("EventName"), e.get("EventTime"), e.get("EventSource")
            read_only = e.get("ReadOnly", inner.get("readOnly"))
            resources = e.get("Resources") or []
            username = e.get("Username")
        ts = parse_ts(t)
        if ts is None or not isinstance(inner, dict):
            stats["dropped"] += 1
            continue
        if inner.get("errorCode") or inner.get("errorMessage"):
            stats["dropped"] += 1
            continue
        ident = inner.get("userIdentity") or {}
        if ident.get("type") == "AWSService" and ident.get("invokedBy"):
            username = ident.get("invokedBy")
        kind, ccat, prio = classify_cloudtrail(name, read_only)
        if kind == "drop":
            stats["dropped"] += 1
            continue
        key = (inner.get("eventID") or e.get("EventId") or ts.isoformat() + str(name))
        if key in seen:
            stats["dropped"] += 1
            continue
        seen.add(key)
        res = None
        for r in resources:
            if isinstance(r, dict) and (r.get("ResourceName") or r.get("ARN")):
                res = short_aws_resource(r.get("ResourceName") or r.get("ARN"))
                break
        if res is None:
            rp = inner.get("requestParameters") or {}
            for k in ("groupId", "functionName", "name", "autoScalingGroupName", "dBInstanceIdentifier",
                      "secretId", "cluster", "service", "roleName", "stackName", "bucketName"):
                if isinstance(rp, dict) and rp.get(k):
                    res = short_aws_resource(rp[k])
                    break
        item = {"time": ts, "platform": "aws", "operation": name, "service": (source or "").replace(".amazonaws.com", ""),
                "resource": res or "(unknown)", "region": inner.get("awsRegion"),
                "caller": pseudonymise_caller(username, redactor)}
        if kind == "secret-read":
            item["description"] = "Secret / parameter read"
            reads.append(item)
        else:
            item.update({"category": ccat, "priority": prio, "description": CATEGORY_LABEL.get(ccat, "Resource change")})
            changes.append(item)
    return changes, reads, stats


def parse_aws_health(data, redactor, parse_ts):
    health, stats = [], {"events": 0, "dropped": 0}
    for e in data.get("events") or []:
        if not isinstance(e, dict):
            continue
        stats["events"] += 1
        ts = parse_ts(e.get("startTime") or e.get("lastUpdatedTime"))
        if ts is None:
            stats["dropped"] += 1
            continue
        health.append({"time": ts, "provider": "aws-health",
                       "title": redactor.redact("%s %s" % (e.get("service") or "", e.get("eventTypeCode") or "")).strip(),
                       "service": e.get("service"), "regions": [e["region"]] if e.get("region") else [],
                       "type": e.get("eventTypeCategory"), "stage": e.get("statusCode"), "tracking_id": None,
                       "resource": None})
    return health, stats


def parse(data, kind, redactor, parse_ts):
    """-> (changes, secret_reads, platform_events, stats); every list sorted by time."""
    if kind == "azure-activity-log":
        ch, rd, hl, st = parse_azure(data, redactor, parse_ts)
    elif kind == "aws-cloudtrail":
        ch, rd, st = parse_cloudtrail(data, redactor, parse_ts)
        hl = []
    elif kind == "aws-health":
        ch, rd = [], []
        hl, st = parse_aws_health(data, redactor, parse_ts)
    else:
        return [], [], [], {"events": 0, "dropped": 0}
    order = lambda x: (x["time"], str(x.get("operation") or x.get("title")), str(x.get("resource")))  # noqa: E731
    return sorted(ch, key=order), sorted(rd, key=order), sorted(hl, key=order), st


def health_summary(h):
    where = ", ".join(h.get("regions") or []) or "an unspecified region"
    svc = h.get("service") or "a platform service"
    if h["provider"] == "azure-resource-health":
        return "platform reported a health event on resource %s (%s)" % (h.get("resource") or "?", h.get("title"))
    return "possible platform incident in region %s (%s: %s)" % (where, svc, h.get("title"))

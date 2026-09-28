# Log Detective - KQL library (Application Insights / Log Analytics)

All queries are read-only. Replace `ago(12h)` with your window; add `| where cloud_RoleName == "<service>"` to focus on one service.

**Run and save as JSON**

```bash
# Classic App Insights resource (tables: requests, exceptions, dependencies, traces)
az monitor app-insights query --app <app-insights-name> -g <resource-group> \
  --analytics-query "<query>" -o json > incident-logs/<name>.json

# Workspace-based (tables: AppRequests, AppExceptions, AppDependencies, AppTraces)
az monitor log-analytics query -w <workspace-guid> --analytics-query "<query>" -o json > incident-logs/<name>.json
```
(`az extension add --name application-insights` is needed for the first command.) Portal alternative: Logs blade → run → Export → CSV/JSON.

Row limits: keep results under ~10k rows; the analyser only needs a representative sample. Use `| take 5000` or `| sample 5000` if needed.

---

## 1. Failed requests (App Insights schema)
```kusto
requests
| where timestamp > ago(12h)
| where success == false or toint(resultCode) >= 500
| project timestamp, itemType, name, resultCode, duration, success, operation_Id, cloud_RoleName
| order by timestamp asc
```

## 2. All requests for one operation (for slowness - needs successes too)
```kusto
requests
| where timestamp > ago(12h) and name == "POST /api/orders"
| project timestamp, itemType, name, resultCode, duration, success, operation_Id, cloud_RoleName
| sample 5000
```

## 3. Exceptions with stack details
```kusto
exceptions
| where timestamp > ago(12h)
| project timestamp, itemType, type, outerMessage, details = tostring(details[0].rawStack), problemId,
          operation_Name, operation_Id, cloud_RoleName
| order by timestamp asc
```
If `rawStack` is empty, use `details = tostring(details)`.

## 4. Failed dependencies (SQL, HTTP, Redis, Service Bus…)
```kusto
dependencies
| where timestamp > ago(12h)
| where success == false
| project timestamp, itemType, type, target, name, resultCode, duration, success, operation_Id, cloud_RoleName
| order by timestamp asc
```

## 5. Dependency latency (successes + failures) for one target
```kusto
dependencies
| where timestamp > ago(12h) and target has "sql-orders"
| project timestamp, itemType, type, target, name, resultCode, duration, success
| sample 5000
```

## 6. Error-level traces (application logs)
```kusto
traces
| where timestamp > ago(12h) and severityLevel >= 3
| project timestamp, itemType, severityLevel, message, operation_Name, operation_Id, cloud_RoleName
| order by timestamp asc
```

## 7. One failing operation end-to-end (use an operation_Id from the report)
```kusto
union requests, dependencies, exceptions, traces
| where operation_Id == "<operation id>"
| project timestamp, itemType, name, type, target, resultCode, duration, success, message, outerMessage
| order by timestamp asc
```

## 8. Quick scope check - error rate per 5 min
```kusto
requests
| where timestamp > ago(12h)
| summarize total = count(), failed = countif(success == false) by bin(timestamp, 5m)
| extend failRate = round(100.0 * failed / total, 1)
| order by timestamp asc
```

---

### Workspace-based equivalents
| Classic | Workspace table | Column differences |
|---|---|---|
| `requests` | `AppRequests` | `timestamp`→`TimeGenerated`, `name`→`Name`, `resultCode`→`ResultCode`, `duration`→`DurationMs`, `success`→`Success`, `cloud_RoleName`→`AppRoleName` |
| `exceptions` | `AppExceptions` | `type`→`ExceptionType`, `outerMessage`→`OuterMessage`, `details`→`Details` |
| `dependencies` | `AppDependencies` | `type`→`DependencyType`, `target`→`Target` |
| `traces` | `AppTraces` | `severityLevel`→`SeverityLevel`, `message`→`Message` |

The analyser understands both column sets.

---

## 9. What changed in Azure: Activity Log (control plane)

Infrastructure changes (app settings, slot swaps, restarts, scale, NSG rules, Key Vault) are in
the Activity Log, not in git. Export the same window as the logs (at least 24 h before the onset):

```bash
# Successful operations only (fewer rows; Started/Failed events are dropped by the analyser anyway)
az monitor activity-log list --offset 24h --status Succeeded -o json > incident-logs/activity-log.json

# Narrow to the app's resource group, or an explicit window
az monitor activity-log list -g <resource-group> --start-time 2026-09-26T08:00:00Z \
  --end-time 2026-09-27T12:00:00Z -o json > incident-logs/activity-log.json

# Service Health and Resource Health for the subscription (platform incidents) in the same window.
# Separate export: these events have status Active / Resolved, so --status Succeeded filters them out.
az monitor activity-log list --offset 24h \
  --query "[?category.value=='ServiceHealth' || category.value=='ResourceHealth']" \
  -o json > incident-logs/service-health.json
```
(An export without `--status` contains everything, including `ServiceHealth`; use it when in doubt.)

Drop the file into the same `incident-logs/` folder: the analyser recognises it by shape and never
counts it as log records. It keeps only real changes (successful write / delete / action
operations), drops reads, failed attempts, tag and policy noise, and lists key or secret
**listing** (`listKeys`, `config/list`) separately as "noted, not a change". Callers are
pseudonymised (`<email-1>`, `<principal-1>`); request bodies (which can contain app setting
values) are never output.

If the Activity Log is exported to a Log Analytics workspace, this query gives the same data:

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue in ("Administrative", "Autoscale", "ServiceHealth", "ResourceHealth")
| project TimeGenerated, OperationNameValue, OperationName, ActivityStatusValue, CategoryValue,
          _ResourceId, Caller, CorrelationId, Properties
| order by TimeGenerated asc
```

## 10. Baseline window (is this normal?)

Run the SAME queries for a comparable earlier window, usually the same hours one week earlier,
and save them in a separate folder (`baseline-logs/`), then pass `--baseline baseline-logs/`:

```kusto
exceptions
| where timestamp between (datetime(2026-09-20T06:00:00Z) .. datetime(2026-09-20T10:00:00Z))
| project timestamp, itemType, type, outerMessage, details = tostring(details[0].rawStack), problemId,
          operation_Name, operation_Id, cloud_RoleName
```

## 11. Blast radius columns (who is affected)

Add the user and client columns to the request / exception queries so the analyser can count
distinct affected users, clients and tenants. It only ever outputs counts, never the values.

```kusto
requests
| where timestamp > ago(12h)
| project timestamp, itemType, name, resultCode, duration, success, operation_Id, cloud_RoleName,
          user_Id, user_AuthenticatedId, client_IP, customDimensions
```
Workspace table columns: `UserId`, `UserAuthenticatedId`, `ClientIP`, `Properties`. Tenant or
customer ids are read from `customDimensions` / `Properties` keys such as `TenantId`, `CustomerId`.
Note that App Insights masks `client_IP` as `0.0.0.0` by default; those values are ignored.

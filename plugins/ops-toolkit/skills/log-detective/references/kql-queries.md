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

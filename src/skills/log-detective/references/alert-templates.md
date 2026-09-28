# Log Detective - alert rule templates (prevention)

The analyser proposes ONE alert for the top signature that is new at the onset (and not normal
baseline noise). It is a proposal in text: the skill never creates, updates or deletes an alert.
A human reviews it, fills in the `<placeholders>`, and applies it through their normal change
process (portal, CLI, or the IaC repo).

## How the threshold is chosen

```
threshold = max(5, ceil(3 x p95 of the 5-minute counts))
```

- The counts are of exactly what the proposed query counts (for example every
  `System.Net.Http.HttpRequestException` from that role, not just this one message).
- Source of the "normal" counts: the `--baseline` window when given, otherwise the part of the
  current window before the onset (`threshold_basis.source` says which).
- The rule fires when the count in a 5-minute window is **greater than** the threshold.
- `threshold_basis.would_have_fired_at` shows when the rule would have fired during this
  incident; `null` means the incident peak did not exceed it (lower the threshold only if the
  baseline supports it).
- The floor of 5 avoids paging on single errors.

Check before applying: is the signal specific enough (one role, one exception type), is 5
minutes the right window for this service, and who receives it (action group / SNS topic)?

## Azure: App Insights / Log Analytics scheduled query alert

Query per signature kind. Classic App Insights tables are used when the export had classic
columns (`timestamp`, `itemType`); workspace tables (`AppExceptions` ...) when it had
`TimeGenerated`. The alert scope must match: classic tables need the App Insights resource id,
workspace tables need the Log Analytics workspace id.

| Signature kind | Classic query | Workspace query |
|---|---|---|
| Exception | `exceptions \| where type == "<ExceptionType>"` | `AppExceptions \| where ExceptionType == "<ExceptionType>"` |
| Failed request | `requests \| where success == false and name == "<op>" and resultCode == "<code>"` | `AppRequests \| where Success == false and Name == "<op>" and ResultCode == "<code>"` |
| Failed dependency | `dependencies \| where success == false and target == "<target>"` | `AppDependencies \| where Success == false and Target == "<target>"` |
| Error trace | `traces \| where severityLevel >= 3 and message contains "<text>"` | `AppTraces \| where SeverityLevel >= 3 and Message contains "<text>"` |

A `| where cloud_RoleName == "<role>"` (workspace: `AppRoleName`) line is added when the
signature comes from a single role. For generic exception types (`System.Exception`) the query
matches on the constant part of the message instead.

**CLI** (a human runs it):

```bash
az monitor scheduled-query create \
  --name ld-<signature-slug> \
  --resource-group <resource-group> \
  --scopes <app-insights-or-workspace-resource-id> \
  --condition "count 'Failures' > <threshold>" \
  --condition-query Failures='<one-line query>' \
  --window-size 5m --evaluation-frequency 5m \
  --severity 2 \
  --action-groups <action-group-resource-id> \
  --description 'Proposed by log-detective after an incident: <signature>. Review before applying.'
```

**Bicep** (for the IaC repo):

```bicep
param appInsightsOrWorkspaceId string
param actionGroupId string
param location string = resourceGroup().location

resource alert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: 'ld-<signature-slug>'
  location: location
  properties: {
    displayName: 'ld-<signature-slug>'
    severity: 2
    enabled: true
    scopes: [ appInsightsOrWorkspaceId ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      allOf: [
        {
          query: '''
            <multi-line query>
            '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: <threshold>
          failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
        }
      ]
    }
    actions: { actionGroups: [ actionGroupId ] }
  }
}
```

## AWS: CloudWatch Logs metric filter + alarm

The filter pattern is a quoted term (the exception type, or the constant part of the message)
or, for structured request logs, a JSON pattern such as
`{ ($.status = 500) && ($.path = "/orders") }`. The log group comes from the `@log` field of a
Logs Insights export (account number removed) or is left as `<log-group-name>`.

```bash
aws logs put-metric-filter \
  --log-group-name <log-group-name> \
  --filter-name ld-<signature-slug> \
  --filter-pattern '"<ExceptionType or text>"' \
  --metric-transformations metricName=<MetricName>,metricNamespace=LogDetective,metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name ld-<signature-slug> \
  --namespace LogDetective --metric-name <MetricName> \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold <threshold> --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions <sns-topic-arn>
```

## GCP: log-based metric

```bash
gcloud logging metrics create ld-<signature-slug> \
  --description='Proposed by log-detective; review before applying' \
  --log-filter='severity>=ERROR AND "<ExceptionType or text>"'
```

Then add an alerting policy on `logging.googleapis.com/user/ld-<signature-slug>` (align with
delta over 300 s, condition above `<threshold>`), in the console or Terraform.

## Plain log files

When the platform cannot be identified (a `.log` file), the report gives the pattern and the
threshold only; create the equivalent rule in whatever platform stores those logs.

# Log Detective - AWS CloudWatch & GCP queries

All read-only. Use a read-only profile (`ViewOnlyAccess` + `CloudWatchLogsReadOnlyAccess`).

## CloudWatch Logs Insights (preferred)

```bash
START=$(date -d '-12 hours' +%s); END=$(date +%s)
QID=$(aws logs start-query --log-group-names /aws/ecs/orders-api \
  --start-time $START --end-time $END \
  --query-string '<query>' --query queryId --output text)
sleep 5   # repeat get-query-results until "status": "Complete"
aws logs get-query-results --query-id $QID -o json > incident-logs/cw-<name>.json
```

### Errors and exceptions
```
fields @timestamp, @message, @logStream
| filter @message like /(?i)(error|exception|fatal|traceback|panic)/
| sort @timestamp asc
| limit 5000
```

### Structured (JSON) request logs - failures
```
fields @timestamp, @message
| filter status >= 500 or level = "error"
| sort @timestamp asc
| limit 5000
```

### Latency for one path (needs successes too)
```
fields @timestamp, @message
| filter path = "/checkout"
| sort @timestamp asc
| limit 5000
```

### Lambda errors and timeouts
```
fields @timestamp, @message, @requestId
| filter @message like /(?i)(Task timed out|Runtime\.|ERROR|Exception)/
| sort @timestamp asc
| limit 5000
```

### Error rate per 5 minutes (scope check)
```
filter @message like /(?i)error/
| stats count(*) as errors by bin(5m)
```

## CloudWatch filter-log-events (simple alternative)

```bash
aws logs filter-log-events --log-group-name /aws/lambda/orders \
  --start-time $(( $(date -d '-12 hours' +%s) * 1000 )) \
  --filter-pattern '?ERROR ?Exception ?Traceback' -o json > incident-logs/cw-events.json
```

## GCP Cloud Logging

```bash
gcloud logging read 'severity>=ERROR AND resource.type="k8s_container" AND timestamp>="2026-09-26T00:00:00Z"' \
  --limit 5000 --format=json > incident-logs/gcp-errors.json
```

## Deployments ("what changed")

```bash
# In the service repo - merge/commit times approximate deploy times:
git log --since="12 hours ago" --format="%H|%cI|%s" > incident-logs/deploys.txt
# Better: release/pipeline completion times as JSON [{"time": "...", "id": "...", "description": "..."}]
```

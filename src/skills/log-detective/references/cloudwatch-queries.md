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

## What changed in AWS: CloudTrail

Infrastructure changes (security groups, Lambda configuration, scaling, IAM, secrets) are in
CloudTrail. Export the window from at least 24 h before the onset:

```bash
# All management events in the window (the CLI follows the pages for you)
aws cloudtrail lookup-events --start-time 2026-09-26T14:00:00Z --end-time 2026-09-27T16:00:00Z \
  -o json > incident-logs/cloudtrail.json

# Only write events (smaller)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  --start-time 2026-09-26T14:00:00Z -o json > incident-logs/cloudtrail-writes.json

# One resource (e.g. the security group or function that is suspect)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=sg-0a1b2c3d4e5f67890 \
  -o json > incident-logs/cloudtrail-sg.json
```

Put the file next to the logs; it is recognised by shape and never counted as log records. The
analyser keeps successful non-read events (not `Describe*`, `Get*`, `List*`, `Lookup*`), drops
logins, role assumptions, log-stream housekeeping and failed calls, and notes secret reads
(`GetSecretValue`, `GetParameter`) separately. Usernames are pseudonymised; account numbers,
access keys and source IPs are never output. Raw CloudTrail files from S3 (`{"Records": [...]}`)
also work.

## Platform events: AWS Health

```bash
aws health describe-events --region us-east-1 \
  --filter startTimes=[{from=2026-09-27T00:00:00Z}] -o json > incident-logs/aws-health.json
```
(Needs a Business or Enterprise support plan.) Open issues in the affected region are shown at
the top of the report as a possible platform incident.

## Baseline window

Run the same Insights query for a comparable earlier window (usually the same hours one week
earlier: subtract 604800 from both `--start-time` and `--end-time`), save it in `baseline-logs/`
and pass `--baseline baseline-logs/`.

## Blast radius fields

Keep `userId` / `user_id`, `clientIp` / `sourceIPAddress` and `tenantId` in structured log lines
(or in the `fields` of the query). The analyser counts distinct affected users, clients and
tenants and never outputs the values; the same fields inside message text are masked.

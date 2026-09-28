---
name: log-detective
description: Diagnoses production and non-production incidents from logs - Azure Application Insights / Log Analytics (KQL), AWS CloudWatch Logs Insights, GCP Logging, or exported log files. Finds when the problem started, which errors are new, what got slower, which code deployment or infrastructure change (Azure Activity Log, AWS CloudTrail) preceded it, whether a platform incident was reported, whether it is really above a normal baseline, how many operations and users are affected, and which code lines are implicated. Proposes an alert rule to catch it next time and drafts a blameless postmortem, then hands a confirmed cause to bug-resolve. Use when the user says "500 errors since…", "the app is slow", "why is X failing in prod/dev", "check App Insights", "look at CloudWatch logs", "incident", "outage", "postmortem", or pastes an error, stack trace or log export. Read-only - never restarts, scales, creates alerts or changes anything.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Log Detective

Turn "something is wrong" into **evidence**: when it started, what is new, what changed just before (code *and* infrastructure), whether it is normal noise, who is affected, and where in the code - then a cause you have checked against the code, an alert that would catch it next time, and a postmortem draft.

## Non-negotiable rules

1. **Read-only.** Query logs, metrics, the Activity Log and CloudTrail only. Never restart, scale, swap slots, change settings, roll back or create alert rules - recommend those to a human with the exact command. The alert rule the analyser proposes is TEXT for a human to review and apply. The bundled guard hook blocks write commands; don't work around it.
2. **Redact first.** Logs contain personal and client data. All analysis goes through `scripts/redact.py` (the analyser does this automatically, including callers in the Activity Log / CloudTrail, which become `<email-1>`, `<user-1>`, `<principal-1>`). Never paste raw log lines containing emails, IPs, tokens or customer identifiers into your answer. User, client and tenant ids are only ever **counted**. For any extra digging beyond the analyser's report, read the data **through the redactor** (`python "<skill-dir>/scripts/redact.py" <file> | ...`) - never `cat`, print or load raw log files directly.
3. **Evidence, not guesses.** "A deploy (or an app-settings change) happened 7 minutes before" is a *lead*, not a cause. Confirm against the code, the diff or the changed setting before stating a root cause, and say how confident you are.
4. **Client data** only with the client's consent, via the access tier they approved.

## Step 1 - Frame the incident (ask only what you can't infer)

- **Symptom** - what users see (errors, slowness, wrong data), which endpoint/feature.
- **When** - roughly when it started; pick a query window of *before + after* (default: 6 h before the reported start to now; at least 2× the incident length before it).
- **Where** - which app/service, environment, and log platform (App Insights app name / Log Analytics workspace / CloudWatch log group / GCP project), and the subscription / AWS account for the change records.
- **Baseline** - a comparable earlier window, usually the same hours one week earlier (ask if last week was unusual, e.g. a release freeze or holiday).
- **Access tier** - Tier 0 (user exports and shares files) or Tier 1 (read-only identity; confirm with `az account show` / `aws sts get-caller-identity` and ask the user to confirm it is read-only). Default Tier 0.

## Step 2 - Pull the right logs and the change records

Use the ready-made queries in `references/kql-queries.md` (Azure) and `references/cloudwatch-queries.md` (AWS). Minimum set for a good diagnosis:

1. **Failed requests** (status, operation, duration) - include `user_Id`, `user_AuthenticatedId`, `client_IP`, `customDimensions` so the blast radius can be counted
2. **Exceptions with stack details**
3. **Failed dependencies** (SQL, HTTP, Redis, Service Bus… - the most common real cause)
4. For slowness: **request durations** for the affected operation

Tier 1: run the queries yourself, saving each result as JSON into `./incident-logs/`. Tier 0: give the user the queries and the exact export commands, and wait for the files. The simplest route for most people is the Azure portal: open the Logs blade, paste the query, run it, then **Export > CSV**; those CSV files work as they are. Pasted text/log files also work.

Also collect **what changed**, for the 24 h before the reported start:

- **Code**: `git log --since="<window start>" --format="%H|%cI|%s" > incident-logs/deploys.txt` in the service's repo (and/or the pipeline's release list as JSON `[{"time","id","description"}]`). Merge time is only an approximation of deploy time - prefer pipeline release times when available.
- **Azure infrastructure**: `az monitor activity-log list --offset 24h --status Succeeded -o json > incident-logs/activity-log.json`, plus Service Health with `az monitor activity-log list --offset 24h --query "[?category.value=='ServiceHealth']" -o json > incident-logs/service-health.json` (details in `references/kql-queries.md`, section 9).
- **AWS infrastructure**: `aws cloudtrail lookup-events --start-time <24 h before> -o json > incident-logs/cloudtrail.json`; optionally AWS Health (`references/cloudwatch-queries.md`).

Change exports can sit in the same folder as the logs: they are recognised by shape and never counted as log records.

For the **baseline**, run the same log queries for the earlier window into a separate folder, e.g. `./baseline-logs/`.

## Step 3 - Analyse

```bash
python "<skill-dir>/scripts/log_detective.py" ./incident-logs --deploys ./incident-logs/deploys.txt \
  --baseline ./baseline-logs --out-dir ./incident-report --postmortem
```

(`<skill-dir>` = this skill's base directory, shown when the skill loads. `--baseline`, `--postmortem`, `--changes <file...>` for change exports kept elsewhere, and `--change-window-hours` are optional.) The report gives:

- time window and problem rate, **onset** and **first new error**, top error **signatures** (grouped; `new_at_onset` separates new problems from background noise), **latency regressions** (p95 before/after), and **in-app code frames** from stack traces (framework frames removed);
- **deploy correlation** (code) and **infra correlation** (the most relevant infrastructure change before the onset: config and app-settings writes, slot swaps, network rules, Key Vault / identity changes and deployments rank above restarts and scale changes), both strong ≤ 2 h, weak ≤ 24 h; the full `infra_changes` list, changes made **after** the onset (often mitigation steps) and key/secret listings noted separately;
- **service_health**: platform incidents reported by Azure Service Health / Resource Health or AWS Health, shown at the top of the report;
- **baseline**: problem-rate ratio now vs the baseline window, whether each top signature also occurred there and at what rate, and an assessment (`matches-baseline` = likely normal noise, `new-problem`, `above-baseline`, `somewhat-elevated`);
- **blast_radius**: affected operations with the share of their requests that failed, roles/services, and distinct affected users / client addresses / tenants (counts only);
- **alert_suggestion**: for the top new signature, a KQL scheduled-query alert with the `az monitor scheduled-query create` command and a Bicep snippet (or a CloudWatch metric filter + alarm, or a GCP log-based metric), threshold `max(5, 3 × p95 of normal 5-minute counts)` from the baseline or the pre-onset data, and when it would have fired; see `references/alert-templates.md`;
- with `--postmortem`: `postmortem-draft.md` next to the report (also `python "<skill-dir>/scripts/postmortem.py" ./incident-report/log-detective.json`).

If Python is unavailable, do the same steps by reading the files: group errors, find the first new one, compare timings, list in-app frames and changes before the onset - and say it was done manually.

## Step 4 - Reason to a cause

Work through, in this order, and write down what each step showed:

1. **Platform first.** If `service_health` shows an active incident for a service and region you depend on, say so in the first lines; it may be the whole story. Still check the evidence matches (the failing dependency is that service).
2. **Is it real?** If the baseline assessment is `matches-baseline`, the "spike" is normal for this time window: say so plainly and stop short of calling it an incident.
3. **New vs noise.** Focus on signatures that are `new_at_onset` and not `in_baseline`. Old errors that were always there are rarely the cause.
4. **Cause vs effect.** A failing *dependency* (SQL timeout, 503 from another service) that starts at the same time as request 500s is usually the cause; the 500s are the effect.
5. **What changed.** Code deploy: read that commit's diff and the code at the implicated frames (`code_candidates`). Infrastructure change: which setting, rule or secret changed, and does it explain *this exact error* (e.g. an app-settings write that changed a host name → "No such host is known"; a security-group egress rule removed → database connection timeouts)? Never read secret values to check; ask a human to compare the setting names or the change history.
6. **No change at all?** Consider: dependency outage or throttling, expired secret/certificate, data change (a new kind of record), traffic spike, quota/disk/connection-pool exhaustion.
7. **Scope.** Use `blast_radius`: which operations, what share of their requests, how many users/tenants. Is it still happening (`last_seen`)?

Rate your confidence: **Confirmed** (code or change + evidence match exactly), **Likely** (strong evidence, one gap), **Hypothesis** (needs another query - say which).

## Step 5 - Report

Use this shape (keep it short; managers read the first three lines):

```
Incident: <symptom> in <service/env>
Started: <first new error time> (<n> errors, <x>% of requests) - still ongoing? <yes/no, last seen>
Likely cause (<Confirmed|Likely|Hypothesis>): <one sentence>
Platform: <Service Health / AWS Health event, or "none reported">
Baseline: <"x3.2 vs same hours last week, new signature" or "matches last week: normal noise">
Evidence: <3-5 bullets: new signature + count, dependency/latency facts, deploy or infra change link, code line>
Impact: <from blast_radius: operations and % of their requests failing, distinct users/tenants affected>
Recommended actions:
  1. Mitigate now (human runs): <e.g. roll back release X / revert the app setting / restore the rule> - exact command or pipeline to use
  2. Fix: hand to bug-resolve with <file:line, failing input shape, repro idea>
  3. Prevent: the proposed alert (name, condition, threshold and why) - human reviews and applies; plus test / guard
Postmortem draft: <path to postmortem-draft.md>, with what still needs confirming
Queries used: <the KQL/Insights queries and change exports, so others can re-run them>
```

Before sharing the postmortem draft, fill what you have confirmed and leave every other `[to be confirmed]` marker in place. Keep it blameless: systems and decisions, never people (the draft deliberately leaves callers out).

## Step 6 - Hand off to fix

If the cause is in code, invoke **bug-resolve** with: the headline error, the implicated `file:line`, the input/data shape that triggers it (redacted), and the operation IDs for tracing. Bug-resolve reproduces it with a failing test before fixing. If the cause is an infrastructure change, hand the human the change record (time, operation, resource) and the proposed revert, and suggest putting that kind of change through review and staged rollout.

## What this skill does not do

- Change, restart, scale, roll back or create alerts (it proposes them; a human applies them).
- Read secrets, app settings values or Key Vault (it only sees that a setting or secret *changed*).
- Output user, client or tenant identifiers (counts only).
- Declare a root cause from timing alone.

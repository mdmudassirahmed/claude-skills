---
name: log-detective
description: Diagnoses production and non-production incidents from logs - Azure Application Insights / Log Analytics (KQL), AWS CloudWatch Logs Insights, GCP Logging, or exported log files. Finds when the problem started, which errors are new, what got slower, which deployment preceded it, and which code lines are implicated, then hands a confirmed cause to bug-resolve. Use when the user says "500 errors since…", "the app is slow", "why is X failing in prod/dev", "check App Insights", "look at CloudWatch logs", "incident", "outage", or pastes an error, stack trace or log export. Read-only - never restarts, scales or changes anything.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Log Detective

Turn "something is wrong" into **evidence**: when it started, what is new, what changed just before, and where in the code - then a cause you have checked against the code.

## Non-negotiable rules

1. **Read-only.** Query logs and metrics only. Never restart, scale, swap slots, change settings or roll back - recommend those to a human with the exact command. The bundled guard hook blocks write commands; don't work around it.
2. **Redact first.** Logs contain personal and client data. All analysis goes through `scripts/redact.py` (the analyser does this automatically). Never paste raw log lines containing emails, IPs, tokens or customer identifiers into your answer. For any extra digging beyond the analyser's report, read the data **through the redactor** (`python "<skill-dir>/scripts/redact.py" <file> | ...`) - never `cat`, print or load raw log files directly.
3. **Evidence, not guesses.** "A deploy happened 7 minutes before" is a *lead*, not a cause. Confirm against the code (and the diff of that deploy) before stating a root cause, and say how confident you are.
4. **Client data** only with the client's consent, via the access tier they approved.

## Step 1 - Frame the incident (ask only what you can't infer)

- **Symptom** - what users see (errors, slowness, wrong data), which endpoint/feature.
- **When** - roughly when it started; pick a query window of *before + after* (default: 6 h before the reported start to now; at least 2× the incident length before it).
- **Where** - which app/service, environment, and log platform (App Insights app name / Log Analytics workspace / CloudWatch log group / GCP project).
- **Access tier** - Tier 0 (user exports and shares files) or Tier 1 (read-only identity; confirm with `az account show` / `aws sts get-caller-identity` and ask the user to confirm it is read-only). Default Tier 0.

## Step 2 - Pull the right logs

Use the ready-made queries in `references/kql-queries.md` (Azure) and `references/cloudwatch-queries.md` (AWS). Minimum set for a good diagnosis:

1. **Failed requests** (status, operation, duration)
2. **Exceptions with stack details**
3. **Failed dependencies** (SQL, HTTP, Redis, Service Bus… - the most common real cause)
4. For slowness: **request durations** for the affected operation

Tier 1: run the queries yourself, saving each result as JSON into `./incident-logs/`. Tier 0: give the user the queries and the exact export commands, and wait for the files. Pasted text/log files also work.

Also collect **what changed**: `git log --since="<window start>" --format="%H|%cI|%s" > incident-logs/deploys.txt` in the service's repo (and/or the pipeline's release list as JSON `[{"time","id","description"}]`). Merge time is only an approximation of deploy time - prefer pipeline release times when available.

## Step 3 - Analyse

```bash
python "<skill-dir>/scripts/log_detective.py" ./incident-logs --deploys ./incident-logs/deploys.txt --out-dir ./incident-report
```

(`<skill-dir>` = this skill's base directory, shown when the skill loads.) The report gives: time window and problem rate, **onset** and **first new error**, top error **signatures** (grouped; `new_at_onset` separates new problems from background noise), **latency regressions** (p95 before/after), **deploy correlation** (strong ≤ 2 h, weak ≤ 24 h), and **in-app code frames** from stack traces (framework frames removed).

If Python is unavailable, do the same steps by reading the files: group errors, find the first new one, compare timings, list in-app frames - and say it was done manually.

## Step 4 - Reason to a cause

Work through, in this order, and write down what each step showed:

1. **New vs noise.** Focus on signatures that are `new_at_onset`. Old errors that were always there are rarely the cause.
2. **Cause vs effect.** A failing *dependency* (SQL timeout, 503 from another service) that starts at the same time as request 500s is usually the cause; the 500s are the effect.
3. **What changed.** If a deploy correlates, read that commit's diff and the code at the implicated frames (`code_candidates`). Does the diff plausibly produce this exact error? (e.g. a new code path that dereferences a field that can be null for some customers.)
4. **No deploy?** Consider: dependency outage or throttling, expired secret/certificate, config change, data change (a new kind of record), traffic spike, quota/disk/connection-pool exhaustion.
5. **Scope.** Which operations, roles, and share of traffic are affected? Is it still happening (`last_seen`)?

Rate your confidence: **Confirmed** (code + evidence match exactly), **Likely** (strong evidence, one gap), **Hypothesis** (needs another query - say which).

## Step 5 - Report

Use this shape (keep it short; managers read the first three lines):

```
Incident: <symptom> in <service/env>
Started: <first new error time> (<n> errors, <x>% of requests) - still ongoing? <yes/no, last seen>
Likely cause (<Confirmed|Likely|Hypothesis>): <one sentence>
Evidence: <3-5 bullets: new signature + count, dependency/latency facts, deploy link, code line>
Impact: <operations/users affected>
Recommended actions:
  1. Mitigate now (human runs): <e.g. roll back release X / feature-flag off> - exact command or pipeline to use
  2. Fix: hand to bug-resolve with <file:line, failing input shape, repro idea>
  3. Prevent: <test / alert / guard to add>
Queries used: <the KQL/Insights queries, so others can re-run them>
```

## Step 6 - Hand off to fix

If the cause is in code, invoke **bug-resolve** with: the headline error, the implicated `file:line`, the input/data shape that triggers it (redacted), and the operation IDs for tracing. Bug-resolve reproduces it with a failing test before fixing.

## What this skill does not do

- Change, restart, scale or roll back anything (recommend it; a human does it).
- Read secrets, app settings values or Key Vault.
- Declare a root cause from timing alone.

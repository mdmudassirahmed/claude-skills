---
name: ops-digest
description: Turns the reports from cloud-cost-scout, log-detective, pipeline-doctor and bug-resolve into one short weekly summary a manager can read in two minutes, as markdown and a single HTML page, with every number traced to its source report. Use when the user asks for a weekly ops summary, a status update for their manager or client, "what happened this week", "put it all together", or a one-pager of savings, incidents, pipeline health and bugs fixed. Read-only and never invents figures.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Ops digest

One page that answers "how are our systems doing, and what needs doing?", built only from the reports the other skills already wrote.

## Rules

1. **No invented numbers.** Every figure in the digest comes from a report file. If something isn't in a report, leave it out or say it's missing. Never estimate savings, error rates or durations yourself.
2. **Read-only.** This skill only reads JSON reports. It doesn't query any system or change anything.
3. **Plain and short.** Write for a busy manager: what happened, what it's worth, what needs doing, who does it. No jargon they'd have to look up.
4. **Keep sensitive details out.** The reports are already redacted; don't paste raw log lines, customer identifiers or secrets into the summary.

## Step 1: Collect the reports

Look for the JSON reports from this period, typically:

- `cost-scout-report/cost-scout-report.json` from cloud-cost-scout
- `incident-report/log-detective.json` from log-detective (one per incident)
- pipeline-doctor output saved as JSON (`pipeline_triage.py ... --json > triage.json`, plus any history, speed or YAML review JSON)
- bug-resolve fix reports saved as JSON

Put them (or copies) in one folder, e.g. `./digest-input`. If a report the user expects is missing, say which one rather than guessing its contents.

## Step 2: Build the digest

```bash
python "<skill-dir>/scripts/ops_digest.py" ./digest-input --title "<team or system>" --period "<dates>" --out-dir ./ops-digest
```

It writes `ops-digest.md`, a self-contained `ops-digest.html` that can be emailed or attached, and `ops-digest.json`. Files it doesn't recognise are listed at the end, not guessed at.

## Step 3: Review and tighten

Read the generated digest before handing it over:

- Check the headline figures match the source reports (the script copies them; confirm nothing looks off, such as a saving larger than the bill).
- Rewrite the "What needs doing" list in plain words if needed, keeping owners.
- Add one or two sentences of context only where the reports support it (for example "the Gold-tier incident is fixed and the alert is in place" only if a bug-resolve report and the alert exist).
- Keep it to one page.

## Step 4: Hand it over

Give the user the headline in a few lines, then the path to the HTML file. Offer to adjust the tone for the audience (team, manager, client).

## What this skill does not do

- Query clouds, logs or pipelines (run the other skills for that).
- Estimate anything that isn't in a report.
- Send the digest anywhere; the user decides who gets it.

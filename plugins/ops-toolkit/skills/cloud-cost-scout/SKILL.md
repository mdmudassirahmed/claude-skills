---
name: cloud-cost-scout
description: Finds cloud waste and savings in Azure or AWS from read-only data and produces a ranked, dollar-quantified list with risk and the safe fix. Use when the user asks to "find cloud waste", "reduce our Azure/AWS bill", "cost optimization", "what are we paying for that we don't use", "idle resources", "FinOps scan", or shares Advisor / Cost Management / Cost Explorer exports. Never changes resources - fixes are proposed as pull requests or handed to the resource owner.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Cloud Cost Scout

Produce an evidence-backed savings list that a manager can repeat without being embarrassed later: every dollar figure says where it came from, and risky items are kept out of the headline.

## Non-negotiable rules

1. **Read-only.** Never run a command that creates, changes, deletes, starts, stops, resizes or deallocates anything, and never read secrets. The bundled guard hook blocks these; do not try to work around it (no scripts, SDK calls or raw REST writes).
2. **No invented numbers.** Only quote savings produced by `cost_scout.py` from real exports. If data is missing, say what export would price it.
3. **Headline = "Actionable now + Confirmed".** Estimated (list-price) and high-risk (production / retention-tagged) figures are shown separately, never added into the headline.
4. **Client environments** only with the client's written consent. If the user is unsure whose subscription it is, stop and ask.

## Step 1 - Choose the access tier

Ask which applies (default to Tier 0 if unsure):

- **Tier 0 - exports only (no cloud access).** The user (or the owning ops team) runs the export commands below and shares the files. Works everywhere, including client estates.
- **Tier 1 - read-only identity.** Only if the current login is a read-only identity (Reader / Cost Management Reader / ViewOnlyAccess). Confirm first: run `az account show` / `aws sts get-caller-identity` and ask the user to confirm the identity is read-only. If they cannot confirm, use Tier 0.

## Step 2 - Collect the data

Put everything in one folder (default `./cost-scout-input/`). The exact commands are in `references/export-commands.md`; the minimum useful set:

| Cloud | File | Why |
|---|---|---|
| Azure | `advisor.json` | Microsoft's own savings estimates (right-size, reservations) |
| Azure | `arg-idle-resources.json` | Idle resources (unattached disks, stopped-not-deallocated VMs, empty plans, old snapshots, orphan IPs/LBs) - query in `references/azure-idle-resources.kql` |
| Azure | cost export `.csv` | Prices idle resources from the **actual bill** (resource-level, last ~30 days) |
| AWS | `volumes.json`, `addresses.json` | Unattached EBS volumes, idle Elastic IPs |
| AWS | `compute-optimizer.json` | AWS's own right-size estimates |
| AWS | `cost-explorer.json` | Spend by service, for context |

In Tier 1 you may run these same commands yourself (they are all read-only). In Tier 0 give the user the commands and wait for the files.

## Step 3 - Analyse

The script ships inside this skill: `<skill-dir>/scripts/cost_scout.py`, where `<skill-dir>` is this skill's base directory (shown when the skill loads).

```bash
python "<skill-dir>/scripts/cost_scout.py" ./cost-scout-input --out-dir ./cost-scout-report
```

It auto-detects each file's format, merges findings per resource, prices idle items from the bill, applies risk rules, and writes `cost-scout-report.md` + `.json`. Files it cannot use are listed with the reason - tell the user about them.

If Python is unavailable, read the files yourself and apply the same rules (below), and state that the numbers were computed manually.

## Step 4 - Review before presenting

Check the report yourself before showing it:

- **Sanity:** a single finding larger than the resource's total monthly cost is an error - investigate.
- **Duplicates:** the same resource should appear once.
- **Context the script can't know:** ask about anything that looks intentional (DR standby VMs, disks kept for an audit, IPs allow-listed by partners). Move those to "needs owner decision" in your summary.
- **Unpriced findings:** say which export would price them.

## Step 5 - Present

Lead with one sentence the user can forward, e.g.:

> **$955/month (≈$11.5k/year) of confirmed, low-risk savings in `dev-subscription`**, plus $126/month that needs owner decisions. No resources were changed.

Then the top items (resource, what's wrong, saving, basis, risk, fix). Then next steps:

1. For each actionable item, the **owner** (from tags) and the **fix as a change to IaC** (Bicep/Terraform) - offer to open a pull request that edits the IaC. Never apply it.
2. High-risk items: a short message the user can send to the owner.
3. Re-run monthly; savings are only real once the bill goes down - suggest comparing next month's cost export.

## Risk rules (what the script applies)

| Condition | Risk |
|---|---|
| Tag `environment/env/stage` = prod/production, or resource group name contains `prod` | high - owner decision |
| Tag `do-not-delete`, `retain`, `keep`, `legal-hold` | high - owner decision |
| Disk/volume detached or created in the last 7 days | medium - may be mid-migration |
| Any right-size | medium - performance risk; watch metrics after |
| Reservations / savings plans | medium - multi-year commitment; finance approval |
| Other idle resources | low |

## What this skill does not do

- Apply any change, purchase reservations, or delete anything.
- Read data inside storage/databases, or secrets.
- Replace a FinOps review for commitments - it flags them for finance.

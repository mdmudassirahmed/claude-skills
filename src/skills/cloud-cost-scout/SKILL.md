---
name: cloud-cost-scout
description: Finds cloud waste and savings in Azure or AWS from read-only data and produces a ranked, dollar-quantified list with risk and the safe fix. Also explains why the bill went up (month-on-month change by resource, service and resource group), finds non-production compute that could be switched off out of hours, logging costs (Log Analytics / Application Insights), licence and offer savings (Hybrid Benefit, Dev/Test, Spot), storage tiering and spend with no owner tag, and points to the IaC files to change. Use when the user asks to "find cloud waste", "reduce our Azure/AWS bill", "why did our cloud bill go up", "cost optimization", "what are we paying for that we don't use", "idle resources", "FinOps scan", or shares Advisor / Cost Management / Cost Explorer / CUR exports. Never changes resources - fixes are proposed as pull requests or handed to the resource owner.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Cloud Cost Scout

Produce an evidence-backed savings list that a manager can repeat without being embarrassed later: every dollar figure says where it came from, and risky or assumed figures are kept out of the headline.

## Non-negotiable rules

1. **Read-only.** Never run a command that creates, changes, deletes, starts, stops, resizes or deallocates anything, and never read secrets. The bundled guard hook blocks these; do not try to work around it (no scripts, SDK calls or raw REST writes). Commands like `az aks stop` or an auto-shutdown schedule appear in the report only as fixes for the owning team to put in IaC or a pipeline. You never run them.
2. **No invented numbers.** Only quote savings produced by `cost_scout.py` from real exports. If data is missing, say which export would price it. Never put a price on a rate optimisation (Hybrid Benefit, Dev/Test, Spot, commitment tier); describe the condition and the typical effect instead.
3. **Headline = "Actionable now + Confirmed".** Estimated figures (list prices, schedules, disk tiers, log plans) and high-risk items (production / retention-tagged) are shown separately and never added into the headline.
4. **Client environments** only with the client's written consent. If the user is unsure whose subscription it is, stop and ask.

## Step 1 - Choose the access tier

Ask which applies (default to Tier 0 if unsure):

- **Tier 0 - exports only (no cloud access).** The user (or the owning ops team) runs the export commands and shares the files. Works everywhere, including client estates.
- **Tier 1 - read-only identity.** Only if the current login is a read-only identity (Reader / Cost Management Reader / Log Analytics Reader / ViewOnlyAccess). Confirm first: run `az account show` / `aws sts get-caller-identity` and ask the user to confirm the identity is read-only. If they cannot confirm, use Tier 0.

## Step 2 - Collect the data

Put everything in one folder (default `./cost-scout-input/`). The exact commands are in `references/export-commands.md`. Everything is optional; each file switches on more checks.

| Cloud | File | What it adds |
|---|---|---|
| Azure | `advisor.json` | Microsoft's own savings estimates (right-size, reservations) |
| Azure | `arg-idle-resources.json` | Idle resources (unattached disks, stopped-not-deallocated VMs, empty plans, old snapshots, orphan IPs/LBs), query `references/azure-idle-resources.kql` |
| Azure | `arg-optimisation.json` | Running non-prod VMs / scale sets / AKS, licence types, subscription offers, disk skus, blob access tiers, workspace retention and caps, query `references/azure-optimisation-candidates.kql` |
| Azure | cost export `.csv` | Prices everything from the **actual bill**. Two months (one file, or one per month) also gives the bill change; keep the Tags column for tag coverage |
| Azure | `usage-<workspace>.json` | Log Analytics billable GB per table (the Usage query in the export commands), one file per workspace, named after it |
| AWS | `volumes.json`, `addresses.json` | Unattached EBS volumes, idle Elastic IPs |
| AWS | `instances.json` | Running non-prod EC2 instances (schedules, Spot) |
| AWS | `compute-optimizer.json` | AWS's own right-size estimates |
| AWS | Cost and Usage Report `.csv` | Resource-level actual cost, bill change and tag coverage for AWS |
| AWS | `cost-explorer.json` | Spend by service, for context |

In Tier 1 you may run these same commands yourself (they are all read-only). In Tier 0 give the user the commands and wait for the files.

## Step 3 - Analyse

The scripts ship inside this skill; `<skill-dir>` is this skill's base directory (shown when the skill loads).

```bash
python "<skill-dir>/scripts/cost_scout.py" ./cost-scout-input --out-dir ./cost-scout-report
```

`<skill-dir>/scripts/cost_scout.py` auto-detects each file's format, merges findings per resource, prices them from the bill, applies risk rules, and writes `cost-scout-report.md` + `.json`. Files it cannot use are listed with the reason; tell the user about them. Add `--as-of YYYY-MM-DD` to pin the date so reruns are identical.

If Python is unavailable, read the files yourself and apply the same rules (below), and state that the numbers were computed manually.

## Step 4 - Read the report

Each finding has a `category` and a `basis`:

| Category | What it is | Basis of the $ figure | In totals? |
|---|---|---|---|
| idle, rightsize, commitment | Waste and provider recommendations | advisor / compute-optimizer / actual-cost (confirmed), list-price-estimate | yes |
| schedule | Non-prod compute running around the clock | `schedule-estimate` = actual monthly cost x (1 - 60/168), for weekdays 12 hours a day | yes, as estimated |
| storage | Premium SSD in non-prod (`tier-change-estimate`), Hot storage accounts above a cost threshold (no price) | estimated or unpriced | estimated only |
| logging | Big Log Analytics tables (`basic-logs-estimate`, `sampling-estimate`), retention over 90 days, dev workspaces without a daily cap | estimated or unpriced | estimated only |
| rate | Azure Hybrid Benefit, Dev/Test offer, Spot, Log Analytics commitment tier | none: `monthly_savings` is always empty | never |

The ratios behind every estimate are in `references/optimisation-assumptions.json` (office hours, Standard vs Premium SSD price ratio, Basic logs price ratio, sampling reduction, thresholds). They are assumptions: say so, and suggest the user checks them for their region and agreement. `references/aws-approx-prices.json` holds the AWS list prices for unattached volumes and idle IPs.

The JSON also has these sections (not findings, never in totals):

- `bill_change`: with two or more calendar months of cost data, the latest month against the previous one. Each month becomes a per-day run rate x 30.4, so a half month compares fairly with a full one. It lists the total change, the top 10 increases and top 5 decreases by resource, by service (MeterCategory or AWS product name) and by resource group, and resources that are new or gone. With one month, `status` is `single-month` and the message says so; ask the user for last month's export.
- `tagging`: share of the latest month's spend on resources with no owner-type tag (owner, createdby, costcenter, cost-center, team, app-owner), and the top 10 untagged resources by spend.
- `logging`: per workspace, billable GB, the actual logging cost from the bill, retention, sku, and the biggest tables with their share of the cost (the workspace cost split by GB share).
- `assumptions`: the values used from the assumptions file.

Idle findings are priced from the latest month's run rate. Optimisation checks (schedules, rate, storage tiering, workspace settings) only run on rows from `references/azure-optimisation-candidates.kql`, which carry `scoutQuery = optimisation-candidates`; rows from the idle query only get the idle rules, so nothing is reported twice.

## Step 5 - Review before presenting

Check the report yourself before showing it:

- **Sanity:** a single finding larger than the resource's total monthly cost is an error; investigate.
- **Overlaps:** a VM can have both a right-size and a schedule finding. The risk notes say when savings overlap; do not add them up as if both apply in full.
- **Context the script can't know:** ask about anything that looks intentional (DR standby VMs, disks kept for an audit, IPs allow-listed by partners, build agents that run overnight, workspaces kept for compliance). Move those to "needs owner decision" in your summary.
- **Unpriced findings:** say which export would price them (usually the cost export, or naming the usage file after its workspace).

## Step 6 - Present

Present in this order, in plain words:

1. **Headline**, one sentence the user can forward, built only from the actionable, confirmed figure. For example: **"$955/month (about $11.5k/year) of confirmed, low-risk savings in `dev-subscription`, plus $126/month that needs owner decisions. No resources were changed."**
2. **Estimated opportunities**: schedules, storage tiering and logging, each with its saving, its `*-estimate` basis and the assumption behind it (for example "if these dev VMs only need to run weekdays, 12 hours a day").
3. **Rate optimisations**, with no price: what it is, the condition (licences with Software Assurance, Visual Studio subscriptions for Dev/Test, interruptible work for Spot) and the typical effect. Suggest who to ask (licensing, billing owner).
4. **Bill change**, if two months were supplied: the total change and the three or four biggest drivers, plus new and gone resources.
5. **Tagging**: the share of spend with no owner and the top untagged resources, which is also why some findings have nobody to contact.

Then next steps:

1. For each actionable item, the **owner** (from tags) and the **fix as an IaC change**. Find where the resource is defined:

   ```bash
   python "<skill-dir>/scripts/iac_locate.py" ./cost-scout-report ./path/to/infra-repo --out-dir ./cost-scout-report
   ```

   `<skill-dir>/scripts/iac_locate.py` lists, per finding, the Bicep, ARM template, Terraform and CloudFormation files and line numbers that mention the resource name (it skips `.git`, `node_modules`, `.terraform`, `bin` and `obj`). Use it to prepare a pull request with the change (sku, licenseType, schedule resource, table plan, lifecycle rule, daily cap). Never apply it, and never run `terraform apply`, `az deployment` or similar. Names built from variables show up as "not found"; say so and ask the owner.
2. High-risk items, and anything a person has to run (for example stopping AKS at night with `az aks stop` from a scheduled pipeline): a short message the user can send to the owner.
3. Re-run monthly with the new cost export. Savings are only real once the bill goes down, and the bill change section will show it.

## Risk rules (what the script applies)

| Condition | Risk |
|---|---|
| Tag `environment/env/stage` = prod/production, or resource group name contains `prod` (but not `non-prod`) | high - owner decision |
| Tag `do-not-delete`, `retain`, `keep`, `legal-hold` | high - owner decision |
| Disk/volume detached or created in the last 7 days | medium - may be mid-migration |
| Any right-size | medium - performance risk; watch metrics after |
| Reservations / savings plans | medium - multi-year commitment; finance approval |
| Schedules | medium - confirm nobody works off-hours or runs overnight jobs |
| Disk tier, blob lifecycle, log plans, sampling, retention, daily cap | medium - check performance, access patterns, alerts and compliance first |
| Rate optimisations | medium - only with the licences or eligibility stated in the condition |
| Other idle resources | low |

**Non-production** means a tag `environment/env/stage` of dev, development, test, testing, qa, uat, sandbox, sbx, nonprod, non-prod or demo, or one of those words as a separate part of the resource group or name (`rg-web-dev`, `vm-qa01`). A production word anywhere wins. Anything tagged `schedule-exempt`, `always-on` or `24x7` (as key or value) is never suggested for a schedule, and VMs that already have an enabled auto-shutdown schedule are skipped.

## What this skill does not do

- Apply any change, stop or start anything, buy reservations, change licences or delete anything.
- Read data inside storage/databases, or secrets.
- Price licence or offer changes; those depend on agreements it cannot see.
- Replace a FinOps review for commitments; it flags them for finance.

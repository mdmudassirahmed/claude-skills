# Changelog

## 1.1.0 (2026-09-28)

Each skill now looks a step further ahead, and there's a fifth skill.

**cloud-cost-scout**
- Explains why the bill changed between the last two months, by resource, service and resource group, including new and removed resources.
- Suggests office-hours schedules for dev and test VMs, scale sets, AKS clusters and EC2 instances.
- Looks at Log Analytics and App Insights costs table by table, with retention and daily-cap advice.
- Lists cheaper rates you may qualify for (Azure Hybrid Benefit for Windows and SQL, Dev/Test pricing, Spot), with the conditions and no made-up prices.
- Flags Premium disks in non-production and hot storage accounts without lifecycle rules.
- Reports how much spend has no owner tag.
- Reads AWS Cost and Usage Report CSVs.
- New `iac_locate.py` finds where each resource is defined in Bicep, ARM, Terraform or CloudFormation so the fix can go in as a pull request.

**log-detective**
- Reads the Azure Activity Log, AWS CloudTrail and Service Health, so infrastructure changes and platform outages show up next to code deploys.
- Compares with a baseline window (for example the same hours last week) so normal noise isn't mistaken for an incident.
- Counts affected operations, users, clients and tenants without ever printing who they are.
- Suggests an alert rule (KQL, Azure CLI and Bicep, or CloudWatch) with a threshold taken from the data, for a person to review.
- Writes a blameless postmortem draft.
- Fixes a privacy gap: user ids inside JSON log lines are now masked in samples and headlines.

**pipeline-doctor**
- Uses run history to tell flaky tests from real regressions (with the first bad commit), finds recurring causes, and reports failure rate, time between failures and time to green.
- Measures step times and suggests caching, shallow checkout, test sharding and more, with estimated time saved.
- Reviews pipeline YAML for 16 security and reliability problems, from unpinned actions to secrets on the command line.
- Knows about 19 more failure causes (58 in total).

**bug-resolve**
- `find_similar.py` finds the same kind of bug elsewhere, from a preset, a regex or the line you just fixed, across Python, C#, TypeScript, JavaScript, Java and SQL.
- A prevention catalogue with compiler and linter settings that stop each bug class coming back, and regression test templates for eight test frameworks.
- `fix_report.py` writes the final report and a pull request comment, and refuses to say a fix was proven unless the before and after test output shows it.

**New: ops-digest**
- Turns the other reports into a one-page weekly summary, as markdown and a single HTML file, with every number traced to its report.

**Also**
- The guard now also blocks `az vm auto-shutdown`, `az resource tag`, `reset-ssh` and `rename`, which the new suggestions mention but must never run.
- The whole test suite also runs on Python 3.8 locally before release.

## 1.0.1 (2026-09-28)

- **log-detective** now reads CSV files exported from the Azure portal (Logs blade, Export, CSV), including the `timestamp [UTC]` column names and US-style dates the portal uses. That's the easiest way to get logs out if you can't use the command line.
- Added a test that fails if a hidden control character ever ends up in the code.

## 1.0.0 (2026-09-28)

The first release, with four skills:

- **cloud-cost-scout** reads Azure Advisor, Resource Graph and Cost Management exports, and AWS EBS, Elastic IP, Compute Optimizer and Cost Explorer output. Every saving says whether it's confirmed or estimated, and risky items are kept out of the headline.
- **log-detective** reads App Insights, Log Analytics, CloudWatch, GCP Logging and plain log files. It finds when a problem started, which errors are new, what got slower, what was deployed just before, and which code lines appear in the stack traces.
- **pipeline-doctor** reads failed Azure Pipelines and GitHub Actions logs, picks out the real error from about forty known causes, and says who can fix it.
- **bug-resolve** fixes bugs test-first and shows the test failing before the fix and passing after.

Also included: a read-only guard hook for Bash and PowerShell, log cleaning for secrets and personal data, one plugin per skill plus a bundle, and a build that only changes what it needs to.

# Changelog

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

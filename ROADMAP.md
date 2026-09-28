# Roadmap

Where these skills are going, and why. The idea running through all of it: an AI assistant should help with the whole life of a system after it ships, stay read-only, and never report a number it can't trace back to data.

## Done

### 1.0: find and fix
- **cloud-cost-scout** finds waste: idle disks, stopped-but-billed VMs, empty plans, old snapshots, Advisor and Compute Optimizer suggestions.
- **log-detective** works out when an incident started, what's new, and which deploy and code lines are involved.
- **pipeline-doctor** finds the real error in a failed run and says who can fix it.
- **bug-resolve** fixes bugs test-first, with proof.
- A read-only guard hook, and log cleaning for secrets and personal data.

### 1.1: think a step ahead
- **Cost**: why the bill changed month to month, office-hours schedules for non-production, Log Analytics and App Insights costs, cheaper rates (Hybrid Benefit, Dev/Test pricing, Spot), storage tiering, spend with no owner tag, AWS Cost and Usage Report support, and a helper that finds where to make each change in your IaC.
- **Incidents**: infrastructure changes from the Azure Activity Log and AWS CloudTrail, platform outages from Service Health, comparison with a normal week, blast radius, a suggested alert so it's caught sooner next time, and a postmortem draft.
- **Pipelines**: flaky versus regression versus recurring failures from run history, slow steps and caching tips, a security and reliability review of pipeline YAML, and more known failure causes.
- **Bugs**: find the same bug pattern elsewhere in the code, pick a guardrail so it can't come back, test templates per stack, and a report that refuses to claim a fix was proven when it wasn't.
- **ops-digest**: one page for a manager, built only from the other reports.

## Next

### 1.2: run on a schedule, without a person
Most of this is useful every week, not just when something breaks.
- A pipeline template (Azure Pipelines and GitHub Actions) that runs the exports with a **read-only, secret-free identity** (workload identity federation), runs the skills headless, and publishes the digest as a pipeline artifact or wiki page.
- Trend history: keep each week's JSON so the digest can say "savings acted on", "incidents this month versus last", "pipeline failure rate going down".
- Budget and anomaly checks against the trend, not just last month.

### 1.3: see the system
- **Architecture from source**: draw Azure, AWS and GCP diagrams (draw.io and Mermaid) from Bicep, Terraform or CloudFormation, or from a read-only inventory.
- **Design versus reality**: compare what the design says with what's actually deployed and flag anything nobody approved.
- **Handover pack**: runbook, troubleshooting queries, diagram and cost baseline in one go at the end of a project.

### 1.4: security and compliance in the running cloud
- Read Defender for Cloud, Azure Policy and AWS Security Hub findings, group them the same way log-detective groups errors, and propose fixes as IaC pull requests.
- Evidence tables for audits, generated from those findings.

## Later ideas
- Kubernetes-aware cost and incident views (AKS, EKS): namespace-level cost, noisy pods, crash loops.
- GCP parity for cost (billing export, Recommender) and incidents.
- Behavioural evals for every skill using `claude plugin eval`, run in CI on each change.
- An optional MCP server wrapping the read-only exporters, for teams that prefer tools over CLI commands.

## Principles that won't change
1. **Read-only.** Changes are pull requests or requests to an owner.
2. **Traceable numbers.** Confirmed or estimated, and always from data.
3. **Privacy first.** Clean logs before the model sees them; use files when in doubt.
4. **Small, self-contained skills.** Install one or all; each works on its own.
5. **Tested properly.** Every feature ships with sample data and tests, and each release is tried in real Claude Code sessions.

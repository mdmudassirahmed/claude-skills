# Cost Scout - read-only export commands

Every command below only **reads**. Run them with a read-only identity (Azure: Reader + Cost Management Reader; AWS: ViewOnlyAccess + Cost Explorer read). Save all outputs in one folder, e.g. `cost-scout-input/`.

## Azure

```bash
# Scope (pick the subscription to analyse)
az account set --subscription "<subscription name or id>"

# 1) Advisor cost recommendations (Microsoft's own savings figures)
az advisor recommendation list --category Cost -o json > cost-scout-input/advisor.json

# 2) Idle-resource candidates (needs: az extension add --name resource-graph)
az graph query -q "@azure-idle-resources.kql" --first 1000 -o json > cost-scout-input/arg-idle-resources.json
#    (file is in this skill's references/ folder; or paste into Portal > Resource Graph Explorer)

# 3) Resource-level cost - prices findings from the real bill.
#    Portal: Cost Management > Cost analysis > "Cost by resource" > Daily > Download > CSV
#    or schedule an Export (Cost Management > Exports, "Actual cost", daily) and download the CSV.
#    For "why did the bill go up?" include the previous month too: one file covering both months,
#    or one file per month (e.g. cost-2026-08.csv and cost-2026-09.csv) in the same folder.
#    Keep the Tags column in the export so tag coverage of spend can be measured.

# 4) Optimisation candidates: running non-prod compute (schedules), licence types (Hybrid Benefit),
#    subscription offers (Dev/Test), disk skus, storage access tiers, Log Analytics workspace settings.
az graph query -q "@azure-optimisation-candidates.kql" --first 1000 -o json > cost-scout-input/arg-optimisation.json
#    (file is in this skill's references/ folder; page with --skip-token if there are more than 1000 rows)

# 5) Log Analytics billable volume per table, one file per workspace, named after the workspace
#    so the cost can be matched (e.g. usage-law-shared-dev.json). --workspace takes the workspace ID (GUID).
az monitor log-analytics query --workspace "<workspace customer id>" -o json \
  --analytics-query "Usage | where TimeGenerated > ago(31d) | where IsBillable == true | summarize IngestedGB = sum(Quantity) / 1024 by DataType, Solution | order by IngestedGB desc" \
  > cost-scout-input/usage-<workspace name>.json
#    The Portal (Logs > Export > JSON) and the REST API return {"tables": [...]}; that shape is accepted too.
#    For Application Insights (classic) run the same query in its Logs blade.
#    If one file holds several workspaces, add  | extend Workspace = "<workspace name>"  to each query.
```

Accepted cost CSV column names (any casing):

| Field | Azure / FOCUS | AWS Cost and Usage Report |
|---|---|---|
| resource id | `ResourceId` / `InstanceId` | `lineItem/ResourceId` (or `line_item_resource_id`) |
| cost | `CostInBillingCurrency` / `Cost` / `PreTaxCost` / `CostInUsd` / `BilledCost` | `lineItem/UnblendedCost` |
| currency | `BillingCurrency` / `Currency` | `lineItem/CurrencyCode` |
| date | `Date` / `UsageDate` / `ChargePeriodStart` | `lineItem/UsageStartDate` |
| service | `MeterCategory` / `ServiceName` / `ConsumedService` | `product/ProductName` / `lineItem/ProductCode` |
| resource group | `ResourceGroup` / `ResourceGroupName` (or taken from the id) | - |
| tags | `Tags` (`"env": "dev","owner": "a"`, with or without braces) | `resourceTags/user:*` columns |

## AWS

```bash
export AWS_PROFILE=<read-only profile>   # ViewOnlyAccess + ce:Get* + compute-optimizer:Get*

aws ec2 describe-volumes --filters Name=status,Values=available -o json > cost-scout-input/volumes.json
aws ec2 describe-addresses -o json > cost-scout-input/addresses.json
aws compute-optimizer get-ec2-instance-recommendations -o json > cost-scout-input/compute-optimizer.json
aws ec2 describe-instances -o json > cost-scout-input/instances.json      # running non-prod instances (schedules, Spot)
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '-30 days' +%F),End=$(date +%F) \
  --granularity MONTHLY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE -o json > cost-scout-input/cost-explorer.json
```

Run `describe-volumes` / `describe-addresses` / `describe-instances` per region you use (add `--region`), and name files e.g. `volumes-eu-west-1.json`.

**Resource-level AWS cost (Cost and Usage Report).** If the account has a CUR (legacy CUR or Data Exports) with resource IDs, download the CSV for the last two months from its S3 bucket (read-only), for example `aws s3 cp s3://<cur-bucket>/<prefix>/<report>-00001.csv.gz .` and unzip it. Include resource tags in the report so tag coverage can be measured. This prices schedules from the real bill and gives the month-on-month bill change for AWS.

## GCP (not yet automated)

`gcloud recommender recommendations list --recommender=google.compute.instance.IdleResourceRecommender ...` output can be shared, but `cost_scout.py` does not parse it yet - Claude will read it directly and label figures as provider estimates.

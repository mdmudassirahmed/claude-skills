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

# 3) Resource-level cost for the last month - prices idle items from the real bill.
#    Portal: Cost Management > Cost analysis > "Cost by resource" > Daily > Download > CSV
#    or schedule an Export (Cost Management > Exports, "Actual cost", daily) and download the CSV.
```

Accepted CSV column names (any casing): resource id = `ResourceId` / `InstanceId`; cost = `CostInBillingCurrency` / `Cost` / `PreTaxCost` / `CostInUsd` / `BilledCost`; currency = `BillingCurrency` / `Currency`; date = `Date` / `UsageDate` / `ChargePeriodStart`.

## AWS

```bash
export AWS_PROFILE=<read-only profile>   # ViewOnlyAccess + ce:Get* + compute-optimizer:Get*

aws ec2 describe-volumes --filters Name=status,Values=available -o json > cost-scout-input/volumes.json
aws ec2 describe-addresses -o json > cost-scout-input/addresses.json
aws compute-optimizer get-ec2-instance-recommendations -o json > cost-scout-input/compute-optimizer.json
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '-30 days' +%F),End=$(date +%F) \
  --granularity MONTHLY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE -o json > cost-scout-input/cost-explorer.json
```

Run `describe-volumes` / `describe-addresses` per region you use (add `--region`), and name files e.g. `volumes-eu-west-1.json`.

## GCP (not yet automated)

`gcloud recommender recommendations list --recommender=google.compute.instance.IdleResourceRecommender ...` output can be shared, but `cost_scout.py` does not parse it yet - Claude will read it directly and label figures as provider estimates.

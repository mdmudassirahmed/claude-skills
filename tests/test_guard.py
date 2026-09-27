"""Tests for the ops-toolkit read-only guard hook.

Two levels:
  * evaluate()  - the decision function, over a large allow/deny table.
  * end-to-end  - the real hook entry (bash wrapper -> Python) fed a Claude Code
                  PreToolUse JSON payload, checking exit code and stderr.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "plugins" / "ops-toolkit" / "hooks"
sys.path.insert(0, str(HOOKS))
import cloud_readonly_guard as guard  # noqa: E402

DENY = [
    # Azure CLI - mutations
    "az group delete -n rg-orders-dev --yes",
    "az vm deallocate -g rg -n vm1",
    "az vm restart -g rg -n vm1",
    "az webapp restart -g rg -n app-orders",
    "az webapp config appsettings set -g rg -n app --settings A=1",
    "az webapp deployment slot swap -g rg -n app --slot staging",
    "az appservice plan update -g rg -n plan --sku B1",
    "az disk delete --ids /subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/disks/d1",
    "az deployment group create -g rg --template-file main.bicep",
    "az role assignment create --assignee x --role Owner --scope /subscriptions/x",
    "az storage account update -n st --min-tls-version TLS1_2",
    "az aks scale -g rg -n aks --node-count 5",
    "az vm run-command invoke -g rg -n vm --command-id RunShellScript --scripts 'id'",
    "az pipelines run --name deploy-prod",
    "az keyvault secret set --vault-name kv -n pwd --value x",
    "az functionapp stop -g rg -n fn",
    "az sql db delete -g rg -s srv -n db --yes",
    "az monitor diagnostic-settings create --resource x --name y",
    # Azure CLI - secret reads
    "az storage account keys list -g rg -n st",
    "az keyvault secret show --vault-name kv -n db-password",
    "az webapp config appsettings list -g rg -n app",
    "az aks get-credentials -g rg -n aks",
    "az acr credential show -n acr",
    "az cosmosdb keys list -g rg -n cos",
    "az account get-access-token",
    "az functionapp keys list -g rg -n fn",
    "az webapp deployment list-publishing-profiles -g rg -n app",
    # az rest
    "az rest --method put --url https://management.azure.com/subscriptions/x/resourceGroups/rg?api-version=2021-04-01 --body {}",
    "az rest -m DELETE --url https://management.azure.com/x",
    "az rest --url https://management.azure.com/x/listKeys?api-version=2023-01-01 --method post",
    "az rest --url https://management.azure.com/x --body @payload.json",
    # AWS CLI
    "aws ec2 terminate-instances --instance-ids i-123",
    "aws ec2 stop-instances --instance-ids i-123",
    "aws s3 rm s3://bucket/key",
    "aws s3 sync ./dist s3://bucket",
    "aws s3 cp s3://bucket/customers.csv .",
    "aws s3api delete-bucket --bucket b",
    "aws s3api get-object --bucket b --key customers.csv out.csv",
    "aws iam attach-role-policy --role-name r --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "aws ecs update-service --cluster c --service s --desired-count 0",
    "aws rds delete-db-instance --db-instance-identifier db1",
    "aws lambda invoke --function-name f out.json",
    "aws cloudformation deploy --template-file t.yaml --stack-name s",
    "aws secretsmanager get-secret-value --secret-id prod/db",
    "aws ssm get-parameter --name /prod/db/password --with-decryption",
    "aws sts assume-role --role-arn arn:aws:iam::1:role/Admin --role-session-name x",
    "aws dynamodb scan --table-name customers",
    "aws --profile prod --region eu-west-1 ec2 delete-volume --volume-id vol-1",
    "aws logs delete-log-group --log-group-name /aws/lambda/f",
    "aws ecr get-login-password",
    # gcloud
    "gcloud compute instances delete vm-1 --zone us-central1-a",
    "gcloud run deploy svc --image gcr.io/p/i",
    "gcloud projects add-iam-policy-binding p --member user:x --role roles/owner",
    "gcloud secrets versions access latest --secret db-pass",
    "gcloud auth print-access-token",
    "gcloud container clusters get-credentials c --zone z",
    "gcloud beta compute instances stop vm-1",
    # kubectl / IaC / helm / pulumi
    "kubectl delete pod orders-7d9 -n prod",
    "kubectl apply -f deploy.yaml",
    "kubectl scale deploy/orders --replicas=0",
    "kubectl rollout restart deploy/orders",
    "kubectl exec -it orders-7d9 -- sh",
    "kubectl get secret db-creds -o yaml",
    "kubectl -n prod get secrets",
    "terraform apply -auto-approve",
    "terraform destroy",
    "tofu apply",
    "terraform state rm aws_instance.web",
    "helm upgrade orders ./chart -n prod",
    "helm uninstall orders",
    "pulumi up --yes",
    # wrapping / chaining / paths / Windows
    'bash -c "az group delete -n rg --yes"',
    "sh -lc 'az group delete -n rg --yes'",
    'pwsh -Command "Remove-AzResourceGroup -Name rg -Force"',
    'eval "az vm delete -g rg -n vm --yes"',
    'cmd /c "az group delete -n rg --yes"',
    "az rest --method put --url https://management.azure.com/x --body '{\"a\": 1}'",
    "az devops invoke --area build --resource builds --http-method POST --in-file queue.json",
    "echo ok && az vm delete -g rg -n vm --yes",
    "az account show; az group delete -n rg",
    "cat ids.txt | xargs -n1 az resource delete --ids",
    "sudo AZURE_CORE_OUTPUT=json az group delete -n rg",
    "/usr/local/bin/aws ec2 terminate-instances --instance-ids i-1",
    "az.cmd group delete -n rg",
    "for rg in $(az group list --query [].name -o tsv); do az group delete -n $rg --yes; done",
    # PowerShell modules
    "Remove-AzResourceGroup -Name rg -Force",
    "Restart-AzWebApp -ResourceGroupName rg -Name app",
    "Get-AzKeyVaultSecret -VaultName kv -Name pwd -AsPlainText",
    "Get-AzStorageAccountKey -ResourceGroupName rg -Name st",
    "Remove-EC2Instance -InstanceId i-1 -Force",
    # raw HTTP to management APIs
    "curl -X DELETE https://management.azure.com/subscriptions/x/resourceGroups/rg?api-version=2021-04-01",
    "curl -s -X PUT -H 'Authorization: Bearer x' https://management.azure.com/x -d @body.json",
    "Invoke-RestMethod -Method Delete -Uri https://management.azure.com/x",
    "curl --request PATCH https://dev.azure.com/org/project/_apis/wit/workitems/1",
    "curl -d '{}' https://ec2.us-east-1.amazonaws.com/",
]

ALLOW = [
    # Azure CLI - reads needed by the skills
    "az login",
    "az account show",
    "az account set --subscription dev-sub",
    "az account list -o table",
    "az group list -o table",
    "az resource list -g rg-orders-dev",
    "az advisor recommendation list --category Cost -o json",
    "az graph query -q \"Resources | where type =~ 'microsoft.compute/disks'\" --first 1000",
    "az monitor app-insights query --app appi-orders --analytics-query 'exceptions | take 50'",
    "az monitor log-analytics query -w 000 --analytics-query 'AppRequests | take 10'",
    "az monitor metrics list --resource x --metric Percentage CPU",
    "az monitor activity-log list --offset 24h",
    "az webapp show -g rg -n app",
    "az webapp log tail -g rg -n app",
    "az consumption usage list --start-date 2026-09-01 --end-date 2026-09-27",
    "az costmanagement query --type ActualCost --scope /subscriptions/x --timeframe MonthToDate",
    "az keyvault secret list --vault-name kv",
    "az deployment group what-if -g rg --template-file main.bicep",
    "az deployment group validate -g rg --template-file main.bicep",
    "az extension add --name resource-graph",
    "az config set core.output=json",
    "az bicep build --file main.bicep",
    "az rest --method get --url https://management.azure.com/subscriptions/x/resourceGroups?api-version=2021-04-01",
    "az rest --url https://management.azure.com/subscriptions/x/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01",
    "az pipelines runs list --status completed --result failed",
    "az pipelines runs show --id 123",
    "az devops invoke --area build --resource logs --route-parameters project=p buildId=1",
    "az security assessment list",
    # AWS CLI - reads
    "aws sts get-caller-identity",
    "aws sso login --profile readonly",
    "aws configure list",
    "aws ce get-cost-and-usage --time-period Start=2026-09-01,End=2026-09-27 --granularity MONTHLY --metrics UnblendedCost",
    "aws ec2 describe-volumes --filters Name=status,Values=available",
    "aws ec2 describe-addresses",
    "aws compute-optimizer get-ec2-instance-recommendations",
    "aws logs start-query --log-group-name /aws/lambda/orders --start-time 1 --end-time 2 --query-string 'fields @message'",
    "aws logs get-query-results --query-id abc",
    "aws logs filter-log-events --log-group-name g --filter-pattern ERROR",
    "aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization",
    "aws s3 ls s3://bucket/",
    "aws --profile prod --region eu-west-1 ec2 describe-instances",
    "aws ssm get-parameter --name /app/feature-flag",
    # gcloud - reads
    "gcloud auth login",
    "gcloud config set project demo",
    "gcloud logging read 'severity>=ERROR' --limit 50",
    "gcloud compute instances list",
    "gcloud recommender recommendations list --recommender=google.compute.instance.IdleResourceRecommender --location=us-central1-a",
    # kubectl / IaC - reads
    "kubectl get pods -n prod",
    "kubectl describe pod orders-7d9 -n prod",
    "kubectl logs orders-7d9 -n prod --since=1h",
    "kubectl top pods -n prod",
    "kubectl rollout status deploy/orders",
    "terraform plan",
    "terraform init",
    "terraform validate",
    "tofu plan -out plan.bin",
    "helm list -A",
    "pulumi preview",
    # PowerShell reads
    "Get-AzResourceGroup",
    "Get-AzWebApp -ResourceGroupName rg",
    "Get-EC2Instance",
    # raw HTTP reads
    "curl -s https://management.azure.com/subscriptions/x/resourceGroups?api-version=2021-04-01",
    "curl -s https://dev.azure.com/org/project/_apis/build/builds/1/logs?api-version=7.1",
    "curl -X POST http://localhost:8080/api/orders -d '{}'",
    # unrelated commands that merely mention trigger words
    "git commit -m 'az group delete docs'",
    "grep -r 'terraform apply' docs/",
    "python cost_scout.py --input exports/",
    "echo 'aws ec2 terminate-instances is blocked by the guard'",
    'git commit -m "fix: handle az group delete errors gracefully"',
    "az graph query -q \"Resources | where type =~ 'microsoft.compute/disks' | where properties.diskState == 'Unattached'\"",
    "npm run build",
    "dotnet test",
    "",
]


class DecisionTable(unittest.TestCase):
    def test_deny(self):
        misses = [c for c in DENY if guard.evaluate(c) is None]
        self.assertEqual(misses, [], f"should be BLOCKED but were allowed: {misses}")

    def test_allow(self):
        wrong = [(c, guard.evaluate(c)) for c in ALLOW
                 if guard.evaluate(c) is not None]
        self.assertEqual(wrong, [], f"should be ALLOWED but were blocked: {wrong}")


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")

    def run_hook(self, command, env_extra=None, tool="Bash"):
        payload = json.dumps({
            "session_id": "t", "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"command": command, "description": "test"},
        })
        env = dict(os.environ)
        env.pop("OPS_TOOLKIT_ALLOW_CLOUD_WRITES", None)
        env.update(env_extra or {})
        return subprocess.run([self.bash, str(HOOKS / "cloud-readonly-guard.sh")], input=payload,
                              capture_output=True, text=True, env=env, timeout=30)

    def setUp(self):
        if not self.bash:
            self.skipTest("bash not available")

    def test_blocks_with_exit_2_and_reason(self):
        r = self.run_hook("az group delete -n rg-orders-dev --yes")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("BLOCKED by the ops-toolkit", r.stderr)
        self.assertIn("pull request", r.stderr)

    def test_allows_read(self):
        r = self.run_hook("az advisor recommendation list --category Cost -o json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr.strip(), "")

    def test_powershell_tool_payload(self):
        r = self.run_hook("Remove-AzResourceGroup -Name rg -Force", tool="PowerShell")
        self.assertEqual(r.returncode, 2)

    def test_override_env(self):
        r = self.run_hook("az group delete -n rg --yes", {"OPS_TOOLKIT_ALLOW_CLOUD_WRITES": "1"})
        self.assertEqual(r.returncode, 0)

    def test_malformed_payload_is_allowed(self):
        r = subprocess.run([self.bash, str(HOOKS / "cloud-readonly-guard.sh")], input="not json",
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)

    def test_fallback_without_python(self):
        """No usable Python on the machine: the conservative bash fallback must still block."""
        env = {"OPS_TOOLKIT_PYTHON": "no-such-python-xyz"}
        blocked = self.run_hook("az group delete -n rg --yes", env)
        allowed = self.run_hook("az group list -o table", env)
        self.assertEqual(blocked.returncode, 2, blocked.stderr)
        self.assertIn("fallback mode", blocked.stderr)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    @unittest.skipUnless(os.name == "nt", "backslash hook paths only occur on Windows")
    def test_windows_backslash_hook_path(self):
        """Claude Code on Windows may pass ${CLAUDE_PLUGIN_ROOT} with backslashes."""
        win_path = str(HOOKS / "cloud-readonly-guard.sh").replace("/", "\\")
        for cmd, want in (("az group delete -n rg --yes", 2), ("az group list", 0)):
            payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
            r = subprocess.run([self.bash, win_path], input=payload, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, want, r.stderr)
            self.assertNotIn("fallback mode", r.stderr)

    def test_guard_crash_uses_fallback_not_blind_decision(self):
        """If the Python guard itself errors (exit 1), the wrapper must use the fallback."""
        import tempfile
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        shutil.copy(HOOKS / "cloud-readonly-guard.sh", d)
        (d / "cloud_readonly_guard.py").write_text("raise SystemExit(1)\n")
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "az group delete -n rg"}})
        r = subprocess.run([self.bash, str(d / "cloud-readonly-guard.sh")], input=payload,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        self.assertIn("fallback mode", r.stderr)

    def _tmpdir(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d


if __name__ == "__main__":
    unittest.main()

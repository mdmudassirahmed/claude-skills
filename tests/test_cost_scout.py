import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "cloud-cost-scout" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import cost_scout as cs  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "cost"
AS_OF = date(2026, 9, 27)


def by_name(report):
    return {f["name"]: f for f in report["findings"]}


class AzureDevSubscription(unittest.TestCase):
    """Typical dev/test subscription: Advisor + Resource Graph + daily cost export."""

    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "azure-dev-subscription"], AS_OF)
        cls.f = by_name(cls.r)

    def test_all_inputs_recognised(self):
        self.assertEqual(sorted(i["type"] for i in self.r["inputs"]),
                         ["azure-advisor", "azure-arg", "azure-cost-csv"])
        self.assertEqual(self.r["skipped"], [])

    def test_finds_every_planted_waste_item(self):
        expected = {"vm-batch-nightly", "disk-legacy-sql-data", "asp-orders-dev-old", "vm-orders-api-dev",
                    "1b2c3d4e-0000-4000-8000-00000000d3v1", "disk-prod-orphan", "snap-sql-before-upgrade",
                    "disk-vm-temp-restore", "lbi-old-internal", "pip-legacy-gateway"}
        self.assertEqual(set(self.f), expected)

    def test_does_not_flag_healthy_resources(self):
        for healthy in ("disk-orders-api-os", "pip-appgw", "asp-free-sandbox", "snap-weekly-recent"):
            self.assertNotIn(healthy, self.f, f"{healthy} is in use / free / recent and must not be flagged")

    def test_non_cost_advisor_recommendations_ignored(self):
        self.assertNotIn("app-orders-dev", self.f)

    def test_idle_resources_priced_from_actual_bill(self):
        vm = self.f["vm-batch-nightly"]
        self.assertEqual(vm["basis"], "actual-cost")
        # 12.10/day over 27 days -> 30.4-day month
        self.assertAlmostEqual(vm["monthly_savings"], 367.84, places=2)
        self.assertIn("cost-export", vm["sources"])

    def test_rightsize_keeps_advisor_estimate_not_full_cost(self):
        vm = self.f["vm-orders-api-dev"]
        self.assertEqual(vm["basis"], "advisor")
        self.assertAlmostEqual(vm["monthly_savings"], 1681.92 / 12, places=2)
        self.assertIn("Standard_D4s_v5", vm["title"])
        self.assertEqual(vm["scope"], "rg-orders-dev")
        self.assertEqual(vm["risk"], "medium")
        self.assertAlmostEqual(vm["evidence"]["actualMonthlyCost"], 279.98, places=2)

    def test_resource_ids_matched_case_insensitively(self):
        self.assertTrue(all("cost-export" in f["sources"] for n, f in self.f.items()
                            if n not in ("1b2c3d4e-0000-4000-8000-00000000d3v1",)))

    def test_risk_rules(self):
        self.assertEqual(self.f["disk-prod-orphan"]["risk"], "high")
        self.assertEqual(self.f["snap-sql-before-upgrade"]["risk"], "high")
        self.assertEqual(self.f["disk-vm-temp-restore"]["risk"], "medium")
        self.assertIn("detached only 2 day(s) ago", " ".join(self.f["disk-vm-temp-restore"]["risk_notes"]))
        self.assertEqual(self.f["1b2c3d4e-0000-4000-8000-00000000d3v1"]["category"], "commitment")
        self.assertEqual(self.f["disk-legacy-sql-data"]["risk"], "low")
        self.assertEqual(self.f["disk-legacy-sql-data"]["evidence"]["owner"], "data-team")

    def test_headline_totals_split_actionable_vs_owner_decision(self):
        usd = self.r["totals_monthly"]["USD"]
        self.assertAlmostEqual(usd["actionable"]["confirmed"], 955.14, places=2)
        self.assertAlmostEqual(usd["needs_owner_decision"]["confirmed"], 125.85, places=2)
        self.assertEqual(usd["actionable"]["estimated"], 0.0)

    def test_sorted_by_saving(self):
        vals = [f["monthly_savings"] for f in self.r["findings"] if f["monthly_savings"] is not None]
        self.assertEqual(vals, sorted(vals, reverse=True))

    def test_markdown_is_self_explaining(self):
        md = cs.to_markdown(self.r)
        for s in ("Actionable now", "Needs owner decision", "vm-batch-nightly", "Read-only analysis",
                  "Top spend"):
            self.assertIn(s, md)
        self.assertNotIn("20.61.1.10", md, "public IP address must not be echoed into the report")


class AwsAccount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "aws-account"], AS_OF)
        cls.f = by_name(cls.r)

    def test_findings(self):
        self.assertEqual(set(self.f), {"etl-scratch-old", "restore-test", "archive-logs", "eipalloc-0idle",
                                       "reporting-worker"})

    def test_ebs_estimates_from_price_table(self):
        self.assertEqual(self.f["etl-scratch-old"]["monthly_savings"], 40.0)
        self.assertEqual(self.f["etl-scratch-old"]["basis"], "list-price-estimate")
        self.assertEqual(self.f["archive-logs"]["monthly_savings"], 90.0)
        self.assertEqual(self.f["archive-logs"]["risk"], "high")  # env=prod tag
        self.assertEqual(self.f["restore-test"]["risk"], "medium")  # 2 days old

    def test_compute_optimizer_picks_best_option(self):
        w = self.f["reporting-worker"]
        self.assertEqual(w["basis"], "compute-optimizer")
        self.assertEqual(w["monthly_savings"], 280.32)
        self.assertIn("m5.2xlarge", w["title"])

    def test_elastic_ip(self):
        self.assertEqual(self.f["eipalloc-0idle"]["monthly_savings"], 3.65)

    def test_spend_by_service(self):
        s = self.r["aws_spend_by_service"]
        self.assertEqual(s[0]["service"], "Amazon Elastic Compute Cloud - Compute")
        self.assertEqual(s[0]["cost"], 4210.55)


class EdgeCases(unittest.TestCase):
    def test_clean_estate_says_so_honestly(self):
        r = cs.analyse([FX / "clean-estate"], AS_OF)
        self.assertEqual(r["finding_count"], 0)
        md = cs.to_markdown(r)
        self.assertIn("No savings opportunities found", md)
        self.assertIn("not that the estate is optimal", md)

    def test_advisor_rest_value_wrapper(self):
        r = cs.analyse([FX / "advisor-rest-format"], AS_OF)
        self.assertEqual(r["finding_count"], 1)

    def test_bad_inputs_are_reported_not_crashed(self):
        r = cs.analyse([FX / "bad-inputs"], AS_OF)
        reasons = {Path(s["file"]).name: s["reason"] for s in r["skipped"]}
        self.assertIn("invalid JSON", reasons["truncated.json"])
        self.assertIn("unrecognised", reasons["unknown.json"])
        self.assertIn("resource-id column", reasons["wrong-columns.csv"])
        self.assertEqual(r["inputs"], [])

    def test_merge_same_resource_from_two_sources(self):
        a = cs.new_finding(resource_id="/subscriptions/x/resourceGroups/rg/providers/p/r1", name="r1",
                           basis="list-price-estimate", monthly_savings=5.0, currency="USD", sources=["s1"])
        b = cs.new_finding(resource_id="/SUBSCRIPTIONS/X/RESOURCEGROUPS/RG/PROVIDERS/P/R1", name="r1",
                           basis="advisor", monthly_savings=9.0, currency="USD", sources=["s2"])
        m = cs.merge([a, b])
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["basis"], "advisor")
        self.assertEqual(m[0]["sources"], ["s1", "s2"])

    def test_date_formats(self):
        for s in ("2026-09-27", "09/27/2026", "20260927", "2026-09-27T10:00:00.1234567+00:00", "2026-09-27T10:00:00Z"):
            self.assertEqual(cs.parse_date(s), date(2026, 9, 27), s)
        self.assertIsNone(cs.parse_date("not a date"))


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "cost_scout.py"), *args],
                              capture_output=True, text=True, encoding="utf-8", timeout=60)

    def test_out_dir_writes_both_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.run_cli(str(FX / "azure-dev-subscription"), "--as-of", "2026-09-27", "--out-dir", d)
            self.assertEqual(p.returncode, 0, p.stderr)
            data = json.loads(Path(d, "cost-scout-report.json").read_text(encoding="utf-8"))
            self.assertEqual(data["finding_count"], 10)
            self.assertIn("Cloud Cost Scout report", Path(d, "cost-scout-report.md").read_text(encoding="utf-8"))

    def test_json_mode(self):
        p = self.run_cli(str(FX / "aws-account"), "--json", "--as-of", "2026-09-27")
        self.assertEqual(json.loads(p.stdout)["finding_count"], 5)

    def test_no_usable_input_exits_nonzero(self):
        self.assertEqual(self.run_cli(str(FX / "bad-inputs")).returncode, 1)


if __name__ == "__main__":
    unittest.main()

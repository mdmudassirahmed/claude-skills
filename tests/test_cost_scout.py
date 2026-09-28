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


# ====================================================================== v2 capabilities
import shutil  # noqa: E402

import iac_locate as il  # noqa: E402

ALL_NEW = ["azure-two-months", "aws-cur", "azure-optimisation", "log-analytics-usage", "cost-edge-cases"]


def checks(report):
    """{(name, check)} for findings that came from the new checks."""
    return {(f["name"], f["check"]) for f in report["findings"] if f["check"]}


def find(report, name, check=None):
    hits = [f for f in report["findings"] if f["name"] == name and f["check"] == check]
    assert len(hits) == 1, f"{name}/{check}: {len(hits)} findings"
    return hits[0]


def usd(report):
    return report["bill_change"]["by_currency"]["USD"]


class BillChange(unittest.TestCase):
    """August (31 full days) vs September (15 days) - each normalised to a 30.4-day month.
    Daily costs per resource (Aug -> Sep): vm-api-dev 10 -> 10, vm-etl-dev 5 -> 20, sqldb-orders 8 -> 6,
    vmss-api-dev 0 -> 16 (new), disk-old-dev 2.5 -> 0 (gone), stlogsshared 1 -> 1.5, law-shared 3 -> 4."""

    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "azure-two-months"], AS_OF)
        cls.c = usd(cls.r)

    def test_months_and_days(self):
        bc = self.r["bill_change"]
        self.assertEqual(bc["status"], "compared")
        self.assertEqual((bc["previous_month"], bc["latest_month"]), ("2026-08", "2026-09"))
        self.assertEqual((bc["previous_days"], bc["latest_days"]), (31, 15))
        self.assertEqual(bc["notes"], [])

    def test_total_change_hand_computed(self):
        # Aug 29.5/day x 30.4 = 896.80 ; Sep 57.5/day x 30.4 = 1748.00
        self.assertAlmostEqual(self.c["previous_monthly"], 896.80, places=2)
        self.assertAlmostEqual(self.c["latest_monthly"], 1748.00, places=2)
        self.assertAlmostEqual(self.c["change"], 851.20, places=2)
        self.assertEqual(self.c["change_pct"], 94.9)

    def test_partial_month_compares_fairly(self):
        # vm-api-dev costs 10/day in both months: 310 in Aug, 150 in half of Sep, but no change in run rate
        names = [x["name"] for x in self.c["top_increases_by_resource"] + self.c["top_decreases_by_resource"]]
        self.assertNotIn("vm-api-dev", names)

    def test_top_increases_by_resource(self):
        got = [(x["name"], x["previous_monthly"], x["latest_monthly"], x["change"])
               for x in self.c["top_increases_by_resource"]]
        self.assertEqual(got, [("vmss-api-dev", 0.0, 486.4, 486.4), ("vm-etl-dev", 152.0, 608.0, 456.0),
                               ("law-shared", 91.2, 121.6, 30.4), ("stlogsshared", 30.4, 45.6, 15.2)])
        self.assertIsNone(self.c["top_increases_by_resource"][0]["change_pct"])  # new: no base to compare
        self.assertEqual(self.c["top_increases_by_resource"][1]["change_pct"], 300.0)

    def test_top_decreases_by_resource(self):
        got = [(x["name"], x["change"]) for x in self.c["top_decreases_by_resource"]]
        self.assertEqual(got, [("disk-old-dev", -76.0), ("sqldb-orders", -60.8)])

    def test_by_service(self):
        ups = {x["service"]: x["change"] for x in self.c["top_increases_by_service"]}
        self.assertAlmostEqual(ups["Virtual Machines"], 942.4, places=2)  # 15/day -> 46/day
        self.assertAlmostEqual(ups["Log Analytics"], 30.4, places=2)
        downs = [(x["service"], x["change"]) for x in self.c["top_decreases_by_service"]]
        self.assertEqual(downs, [("SQL Database", -60.8), ("Storage", -60.8)])  # tie -> sorted by name

    def test_by_resource_group(self):
        got = {x["resource_group"]: x["change"] for x in self.c["top_increases_by_resource_group"]}
        self.assertEqual(got, {"rg-app-dev": 410.4, "rg-data-dev": 395.2, "rg-shared": 45.6})
        self.assertEqual(self.c["top_decreases_by_resource_group"], [])

    def test_new_and_gone(self):
        self.assertEqual([(x["name"], x["latest_monthly"]) for x in self.c["new_resources"]], [("vmss-api-dev", 486.4)])
        self.assertEqual([(x["name"], x["previous_monthly"]) for x in self.c["gone_resources"]], [("disk-old-dev", 76.0)])
        self.assertEqual((self.c["new_resource_count"], self.c["gone_resource_count"]), (1, 1))

    def test_ids_matched_across_months_case_insensitively(self):
        # August ids are upper-case, September lower-case: still one resource each
        ids = [x["resource_id"] for x in self.c["top_increases_by_resource"]]
        self.assertEqual(len(ids), len(set(i.lower() for i in ids)))
        self.assertTrue(all(i == i.lower() for i in ids))

    def test_idle_enrichment_uses_latest_month(self):
        f = find(self.r, "vm-etl-dev")
        self.assertEqual(f["basis"], "actual-cost")
        self.assertAlmostEqual(f["monthly_savings"], 608.0, places=2)  # 20/day x 30.4, not the 2-month blend
        self.assertEqual(self.r["totals_monthly"]["USD"]["actionable"]["confirmed"], 608.0)

    def test_one_file_with_both_months_gives_same_answer(self):
        with tempfile.TemporaryDirectory() as d:
            src = FX / "azure-two-months"
            a = (src / "cost-2026-08.csv").read_text(encoding="utf-8").splitlines()
            b = (src / "cost-2026-09.csv").read_text(encoding="utf-8").splitlines()
            Path(d, "both.csv").write_text("\n".join(a + b[1:]) + "\n", encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        self.assertEqual(r["bill_change"], self.r["bill_change"])

    def test_overlapping_exports_are_not_double_counted(self):
        with tempfile.TemporaryDirectory() as d:
            for f in ("cost-2026-08.csv", "cost-2026-09.csv"):
                shutil.copy(FX / "azure-two-months" / f, Path(d, f))
            shutil.copy(FX / "azure-two-months" / "cost-2026-09.csv", Path(d, "cost-2026-09-copy.csv"))
            r = cs.analyse([d], AS_OF)
        self.assertEqual(usd(r)["latest_monthly"], 1748.0)

    def test_gap_between_months_is_explained(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "c.csv").write_text("Date,ResourceId,Cost\n2026-06-01,/x/r1,10\n2026-06-02,/x/r1,10\n"
                                        "2026-07-01,/x/r1,1\n2026-09-01,/x/r1,20\n", encoding="utf-8")
            bc = cs.analyse([d], AS_OF)["bill_change"]
        self.assertEqual((bc["previous_month"], bc["latest_month"]), ("2026-07", "2026-09"))
        self.assertIn("months in between are missing", " ".join(bc["notes"]))
        self.assertIn("2026-06", " ".join(bc["notes"]))
        # 1/day in July (1 day of data) -> 30.4 ; 20/day in Sep -> 608
        self.assertEqual((usd({"bill_change": bc})["previous_monthly"], usd({"bill_change": bc})["latest_monthly"]),
                         (30.4, 608.0))

    def test_single_month_says_so_plainly(self):
        bc = cs.analyse([FX / "azure-dev-subscription"], AS_OF)["bill_change"]
        self.assertEqual(bc["status"], "single-month")
        self.assertEqual(bc["months"], ["2026-09"])
        self.assertIn("one calendar month (2026-09)", bc["message"])
        self.assertIn("previous month", bc["message"])

    def test_no_cost_data(self):
        r = cs.analyse([FX / "aws-account"], AS_OF)
        self.assertEqual(r["bill_change"]["status"], "no-cost-data")
        self.assertEqual(r["tagging"]["status"], "no-cost-data")

    def test_no_date_column(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "c.csv").write_text("ResourceId,Cost\n/x/r1,10\n", encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        self.assertEqual(r["bill_change"]["status"], "no-dates")
        self.assertEqual(r["top_spend"][0]["monthly"], 10.13)  # undated: old 30-day behaviour


class Tagging(unittest.TestCase):
    def test_azure_tags_column(self):
        t = cs.analyse([FX / "azure-two-months"], AS_OF)["tagging"]
        self.assertEqual(t["status"], "ok")
        self.assertEqual(t["period"], "2026-09")
        u = t["by_currency"]["USD"]
        # Sep run rates: owned = vm-api-dev 304 (owner), sqldb 182.4 (costcenter, JSON with braces),
        # stlogsshared 45.6 (Team); unowned = vm-etl-dev 608 (env only), vmss 486.4 (no tags), law-shared 121.6 (empty owner)
        self.assertEqual(u["total_monthly"], 1748.0)
        self.assertEqual(u["untagged_monthly"], 1216.0)
        self.assertEqual(u["untagged_pct"], 69.6)
        self.assertEqual((u["tagged_resources"], u["untagged_resources"]), (3, 3))
        self.assertEqual([x["name"] for x in u["top_untagged"]], ["vm-etl-dev", "vmss-api-dev", "law-shared"])

    def test_aws_cur_tag_columns(self):
        u = cs.analyse([FX / "aws-cur"], AS_OF)["tagging"]["by_currency"]["USD"]
        # Sep: web 145.92 + prod 304 owned; batch 182.4 + volume 30.4 unowned
        self.assertEqual(u["total_monthly"], 662.72)
        self.assertEqual(u["untagged_monthly"], 212.8)
        self.assertEqual(u["untagged_pct"], 32.1)
        self.assertEqual([x["name"] for x in u["top_untagged"]], ["i-0batch000000002", "vol-0data00000004"])

    def test_no_tag_column(self):
        t = cs.analyse([FX / "azure-dev-subscription"], AS_OF)["tagging"]
        self.assertEqual(t["status"], "no-tag-column")
        self.assertIn("Tags column", t["message"])

    def test_tag_text_parsing_is_lenient(self):
        self.assertEqual(cs.parse_tag_text('"env": "dev","owner": "a"'), {"env": "dev", "owner": "a"})
        self.assertEqual(cs.parse_tag_text('{"env": "dev"}'), {"env": "dev"})
        self.assertEqual(cs.parse_tag_text("env=dev;owner=ana"), {"env": "dev", "owner": "ana"})
        self.assertEqual(cs.parse_tag_text('"a": "x", "b": "y" trailing junk'), {"a": "x", "b": "y"})
        self.assertEqual(cs.parse_tag_text(""), {})
        self.assertEqual(cs.parse_tag_text("{not json"), {})
        self.assertEqual(cs.parse_tag_text('{"n": null}'), {"n": ""})

    def test_owner_keys(self):
        for k in ("owner", "Owner", "createdBy", "cost-center", "cost_center", "CostCenter", "team", "app-owner",
                  "user:owner", "aws:createdBy"):
            self.assertTrue(cs.is_owner_key(k), k)
        for k in ("env", "name", "ownership-notes"):
            self.assertFalse(cs.is_owner_key(k), k)


class AwsCur(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "aws-cur"], AS_OF)

    def test_detected_as_cur(self):
        self.assertEqual(sorted(i["type"] for i in self.r["inputs"]), ["aws-cur-csv", "aws-ec2-instances"])

    def test_actual_cost_per_resource_from_latest_month(self):
        spend = {x["resource_id"]: x["monthly"] for x in self.r["top_spend"]}
        self.assertEqual(spend["i-0web00000000001"], 145.92)  # 4.8/day x 30.4
        self.assertEqual(spend["i-0batch000000002"], 182.4)   # 6/day in Sep (was 2/day in Aug)
        self.assertNotIn("", spend)  # the tax line has no resource id

    def test_bill_change_includes_unattributed_lines(self):
        c = usd(self.r)
        # Aug: (17.8/day x 31 + 20 tax) / 31 x 30.4 ; Sep: 21.8/day x 30.4
        self.assertAlmostEqual(c["previous_monthly"], round((17.8 * 31 + 20) / 31 * 30.4, 2), places=2)
        self.assertAlmostEqual(c["latest_monthly"], 662.72, places=2)
        self.assertEqual(c["top_increases_by_resource"][0]["name"], "i-0batch000000002")
        self.assertEqual(c["top_increases_by_resource"][0]["change"], 121.6)
        self.assertEqual(c["top_increases_by_service"][0]["service"], "Amazon Elastic Compute Cloud")
        self.assertEqual(c["top_increases_by_resource_group"][0]["resource_group"], "(no resource group)")

    def test_cur_columns_any_case(self):
        with tempfile.TemporaryDirectory() as d:
            text = (FX / "aws-cur" / "cur-2026-08-09.csv").read_text(encoding="utf-8").splitlines()
            Path(d, "cur.csv").write_text("\n".join([text[0].lower()] + text[1:]) + "\n", encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        self.assertEqual(r["inputs"][0]["type"], "aws-cur-csv")
        self.assertEqual(usd(r)["latest_monthly"], 662.72)
        self.assertEqual(r["tagging"]["by_currency"]["USD"]["untagged_pct"], 32.1)

    def test_cur2_underscore_columns(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "cur2.csv").write_text(
                "line_item_usage_start_date,line_item_resource_id,line_item_unblended_cost,line_item_currency_code,"
                "line_item_product_code,resource_tags_user_owner\n"
                "2026-09-01T00:00:00Z,i-1,3.0,USD,AmazonEC2,ops\n2026-09-02T00:00:00Z,i-1,3.0,USD,AmazonEC2,ops\n",
                encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        self.assertEqual(r["inputs"][0]["type"], "aws-cur-csv")
        self.assertEqual(r["top_spend"][0]["monthly"], 91.2)
        self.assertEqual(r["tagging"]["by_currency"]["USD"]["untagged_pct"], 0.0)


class Schedules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.az = cs.analyse([FX / "azure-optimisation"], AS_OF)
        cls.aws = cs.analyse([FX / "aws-cur"], AS_OF)

    def sched(self, r):
        return {f["name"]: f for f in r["findings"] if f["check"] == "schedule"}

    def test_azure_schedule_candidates(self):
        self.assertEqual(set(self.sched(self.az)), {
            "vm-web-dev", "vm-win-dev", "vm-desktop-dev", "vm-app01", "vm-nightly-uat",
            "vmss-build-agents-dev", "vmss-render-test", "aks-dev"})

    def test_saving_maths(self):
        s = self.sched(self.az)
        # actual monthly cost x (1 - 60/168)
        for name, per_day in (("vm-web-dev", 6.0), ("vm-win-dev", 10.0), ("vmss-build-agents-dev", 12.0),
                              ("vm-app01", 5.0)):
            self.assertEqual(s[name]["monthly_savings"], round(per_day * 30.4 * (1 - 60 / 168), 2), name)
            self.assertEqual(s[name]["basis"], "schedule-estimate")
        self.assertEqual(s["vm-web-dev"]["monthly_savings"], 117.26)

    def test_aks_priced_from_node_pool_scale_sets(self):
        f = self.sched(self.az)["aks-dev"]
        self.assertEqual(f["evidence"]["nodePoolScaleSets"], ["aks-nodepool1-12345678-vmss"])
        self.assertEqual(f["monthly_savings"], 390.86)  # 20/day x 30.4 x (1 - 60/168)
        self.assertIn("az aks stop", f["action"])
        self.assertIn("not run by this skill", f["action"].lower())

    def test_exclusions(self):
        s = self.sched(self.az)
        for name, why in (("vm-win-ahb", "schedule-exempt tag"), ("vm-reporting-qa", "24x7 tag value"),
                          ("vm-dev-autoshutdown", "already has auto-shutdown"), ("vm-web-prod", "prod"),
                          ("vm-jumpbox", "env=Production tag"), ("vm-stopped-dev", "deallocated"),
                          ("vmss-worker-prod", "prod"), ("vmss-idle-dev", "capacity 0"), ("aks-qa", "stopped"),
                          ("aks-nodepool1-12345678-vmss", "AKS node pool, counted via the cluster")):
            self.assertNotIn(name, s, why)

    def test_unpriced_without_cost_data(self):
        s = self.sched(self.az)
        for name in ("vm-desktop-dev", "vm-nightly-uat", "vmss-render-test"):
            self.assertIsNone(s[name]["monthly_savings"])
            self.assertEqual(s[name]["basis"], "unknown")

    def test_risk_and_wording(self):
        for f in self.sched(self.az).values():
            self.assertEqual(f["risk"], "medium", f["name"])
            self.assertIn("confirm nobody works off-hours or runs overnight jobs", " ".join(f["risk_notes"]))
            self.assertEqual(f["category"], "schedule")
        vm = self.sched(self.az)["vm-web-dev"]
        self.assertIn("auto-shutdown", vm["action"])
        self.assertIn("not by this skill", vm["action"])
        self.assertEqual(vm["evidence"]["officeHoursPerWeek"], 60)

    def test_non_prod_resource_group_is_not_treated_as_prod(self):
        self.assertEqual(self.sched(self.az)["vm-app01"]["risk"], "medium")

    def test_schedules_count_as_estimated_never_confirmed(self):
        usd_t = self.az["totals_monthly"]["USD"]
        self.assertEqual(usd_t["actionable"]["confirmed"], 0.0)
        priced = sum(f["monthly_savings"] for f in self.az["findings"]
                     if f["monthly_savings"] is not None and f["risk"] != "high")
        self.assertAlmostEqual(usd_t["actionable"]["estimated"], round(priced, 2), places=2)
        self.assertAlmostEqual(usd_t["actionable"]["estimated"], 1058.57, places=2)

    def test_aws_instances(self):
        s = self.sched(self.aws)
        self.assertEqual(set(s), {"web-dev", "batch-worker-dev", "qa-runner", "render-farm-dev"})
        self.assertEqual(s["web-dev"]["monthly_savings"], 93.81)          # 145.92 x 108/168
        self.assertEqual(s["batch-worker-dev"]["monthly_savings"], 117.26)  # 182.40 x 108/168
        self.assertIsNone(s["qa-runner"]["monthly_savings"])               # not in the CUR
        self.assertIn("Instance Scheduler", s["web-dev"]["action"])
        self.assertAlmostEqual(self.aws["totals_monthly"]["USD"]["actionable"]["estimated"], 211.07, places=2)

    def test_assumption_comes_from_reference_file(self):
        row = {"id": "/subscriptions/s/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/vm1",
               "name": "vm1", "type": "microsoft.compute/virtualmachines", "resourceGroup": "rg-dev",
               "powerState": "PowerState/running", "scoutQuery": "optimisation-candidates"}
        costs = {cs.norm_id(row["id"]): {"monthly": 168.0, "currency": "USD"}}
        f = cs.azure_optimisation_findings([row], costs, {"office_hours_per_week": 40})[0]
        self.assertEqual(f["monthly_savings"], 128.0)  # 168 x (1 - 40/168)
        f = cs.azure_optimisation_findings([row], costs, {})[0]
        self.assertIsNone(f["monthly_savings"])  # no assumption -> no price
        self.assertEqual(cs.load_assumptions()["office_hours_per_week"], 60)

    def test_environment_and_exemption_rules(self):
        ec = cs.environment_class
        self.assertEqual(ec({"env": "DEV"}), "nonprod")
        self.assertEqual(ec({"Environment": "Production"}, "rg-dev"), "prod")
        self.assertEqual(ec({"env": "dev"}, "rg-prod"), "nonprod")  # the tag wins over names
        self.assertEqual(ec({}, "rg-web-dev01"), "nonprod")
        self.assertEqual(ec({}, "rg-app-non-prod"), "nonprod")
        self.assertEqual(ec({}, "rg-prod-devtools"), "prod")  # a production word anywhere wins
        self.assertIsNone(ec({}, "rg-latest", "vm-developer"))  # tokens, not substrings
        self.assertIsNone(ec({"env": "shared"}, "rg-core"))
        self.assertTrue(cs.schedule_exempt({"schedule-exempt": "true"}))
        self.assertTrue(cs.schedule_exempt({"Always_On": "yes"}))
        self.assertTrue(cs.schedule_exempt({"availability": "24x7"}))
        self.assertTrue(cs.schedule_exempt({"schedule": "24/7"}))
        self.assertFalse(cs.schedule_exempt({"always-on": "false"}))
        self.assertFalse(cs.schedule_exempt({"owner": "a"}))

    def test_idle_query_rows_never_get_optimisation_checks(self):
        # azure-dev-subscription has a running dev VM and an attached Premium disk, but from the idle query
        r = cs.analyse([FX / "azure-dev-subscription"], AS_OF)
        self.assertEqual(checks(r), set())
        self.assertTrue(all(f["check"] is None for f in r["findings"]))


class RateOptimisations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "azure-optimisation"], AS_OF)
        cls.rate = {(f["name"], f["check"]): f for f in cls.r["findings"] if f["category"] == "rate"}

    def test_expected_candidates_exactly(self):
        self.assertEqual(set(self.rate), {
            ("vm-win-dev", "ahb-windows"), ("vm-web-prod", "ahb-windows"),
            ("sqldb-orders-dev", "ahb-sql"), ("sqlvm-dev", "ahb-sql"),
            ("shop-dev", "devtest-offer"), ("shop-lab", "devtest-offer"),
            ("vmss-build-agents-dev", "spot"), ("vm-nightly-uat", "spot")})

    def test_negatives(self):
        names = {n for n, _ in self.rate}
        for name, why in (("vm-win-ahb", "already Windows_Server"), ("vm-desktop-dev", "Windows client image"),
                          ("vm-stopped-dev", "deallocated"), ("vm-web-dev", "Linux"),
                          ("master", "system database"), ("sqldb-basic", "DTU, no licence type"),
                          ("sqldb-reports", "already BasePrice"), ("sqlvm-express", "free edition"),
                          ("sqlvm-ahb", "already AHUB"), ("shop-prod", "production"),
                          ("shop-test", "already Dev/Test"), ("shared-services", "not non-prod"),
                          ("team-dev-credits", "Visual Studio offer"), ("vmss-render-test", "already Spot"),
                          ("aks-nodepool1-12345678-vmss", "AKS node pool"), ("vmss-worker-prod", "prod")):
            self.assertNotIn(name, names, why)
        self.assertNotIn(("vm-web-dev", "spot"), self.rate)

    def test_unpriced_with_condition_and_effect(self):
        for key, f in self.rate.items():
            self.assertIsNone(f["monthly_savings"], key)
            self.assertIsNone(f["currency"], key)
            self.assertTrue(f["evidence"]["condition"], key)
            self.assertTrue(f["evidence"]["typical_effect"], key)
        self.assertIn("Software Assurance", self.rate[("vm-win-dev", "ahb-windows")]["evidence"]["condition"])
        self.assertIn("Visual Studio", self.rate[("shop-dev", "devtest-offer")]["evidence"]["condition"])
        self.assertIn("eviction", self.rate[("vmss-build-agents-dev", "spot")]["evidence"]["condition"])

    def test_devtest_scope_is_the_subscription(self):
        self.assertEqual(self.rate[("shop-dev", "devtest-offer")]["scope"], "11111111-0000-4000-8000-000000000001")

    def test_prod_rate_item_needs_owner_decision(self):
        self.assertEqual(self.rate[("vm-web-prod", "ahb-windows")]["risk"], "high")

    def test_never_counted_in_totals_even_if_priced(self):
        fake = cs.new_finding(name="x", category="rate", check="spot", monthly_savings=999.0, currency="USD",
                              basis="advisor")
        self.assertEqual(cs.compute_totals([fake]), {})

    def test_same_resource_keeps_separate_checks(self):
        both = [f for f in self.r["findings"] if f["name"] == "vm-win-dev"]
        self.assertEqual(sorted(f["check"] for f in both), ["ahb-windows", "schedule"])

    def test_aws_spot(self):
        r = cs.analyse([FX / "aws-cur"], AS_OF)
        spot = {f["name"] for f in r["findings"] if f["check"] == "spot"}
        self.assertEqual(spot, {"batch-worker-dev"})  # render-farm-dev already runs on Spot


class StorageTiering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "azure-optimisation"], AS_OF)
        cls.s = {(f["name"], f["check"]): f for f in cls.r["findings"] if f["category"] == "storage"}

    def test_candidates(self):
        self.assertEqual(set(self.s), {("disk-web-dev-data", "premium-disk"), ("disk-premium-nocost", "premium-disk"),
                                       ("stlogsdev", "blob-lifecycle")})

    def test_premium_disk_saving(self):
        f = self.s[("disk-web-dev-data", "premium-disk")]
        self.assertEqual(f["monthly_savings"], 22.8)  # 1.5/day x 30.4 = 45.60 x (1 - 0.5)
        self.assertEqual(f["basis"], "tier-change-estimate")
        self.assertIn("StandardSSD", f["action"])
        self.assertIsNone(self.s[("disk-premium-nocost", "premium-disk")]["monthly_savings"])

    def test_lifecycle_rule_is_unpriced_and_above_threshold_only(self):
        f = self.s[("stlogsdev", "blob-lifecycle")]
        self.assertIsNone(f["monthly_savings"])
        self.assertEqual(f["evidence"]["accountMonthlyCost"], 152.0)
        self.assertIn("Cool after 30 days", f["action"])
        self.assertIn("Archive after 180", f["action"])
        names = {n for n, _ in self.s}
        for name in ("stsmallhot", "stcooldev", "sthotnocost", "disk-web-prod-data", "disk-std-dev", "disk-premv2-dev"):
            self.assertNotIn(name, names)


class Logging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "log-analytics-usage"], AS_OF)
        cls.ws = {w["workspace"]: w for w in cls.r["logging"]["workspaces"]}

    def test_both_usage_shapes_recognised(self):
        types = [i["type"] for i in self.r["inputs"]]
        self.assertEqual(types.count("azure-log-usage"), 3)
        self.assertEqual(self.r["skipped"], [])

    def test_workspace_cost_apportioned_by_gb_share(self):
        w = self.ws["law-dev"]
        self.assertEqual(w["monthly_cost"], 912.0)  # Log Analytics 30/day x 30.4; Sentinel meter left out
        self.assertEqual(w["cost_basis"], "actual-cost")
        self.assertEqual(w["billable_gb"], 1000.0)
        self.assertEqual(w["matched_by"], "file name")
        t = {x["table"]: x for x in w["tables"]}
        self.assertEqual(t["ContainerLogV2"]["gb"], 600.0)  # two Solution rows summed
        self.assertEqual(t["ContainerLogV2"]["solutions"], ["ContainerInsights", "LogManagement"])
        self.assertEqual(t["ContainerLogV2"]["monthly_cost_share"], 547.2)
        self.assertEqual(t["AppTraces"]["monthly_cost_share"], 182.4)
        self.assertEqual(t["Perf"]["share_pct"], 3.0)
        self.assertEqual(t["Syslog"]["suggestion"], "small table")
        self.assertEqual([x["table"] for x in w["tables"]][:2], ["ContainerLogV2", "AppTraces"])

    def test_table_findings_and_estimates(self):
        got = {(f["name"], f["check"]): (f["monthly_savings"], f["basis"]) for f in self.r["findings"]
               if f["name"].startswith("law-dev/")}
        self.assertEqual(got, {
            ("law-dev/ContainerLogV2", "basic-logs"): (437.76, "basic-logs-estimate"),   # 547.20 x (1 - 0.2)
            ("law-dev/AppTraces", "basic-logs"): (145.92, "basic-logs-estimate"),        # 182.40 x 0.8
            ("law-dev/AzureDiagnostics", "basic-logs"): (72.96, "basic-logs-estimate"),  # 91.20 x 0.8
            ("law-dev/AppRequests", "sampling"): (27.36, "sampling-estimate"),           # 54.72 x 0.5
        })
        f = find(self.r, "law-dev/ContainerLogV2", "basic-logs")
        self.assertEqual(f["evidence"]["tableMonthlyCost"], 547.2)
        self.assertEqual(f["evidence"]["tableMonthlyCostBasis"], "actual-cost")
        self.assertIn("lower the logging level", find(self.r, "law-dev/AppTraces", "basic-logs")["action"])

    def test_workspace_settings(self):
        self.assertIn(("law-dev", "retention"), checks(self.r))
        self.assertIn(("law-dev", "daily-cap"), checks(self.r))
        self.assertIsNone(find(self.r, "law-dev", "retention")["monthly_savings"])
        for name in ("law-prod", "law-sandbox-capped"):
            self.assertNotIn((name, "retention"), checks(self.r))
            self.assertNotIn((name, "daily-cap"), checks(self.r))

    def test_prod_workspace(self):
        f = find(self.r, "law-prod/ContainerLogV2", "basic-logs")
        self.assertEqual(f["monthly_savings"], round(round(12160.0 * 2500 / 3500, 2) * 0.8, 2))
        self.assertEqual(f["risk"], "high")
        ct = find(self.r, "law-prod", "commitment-tier")  # 3500 GB / 31 days = 112.9 GB/day
        self.assertEqual(ct["category"], "rate")
        self.assertIsNone(ct["monthly_savings"])
        self.assertNotIn(("law-dev", "commitment-tier"), checks(self.r))

    def test_unmatched_usage_is_unpriced_with_a_note(self):
        w = self.ws["usage-mystery"]
        self.assertIsNone(w["matched_by"])
        self.assertIn("could not tell which workspace", " ".join(w["notes"]))
        self.assertIsNone(find(self.r, "usage-mystery/ContainerLogV2", "basic-logs")["monthly_savings"])

    def test_totals(self):
        t = self.r["totals_monthly"]["USD"]
        self.assertAlmostEqual(t["actionable"]["estimated"], 684.0, places=2)
        self.assertEqual(t["actionable"]["confirmed"], 0.0)
        self.assertAlmostEqual(t["needs_owner_decision"]["estimated"], 8338.28, places=2)

    def test_single_workspace_and_no_cost(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "anything.json").write_text(json.dumps(
                [{"DataType": "AppRequests", "Solution": "LogManagement", "IngestedGB": 40}]), encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        f = find(r, "anything/AppRequests", "sampling")
        self.assertIsNone(f["monthly_savings"])  # no cost export -> unpriced
        self.assertEqual(r["totals_monthly"], {})

    def test_usage_rows_variants(self):
        rows = cs.usage_rows([{"DataType": "Perf", "Quantity": 2048}, {"DataType": "", "IngestedGB": 3},
                              {"DataType": "X", "IngestedGB": -1}, "junk"])
        self.assertEqual(rows, [{"table": "Perf", "solution": "", "gb": 2.0, "workspace": ""}])
        rows = cs.usage_rows([{"DataType": "Perf", "IngestedGB": "1,024.5", "Workspace": "law-a"}])
        self.assertEqual((rows[0]["gb"], rows[0]["workspace"]), (1024.5, "law-a"))
        with self.assertRaises(ValueError):
            cs.usage_rows({"tables": [{"columns": [{"name": "DataType"}], "rows": []}]})

    def test_workspace_column_splits_one_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "usage.json").write_text(json.dumps([
                {"DataType": "AppTraces", "IngestedGB": 30, "Workspace": "law-a"},
                {"DataType": "AppTraces", "IngestedGB": 10, "Workspace": "law-b"}]), encoding="utf-8")
            r = cs.analyse([d], AS_OF)
        self.assertEqual(sorted(w["workspace"] for w in r["logging"]["workspaces"]), ["law-a", "law-b"])
        self.assertEqual({w["matched_by"] for w in r["logging"]["workspaces"]}, {"workspace column"})


class EdgeCasesV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = cs.analyse([FX / "cost-edge-cases"], AS_OF)

    def test_bad_files_reported_not_crashed(self):
        reasons = {Path(s["file"]).name: s["reason"] for s in self.r["skipped"]}
        self.assertEqual(set(reasons), {"empty.csv", "usage-empty.json", "usage-bad-values.json"})
        self.assertIn("resource-id column", reasons["empty.csv"])
        self.assertIn("no rows with DataType", reasons["usage-bad-values.json"])
        self.assertIn("header-only.csv", {Path(i["file"]).name for i in self.r["inputs"]})

    def test_messy_rows(self):
        spend = {x["resource_id"].split("/")[-1]: x for x in self.r["top_spend"]}
        # 3 dated days (Sep 1-3): res-good 10 (bad numbers skipped, undated row left out) -> 10 x 30.4 / 3
        self.assertEqual(spend["res-good"]["monthly"], 101.33)
        self.assertEqual(spend["res-good"]["currency"], "EUR")
        self.assertEqual(spend["res-bad-tags"]["monthly"], 20.27)
        t = self.r["tagging"]["by_currency"]["EUR"]
        self.assertEqual(t["untagged_pct"], 16.7)  # res-bad-tags has unreadable tags -> no owner
        self.assertEqual(t["unattributed_monthly"], 30.4)  # the row with no resource id

    def test_odd_instances_are_ignored(self):
        self.assertEqual(self.r["findings"], [])

    def test_markdown_still_renders(self):
        md = cs.to_markdown(self.r)
        self.assertIn("## Tagging hygiene", md)
        self.assertIn("No savings opportunities found", md)

    def test_missing_assumptions_file_means_unpriced(self):
        self.assertEqual(cs.load_json_reference(FX / "does-not-exist.json"), {})
        self.assertEqual(cs.load_json_reference(FX / "bad-inputs" / "truncated.json"), {})

    def test_detect_new_formats(self):
        self.assertEqual(cs.detect(FX / "aws-cur" / "cur-2026-08-09.csv", None), "aws-cur-csv")
        self.assertEqual(cs.detect(Path("x.json"), [{"DataType": "A", "IngestedGB": 1}]), "azure-log-usage")
        self.assertEqual(cs.detect(Path("x.json"), {"tables": [{"columns": [{"name": "DataType"},
                                                                            {"name": "IngestedGB"}]}]}),
                         "azure-log-usage")
        self.assertEqual(cs.detect(Path("x.json"), {"Reservations": []}), "aws-ec2-instances")
        self.assertIsNone(cs.detect(Path("x.json"), {"tables": [{"columns": [{"name": "Other"}]}]}))

    def test_legacy_cost_csv_api_still_works(self):
        c = cs.cost_csv(FX / "azure-dev-subscription" / "cost-export-sep-2026.csv")
        vm = next(v for k, v in c.items() if k.endswith("/vm-batch-nightly"))
        self.assertEqual((vm["monthly"], vm["days"]), (367.84, 27))


class ExistingBehaviourUnchanged(unittest.TestCase):
    def test_azure_dev_subscription_sections(self):
        r = cs.analyse([FX / "azure-dev-subscription"], AS_OF)
        self.assertEqual(r["finding_count"], 10)
        self.assertEqual(r["logging"]["workspaces"], [])
        self.assertTrue(r["assumptions"]["loaded"])
        self.assertEqual(r["assumptions"]["values"]["office_hours_per_week"], 60)

    def test_aws_account_unchanged(self):
        r = cs.analyse([FX / "aws-account"], AS_OF)
        self.assertEqual(r["finding_count"], 5)
        self.assertEqual(checks(r), set())


class MarkdownAndDeterminism(unittest.TestCase):
    def test_markdown_mentions_every_new_section(self):
        md = cs.to_markdown(cs.analyse([FX / n for n in ALL_NEW], AS_OF))
        for s in ("## Bill change", "## Tagging hygiene", "## Logging (Log Analytics / Application Insights)",
                  "## Estimated opportunities (schedules, storage, logging)",
                  "## Rate optimisations (no price; check the condition first)",
                  "schedule-estimate", "basic-logs-estimate", "tier-change-estimate", "Biggest increases by resource",
                  "New this month", "Gone this month", "Increases by service", "Increases by resource group",
                  "Software Assurance", "never in these totals"):
            self.assertIn(s, md)
        self.assertNotIn(chr(0x2014), md)

    def test_single_month_markdown(self):
        md = cs.to_markdown(cs.analyse([FX / "azure-dev-subscription"], AS_OF))
        self.assertIn("covers one calendar month (2026-09)", md)
        self.assertIn("no Tags column", md)
        self.assertIn("No Log Analytics usage export", md)
        self.assertNotIn("## Rate optimisations", md)

    def test_same_input_same_output(self):
        for name in ALL_NEW:
            a = cs.analyse([FX / name], AS_OF)
            b = cs.analyse([FX / name], AS_OF)
            self.assertEqual(json.dumps(a, indent=2), json.dumps(b, indent=2), name)
            self.assertEqual(cs.to_markdown(a), cs.to_markdown(b), name)

    def test_cli_twice_is_byte_identical(self):
        outs = []
        for _ in range(2):
            p = subprocess.run([sys.executable, str(SCRIPTS / "cost_scout.py"), *[str(FX / n) for n in ALL_NEW],
                                "--json", "--as-of", "2026-09-27"],
                               capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            outs.append(p.stdout)
        self.assertEqual(outs[0], outs[1])
        self.assertGreater(json.loads(outs[0])["finding_count"], 30)


class IacLocate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.repo = root / "repo"
        shutil.copytree(FX / "iac-repo", cls.repo)
        decoy = "resource \"x\" \"y\" {\n  name = \"vm-web-dev\"\n}\n"
        for sub in (".git", "node_modules/pkg", ".terraform/modules/m", "bin", "obj/Debug"):
            (cls.repo / sub).mkdir(parents=True, exist_ok=True)
            (cls.repo / sub / "decoy.tf").write_text(decoy, encoding="utf-8")
        report = cs.analyse([FX / "azure-optimisation", FX / "aws-cur"], AS_OF)
        cls.report_dir = root / "report"
        cls.report_dir.mkdir()
        (cls.report_dir / "cost-scout-report.json").write_text(json.dumps(report), encoding="utf-8")
        cls.res = il.locate(il.load_report(cls.report_dir), cls.repo)
        cls.by = {}
        for x in cls.res["results"]:
            cls.by.setdefault(x["name"], []).append(x)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def where(self, name):
        return sorted({(m["file"], tuple(m["lines"]), m["kind"]) for x in self.by[name] for m in x["matches"]})

    def test_finds_the_right_files_and_lines(self):
        self.assertEqual(self.where("vm-web-dev"), [("infra/main.bicep", (4,), "bicep")])
        self.assertEqual(self.where("disk-web-dev-data"), [("infra/main.bicep", (12,), "bicep")])
        self.assertEqual(self.where("vm-win-dev"), [("infra/arm/azuredeploy.json", (8,), "arm")])
        self.assertEqual(self.where("vmss-build-agents-dev"), [("terraform/main.tf", (2,), "terraform")])
        self.assertEqual(self.where("stlogsdev"), [("terraform/storage.tf", (2,), "terraform")])
        self.assertEqual(self.where("batch-worker-dev"), [("cloudformation/batch.yaml", (9,), "cloudformation")])

    def test_ignores_excluded_dirs_non_iac_files_and_longer_names(self):
        files = {m["file"] for x in self.res["results"] for m in x["matches"]}
        for bad in ("docs/README.md", "infra/arm/appsettings.json"):
            self.assertNotIn(bad, files)
        self.assertFalse(any(part in f for f in files for part in (".git/", "node_modules/", ".terraform/",
                                                                     "bin/", "obj/")))
        self.assertEqual(self.res["iac_files_scanned"], 5)
        self.assertEqual(self.res["iac_files_by_kind"], {"arm": 1, "bicep": 1, "cloudformation": 1, "terraform": 2})

    def test_not_found_listed(self):
        self.assertIn("aks-dev", self.res["not_found"])
        self.assertIn("web-dev", self.res["not_found"])  # only "vm-web-dev" exists; whole-name match

    def test_iac_kind(self):
        self.assertEqual(il.iac_kind(Path("a.json"), '{"$schema": "https://x/deploymentTemplate.json#"}'), "arm")
        self.assertIsNone(il.iac_kind(Path("a.json"), '{"$schema": "https://x/deploymentParameters.json#"}'))
        self.assertEqual(il.iac_kind(Path("t.json"), '{"Resources": {"A": {"Type": "AWS::S3::Bucket"}}}'),
                         "cloudformation")
        self.assertIsNone(il.iac_kind(Path("pipeline.yml"), "steps:\n  - run: echo\n"))
        self.assertEqual(il.iac_kind(Path("m.tf.json"), "{}"), "terraform")

    def test_search_terms(self):
        self.assertEqual(il.search_terms({"name": "law-dev/ContainerLogV2", "evidence": {"workspace": "law-dev"}}),
                         ["law-dev", "ContainerLogV2"])
        self.assertEqual(il.search_terms({"name": "ab"}), [])

    def test_cli_outputs_and_errors(self):
        with tempfile.TemporaryDirectory() as out:
            p = subprocess.run([sys.executable, str(SCRIPTS / "iac_locate.py"), str(self.report_dir), str(self.repo),
                                "--out-dir", out], capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            data = json.loads(Path(out, "iac-locations.json").read_text(encoding="utf-8"))
            md = Path(out, "iac-locations.md").read_text(encoding="utf-8")
        self.assertEqual(data["iac_files_scanned"], 5)
        self.assertIn("`infra/main.bicep`", md)
        self.assertIn("pull request", md)
        p = subprocess.run([sys.executable, str(SCRIPTS / "iac_locate.py"), str(self.report_dir / "cost-scout-report.json"),
                            str(self.repo), "--json"], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(json.loads(p.stdout)["iac_files_scanned"], 5)
        p = subprocess.run([sys.executable, str(SCRIPTS / "iac_locate.py"), str(FX / "bad-inputs" / "unknown.json"),
                            str(self.repo)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(p.returncode, 2)
        p = subprocess.run([sys.executable, str(SCRIPTS / "iac_locate.py"), str(self.report_dir),
                            str(self.repo / "missing")], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(p.returncode, 2)

    def test_deterministic(self):
        again = il.locate(il.load_report(self.report_dir), self.repo)
        self.assertEqual(json.dumps(again), json.dumps(self.res))


if __name__ == "__main__":
    unittest.main()

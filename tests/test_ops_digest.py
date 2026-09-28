import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "ops-toolkit" / "skills"
SCRIPTS = SKILLS / "ops-digest" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import ops_digest as od  # noqa: E402

FX = ROOT / "tests" / "fixtures"
WEEK = FX / "digest" / "week-38"


class FromSavedReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = od.build([WEEK])
        cls.md = od.to_markdown(cls.d, "Orders platform", "22-28 Sep 2026")

    def test_each_report_recognised(self):
        self.assertEqual(len(self.d["cost"]), 1)
        self.assertEqual(len(self.d["incidents"]), 1)
        self.assertEqual(len(self.d["pipelines"]), 1)
        self.assertEqual(self.d["unrecognised"], ["notes.json"])
        self.assertEqual(self.d["invalid"], ["broken.json"])

    def test_figures_copied_not_invented(self):
        src = json.loads((WEEK / "cost-scout-report.json").read_text(encoding="utf-8"))
        lane = self.d["cost"][0]["lanes"][0]
        self.assertAlmostEqual(lane["actionable_confirmed"], src["totals_monthly"]["USD"]["actionable"]["confirmed"])
        self.assertIn("USD 955/month", self.md)

    def test_high_risk_items_not_in_actions(self):
        self.assertFalse(any("disk-prod-orphan" in a or "snap-sql" in a for a in self.d["actions"]))

    def test_incident_summary(self):
        i = self.d["incidents"][0]
        self.assertEqual(i["verdict"], "error-spike")
        self.assertTrue(i["started"].startswith("2026-09-26T09:42:20"))
        self.assertEqual(i["deploy"]["id"], "a1b2c3d4e5f6")
        self.assertIn("DiscountService.cs:57", " ".join(i["code"]))

    def test_actions_owner_routing_and_clean_truncation(self):
        acts = " | ".join(self.d["actions"])
        self.assertIn("ask pipeline-admin", acts)
        self.assertNotIn("<email-", acts.replace("<email-1>", ""))  # placeholders never split

    def test_markdown_and_html(self):
        html = od.to_html(self.md, "Orders platform")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("<h2>What needs doing</h2>", html)
        self.assertIn("&lt;email-1&gt;", html)  # escaped, not raw HTML
        self.assertNotIn("<script", html.lower())
        self.assertIn("Nothing was changed in any system", self.md)

    def test_no_pii_or_em_dash(self):
        blob = self.md + json.dumps(self.d)
        for bad in ("contoso.com", "fabrikam.io", "\u2014"):
            self.assertNotIn(bad, blob)


class FromFreshReports(unittest.TestCase):
    """Regenerate reports with the CURRENT skill scripts, so a format change in any skill breaks this test."""

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            run = lambda args: subprocess.run([sys.executable, *args], capture_output=True, text=True,
                                              encoding="utf-8", timeout=120)
            r1 = run([str(SKILLS / "cloud-cost-scout" / "scripts" / "cost_scout.py"),
                      str(FX / "cost" / "azure-dev-subscription"), "--as-of", "2026-09-27", "--out-dir", str(t / "cost")])
            d = FX / "logs" / "appinsights-nullref-after-deploy"
            r2 = run([str(SKILLS / "log-detective" / "scripts" / "log_detective.py"), str(d),
                      "--deploys", str(d / "deploys.txt"), "--out-dir", str(t / "incident")])
            r3 = run([str(SKILLS / "pipeline-doctor" / "scripts" / "pipeline_triage.py"),
                      str(FX / "pipelines" / "ado-npm-eresolve.log"), "--json"])
            for r in (r1, r2, r3):
                self.assertEqual(r.returncode, 0, r.stderr)
            (t / "triage.json").write_text(r3.stdout, encoding="utf-8")
            out = t / "digest"
            r4 = run([str(SCRIPTS / "ops_digest.py"), str(t / "cost"), str(t / "incident"), str(t / "triage.json"),
                      "--title", "Test", "--out-dir", str(out)])
            self.assertEqual(r4.returncode, 0, r4.stderr)
            data = json.loads((out / "ops-digest.json").read_text(encoding="utf-8"))
            self.assertEqual((len(data["cost"]), len(data["incidents"]), len(data["pipelines"])), (1, 1, 1))
            self.assertTrue((out / "ops-digest.html").exists())

    def test_incident_extras_from_current_log_detective(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            ld = SKILLS / "log-detective" / "scripts" / "log_detective.py"
            for name in ("activitylog-config-change", "users-blast-radius"):
                r = subprocess.run([sys.executable, str(ld), str(FX / "logs" / name), "--out-dir", str(t / name)],
                                   capture_output=True, text=True, encoding="utf-8", timeout=120)
                self.assertEqual(r.returncode, 0, r.stderr)
            d = od.build([t])
            by_src = {i["source"]: i for i in d["incidents"]}
            self.assertEqual(len(by_src), 1, "both reports are named log-detective.json")
            incs = d["incidents"]
            change = [i["infra_change"] for i in incs if i["infra_change"]]
            self.assertEqual(change[0]["operation"], "App settings changed")
            self.assertEqual(change[0]["minutes_before"], 2)
            blast = [i["blast_radius"] for i in incs if i["blast_radius"] and "users" in i["blast_radius"]]
            self.assertEqual(blast[0]["users"], 39)
            md = od.to_markdown(d, "t", "")
            self.assertIn("39 users", md)
            self.assertIn("1 tenant,", md)

    def test_pipeline_and_bugfix_reports(self):
        F = FX
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            pd = SKILLS / "pipeline-doctor" / "scripts"
            br = SKILLS / "bug-resolve" / "scripts"
            jobs = {
                "history.json": [pd / "pipeline_history.py", F / "pipelines/history/azure/runs.json",
                                 "--logs", F / "pipelines/history/azure/logs", "--json"],
                "speed.json": [pd / "pipeline_speed.py", F / "pipelines/speed/ado-build.log", "--json"],
                "yaml.json": [pd / "pipeline_yaml_review.py", F / "pipelines/yaml/azure-pipelines-bad.yml", "--json"],
                "fix-ok.json": [br / "fix_report.py", "--json", "--bug", "KeyError currency", "--test-name", "t",
                                "--before", F / "bugs/outputs/pytest-before-fail.txt",
                                "--after", F / "bugs/outputs/pytest-after-pass.txt",
                                "--suite", F / "bugs/outputs/pytest-suite-pass.txt"],
                "fix-fake.json": [br / "fix_report.py", "--json", "--bug", "Fake fix", "--test-name", "t",
                                  "--before", F / "bugs/outputs/just-words.txt",
                                  "--after", F / "bugs/outputs/pytest-after-pass.txt"],
            }
            for name, args in jobs.items():
                r = subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True,
                                   encoding="utf-8", timeout=120)
                self.assertTrue(r.stdout.strip().startswith("{"), f"{name}: {r.stderr}")
                (t / name).write_text(r.stdout, encoding="utf-8")
            d = od.build([t])
            kinds = sorted(p.get("kind") for p in d["pipelines"])
            self.assertEqual(kinds, ["pipeline-history", "pipeline-speed", "pipeline-yaml"])
            hist = next(p for p in d["pipelines"] if p["kind"] == "pipeline-history")["facts"]
            self.assertEqual((hist["flaky_tests"], hist["regressed_tests"]), (1, 1))
            self.assertAlmostEqual(hist["failure_rate"], 0.75)
            proofs = {b["summary"]: b["proof_ok"] for b in d["bugfixes"]}
            self.assertEqual(proofs, {"fix: KeyError currency": True, "fix: Fake fix": False})
            acts = " | ".join(d["actions"])
            self.assertIn("NOT proven", acts)
            self.assertIn("high-severity", acts)
            md = od.to_markdown(d, "t", "")
            self.assertIn("failure rate: 75%", md)
            self.assertIn("Build failure rate **75%**", md)
            self.assertIn("**1** bug fix(es) with test proof", md)
            self.assertIn("**1** bug fix(es) NOT yet proven", md)
            self.assertIn("test sharding on 'dotnet test'", md)

    def test_bill_change_and_tagging_from_cost_scout(self):
        """Regression: 1.1 E2E showed the digest printing '+n/a' for the bill change."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "cost"
            r = subprocess.run([sys.executable, str(SKILLS / "cloud-cost-scout" / "scripts" / "cost_scout.py"),
                                str(FX / "cost" / "azure-two-months"), "--as-of", "2026-09-27", "--out-dir", str(out)],
                               capture_output=True, text=True, encoding="utf-8", timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            src = json.loads((out / "cost-scout-report.json").read_text(encoding="utf-8"))
            usd = src["bill_change"]["by_currency"]["USD"]
            d = od.build([out])
            bc = d["cost"][0]["bill_change"][0]
            self.assertEqual((bc["change"], bc["change_pct"]), (usd["change"], usd["change_pct"]))
            md = od.to_markdown(d, "t", "")
            self.assertNotIn("n/a", md.split("## Cloud cost")[1].split("##")[0])
            self.assertIn("Cloud run rate up", md)
            self.assertIn("Spend with no owner tag", md)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for i in range(2):
                o = Path(tmp) / f"o{i}"
                subprocess.run([sys.executable, str(SCRIPTS / "ops_digest.py"), str(WEEK), "--out-dir", str(o)],
                               capture_output=True, timeout=60)
                outs.append({p.name: p.read_bytes() for p in o.iterdir()})
            self.assertEqual(outs[0], outs[1])

    def test_nothing_recognised_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.json").write_text('{"a": 1}', encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "ops_digest.py"), tmp], capture_output=True, timeout=60)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()

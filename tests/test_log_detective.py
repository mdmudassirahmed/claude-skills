import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "log-detective" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import log_detective as ld  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "logs"


def run(scenario, with_deploys=True):
    d = FX / scenario
    dep = d / "deploys.txt"
    return ld.analyse([d], str(dep) if with_deploys and dep.exists() else None)


class NullRefAfterDeploy(unittest.TestCase):
    """App Insights: new NullReferenceException 7 minutes after a deployment."""

    @classmethod
    def setUpClass(cls):
        cls.r = run("appinsights-nullref-after-deploy")

    def test_detects_error_spike_and_onset(self):
        self.assertEqual(self.r["verdict_hint"], "error-spike")
        self.assertTrue(self.r["onset"].startswith("2026-09-26T09:40"))
        self.assertTrue(self.r["first_new_error"].startswith("2026-09-26T09:42"))

    def test_new_signature_vs_background_noise(self):
        sigs = {s["signature"].split(":")[0]: s for s in self.r["signatures"]}
        self.assertTrue(sigs["System.NullReferenceException"]["new_at_onset"])
        self.assertFalse(sigs["System.Threading.Tasks.TaskCanceledException"]["new_at_onset"],
                         "pre-existing noise must not be reported as new")

    def test_links_to_the_deploy_just_before(self):
        d = self.r["deploy_correlation"]
        self.assertEqual(d["id"], "a1b2c3d4e5f6")
        self.assertEqual(d["strength"], "strong")
        self.assertEqual(d["minutes_before_onset"], 7)

    def test_in_app_code_frames_only(self):
        files = [(c["file"], c["line"]) for c in self.r["code_candidates"]]
        self.assertEqual(files[0], ("/src/Orders.Api/Services/DiscountService.cs", 57))
        self.assertIn(("/src/Orders.Api/Services/OrderService.cs", 142), files)
        self.assertFalse(any("ActionMethodExecutor" in c["function"] for c in self.r["code_candidates"]))

    def test_customer_emails_never_reach_output(self):
        blob = json.dumps(self.r, default=str) + ld.to_markdown(self.r)
        for leaked in ("jane.doe", "raj.patel", "contoso.com", "fabrikam.io"):
            self.assertNotIn(leaked, blob)
        self.assertGreater(self.r["redactions"]["email"], 100)

    def test_deploy_file_not_treated_as_log(self):
        self.assertFalse(any("deploys.txt" in s["file"] for s in self.r["skipped"]))

    def test_without_deploy_data_no_correlation_claimed(self):
        r = run("appinsights-nullref-after-deploy", with_deploys=False)
        self.assertIsNone(r["deploy_correlation"])
        self.assertEqual(r["deploys_considered"], 0)


class SqlTimeoutNoDeploy(unittest.TestCase):
    """Log Analytics: SQL dependency timeouts cause 500s; no deployment involved."""

    @classmethod
    def setUpClass(cls):
        cls.r = run("loganalytics-sql-timeout")

    def test_dependency_and_request_separated(self):
        top = [s["signature"] for s in self.r["signatures"][:2]]
        self.assertTrue(any(t.startswith("dependency sql-orders.database.windows.net") and "-2" in t for t in top), top)
        self.assertIn("GET /api/orders/{id} -> 500", top)

    def test_onset_and_no_deploy(self):
        self.assertTrue(self.r["onset"].startswith("2026-09-26T14:10"))
        self.assertIsNone(self.r["deploy_correlation"])
        self.assertIn("No deployment in the 24 h before the onset", ld.to_markdown(self.r))

    def test_sql_latency_jump(self):
        ops = {x["operation"]: x for x in self.r["latency_regressions"]}
        self.assertGreaterEqual(ops["ordersdb"]["p95_after_ms"], 29000)

    def test_table_name_not_mistaken_for_exception_type(self):
        self.assertFalse(any("AppDependencies" in s["signature"] for s in self.r["signatures"]))


class LatencyOnly(unittest.TestCase):
    """CloudWatch Logs Insights: /checkout 12x slower after a deploy, zero errors."""

    @classmethod
    def setUpClass(cls):
        cls.r = run("cloudwatch-latency-regression")

    def test_latency_regression_without_errors(self):
        self.assertEqual(self.r["problems"], 0)
        self.assertEqual(self.r["verdict_hint"], "latency-regression")
        reg = self.r["latency_regressions"][0]
        self.assertEqual(reg["operation"], "/checkout")
        self.assertGreater(reg["factor"], 5)
        self.assertNotIn("/health", [x["operation"] for x in self.r["latency_regressions"]])

    def test_latency_onset_and_deploy(self):
        self.assertTrue(self.r["latency_onset"].startswith("2026-09-26T18:00"))
        self.assertEqual(self.r["deploy_correlation"]["id"], "c0ffee000001")


class PythonTraceback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run("text-python-traceback")

    def test_multiline_records_joined(self):
        self.assertEqual(self.r["records"], 300)  # one record per timestamped line

    def test_exception_headline_and_frames(self):
        top = self.r["signatures"][0]
        self.assertEqual(top["headline"], "KeyError: 'currency'")
        files = [(c["file"], c["line"]) for c in self.r["code_candidates"]]
        self.assertIn(("/app/pricing/convert.py", 88), files)
        self.assertFalse(any("site-packages" in f for f, _ in files))

    def test_ops_email_redacted(self):
        self.assertNotIn("acme-internal.com", json.dumps(self.r, default=str))


class OtherSources(unittest.TestCase):
    def test_gcp_java(self):
        r = run("gcp-java-errors")
        self.assertEqual({i["file"].split("\\")[-1].split("/")[-1] for i in r["inputs"]}, {"logging-read.json"})
        self.assertEqual(r["verdict_hint"], "steady-errors")
        self.assertIn(("PoolManager.java", 77), [(c["file"], c["line"]) for c in r["code_candidates"]])
        self.assertFalse(any("springframework" in c["function"] for c in r["code_candidates"]))
        self.assertEqual(r["signatures"][0]["signature"].count("IllegalStateException"), 1)

    def test_healthy_system_is_reported_honestly(self):
        r = run("quiet-healthy")
        self.assertEqual(r["verdict_hint"], "no-problem-signal")
        self.assertIn("No error or failure signal found", ld.to_markdown(r))

    def test_bad_inputs(self):
        r = run("bad-inputs")
        self.assertEqual(r["records"], 0)
        reasons = " ".join(s["reason"] for s in r["skipped"])
        self.assertIn("invalid JSON", reasons)
        self.assertIn("no log records", reasons)


class PortalCsvExport(unittest.TestCase):
    """Azure portal Logs blade > Export > CSV: "timestamp [UTC]" headers, US-style dates."""

    @classmethod
    def setUpClass(cls):
        d = FX / "appinsights-nullref-after-deploy"
        cls.r = ld.analyse([FX / "portal-csv-export"], str(d / "deploys.txt"))

    def test_same_diagnosis_as_json_export(self):
        self.assertEqual(self.r["inputs"][0]["records"], 157)
        self.assertEqual(self.r["verdict_hint"], "error-spike")
        self.assertTrue(self.r["first_new_error"].startswith("2026-09-26T09:42:20"))
        self.assertEqual(self.r["deploy_correlation"]["id"], "a1b2c3d4e5f6")
        self.assertIn(("/src/Orders.Api/Services/DiscountService.cs", 57),
                      [(c["file"], c["line"]) for c in self.r["code_candidates"]])

    def test_emails_redacted(self):
        self.assertNotIn("contoso.com", json.dumps(self.r, default=str))


class Units(unittest.TestCase):
    def test_portal_date_formats(self):
        self.assertEqual(ld.parse_ts("9/26/2026, 9:42:20.123 AM").isoformat(), "2026-09-26T09:42:20.123000+00:00")
        self.assertEqual(ld.parse_ts("9/26/2026, 9:42:20 PM").isoformat(), "2026-09-26T21:42:20+00:00")
        self.assertEqual(ld.parse_ts("9/26/2026, 9:42:20.1234567 AM").microsecond, 123456)

    def test_timestamp_formats(self):
        for v in ("2026-09-26T09:42:20.1234567Z", "2026-09-26 09:42:20.000", "2026-09-26T09:42:20+00:00",
                  1790415740000, "2026-09-26 09:42:20,123"):
            self.assertIsNotNone(ld.parse_ts(v), v)

    def test_timespan_duration(self):
        self.assertAlmostEqual(ld.to_num("00:00:01.5320000"), 1532.0)

    def test_signature_groups_varying_ids(self):
        r = ld.Redactor()
        a = ld.normalise({"timestamp": "2026-09-26T10:00:00Z", "message": "ERROR order 12345 failed id=9f1c2e3d4b5a6978"}, "t", r)
        b = ld.normalise({"timestamp": "2026-09-26T10:01:00Z", "message": "ERROR order 99881 failed id=0a1b2c3d4e5f6071"}, "t", r)
        self.assertEqual(ld.signature(a), ld.signature(b))

    def test_frames_multiple_languages(self):
        text = ('at App.Svc.Run() in C:\\src\\App\\Svc.cs:line 12\n'
                'File "/app/x.py", line 3, in main\n'
                'at handler (/var/task/src/index.js:44:9)\n'
                'at com.acme.Foo.bar(Foo.java:10)\n'
                'at Microsoft.Extensions.Hosting.Run() in /_/src/Host.cs:line 1\n'
                'at Object.<anonymous> (/app/node_modules/express/lib/router.js:1:1)')
        got = {(f["file"].split("/")[-1], f["line"]) for f in ld.frames_from(text)}
        self.assertEqual(got, {("Svc.cs", 12), ("x.py", 3), ("index.js", 44), ("Foo.java", 10)})


class Cli(unittest.TestCase):
    def test_out_dir_and_exit_codes(self):
        s = str(SCRIPTS / "log_detective.py")
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, s, str(FX / "loganalytics-sql-timeout"), "--out-dir", d],
                               capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(Path(d, "log-detective.md").exists())
            json.loads(Path(d, "log-detective.json").read_text(encoding="utf-8"))
        p = subprocess.run([sys.executable, s, str(FX / "bad-inputs")], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()

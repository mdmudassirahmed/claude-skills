import json
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "log-detective" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import log_detective as ld  # noqa: E402
import alert_rules  # noqa: E402
import infra_changes  # noqa: E402
import postmortem  # noqa: E402

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


# =====================================================================================
# Step-ahead capabilities: infrastructure changes, platform events, baseline, blast
# radius, alert suggestion, postmortem draft.
# =====================================================================================
def table_rows(path):
    """Rows of an App Insights tables export (or a Log Analytics list) as dicts, read independently."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "tables" in data:
        t = data["tables"][0]
        cols = [c["name"] for c in t["columns"]]
        return [dict(zip(cols, r)) for r in t["rows"]]
    return data


def everything(r):
    """Every piece of text the skill can emit for a report: JSON, markdown and postmortem."""
    return (json.dumps(r, default=str) + ld.to_markdown(r)
            + postmortem.render(json.loads(json.dumps(r, default=str))))


def p95(counts):
    return ld.percentile(counts, 95) or 0


CALLER = re.compile(r"^(<(email|principal|user)-\d+>|[a-z0-9.-]+\.amazonaws\.com)$")


class ActivityLogConfigChange(unittest.TestCase):
    """App settings write + restart in the Activity Log, then failures; no code deploy."""

    @classmethod
    def setUpClass(cls):
        cls.d = FX / "activitylog-config-change"
        cls.r = run("activitylog-config-change")
        cls.blob = everything(cls.r)

    def test_activity_log_detected_not_counted_as_logs(self):
        self.assertEqual(sorted(Path(i["file"]).name for i in self.r["inputs"]), ["exceptions.json", "requests.json"])
        self.assertFalse(any("activity-log" in s["file"] for s in self.r["skipped"]))
        expected = len(table_rows(self.d / "requests.json")) + len(table_rows(self.d / "exceptions.json"))
        self.assertEqual(self.r["records"], expected)
        ci = self.r["change_inputs"]
        self.assertEqual([(Path(c["file"]).name, c["kind"], c["events"]) for c in ci],
                         [("activity-log.json", "azure-activity-log", 13)])

    def test_only_real_successful_changes_kept(self):
        ops = [c["operation"] for c in self.r["infra_changes"]]
        self.assertEqual(ops, ["Microsoft.Network/networkSecurityGroups/securityRules/write",
                               "Microsoft.Web/sites/config/write", "Microsoft.Web/sites/restart/action"])
        text = json.dumps(self.r["infra_changes"] + self.r["infra_changes_after_onset"])
        self.assertNotIn("slotsswap", text, "a failed slot swap is not a change")
        self.assertNotIn("policies/audit", text, "policy audit events are noise")
        self.assertNotIn("accessPolicies", text, "Key Vault change 26 h earlier is outside the 24 h window")
        self.assertNotIn("listKeys", text)

    def test_secret_listing_noted_separately(self):
        self.assertEqual([c["operation"] for c in self.r["secret_reads_noted"]],
                         ["Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.Web/sites/config/list/action"])
        self.assertIn("2 key / secret listing operation(s)", ld.to_markdown(self.r))

    def test_app_settings_write_correlated_strong(self):
        c = self.r["infra_correlation"]
        self.assertEqual(c["operation"], "Microsoft.Web/sites/config/write")
        self.assertEqual(c["resource"], "payments-api/appsettings")
        self.assertEqual(c["description"], "App settings changed")
        self.assertEqual(c["category"], "app-config")
        self.assertEqual(c["minutes_before_onset"], 2)
        self.assertEqual(c["strength"], "strong")
        self.assertEqual(c["other_changes_in_window"], 2)
        self.assertIsNone(self.r["deploy_correlation"], "the only commit is 3 days old")
        self.assertEqual(self.r["deploys_considered"], 1)
        md = ld.to_markdown(self.r)
        self.assertIn("No deployment in the 24 h before the onset, but an infrastructure change was recorded", md)
        self.assertIn("**Infrastructure change just before:** App settings changed on `payments-api/appsettings`", md)

    def test_weak_change_and_minutes(self):
        nsg = self.r["infra_changes"][0]
        self.assertEqual(nsg["resource"], "nsg-payments/allow-https")
        self.assertEqual(nsg["minutes_before_onset"], 1272)
        self.assertNotIn("subscriptions", json.dumps(self.r["infra_changes"]), "subscription ids are dropped")

    def test_changes_after_onset_listed_as_possible_mitigation(self):
        after = self.r["infra_changes_after_onset"]
        self.assertEqual([(c["operation"], c["minutes_after_onset"]) for c in after],
                         [("Microsoft.Web/sites/config/write", 51), ("Microsoft.Web/sites/restart/action", 52)])
        self.assertTrue(any("possibly a mitigation step" in e["event"] for e in self.r["timeline_events"]))

    def test_callers_and_setting_values_never_output(self):
        for leaked in ("ops.engineer", "contoso-ops", "3f1d2c4b-5a69-4788-9b0c-d1e2f3a4b5c6", "Ops Engineer",
                       "198.51.100.23", "sk_live", "PaymentGateway__ApiKey", "requestbody", "responseBody",
                       "5d2c9f4e-1b7a-4c3e-9a0d-6f8e2b1c4d7a", "northwind", "adventure-works"):
            self.assertNotIn(leaked, self.blob)
        callers = {c["caller"] for c in self.r["infra_changes"] + self.r["infra_changes_after_onset"]
                   + self.r["secret_reads_noted"]}
        self.assertTrue(all(CALLER.match(c) for c in callers), callers)
        self.assertNotRegex(self.blob, r"[\w.+-]+@[\w-]+\.\w{2,}")

    def test_alert_suggestion_kql_threshold_from_pre_onset_data(self):
        a = self.r["alert_suggestion"]
        self.assertEqual((a["status"], a["platform"], a["schema"], a["table"]), ("suggested", "azure", "classic", "exceptions"))
        # Independent threshold: only the NEW error (type AND its stable message) per 5 min before onset.
        # Other HttpRequestExceptions are background noise and must not be counted.
        onset = ld.parse_ts(self.r["onset"])
        start = ld.floor_to(ld.parse_ts(self.r["window"]["start"]), timedelta(minutes=5))
        n = int((onset - start) / timedelta(minutes=5))
        counts = [0] * n
        for row in table_rows(self.d / "exceptions.json"):
            t = ld.parse_ts(row["timestamp"])
            if (row["type"] == "System.Net.Http.HttpRequestException" and "no such host is known." in row["outerMessage"].lower()
                    and t < onset):
                counts[int((t - start) / timedelta(minutes=5))] += 1
        self.assertEqual(p95(counts), 0)
        self.assertEqual(a["threshold"], max(5, 3 * p95(counts)))
        self.assertEqual(a["threshold"], 5)
        b = a["threshold_basis"]
        self.assertEqual((b["source"], b["p95_5min_count"], b["normal_buckets"]), ("pre-onset", 0, n))
        self.assertGreater(b["incident_peak_5min_count"], a["threshold"], "the rule must be able to fire for this incident")
        self.assertIsNotNone(b["would_have_fired_at"])
        self.assertNotIn("warning", a)
        self.assertIn('exceptions\n| where type == "System.Net.Http.HttpRequestException"\n'
                      '| where outerMessage contains "No such host is known."\n'
                      '| where cloud_RoleName == "payments-api"', a["kql"])
        self.assertIn("az monitor scheduled-query create", a["az_cli"])
        self.assertIn("--condition \"count 'Failures' > 5\"", a["az_cli"])
        self.assertIn("--window-size 5m --evaluation-frequency 5m", a["az_cli"])
        self.assertIn("--condition-query Failures='exceptions | where type == \"System.Net.Http.HttpRequestException\"",
                      a["az_cli"])
        for piece in ("Microsoft.Insights/scheduledQueryRules@2022-06-15", "threshold: 5", "evaluationFrequency: 'PT5M'",
                      "windowSize: 'PT5M'", "timeAggregation: 'Count'", "operator: 'GreaterThan'",
                      "            exceptions\n"):
            self.assertIn(piece, a["bicep"])
        self.assertEqual(a["bicep"].count("'''"), 2)
        self.assertIn("## Proposed alert (not applied", ld.to_markdown(self.r))

    def test_timeline_and_peak(self):
        ev = [e["event"] for e in self.r["timeline_events"]]
        self.assertTrue(ev[0].startswith("Earliest recorded change in the 24 h before onset: Create or Update Security Rule"))
        self.assertTrue(any(e.startswith("App settings changed on `payments-api/appsettings`") for e in ev))
        self.assertTrue(any(e.startswith("First new error: `System.Net.Http.HttpRequestException: No such host") for e in ev))
        times = [e["time"] for e in self.r["timeline_events"]]
        self.assertEqual(times, sorted(times))
        self.assertEqual(self.r["peak"]["bucket_minutes"], 5)
        self.assertEqual(self.r["peak"]["count"], max(self.r["timeline_counts"]))

    def test_postmortem_draft(self):
        pm = postmortem.render(json.loads(json.dumps(self.r, default=str)))
        for section in ("# Postmortem draft", "## Summary", "## Impact", "## Timeline (UTC", "## Evidence",
                        "## Root cause **[to be confirmed]**", "## Action items"):
            self.assertIn(section, pm)
        self.assertGreaterEqual(pm.count("[to be confirmed]"), 8)
        self.assertIn("Blameless", pm)
        self.assertIn("| 2026-09-27 08:12:09 UTC | App settings changed on `payments-api/appsettings`", pm)
        self.assertIn("| 2026-09-27 08:20:00 UTC | The proposed alert", pm)
        self.assertIn("Review and apply the proposed alert `ld-system-net-http-httprequestexception-no`", pm)
        self.assertIn("/src/Payments.Api/Clients/GatewayClient.cs:41", pm)
        self.assertIn("Leading hypothesis from timing: the app settings changed", pm)
        self.assertIn("36.2% of 345 requests failed", pm)
        self.assertNotIn("<email-", pm.replace("payer=<email-", ""), "no callers in a blameless postmortem")
        self.assertNotIn(" by <", pm)
        self.assertNotIn(chr(0x2014), pm)


class CloudTrailSecurityGroupChange(unittest.TestCase):
    """CloudWatch logs + CloudTrail: an egress rule revoked, then DB connection timeouts."""

    @classmethod
    def setUpClass(cls):
        cls.d = FX / "cloudtrail-sg-change"
        cls.r = run("cloudtrail-sg-change")
        cls.blob = everything(cls.r)

    def test_cloudtrail_detected_not_counted_as_logs(self):
        self.assertEqual([Path(i["file"]).name for i in self.r["inputs"]], ["insights-results.json"])
        results = json.loads((self.d / "insights-results.json").read_text(encoding="utf-8"))["results"]
        self.assertEqual(self.r["records"], len(results))
        c = self.r["change_inputs"][0]
        self.assertEqual((c["kind"], c["events"], c["changes"], c["secret_reads"]), ("aws-cloudtrail", 10, 4, 1))

    def test_reads_noise_and_failed_calls_dropped(self):
        ops = [c["operation"] for c in self.r["infra_changes"]]
        self.assertEqual(ops, ["UpdateFunctionConfiguration20150331v2", "SetDesiredCapacity", "RevokeSecurityGroupEgress"])
        text = json.dumps(self.r["infra_changes"] + self.r["infra_changes_after_onset"])
        for dropped in ("DescribeSecurityGroups", "ConsoleLogin", "AssumeRole", "CreateLogStream",
                        "AuthorizeSecurityGroupIngress"):
            self.assertNotIn(dropped, text)
        self.assertEqual([c["operation"] for c in self.r["secret_reads_noted"]], ["GetSecretValue"])
        self.assertEqual(self.r["secret_reads_noted"][0]["resource"], "orders-db-credentials-AbCdEf")

    def test_network_change_beats_closer_ranked_scale_change(self):
        c = self.r["infra_correlation"]
        self.assertEqual((c["operation"], c["category"], c["strength"], c["minutes_before_onset"]),
                         ("RevokeSecurityGroupEgress", "network", "strong", 2))
        self.assertEqual((c["resource"], c["service"], c["region"]), ("sg-0a1b2c3d4e5f67890", "ec2", "eu-west-1"))
        weak = self.r["infra_changes"][0]
        self.assertEqual((weak["resource"], weak["minutes_before_onset"]), ("orders-notifier", 320))
        self.assertEqual([c["operation"] for c in self.r["infra_changes_after_onset"]], ["AuthorizeSecurityGroupEgress"])

    def test_callers_pseudonymised_services_kept(self):
        callers = [c["caller"] for c in self.r["infra_changes"]]
        self.assertEqual(callers[1], "autoscaling.amazonaws.com")
        self.assertTrue(all(CALLER.match(c) for c in callers), callers)
        self.assertEqual(self.r["infra_correlation"]["caller"], self.r["infra_changes_after_onset"][0]["caller"],
                         "the same person gets the same pseudonym")
        for leaked in ("alice", "bob.jones", "deploy-bot", "orders-api-task", "ASIAEXAMPLE", "203.0.113.77",
                       "arn:aws", "AROAEXAMPLE", "cust-0"):
            self.assertNotIn(leaked, self.blob)

    def test_cloudwatch_alarm_suggestion(self):
        a = self.r["alert_suggestion"]
        self.assertEqual((a["status"], a["platform"], a["threshold"]), ("suggested", "aws-cloudwatch", 5))
        self.assertNotIn("kql", a)
        self.assertEqual(a["log_group"], "/aws/ecs/orders-api")
        self.assertEqual(a["filter_pattern"], '"psycopg2.OperationalError"')
        for piece in ("aws logs put-metric-filter", "--log-group-name /aws/ecs/orders-api",
                      "--filter-pattern '\"psycopg2.OperationalError\"'", "metricNamespace=LogDetective",
                      "aws cloudwatch put-metric-alarm", "--period 300", "--threshold 5",
                      "--comparison-operator GreaterThanThreshold"):
            self.assertIn(piece, a["aws_cli"])
        self.assertEqual(a["threshold_basis"]["p95_5min_count"], 0)

    def test_blast_radius_matches_independent_count(self):
        br = self.r["blast_radius"]
        scope = ld.parse_ts(br["scope_start"])
        hit, seen, ips_hit, ips_seen = set(), set(), set(), set()
        for res in json.loads((self.d / "insights-results.json").read_text(encoding="utf-8"))["results"]:
            f = {x["field"]: x["value"] for x in res}
            m = json.loads(f["@message"])
            if ld.parse_ts(f["@timestamp"]) < scope:
                continue
            if m.get("userId"):
                seen.add(m["userId"])
                ips_seen.add(m["clientIp"])
                if m["level"] == "error":
                    hit.add(m["userId"])
                    ips_hit.add(m["clientIp"])
        self.assertEqual((br["users"]["affected"], br["users"]["seen"]), (len(hit), len(seen)))
        self.assertEqual((br["clients"]["affected"], br["clients"]["seen"]), (len(ips_hit), len(ips_seen)))
        self.assertIsNone(br["tenants"])

    def test_ids_inside_json_messages_masked(self):
        req = next(s for s in self.r["signatures"] if s["signature"] == "/orders -> 500")
        self.assertIn('"userId": "<id>"', req["sample"])
        self.assertGreater(self.r["redactions"]["identifier"], 100)


class BaselineNoise(unittest.TestCase):
    """The nightly job's deadlock spike happens every night: normal noise, not an incident."""

    @classmethod
    def setUpClass(cls):
        cls.d = FX / "baseline-noise"
        cls.alone = ld.analyse([cls.d / "current"])
        cls.r = ld.analyse([cls.d / "current"], None, [cls.d / "last-week"])

    def test_without_baseline_it_looks_like_an_incident(self):
        self.assertEqual(self.alone["verdict_hint"], "error-spike")
        self.assertEqual(self.alone["alert_suggestion"]["status"], "suggested")
        self.assertIsNone(self.alone["baseline"])
        self.assertNotIn("in_baseline", self.alone["signatures"][0], "no baseline keys without --baseline")

    def test_baseline_says_normal_noise(self):
        b = self.r["baseline"]
        self.assertEqual(b["assessment"], "matches-baseline")
        self.assertTrue(b["same_pattern_in_baseline"])
        self.assertEqual(b["onset_in_baseline"], "2026-09-20T02:00:00+00:00")
        cur = [r for r in table_rows(self.d / "current" / "requests-and-exceptions.json")]
        old = [r for r in table_rows(self.d / "last-week" / "requests-and-exceptions.json")]
        cur_rate = sum(1 for r in cur if r["Type"] == "AppExceptions") / len(cur)
        old_rate = sum(1 for r in old if r["Type"] == "AppExceptions") / len(old)
        self.assertEqual(b["rate_ratio"], round(cur_rate / old_rate, 2))
        self.assertLess(abs(b["rate_ratio"] - 1), 0.2)
        self.assertEqual((b["records"], b["problems"]), (len(old), sum(1 for r in old if r["Type"] == "AppExceptions")))
        self.assertIn("Likely normal noise, not an incident", ld.to_markdown(self.r))

    def test_each_top_signature_flagged_with_rate(self):
        top = self.r["signatures"][0]
        self.assertTrue(top["signature"].startswith("Microsoft.Data.SqlClient.SqlException: Transaction (Process ID <n>)"))
        self.assertTrue(top["new_at_onset"])
        self.assertTrue(top["in_baseline"])
        self.assertEqual((top["count"], top["baseline_count"]), (62, 58))
        self.assertAlmostEqual(top["rate_vs_baseline"], 1.07, places=2)
        self.assertTrue(all(s["in_baseline"] for s in self.r["baseline"]["signatures"]))

    def test_no_alert_for_normal_noise(self):
        a = self.r["alert_suggestion"]
        self.assertEqual(a["status"], "not-suggested")
        self.assertIn("baseline", a["reason"])

    def test_baseline_files_never_mixed_into_current(self):
        self.assertEqual(self.r["records"], self.alone["records"])
        self.assertEqual(self.r["baseline"]["ignored_change_exports"], 1)
        nested = ld.analyse([self.d], None, [self.d / "last-week"])
        self.assertEqual(nested["records"], self.alone["records"], "baseline folder inside the log folder is excluded")
        self.assertEqual(nested["change_inputs"], [])


class BaselineShowsNewProblem(unittest.TestCase):
    """Last week had only the background noise: the new error is not normal, and the alert
    threshold comes from last week's (noisier) background."""

    @classmethod
    def setUpClass(cls):
        d = FX / "activitylog-config-change"
        cls.lw = FX / "activitylog-config-change-lastweek"
        cls.r = ld.analyse([d], str(d / "deploys.txt"), [cls.lw])

    def test_new_problem_assessment(self):
        b = self.r["baseline"]
        self.assertEqual(b["assessment"], "new-problem")
        self.assertGreater(b["rate_ratio"], 2)
        sigs = {s["signature"].split(":")[0] + ("/bg" if "sending the request" in s["signature"] else ""): s
                for s in self.r["signatures"]}
        self.assertFalse(sigs["System.Net.Http.HttpRequestException"]["in_baseline"])
        self.assertTrue(sigs["System.Net.Http.HttpRequestException/bg"]["in_baseline"])

    def test_threshold_from_baseline(self):
        # Last week had plenty of HttpRequestExceptions (noise), but none of the new "No such host" error,
        # so the threshold must stay at the floor of 5 and the rule must fire during the incident.
        counts = {}
        for row in table_rows(self.lw / "exceptions.json"):
            if "no such host is known." not in row.get("outerMessage", "").lower():
                continue
            t = ld.floor_to(ld.parse_ts(row["timestamp"]), timedelta(minutes=5))
            counts[t] = counts.get(t, 0) + 1
        per_bucket = [counts.get(ld.parse_ts("2026-09-20T06:00:00Z") + i * timedelta(minutes=5), 0) for i in range(48)]
        b = self.r["alert_suggestion"]["threshold_basis"]
        self.assertEqual((b["source"], b["p95_5min_count"]), ("baseline", p95(per_bucket)))
        self.assertEqual(self.r["alert_suggestion"]["threshold"], max(5, 3 * p95(per_bucket)))
        self.assertEqual(self.r["alert_suggestion"]["threshold"], 5)
        self.assertIsNotNone(b["would_have_fired_at"], "regression: noise of the same type silenced the alert in 1.1 testing")
        self.assertIn("threshold: 5", self.r["alert_suggestion"]["bicep"])

    def test_nothing_healthy_as_baseline(self):
        r = ld.analyse([FX / "appinsights-nullref-after-deploy"], None, [FX / "quiet-healthy"])
        self.assertEqual(r["baseline"]["assessment"], "new-problem")
        self.assertEqual(r["baseline"]["problems"], 0)
        self.assertIsNone(r["baseline"]["rate_ratio"])
        empty = ld.analyse([FX / "appinsights-nullref-after-deploy"], None, [FX / "bad-inputs"])
        self.assertEqual(empty["baseline"]["assessment"], "no-baseline-data")


class ServiceHealthEvent(unittest.TestCase):
    """Azure Service Health reports Storage degraded in West Europe; blob calls fail."""

    @classmethod
    def setUpClass(cls):
        cls.r = run("service-health")

    def test_platform_incident_surfaced_prominently(self):
        sh = self.r["service_health"]
        self.assertEqual(len(sh), 1, "two updates of one incident become one entry")
        h = sh[0]
        self.assertEqual((h["provider"], h["regions"], h["stage"], h["tracking_id"], h["time"]),
                         ("azure-service-health", ["West Europe"], "Resolved", "VT3K-9XZ", "2026-09-27T10:22:00+00:00"))
        self.assertEqual(h["minutes_before_onset"], 8)
        self.assertIn("possible platform incident in region West Europe", h["summary"])
        md = ld.to_markdown(self.r)
        self.assertLess(md.index("possible platform incident in region West Europe"), md.index("_Window "))
        self.assertIn("Platform event: possible platform incident in region West Europe",
                      postmortem.render(json.loads(json.dumps(self.r, default=str))))

    def test_noise_dropped_and_not_counted_as_logs(self):
        self.assertEqual(self.r["infra_changes"], [], "a tag write is not a behaviour change")
        self.assertIsNone(self.r["infra_correlation"])
        self.assertEqual(self.r["change_inputs"][0]["platform_events"], 1)
        self.assertEqual(sorted(Path(i["file"]).name for i in self.r["inputs"]), ["dependencies.json", "requests.json"])
        blob = everything(self.r)
        for leaked in ("storage-ops@", "partner-example", "finance.admin"):
            self.assertNotIn(leaked, blob)

    def test_dependency_alert(self):
        a = self.r["alert_suggestion"]
        self.assertEqual(a["table"], "dependencies")
        self.assertIn('| where success == false and target == "orderstore.blob.core.windows.net"', a["kql"])


class UsersBlastRadius(unittest.TestCase):
    """One tenant's users cannot check out; user, client and tenant ids are only counted."""

    @classmethod
    def setUpClass(cls):
        cls.d = FX / "users-blast-radius"
        cls.r = run("users-blast-radius")
        cls.br = cls.r["blast_radius"]

    def expected(self):
        scope = ld.parse_ts(self.br["scope_start"])
        users, users_hit, ips, ips_hit, ten, ten_hit = set(), set(), set(), set(), set(), set()
        per_op = {}
        rows = [(r, False) for r in table_rows(self.d / "requests.json")] + \
               [(r, True) for r in table_rows(self.d / "exceptions.json")]
        for row, is_exc in rows:
            if ld.parse_ts(row["timestamp"]) < scope:
                continue
            failed = is_exc or row["success"] == "False"
            user = row["user_AuthenticatedId"] or row["user_Id"]
            dims = row["customDimensions"]
            tenant = (json.loads(dims) if isinstance(dims, str) else dims)["TenantId"]
            users.add(user)
            ten.add(tenant)
            if row["client_IP"] != "0.0.0.0":
                ips.add(row["client_IP"])
            if failed:
                users_hit.add(user)
                ten_hit.add(tenant)
                if row["client_IP"] != "0.0.0.0":
                    ips_hit.add(row["client_IP"])
            if not is_exc:
                t = per_op.setdefault(row["name"], [0, 0])
                t[0] += 1
                t[1] += failed
        return (len(users_hit), len(users)), (len(ips_hit), len(ips)), (len(ten_hit), len(ten)), per_op

    def test_counts_match_independent_calculation(self):
        users, ips, tenants, per_op = self.expected()
        self.assertEqual((self.br["users"]["affected"], self.br["users"]["seen"]), users)
        self.assertEqual((self.br["clients"]["affected"], self.br["clients"]["seen"]), ips)
        self.assertEqual((self.br["tenants"]["affected"], self.br["tenants"]["seen"]), tenants)
        self.assertEqual(tenants, (1, 5))
        items = {o["operation"]: o for o in self.br["operations"]["items"]}
        self.assertEqual(sorted(items), ["GET /api/cart", "POST /api/cart/checkout"], "catalog is not affected")
        for op, o in items.items():
            total, failed = per_op[op]
            self.assertEqual((o["total_requests"], o["failed_requests"]), (total, failed))
            self.assertEqual(o["failure_share"], round(failed / total, 4))
        self.assertEqual(self.br["roles"], {"count": 1, "names": ["cart-api"]})

    def test_identifiers_never_output(self):
        self.assertFalse(self.br["identifiers_output"])
        blob = everything(self.r)
        for leaked in ("shopper0", "mail-example", "anon-0", "203.0.113.", "tenant-03", "tenant-0"):
            self.assertNotIn(leaked, blob)
        md = ld.to_markdown(self.r)
        self.assertIn("users seen in this period were affected", md)
        self.assertIn("Counts only; identifiers are never written out", md)

    def test_failed_request_alert(self):
        a = self.r["alert_suggestion"]
        self.assertEqual(a["table"], "requests")
        self.assertIn('| where success == false and name == "POST /api/cart/checkout" and resultCode == "500"', a["kql"])


class ChangeExportRouting(unittest.TestCase):
    def test_changes_flag_and_existing_scenarios_unaffected(self):
        d = FX / "appinsights-nullref-after-deploy"
        base = run("appinsights-nullref-after-deploy")
        r = ld.analyse([d], str(d / "deploys.txt"), None, [FX / "activitylog-config-change" / "activity-log.json"])
        self.assertEqual(r["records"], base["records"])
        self.assertEqual(r["signatures"], base["signatures"])
        self.assertEqual(r["deploy_correlation"], base["deploy_correlation"])
        self.assertEqual(len(r["change_inputs"]), 1)
        self.assertEqual(base["change_inputs"], [])
        self.assertIsNone(base["infra_correlation"])

    def test_activity_log_passed_as_deploys(self):
        d = FX / "activitylog-config-change"
        r = ld.analyse([d / "requests.json", d / "exceptions.json"], str(d / "activity-log.json"))
        self.assertEqual(r["deploys_considered"], 0)
        self.assertEqual(r["infra_correlation"]["operation"], "Microsoft.Web/sites/config/write")

    def test_non_change_file_in_changes_is_skipped(self):
        r = ld.analyse([FX / "quiet-healthy"], None, None, [FX / "quiet-healthy" / "requests.json"])
        self.assertIn("not a recognised Activity Log", " ".join(s["reason"] for s in r["skipped"]))

    def test_only_change_records_no_logs(self):
        r = ld.analyse([FX / "cloudtrail-sg-change" / "cloudtrail.json"])
        self.assertEqual((r["records"], r["verdict_hint"]), (0, "no-data"))
        self.assertEqual(len(r["infra_changes"]), 4)
        self.assertTrue(all(c["minutes_before_onset"] is None for c in r["infra_changes"]))
        self.assertIn("## Infrastructure changes", ld.to_markdown(r))


class InfraUnits(unittest.TestCase):
    def test_azure_classification(self):
        cases = {
            ("Microsoft.Web/sites/config/write", "/x/providers/Microsoft.Web/sites/a/config/appsettings"): ("change", "app-config"),
            ("Microsoft.Web/sites/slots/slotsswap/action", ""): ("change", "slot-swap"),
            ("Microsoft.Web/sites/restart/action", ""): ("change", "restart"),
            ("Microsoft.Web/sites/stop/action", ""): ("change", "restart"),
            ("Microsoft.Web/serverfarms/write", ""): ("change", "scale"),
            ("Microsoft.Insights/AutoscaleSettings/Scaleup/Action", ""): ("change", "scale"),
            ("Microsoft.Network/networkSecurityGroups/securityRules/delete", ""): ("change", "network"),
            ("Microsoft.KeyVault/vaults/accessPolicies/write", ""): ("change", "secrets-identity"),
            ("Microsoft.KeyVault/vaults/secrets/write", ""): ("change", "secrets-identity"),
            ("Microsoft.Resources/deployments/write", ""): ("change", "deployment"),
            ("Microsoft.Storage/storageAccounts/listKeys/action", ""): ("secret-read", None),
            ("Microsoft.Web/sites/config/list/action", ""): ("secret-read", None),
            ("Microsoft.Web/sites/publishxml/action", ""): ("secret-read", None),
            ("Microsoft.Web/sites/read", ""): ("drop", None),
            ("Microsoft.Resources/tags/write", ""): ("drop", None),
            ("Microsoft.Insights/diagnosticSettings/write", ""): ("drop", None),
        }
        for (op, rid), want in cases.items():
            with self.subTest(op):
                got = infra_changes.classify_azure(op, rid, "Administrative")
                self.assertEqual(got[:2], want)
        self.assertEqual(infra_changes.classify_azure("Microsoft.Web/sites/write", "", "Policy")[0], "drop")

    def test_cloudtrail_classification(self):
        cases = {"RevokeSecurityGroupIngress": "network", "UpdateFunctionCode20150331v2": "deployment",
                 "PutParameter": "app-config", "UpdateAutoScalingGroup": "scale", "PutScalingPolicy": "scale",
                 "AttachRolePolicy": "secrets-identity", "PutSecretValue": "secrets-identity",
                 "RebootDBInstance": "restart", "TerminateInstances": "restart", "CreateBucket": "other"}
        for name, cat in cases.items():
            with self.subTest(name):
                self.assertEqual(infra_changes.classify_cloudtrail(name, "false")[:2], ("change", cat))
        for name in ("DescribeInstances", "ListFunctions", "LookupEvents", "ConsoleLogin", "AssumeRole"):
            self.assertEqual(infra_changes.classify_cloudtrail(name, None)[0], "drop", name)
        self.assertEqual(infra_changes.classify_cloudtrail("GetSecretValue", "true")[0], "secret-read")
        self.assertEqual(infra_changes.classify_cloudtrail("CreateBucket", "true")[0], "drop")

    def test_detect_shapes(self):
        self.assertEqual(infra_changes.detect([{"TimeGenerated": "x", "OperationNameValue": "a/write",
                                                "ActivityStatusValue": "Success", "CategoryValue": "Administrative"}]),
                         "azure-activity-log")
        self.assertEqual(infra_changes.detect({"Records": [{"eventName": "RunInstances"}]}), "aws-cloudtrail")
        self.assertEqual(infra_changes.detect({"events": [{"eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE"}]}), "aws-health")
        self.assertIsNone(infra_changes.detect({"events": [{"timestamp": 1, "message": "x"}]}), "CloudWatch events stay logs")
        self.assertIsNone(infra_changes.detect([{"TimeGenerated": "x", "Name": "GET /"}]))
        self.assertIsNone(infra_changes.detect([]))

    def test_log_analytics_azure_activity_rows(self):
        rows = [{"TimeGenerated": "2026-09-27T08:12:09Z", "OperationNameValue": "MICROSOFT.WEB/SITES/CONFIG/WRITE",
                 "OperationName": "Update Web App Config", "ActivityStatusValue": "Success",
                 "CategoryValue": "Administrative", "Caller": "someone@corp.test", "CorrelationId": "c1",
                 "_ResourceId": "/subscriptions/s/resourcegroups/rg/providers/microsoft.web/sites/app/config/appsettings"}]
        red = ld.Redactor()
        ch, rd, hl, st = infra_changes.parse(rows, "azure-activity-log", red, ld.parse_ts)
        self.assertEqual((len(ch), ch[0]["category"], ch[0]["resource"], ch[0]["caller"]),
                         (1, "app-config", "app/appsettings", "<email-1>"))

    def test_raw_cloudtrail_records_and_aws_health(self):
        raw = {"Records": [{"eventName": "AuthorizeSecurityGroupIngress", "eventTime": "2026-09-27T10:00:00Z",
                            "eventSource": "ec2.amazonaws.com", "readOnly": False, "awsRegion": "us-east-1",
                            "userIdentity": {"type": "IAMUser", "userName": "carol"},
                            "requestParameters": {"groupId": "sg-123"}, "eventID": "e1"}]}
        red = ld.Redactor()
        ch, _, _, _ = infra_changes.parse(raw, "aws-cloudtrail", red, ld.parse_ts)
        self.assertEqual((ch[0]["resource"], ch[0]["caller"], ch[0]["category"]), ("sg-123", "<user-1>", "network"))
        health = {"events": [{"arn": "arn:aws:health:x", "service": "EC2", "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
                              "eventTypeCategory": "issue", "region": "eu-west-1",
                              "startTime": "2026-09-27T09:55:00+00:00", "statusCode": "open"}]}
        _, _, hl, _ = infra_changes.parse(health, "aws-health", red, ld.parse_ts)
        self.assertIn("possible platform incident in region eu-west-1", infra_changes.health_summary(hl[0]))

    def test_same_person_same_pseudonym_in_logs_and_changes(self):
        red = ld.Redactor()
        a = red.redact("login failed for pat@corp.test")
        b = infra_changes.pseudonymise_caller("pat@corp.test", red)
        self.assertIn(b, a)
        self.assertEqual(infra_changes.pseudonymise_caller("7F3C2A10-9D4E-4B1A-8C55-2E6F1A0B9C33", red), "<principal-1>")
        self.assertEqual(infra_changes.pseudonymise_caller("Microsoft.Insights/autoscaleSettings", red),
                         "Microsoft.Insights/autoscaleSettings")

    def test_resource_names_drop_account_and_subscription(self):
        self.assertEqual(infra_changes.short_aws_resource("arn:aws:lambda:eu-west-1:123456789012:function:orders"), "orders")
        self.assertEqual(infra_changes.short_aws_resource("arn:aws:iam::123456789012:role/app-role"), "app-role")
        name, rtype, rg = infra_changes.short_azure_resource(
            "/subscriptions/0000/resourceGroups/rg-a/providers/Microsoft.Network/networkSecurityGroups/nsg/securityRules/r1")
        self.assertEqual((name, rtype, rg), ("nsg/r1", "Microsoft.Network/networkSecurityGroups/securityRules", "rg-a"))


class AlertUnits(unittest.TestCase):
    def test_threshold_rule(self):
        for p, want in ((0, 5), (1, 5), (1.2, 5), (2, 6), (2.5, 8), (3, 9), (5, 15)):
            self.assertEqual(alert_rules.threshold(p), want, p)

    def test_stable_term(self):
        self.assertEqual(alert_rules.stable_term(
            "Object reference not set to an instance of an object. customer=<email-1> tier=Gold"),
            "Object reference not set to an instance of an object.")
        self.assertEqual(alert_rules.stable_term("KeyError: 'currency'", "KeyError"), None)
        self.assertEqual(alert_rules.stable_term("ERROR payment gateway rejected card 4242", None),
                         "payment gateway rejected card")

    def test_workspace_schema_and_generic_exception(self):
        s = {"kind": "exception", "type": "System.Exception", "headline": "Payment provider returned 402 for order",
             "role": None}
        lines = alert_rules.kql_for(s, "workspace")
        self.assertEqual(lines, ["AppExceptions", '| where OuterMessage contains "Payment provider returned"'])
        s2 = {"kind": "log", "type": None, "headline": "ERROR queue consumer stalled after 3 retries", "role": "worker"}
        self.assertEqual(alert_rules.kql_for(s2, "classic"),
                         ["traces", '| where severityLevel >= 3 and message contains "queue consumer stalled after"',
                          '| where cloud_RoleName == "worker"'])

    def test_cloudwatch_json_request_pattern(self):
        s = {"kind": "request", "op": "/checkout", "status": "500", "json_keys": {"path": "path", "status": "status"},
             "role": "123456789012:/aws/lambda/checkout", "type": None, "headline": ""}
        t = alert_rules.cloudwatch_texts(s, "ld-checkout-500", 7)
        self.assertEqual(t["filter_pattern"], '{ ($.status = 500) && ($.path = "/checkout") }')
        self.assertEqual(t["log_group"], "/aws/lambda/checkout")
        self.assertIn("--threshold 7", t["aws_cli"])

    def test_gcp_and_unknown_platforms(self):
        sig = {"signature": "java.lang.IllegalStateException: pool exhausted"}
        basis = {"threshold": 6}
        g = alert_rules.build(sig, {"kind": "exception", "type": "java.lang.IllegalStateException",
                                    "source": "gcp-logging", "headline": "pool exhausted"}, "classic", basis)
        self.assertIn("gcloud logging metrics create ld-java-lang-illegalstateexception-pool", g["gcloud_cli"])
        self.assertIn('severity>=ERROR AND "java.lang.IllegalStateException"', g["gcloud_cli"])
        u = alert_rules.build(sig, {"kind": "log", "type": None, "source": "text",
                                    "headline": "worker pool exhausted after 30s"}, "classic", basis)
        self.assertEqual((u["platform"], u["pattern"]), ("unknown", "worker pool exhausted after"))

    def test_no_alert_without_onset(self):
        r = run("gcp-java-errors")
        self.assertEqual(r["alert_suggestion"]["status"], "not-suggested")


class PostmortemAndDeterminism(unittest.TestCase):
    def test_cli_postmortem_is_deterministic_and_regenerable(self):
        s = str(SCRIPTS / "log_detective.py")
        d = FX / "activitylog-config-change"
        snaps = []
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(2):
                out = Path(tmp, "run%d" % i)
                p = subprocess.run([sys.executable, s, str(d), "--deploys", str(d / "deploys.txt"),
                                    "--baseline", str(FX / "activitylog-config-change-lastweek"),
                                    "--out-dir", str(out), "--postmortem"],
                                   capture_output=True, text=True, encoding="utf-8", timeout=120)
                self.assertEqual(p.returncode, 0, p.stderr)
                snaps.append({f: Path(out, f).read_bytes() for f in
                              ("log-detective.json", "log-detective.md", "postmortem-draft.md")})
            self.assertEqual(snaps[0], snaps[1])
            regen = Path(tmp, "regen.md")
            p = subprocess.run([sys.executable, str(SCRIPTS / "postmortem.py"), str(Path(tmp, "run0", "log-detective.json")),
                                "--out", str(regen)], capture_output=True, text=True, encoding="utf-8", timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(regen.read_bytes(), snaps[0]["postmortem-draft.md"])
        pm = snaps[0]["postmortem-draft.md"].decode("utf-8")
        self.assertIn("Compared with baseline", pm)
        self.assertIn("in the baseline window: no", pm)
        self.assertNotRegex(pm, r"[\w.+-]+@[\w-]+\.\w{2,}")

    def test_postmortem_for_a_healthy_or_empty_report(self):
        for scenario in ("quiet-healthy", "bad-inputs"):
            pm = postmortem.render(json.loads(json.dumps(run(scenario), default=str)))
            self.assertIn("## Action items", pm)
            self.assertIn("[to be confirmed]", pm)


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "pipeline-doctor" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import pipeline_speed as ps  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "pipelines" / "speed"
TIPS = ps.load_tips()


def run(*names, **kw):
    return ps.analyse([FX / n for n in names], **kw)


def tips(res):
    return sorted((t["rule"], t["step"]) for t in res["tips"])


class AzureLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run("ado-build.log")

    def test_step_timings_and_order(self):
        got = [(s["step"], s["seconds"]) for s in self.res["slowest_steps"]]
        self.assertEqual(got, [("dotnet test", 420.0), ("Build image", 240.0), ("npm ci", 180.0), ("dotnet restore", 120.0),
                               ("Checkout orders-api@main to s", 95.0), ("PublishPipelineArtifact", 90.0), ("dotnet build", 60.0),
                               ("Use Node 20", 5.0), ("Initialize job", 4.0), ("Finalize Job", 1.0)])
        self.assertEqual(self.res["slowest_steps"][0]["share"], round(420 / 1215, 3))
        self.assertEqual((self.res["wall_clock_seconds"], self.res["agent_seconds"], self.res["step_count"]), (1215.0, 1215.0, 10))

    def test_top_limits_list(self):
        self.assertEqual(len(run("ado-build.log", top=3)["slowest_steps"]), 3)

    def test_rules_fire(self):
        self.assertEqual(tips(self.res), [
            ("dependency-cache", "dotnet restore"), ("dependency-cache", "npm ci"), ("docker-layer-cache", "Build image"),
            ("large-artifact", "PublishPipelineArtifact"), ("shallow-checkout", "Checkout orders-api@main to s"),
            ("test-sharding", "dotnet test")])

    def test_dockerfile_restore_is_not_a_pipeline_install(self):
        self.assertNotIn(("dependency-cache", "Build image"), tips(self.res))

    def test_estimates_use_measured_times_and_ratios(self):
        est = {(t["rule"], t["step"]): t["estimate_seconds"] for t in self.res["tips"]}
        r = TIPS["saving_ratio"]
        self.assertEqual(est[("dependency-cache", "npm ci")], round(180 * r["npm"], 1))
        self.assertEqual(est[("dependency-cache", "dotnet restore")], round(120 * r["nuget"], 1))
        self.assertEqual(est[("docker-layer-cache", "Build image")], round(240 * r["docker_build"], 1))
        self.assertEqual(est[("shallow-checkout", "Checkout orders-api@main to s")], round(95 * r["shallow_checkout"], 1))
        self.assertEqual(est[("test-sharding", "dotnet test")], round(420 * r["test_sharding"], 1))
        self.assertEqual(est[("large-artifact", "PublishPipelineArtifact")], round(90 * r["artifact"], 1))
        self.assertEqual(self.res["estimated_saving_seconds"], round(sum(est.values()), 1))
        # sharding saves wall clock only, so it is not in the agent-minute saving
        self.assertEqual(self.res["estimated_agent_seconds_saved"], round(sum(est.values()) - est[("test-sharding", "dotnet test")], 1))
        for t in self.res["tips"]:
            self.assertIn("references/speed-tips.json", t["assumption"])

    def test_tips_sorted_by_saving(self):
        est = [t["estimate_seconds"] for t in self.res["tips"]]
        self.assertEqual(est, sorted(est, reverse=True))

    def test_platform_specific_fix(self):
        npm = next(t for t in self.res["tips"] if t["step"] == "npm ci")
        self.assertEqual(len(npm["fix"]), 1)
        self.assertTrue(npm["fix"][0].startswith("Azure Pipelines: Cache@2"))
        self.assertIn("package-lock.json", npm["fix"][0])
        art = next(t for t in self.res["tips"] if t["rule"] == "large-artifact")
        self.assertIn("1284.6 MB", art["why"])

    def test_queue_from_run_json(self):
        res = run("ado-build.log", "ado-run.json")
        self.assertEqual(res["queue"], {"seconds": 30.0, "duration": "30s", "method": "run startTime - queueTime"})
        self.assertNotIn("queue-wait", [t["rule"] for t in res["tips"]])

    def test_cost_from_supplied_rate(self):
        res = run("ado-build.log", rate=0.008)
        self.assertEqual(res["cost"]["run_cost"], round(1215 / 60 * 0.008, 4))
        self.assertEqual(res["cost"]["estimated_saving_per_run"], round(res["estimated_agent_seconds_saved"] / 60 * 0.008, 4))
        self.assertNotIn("cost", self.res)


class CacheAwareness(unittest.TestCase):
    def test_cache_hit_suppresses_npm_tip_but_not_nuget(self):
        res = run("ado-cached.log")
        # npm ci took 75 s but Cache npm had a hit; docker used --cache-from; checkout was shallow; tests < 5 min
        self.assertEqual(tips(res), [("dependency-cache", "dotnet restore")])

    def test_github_cache_hit_no_tip(self):
        res = run("gha-cache-hit.log")
        npm = next(s for s in res["slowest_steps"] if s["step"] == "Run npm ci")
        self.assertGreaterEqual(npm["seconds"], TIPS["thresholds_seconds"]["install"])
        self.assertEqual(res["tips"], [])

    def test_cache_miss_rule(self):
        res = run("gha-cache-miss.log")
        self.assertEqual(tips(res), [("cache-miss", "Run npm ci")])
        self.assertIn("key", res["tips"][0]["fix"][0])

    def test_thresholds_are_configurable(self):
        custom = json.loads(json.dumps(TIPS))
        custom["thresholds_seconds"]["tests"] = 150
        res = run("ado-cached.log", tips=custom)
        self.assertIn(("test-sharding", "dotnet test"), tips(res))


class GitHubLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run("gha-run.log")

    def test_jobs_steps_and_totals(self):
        got = [(s["job"], s["step"], s["seconds"]) for s in self.res["slowest_steps"][:3]]
        self.assertEqual(got, [("build", "Run npm test", 380.0), ("build", "Run npm ci", 110.0), ("lint", "Run npm run lint", 45.0)])
        self.assertEqual(self.res["wall_clock_seconds"], 505.0)  # parallel jobs: latest timestamp, not last line
        self.assertEqual(self.res["agent_seconds"], 552.0)
        self.assertEqual(self.res["platform"], "github")

    def test_rules(self):
        self.assertEqual(tips(self.res), [("dependency-cache", "Run npm ci"), ("test-sharding", "Run npm test")])
        npm = next(t for t in self.res["tips"] if t["rule"] == "dependency-cache")
        self.assertTrue(npm["fix"][0].startswith("GitHub Actions: actions/setup-node with `cache: npm`"))


class StructuredSources(unittest.TestCase):
    def test_timeline(self):
        res = run("timeline.json")
        self.assertEqual([(s["job"], s["step"], s["seconds"]) for s in res["slowest_steps"][:2]],
                         [("Build and test", "dotnet test", 490.0), ("Build and test", "npm ci", 150.0)])
        self.assertEqual(res["step_count"], 6)  # the skipped task without times is ignored
        self.assertEqual(res["jobs"], [{"name": "Build and test", "seconds": 720.0, "duration": "12m 00s", "wait_seconds": 240.0}])
        self.assertEqual(res["queue"]["seconds"], 240.0)
        self.assertIn("approximate", res["queue"]["method"])
        self.assertEqual(tips(res), [("dependency-cache", "npm ci"), ("queue-wait", None), ("test-sharding", "dotnet test")])
        q = next(t for t in res["tips"] if t["rule"] == "queue-wait")
        self.assertEqual(q["estimate_seconds"], round(240 * TIPS["saving_ratio"]["queue"], 1))
        self.assertIn("wall-clock only", q["affects"])

    def test_timeline_plus_log_content(self):
        res = run("timeline.json", "timeline-cache.log")
        self.assertEqual(tips(res), [("queue-wait", None), ("test-sharding", "dotnet test")])  # cache hit seen in the log
        self.assertEqual(res["step_count"], 6)  # log steps add content, not duplicate timings

    def test_gh_jobs_json(self):
        res = run("gh-run-jobs.json")
        self.assertEqual(res["queue"], {"seconds": 210.0, "duration": "3m 30s", "method": "first job start - run createdAt"})
        self.assertEqual(tips(res), [("dependency-cache", "Run pip install -r requirements.txt"), ("queue-wait", None)])
        self.assertEqual(res["agent_seconds"], 510.0)


class SafetyAndCli(unittest.TestCase):
    def test_references_note_and_ratios(self):
        self.assertIn("ESTIMATE", TIPS["_note"])
        for k, v in TIPS["saving_ratio"].items():
            self.assertTrue(0 < v < 1, k)

    def test_step_names_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "run.log"
            p.write_text("2026-09-27T09:00:00.0000000Z ##[section]Starting: Notify dev.lead@example.com\n"
                         "2026-09-27T09:06:40.0000000Z ##[section]Finishing: Notify dev.lead@example.com\n", encoding="utf-8")
            blob = json.dumps(ps.analyse([p]))
            self.assertNotIn("dev.lead@example.com", blob)
            self.assertIn("<email-1>", blob)

    def test_cli_json_deterministic_and_markdown(self):
        args = [sys.executable, str(SCRIPTS / "pipeline_speed.py"), str(FX / "ado-build.log"), str(FX / "ado-run.json")]
        a = subprocess.run(args + ["--json"], capture_output=True, text=True, encoding="utf-8", timeout=60)
        b = subprocess.run(args + ["--json"], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        doc = json.loads(a.stdout)
        for key in ("sources", "platform", "wall_clock_seconds", "agent_seconds", "queue", "jobs", "slowest_steps", "tips",
                    "estimated_saving_seconds", "estimated_agent_seconds_saved", "assumptions"):
            self.assertIn(key, doc)
        md = subprocess.run(args + ["--per-minute-rate", "0.008"], capture_output=True, text=True, encoding="utf-8", timeout=60).stdout
        self.assertIn("## Slowest steps", md)
        self.assertIn("(estimate)", md)
        self.assertIn("No pipeline or run was changed", md)


if __name__ == "__main__":
    unittest.main()

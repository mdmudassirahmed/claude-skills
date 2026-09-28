import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "pipeline-doctor" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import pipeline_history as ph  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "pipelines" / "history"
AZ = FX / "azure"
GH = FX / "github"


def sha(label):
    return hashlib.sha1(label.encode()).hexdigest()


def load(folder, **kw):
    return ph.analyse(json.loads((folder / "runs.json").read_text(encoding="utf-8")), folder / "logs", **kw)


def by_test(res):
    return {t["test"]: t for t in res["tests"]}


F_TEST = "Orders.Api.Tests.CheckoutTests.Retry_Succeeds_Eventually"
R_TEST = "Orders.Api.Tests.DiscountServiceTests.GoldCustomer_GetsTenPercent"
T1 = "tests/test_api.py::test_timeout_retry"
T2 = "tests/test_convert.py::test_rounding_half_even"
T3 = "tests/test_io.py::test_tmpdir_cleanup"


class AzureHistory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = load(AZ)

    def test_runs_sorted_chronologically_and_normalised(self):
        ids = [r["id"] for r in self.res["runs"]]
        self.assertEqual(ids, ["101", "102", "103", "104", "110", "111", "105", "106", "107", "112", "113", "108", "109", "114"])
        first = self.res["runs"][0]
        self.assertEqual(first["branch"], "main")  # refs/heads/ stripped
        self.assertEqual(first["commit"], sha("c1"))
        self.assertEqual(self.res["pipeline"], "orders-api-ci")
        self.assertEqual(self.res["platform"], "azure")

    def test_log_discovery_by_run_id(self):
        logs = {r["id"]: r["log_files"] for r in self.res["runs"]}
        self.assertEqual(logs["102"], ["run-102.log"])
        self.assertEqual(logs["105"], ["105/1_Initialize job.txt", "105/4_dotnet test.txt"])
        self.assertEqual(logs["107"], ["build_107.log"])
        self.assertEqual(logs["110"], ["110.log"])
        self.assertEqual(logs["112"], ["run_112.txt"])
        self.assertEqual(logs["108"], [])
        self.assertEqual(self.res["missing_logs"], ["108"])
        self.assertEqual(self.res["unmatched_logs"], ["run-999.log"])

    def test_regression_first_bad_and_last_good_commit(self):
        t = by_test(self.res)[R_TEST]
        self.assertEqual(t["status"], "regression")
        self.assertEqual(t["confidence"], "high")
        self.assertEqual(t["first_bad_commit"], sha("c4"))
        self.assertEqual(t["last_good_commit"], sha("c3"))
        self.assertEqual((t["first_bad_run"], t["last_good_run"]), ("105", "104"))
        self.assertEqual(t["failed_runs"], ["105", "106", "107", "109"])
        self.assertIn(f"git log --oneline {sha('c3')[:10]}..{sha('c4')[:10]}", t["advice"])

    def test_flaky_same_commit_pass_and_absent_from_later_failure(self):
        t = by_test(self.res)[F_TEST]
        self.assertEqual(t["status"], "flaky")
        self.assertEqual(t["confidence"], "high")
        ev = {e["commit"]: e for e in t["evidence"]}
        # c2: failed in 102, the re-run 103 on the same commit was green
        self.assertEqual((ev[sha("c2")]["failed_runs"], ev[sha("c2")]["passed_runs"]), (["102"], ["103"]))
        # c5: failed in 106, absent from the later failure 107 of the same commit (tests ran there)
        self.assertEqual((ev[sha("c5")]["failed_runs"], ev[sha("c5")]["passed_runs"]), (["106"], ["107"]))

    def test_regression_listed_before_flaky(self):
        self.assertEqual([t["status"] for t in self.res["tests"]], ["regression", "flaky"])

    def test_recurring_signatures(self):
        rec = [(v["id"], v["count"], v["runs"]) for v in self.res["recurring"]]
        self.assertEqual(rec, [("dotnet-tests-failed", 5, ["102", "105", "106", "107", "109"]),
                               ("nuget-feed-auth", 3, ["110", "111", "112"])])
        nuget = self.res["recurring"][1]
        self.assertEqual(nuget["owner"], "pipeline-admin")
        self.assertEqual(nuget["branches"], ["feature/payments"])
        self.assertEqual((nuget["first_seen"], nuget["last_seen"]), ("2026-09-21T11:05:05Z", "2026-09-22T15:05:05Z"))

    def test_recurring_threshold_flag(self):
        res = load(AZ, recurring_min=4)
        self.assertEqual([v["id"] for v in res["recurring"]], ["dotnet-tests-failed"])

    def test_metrics(self):
        m = self.res["metrics"]
        self.assertEqual((m["runs_total"], m["completed"], m["failed"], m["succeeded"]), (14, 12, 9, 3))
        self.assertEqual((m["cancelled"], m["in_progress_or_other"]), (1, 1))
        self.assertEqual(m["failure_rate"], 0.75)
        self.assertEqual(m["incidents"], 3)
        # main: red at 102 (09:12:05) -> green at 103 (09:40:05) = 28 min
        self.assertEqual((m["mttg_seconds"], m["mttg_samples"], m["mttg"]), (1680.0, 1, "28m 00s"))
        # main: incident starts 2026-09-20 09:12:05 and 2026-09-21 14:12:05 = 29 h; feature has only one incident
        self.assertEqual((m["mtbf_seconds"], m["mtbf_samples"], m["mtbf"]), (104400.0, 1, "1d 05h"))

    def test_open_incidents_measured_to_latest_completed_run(self):
        opened = {o["branch"]: o for o in self.res["metrics"]["open_incidents"]}
        self.assertEqual(opened["main"]["since_run"], "105")
        self.assertEqual(opened["main"]["open_for_seconds"], 241200.0)  # to run 109 finish, not the in-progress 114
        self.assertEqual(opened["feature/payments"]["open_for_seconds"], 252420.0)

    def test_branch_views(self):
        b = {x["branch"]: x for x in self.res["branches"]}
        self.assertEqual(b["main"]["status"], "regression")
        self.assertEqual((b["main"]["red_since_run"], b["main"]["last_good_run"]), ("105", "104"))
        self.assertEqual(b["main"]["first_bad_commit"], sha("c4"))
        self.assertEqual(b["main"]["diagnoses"], ["dotnet-tests-failed"])
        self.assertEqual(b["feature/payments"]["status"], "red-throughout-window")
        self.assertIsNone(b["feature/payments"]["last_good_commit"])
        self.assertEqual(b["feature/payments"]["red_runs"], ["110", "111", "112"])  # cancelled 113 ignored

    def test_markdown(self):
        md = ph.to_markdown(self.res)
        for frag in ("Failure rate | 75.0%", "**regression** (high)", "**flaky** (high)", "Recurring causes",
                     "Failed runs without logs (not classified): 108", "No pipeline or run was changed"):
            self.assertIn(frag, md)
        self.assertNotIn("\u2014", md)


class GitHubHistory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = load(GH)

    def test_classification(self):
        t = by_test(self.res)
        self.assertEqual(t[T1]["status"], "flaky")
        self.assertEqual(t[T1]["evidence"], [{"commit": sha("g2"), "failed_runs": ["5002"], "passed_runs": ["5003"]}])
        self.assertEqual(t[T2]["status"], "fixed")
        self.assertEqual((t[T2]["first_bad_run"], t[T2]["fixed_run"]), ("5002", "5006"))
        self.assertEqual(t[T2]["fixed_commit"], sha("g5"))
        self.assertEqual(t[T3]["status"], "intermittent")
        self.assertEqual(t[T3]["failed_runs"], ["5007", "5009"])
        self.assertEqual([x["status"] for x in self.res["tests"]], ["flaky", "intermittent", "fixed"])

    def test_metrics(self):
        m = self.res["metrics"]
        self.assertEqual((m["completed"], m["failed"], m["failure_rate"]), (10, 7, 0.7))
        self.assertEqual(m["in_progress_or_other"], 1)
        # recoveries: 5002 -> 5006 (46h59m) and 5007 -> 5008 (2h59m)
        self.assertEqual(m["mttg_seconds"], (169140 + 10740) / 2)
        # incident starts: 09-10 10:07, 09-12 13:07, 09-13 09:07 -> gaps 51h and 20h
        self.assertEqual(m["mtbf_seconds"], (183600 + 72000) / 2)
        self.assertEqual(m["open_incidents"][0]["since_run"], "5009")
        self.assertEqual(m["open_incidents"][0]["open_for_seconds"], 7080.0)

    def test_recurring_and_branch(self):
        self.assertEqual([(v["id"], v["count"]) for v in self.res["recurring"]], [("pytest-failed", 6)])
        b = self.res["branches"][0]
        self.assertEqual((b["status"], b["red_since_run"], b["last_good_run"]), ("regression", "5009", "5008"))
        self.assertEqual(b["diagnoses"], ["pytest-failed", "docker-rate-limit"])

    def test_non_test_failure_leaves_test_state_unknown(self):
        run = next(r for r in self.res["runs"] if r["id"] == "5010")
        self.assertEqual((run["diagnoses"], run["failing_tests"]), (["docker-rate-limit"], []))


def scenario(runs, logs=None):
    tmp = tempfile.TemporaryDirectory()
    d = Path(tmp.name)
    (d / "logs").mkdir()
    for name, text in (logs or {}).items():
        (d / "logs" / name).write_text(text, encoding="utf-8")
    return tmp, ph.analyse(runs, d / "logs")


def gh_run(i, sha_, concl, hour):
    return {"databaseId": i, "conclusion": concl, "status": "completed", "headSha": sha_, "headBranch": "main",
            "createdAt": f"2026-09-01T{hour:02d}:00:00Z", "updatedAt": f"2026-09-01T{hour:02d}:05:00Z", "name": "CI"}


def pytest_log(*failing):
    lines = [f"test\tRun tests\t2026-09-01T00:00:0{i}.0000000Z FAILED {t} - AssertionError" for i, t in enumerate(failing)]
    lines.append(f"test\tRun tests\t2026-09-01T00:00:09.0000000Z ===== {len(failing)} failed, 10 passed in 1.00s =====")
    return "\n".join(lines) + "\n"


DOCKER_LOG = ("build\tBuild\t2026-09-01T00:00:00.0000000Z toomanyrequests: You have reached your pull rate limit.\n")


class EdgeCases(unittest.TestCase):
    def test_single_green_run(self):
        tmp, res = scenario([gh_run(1, "a", "success", 1)])
        with tmp:
            m = res["metrics"]
            self.assertEqual((m["failure_rate"], m["mtbf_seconds"], m["mttg_seconds"], m["mttg"]), (0.0, None, None, "n/a"))
            self.assertEqual((res["tests"], res["recurring"], m["open_incidents"]), ([], [], []))
            self.assertEqual(res["branches"][0]["status"], "green")

    def test_single_failed_run_is_persistent(self):
        tmp, res = scenario([gh_run(7, "a", "failure", 1)], {"7.log": pytest_log("t::x")})
        with tmp:
            self.assertEqual(res["tests"][0]["status"], "persistent")
            self.assertEqual(res["branches"][0]["status"], "red-throughout-window")
            self.assertEqual(res["metrics"]["failure_rate"], 1.0)
            self.assertEqual(res["recurring"], [])

    def test_all_green(self):
        tmp, res = scenario([gh_run(i, f"s{i}", "success", i) for i in range(1, 4)])
        with tmp:
            self.assertEqual((res["metrics"]["failed"], res["metrics"]["incidents"]), (0, 0))
            self.assertEqual(res["missing_logs"], [])

    def test_missing_logs_folder(self):
        res = ph.analyse([gh_run(1, "a", "success", 1), gh_run(2, "b", "failure", 2)], None)
        self.assertEqual(res["missing_logs"], ["2"])
        self.assertEqual(res["tests"], [])
        self.assertEqual(res["branches"][0]["status"], "regression")

    def test_same_commit_green_before_failure_is_flaky(self):
        tmp, res = scenario([gh_run(1, "a", "success", 1), gh_run(2, "a", "failure", 2)], {"run-2.log": pytest_log("t::x")})
        with tmp:
            self.assertEqual(res["tests"][0]["status"], "flaky")
            self.assertEqual(res["branches"][0]["status"], "broke-without-code-change")

    def test_absent_from_failure_that_did_not_run_tests_is_not_proof(self):
        runs = [gh_run(1, "a", "success", 1), gh_run(2, "b", "failure", 2), gh_run(3, "b", "failure", 3)]
        tmp, res = scenario(runs, {"2.log": pytest_log("t::x"), "3.log": DOCKER_LOG})
        with tmp:
            t = res["tests"][0]
            self.assertEqual((t["status"], t["confidence"]), ("regression", "medium"))
            self.assertEqual((t["first_bad_commit"], t["last_good_commit"]), ("b", "a"))

    def test_azure_invoke_value_wrapper_and_partial(self):
        runs = {"count": 2, "value": [
            {"id": 2, "result": "partiallySucceeded", "status": "completed", "sourceVersion": "b", "sourceBranch": "refs/heads/main",
             "startTime": "2026-09-01T02:00:00Z", "finishTime": "2026-09-01T02:05:00Z", "definition": {"name": "p"}},
            {"id": 1, "result": "failed", "status": "completed", "sourceVersion": "a", "sourceBranch": "refs/heads/main",
             "startTime": "2026-09-01T01:00:00Z", "finishTime": "2026-09-01T01:05:00Z", "definition": {"name": "p"}}]}
        res = ph.analyse(runs, None)
        self.assertEqual([r["id"] for r in res["runs"]], ["1", "2"])
        self.assertEqual((res["metrics"]["partially_succeeded"], res["metrics"]["failure_rate"]), (1, 0.5))

    def test_recurring_needs_three_runs(self):
        runs = [gh_run(i, f"s{i}", "failure", i) for i in (1, 2)]
        tmp, res = scenario(runs, {"1.log": DOCKER_LOG, "2.log": DOCKER_LOG})
        with tmp:
            self.assertEqual(res["recurring"], [])


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        p = subprocess.run([sys.executable, str(SCRIPTS / "pipeline_history.py"), *args],
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def test_json_shape_and_determinism(self):
        args = [str(AZ / "runs.json"), "--logs", str(AZ / "logs"), "--json"]
        a, b = self.run_cli(*args), self.run_cli(*args)
        self.assertEqual(a, b)
        doc = json.loads(a)
        for key in ("pipeline", "platform", "window", "metrics", "branches", "tests", "recurring",
                    "missing_logs", "unmatched_logs", "runs", "definitions"):
            self.assertIn(key, doc)

    def test_markdown_cli(self):
        out = self.run_cli(str(GH / "runs.json"), "--logs", str(GH / "logs"))
        self.assertIn("# Pipeline Doctor - run history", out)
        self.assertIn("**intermittent**", out)


if __name__ == "__main__":
    unittest.main()

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "pipeline-doctor" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import pipeline_triage as pt  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "pipelines"
SIGS = pt.load_library()

# fixture -> (expected diagnosis id, expected step, expected text fragments in title/details)
EXPECTED = {
    "ado-npm-eresolve.log": ("npm-eresolve", "npm ci", []),
    "ado-nuget-401.log": ("nuget-feed-auth", "dotnet restore", []),
    "ado-dotnet-compile.log": ("dotnet-compile-error", "dotnet build", ["CS0246", "DiscountService.cs", "57"]),
    "ado-dotnet-tests.log": ("dotnet-tests-failed", "dotnet test", ["2 .NET test(s) failed"]),
    "ado-sp-secret-expired.log": ("aad-secret-expired", "Deploy infra (AzureCLI)", []),
    "ado-undefined-variable.log": ("unexpanded-variable", "Run DB migrations", ["OrdersDbConnectionString"]),
    "gha-docker-rate-limit.log": ("docker-rate-limit", "Build and push", []),
    "gha-node-heap.log": ("js-heap-oom", "Build", []),
    "ado-terraform-lock.log": ("terraform-state-lock", "terraform plan", []),
    "ado-tool-missing.log": ("tool-missing", "Run unit tests (python)", []),
    "ado-job-timeout.log": ("job-timeout", "Integration tests", []),
    "gha-python-module.log": ("python-module-missing", "Run tests", ["freezegun"]),
    "gha-pytest-failed.log": ("pytest-failed", "Run tests", ["2 pytest"]),
    "ado-unknown-error.log": ("unknown", "Publish artifacts", []),
}


def triage(name):
    return pt.triage((FX / name).read_text(encoding="utf-8"), SIGS, pt.Redactor())


class EveryScenario(unittest.TestCase):
    def test_fixture_set_is_complete(self):
        self.assertEqual(sorted(p.name for p in FX.glob("*.log")), sorted(EXPECTED))

    def test_diagnosis_step_and_details(self):
        for name, (sig_id, step, fragments) in EXPECTED.items():
            with self.subTest(name):
                d = triage(name)["diagnosis"]
                self.assertEqual(d["id"], sig_id)
                self.assertEqual(d["step"], step)
                blob = d["title"] + " " + json.dumps(d["details"])
                for frag in fragments:
                    self.assertIn(frag, blob)
                self.assertTrue(d["fix"], "every diagnosis must carry fix steps")


class RootNotCascade(unittest.TestCase):
    def test_exit_code_lines_never_chosen(self):
        for name in EXPECTED:
            d = triage(name)["diagnosis"]
            self.assertNotRegex(d["evidence"] or "", r"exit(ed)? (with )?code", name)

    def test_timeout_beats_generic_cancel(self):
        r = triage("ado-job-timeout.log")
        self.assertEqual(r["diagnosis"]["id"], "job-timeout")
        self.assertIn("job-canceled", [o["id"] for o in r["other_signals"]])

    def test_first_compile_error_reported(self):
        d = triage("ado-dotnet-compile.log")["diagnosis"]
        self.assertEqual(d["details"]["line"], "57")

    def test_unknown_falls_back_to_first_real_error(self):
        d = triage("ado-unknown-error.log")["diagnosis"]
        self.assertEqual(d["confidence"], "low")
        self.assertIn("manifest checksum mismatch", d["evidence"])


class TestsAndOwners(unittest.TestCase):
    def test_failing_test_names_collected(self):
        self.assertEqual(triage("ado-dotnet-tests.log")["diagnosis"]["failing_tests"], [
            "Orders.Api.Tests.DiscountServiceTests.GoldCustomer_GetsTenPercent",
            "Orders.Api.Tests.DiscountServiceTests.NullLoyaltyProfile_DoesNotThrow"])
        self.assertEqual(len(triage("gha-pytest-failed.log")["diagnosis"]["failing_tests"]), 2)

    def test_owner_routing(self):
        self.assertEqual(triage("ado-sp-secret-expired.log")["diagnosis"]["owner"], "pipeline-admin")
        self.assertEqual(triage("gha-docker-rate-limit.log")["diagnosis"]["owner"], "platform-team")
        self.assertEqual(triage("ado-npm-eresolve.log")["diagnosis"]["owner"], "developer")

    def test_secret_fix_recommends_federation_not_secret_in_yaml(self):
        fix = " ".join(triage("ado-sp-secret-expired.log")["diagnosis"]["fix"])
        self.assertIn("workload identity federation", fix)


class Safety(unittest.TestCase):
    def test_tokens_redacted_in_all_output(self):
        r = triage("ado-nuget-401.log")
        blob = json.dumps(r)
        self.assertNotIn("QWxhZGRpbjpvcGVuIHNlc2FtZQxyz123", blob)

    def test_no_secret_values_anywhere(self):
        for name in EXPECTED:
            blob = json.dumps(triage(name))
            self.assertNotRegex(blob, r"_authToken=[A-Za-z0-9]{10,}")


class Library(unittest.TestCase):
    def test_library_is_valid(self):
        ids = [s["id"] for s in SIGS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate signature ids")
        for s in SIGS:
            for key in ("id", "category", "weight", "confidence", "pattern", "title", "why", "fix", "owner"):
                self.assertIn(key, s, s.get("id"))
            self.assertIn(s["weight"], (1, 2, 3))
            self.assertIn(s["owner"], ("developer", "pipeline-admin", "platform-team"))
            self.assertIn(s["confidence"], ("high", "medium", "low"))
            # every {placeholder} in text fields must be a named group in the pattern
            groups = set(re.findall(r"\(\?P<(\w+)>", s["pattern"]))
            groups |= {re.sub(r"\d+$", "", g) for g in groups}
            for text in [s["title"], s["why"], *s["fix"]]:
                for ph in re.findall(r"\{(\w+)\}", text):
                    self.assertIn(ph, groups, f"{s['id']}: placeholder {{{ph}}} has no named group")

    def test_custom_library_flag(self):
        p = subprocess.run([sys.executable, str(SCRIPTS / "pipeline_triage.py"),
                            str(FX / "ado-npm-eresolve.log"), "--json"],
                           capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)[0]["diagnosis"]["id"], "npm-eresolve")

    def test_markdown(self):
        md = pt.to_markdown([dict(triage("ado-dotnet-tests.log"), file="x.log")])
        self.assertIn("Failing tests", md)
        self.assertIn("No pipeline, service connection or resource was changed", md)


MORE = FX / "more-signatures"
# fixture -> (expected diagnosis id, expected step, expected owner, {detail: value})
MORE_EXPECTED = {
    "ado-maven-401.log": ("maven-repo-auth", "Maven build", "pipeline-admin", {"repo": "internal-feed"}),
    "gha-gradle-oom.log": ("gradle-jvm-oom", "Build with Gradle", "developer", {"kind": "Java heap space"}),
    "gha-go-checksum.log": ("go-checksum-mismatch", "Build", "developer", {"module": "github.com/acme/money@v1.4.2"}),
    "gha-rust-compile.log": ("rust-compile-error", "Run cargo build", "developer", {"code": "0425"}),
    "gha-cargo-locked.log": ("cargo-lockfile-outdated", "Run cargo test", "developer", {}),
    "ado-pip-pep668.log": ("pip-externally-managed", "Install dependencies", "developer", {}),
    "gha-npm-e404.log": ("npm-package-not-found", "Install", "developer", {}),
    "ado-sonar-auth.log": ("sonar-auth", "Run Code Analysis", "pipeline-admin", {}),
    "ado-keyvault-denied.log": ("keyvault-access-denied", "AzureKeyVault", "platform-team", {}),
    "ado-arm-quota.log": ("arm-quota-or-sku", "Deploy infra (AzureCLI)", "platform-team", {}),
    "ado-parallelism.log": ("agent-parallelism-limit", "Job", "pipeline-admin", {}),
    "ado-agent-demands.log": ("agent-demands-not-met", None, "platform-team", {"pool": "Linux-Build"}),
    "gha-token-permissions.log": ("gh-token-permissions", "Comment on PR", "developer", {}),
    "gha-spending-limit.log": ("gha-spending-limit", "Set up job", "pipeline-admin", {}),
    "gha-input-missing.log": ("action-input-missing", "Publish release notes", "developer", {"input": "token"}),
    "ado-helm-lock.log": ("helm-operation-in-progress", "Helm upgrade", "platform-team", {}),
    "ado-kubectl-unauthorized.log": ("kubectl-unauthorized", "Deploy manifests", "pipeline-admin", {}),
    "gha-playwright.log": ("playwright-browsers-missing", "Run Playwright tests", "developer", {}),
    "gha-cypress.log": ("cypress-binary-missing", "Cypress run", "developer", {}),
}


class MoreSignatures(unittest.TestCase):
    def diag(self, name):
        return pt.triage((MORE / name).read_text(encoding="utf-8"), SIGS, pt.Redactor())["diagnosis"]

    def test_fixture_set_is_complete(self):
        self.assertEqual(sorted(p.name for p in MORE.glob("*.log")), sorted(MORE_EXPECTED))

    def test_each_new_signature(self):
        for name, (sig_id, step, owner, details) in MORE_EXPECTED.items():
            with self.subTest(name):
                d = self.diag(name)
                self.assertEqual((d["id"], d["step"], d["owner"]), (sig_id, step, owner))
                for k, v in details.items():
                    self.assertEqual(d["details"].get(k), v)
                self.assertNotIn("?", d["title"], "every title placeholder must be filled")
                self.assertNotRegex(d["evidence"] or "", r"exit(ed)? (with )?code")

    def test_titles_use_details(self):
        self.assertEqual(self.diag("gha-rust-compile.log")["title"], "Rust compile error E0425")
        self.assertEqual(self.diag("ado-agent-demands.log")["title"], "No agent in pool Linux-Build satisfies the job's demands")

    def test_specific_arm_code_beats_generic_deployment_failed(self):
        r = pt.triage((MORE / "ado-arm-quota.log").read_text(encoding="utf-8"), SIGS, pt.Redactor())
        self.assertEqual(r["diagnosis"]["id"], "arm-quota-or-sku")
        self.assertIn("arm-deployment-error", [o["id"] for o in r["other_signals"]])

    def test_generic_arm_error_still_diagnosed_alone(self):
        text = ("2026-09-27T10:00:00.0000000Z ##[section]Starting: Deploy\n"
                "2026-09-27T10:00:01.0000000Z ERROR: InvalidTemplateDeployment - The template deployment 'main' is not valid\n")
        self.assertEqual(pt.triage(text, SIGS, pt.Redactor())["diagnosis"]["id"], "arm-deployment-error")

    def test_maven_401_beats_generic_dependency_resolution(self):
        r = pt.triage((MORE / "ado-maven-401.log").read_text(encoding="utf-8"), SIGS, pt.Redactor())
        self.assertEqual(r["diagnosis"]["id"], "maven-repo-auth")

    def test_library_grew_by_at_least_ten(self):
        self.assertGreaterEqual(len(SIGS), 40 + 10)
        self.assertTrue(set(v[0] for v in MORE_EXPECTED.values()) <= {s["id"] for s in SIGS})


if __name__ == "__main__":
    unittest.main()

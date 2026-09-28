import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "plugins" / "ops-toolkit" / "skills" / "pipeline-doctor" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import pipeline_yaml_review as yr  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "pipelines" / "yaml"
WF = ".github/workflows/"


def line_of(rel, needle, nth=1):
    hits = [i for i, l in enumerate((FX / rel).read_text(encoding="utf-8").splitlines(), 1) if needle in l]
    return hits[nth - 1]


# (file, rule, severity, needle identifying the line)
EXPECTED = [
    ("azure-pipelines-bad.yml", "floating-image", "low", "vmImage: ubuntu-latest"),
    ("azure-pipelines-bad.yml", "plaintext-secret", "high", "sqlAdminPassword:"),
    ("azure-pipelines-bad.yml", "missing-timeout", "low", "- job: Build"),
    ("azure-pipelines-bad.yml", "legacy-peer-deps", "medium", "--legacy-peer-deps"),
    ("azure-pipelines-bad.yml", "set-plus-e", "medium", "set +e"),
    ("azure-pipelines-bad.yml", "swallowed-failure", "medium", "npm test || true"),
    ("azure-pipelines-bad.yml", "secret-echo", "high", 'echo "Connecting with'),
    ("azure-pipelines-bad.yml", "continue-on-error", "medium", "continueOnError: true"),
    ("azure-pipelines-bad.yml", "az-login-secret", "medium", "az login --service-principal"),
    ("azure-pipelines-bad.yml", "secret-in-command-line", "high", "az login --service-principal"),
    ("azure-pipelines-bad.yml", "no-verify", "medium", "--no-verify"),
    ("azure-pipelines-bad.yml", "secret-in-command-line", "high", "$(ArtifactsPat)"),
    ("azure-pipelines-list-vars.yml", "plaintext-secret", "high", "value: 'S3cure-but-committed'"),
    ("azure-pipelines-list-vars.yml", "missing-timeout", "low", "steps:"),
    (WF + "pr-target-bad.yml", "write-all-permissions", "medium", "permissions: write-all"),
    (WF + "pr-target-bad.yml", "plaintext-secret", "high", "NPM_TOKEN:"),
    (WF + "pr-target-bad.yml", "missing-timeout", "low", "  test:"),
    (WF + "pr-target-bad.yml", "floating-image", "low", "runs-on: ubuntu-latest"),
    (WF + "pr-target-bad.yml", "unpinned-action", "low", "actions/checkout@v4"),
    (WF + "pr-target-bad.yml", "pr-target-checkout", "high", "ref: ${{ github.event.pull_request.head.sha }}"),
    (WF + "pr-target-bad.yml", "unpinned-action", "medium", "actions/setup-node@main"),
    (WF + "pr-target-bad.yml", "unpinned-action", "medium", "tj-actions/changed-files@v45"),
    (WF + "pr-target-bad.yml", "swallowed-failure", "medium", "npx eslint . || true"),
    (WF + "pr-target-bad.yml", "continue-on-error", "medium", "continue-on-error: true"),
    (WF + "pr-target-bad.yml", "script-injection", "high", "github.event.pull_request.title"),
    (WF + "pr-target-bad.yml", "secret-echo", "high", "echo \"token is"),
    (WF + "pr-target-bad.yml", "secret-in-command-line", "high", "curl -H"),
    (WF + "pr-target-bad.yml", "unpinned-action", "medium", "azure/login@v2"),
    (WF + "pr-target-bad.yml", "az-login-secret", "medium", "creds:"),
    (WF + "nightly-missing-perms.yml", "missing-permissions", "medium", "on:"),
    (WF + "nightly-missing-perms.yml", "swallowed-failure", "medium", "trivy fs"),
]
CLEAN = ["azure-pipelines-good.yml", "azure-pipelines-suppressed.yml", WF + "ci-good.yml", WF + "label-job-perms.yml"]


class Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = yr.review([FX], base=FX)

    def test_discovery(self):
        self.assertEqual(self.res["files"], [WF + "ci-good.yml", WF + "label-job-perms.yml", WF + "nightly-missing-perms.yml",
                                             WF + "pr-target-bad.yml", "azure-pipelines-bad.yml", "azure-pipelines-good.yml",
                                             "azure-pipelines-list-vars.yml", "azure-pipelines-suppressed.yml"])
        self.assertNotIn("docker-compose.yml", self.res["files"])  # not a pipeline file

    def test_exact_findings_with_line_numbers(self):
        want = sorted((f, line_of(f, needle), rule, sev) for f, rule, sev, needle in EXPECTED)
        got = sorted((x["file"], x["line"], x["rule"], x["severity"]) for x in self.res["findings"])
        self.assertEqual(got, want)

    def test_clean_files_have_no_findings(self):
        for f in CLEAN:
            with self.subTest(f):
                self.assertEqual([x for x in self.res["findings"] if x["file"] == f], [])

    def test_summary(self):
        s = self.res["summary"]
        self.assertEqual(s, {sev: sum(1 for e in EXPECTED if e[2] == sev) for sev in ("high", "medium", "low")})

    def test_every_rule_fires_somewhere_and_has_text(self):
        fired = {x["rule"] for x in self.res["findings"]}
        self.assertEqual(fired, set(yr.RULES))
        for x in self.res["findings"]:
            self.assertTrue(x["why"] and x["fix"] and x["category"] in ("security", "reliability", "reproducibility"))
            self.assertIn(x["platform"], ("azure", "github"))

    def test_secret_values_never_shown(self):
        blob = json.dumps(self.res) + yr.to_markdown(self.res)
        for secret in ("Winter2026!Orders", "S3cure-but-committed", "npm_AbCdEf123456GhIjKl7890"):
            self.assertNotIn(secret, blob)
        ev = {x["evidence"] for x in self.res["findings"] if x["rule"] == "plaintext-secret"}
        self.assertEqual(ev, {"sqlAdminPassword: <redacted>", "DbPassword value: <redacted>", "NPM_TOKEN: <redacted>"})

    def test_unpinned_fix_names_the_action(self):
        f = next(x for x in self.res["findings"] if x["rule"] == "unpinned-action" and "changed-files" in x["evidence"])
        self.assertIn("tj-actions/changed-files@<sha> # v45", f["fix"])

    def test_markdown(self):
        md = yr.to_markdown(self.res)
        self.assertIn("# Pipeline Doctor - YAML health check", md)
        self.assertIn("### `pr-target-checkout` (high", md)
        self.assertIn("propose the fixes as a pull request", md)


def review(text, name="azure-pipelines.yml"):
    return [(f["rule"], f["line"]) for f in yr.review_text(text, name)]


class Negatives(unittest.TestCase):
    """Should-not-fire cases next to their should-fire twins."""

    def test_pinned_and_local_actions(self):
        text = ("on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n"
                "    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
                "      - uses: ./.github/actions/setup\n      - uses: docker://alpine:3.20\n")
        self.assertEqual(review(text, ".github/workflows/x.yml"), [])
        self.assertEqual(review(text.replace("@11bd71901bbe5b1630ceea73d27597364c9af683", "@v4"), ".github/workflows/x.yml"),
                         [("unpinned-action", 9)])

    def test_pr_target_without_head_checkout(self):
        base = ("on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n"
                "    timeout-minutes: 5\n    steps:\n      - run: echo labelling\n")
        self.assertEqual(review(base, ".github/workflows/x.yml"), [])
        risky = base.replace("echo labelling", "git checkout ${{ github.head_ref }}")
        self.assertIn(("pr-target-checkout", 9), review(risky, ".github/workflows/x.yml"))

    def test_plain_push_with_head_ref_is_not_pr_target(self):
        text = ("on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n"
                "    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n"
                "          ref: ${{ github.event.pull_request.head.sha }}\n")
        self.assertEqual(review(text, ".github/workflows/x.yml"), [])

    def test_script_lines_only(self):
        # 'set +e', '|| true' and '--no-verify' inside a displayName or comment are not script code
        text = ("trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n"
                "      - script: echo ok  # npm test || true, set +e, --no-verify\n        displayName: 'set +e demo'\n")
        self.assertEqual(review(text), [])

    def test_comment_hash_inside_quotes_kept(self):
        lines = yr.model('- script: echo "a # b" --no-verify\n')
        self.assertIn("--no-verify", lines[0]["value"])

    def test_block_scalar_model(self):
        lines = yr.model("steps:\n  - bash: |\n      set +e\n      echo done\n    displayName: x\n")
        self.assertEqual([l["kind"] for l in lines], ["key", "item", "block", "block", "key"])
        self.assertEqual([l["script"] for l in lines], [False, False, True, True, False])
        self.assertEqual(lines[4]["parents"], ("steps",))

    def test_masked_secret_and_env_mapping(self):
        text = ("trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n"
                "      - script: echo \"##vso[task.setvariable variable=t;issecret=true]$(RawToken)\"\n"
                "      - script: ./deploy.sh\n        env:\n          TOKEN: $(DeployToken)\n")
        self.assertEqual(review(text), [])

    def test_env_var_echo_is_secret_echo(self):
        text = "trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n      - script: echo $DB_PASSWORD\n"
        self.assertEqual(review(text), [("secret-echo", 6)])

    def test_az_login_federated_is_fine(self):
        ok = ("trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n"
              "      - script: az login --service-principal -u $(ClientId) --tenant $(TenantId) --federated-token \"$(cat $TOKEN_FILE)\"\n")
        self.assertEqual(review(ok), [])

    def test_continue_on_error_non_test_step(self):
        text = ("trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n"
                "      - script: ./notify-slack.sh\n        continueOnError: true\n"
                "      - script: npm audit --audit-level=high\n        continueOnError: true\n")
        self.assertEqual(review(text), [("continue-on-error", 9)])

    def test_set_plus_e_and_powershell_preference(self):
        text = ("trigger: none\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n      - pwsh: |\n"
                "          $ErrorActionPreference = 'SilentlyContinue'\n          Invoke-Build\n")
        self.assertEqual(review(text), [("set-plus-e", 7)])

    def test_template_needs_no_timeout(self):
        self.assertEqual(review((FX / "steps-template.yml").read_text(encoding="utf-8"), "steps-template.yml"), [])

    def test_reusable_workflow_job_needs_no_timeout(self):
        text = "on: push\npermissions:\n  contents: read\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n"
        self.assertEqual(review(text, ".github/workflows/x.yml"), [])

    def test_all_jobs_with_permissions(self):
        text = ("on: push\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    permissions:\n      contents: read\n"
                "  b:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n")
        self.assertEqual(review(text, ".github/workflows/x.yml"), [("missing-permissions", 1)])
        fixed = text.replace("      - run: echo hi\n", "      - run: echo hi\n    permissions:\n      contents: read\n")
        self.assertEqual(review(fixed, ".github/workflows/x.yml"), [])

    def test_secret_like_names_with_references_or_non_secret_names(self):
        text = ("trigger: none\nvariables:\n  apiKeyName: orders-api-key\n  tokenAudience: api://orders\n  sqlPassword: $(fromVault)\n"
                "  sonarToken: ''\njobs:\n  - job: A\n    timeoutInMinutes: 5\n    steps:\n      - script: echo hi\n")
        self.assertEqual(review(text), [])
        self.assertEqual(review(text.replace("sqlPassword: $(fromVault)", "sqlPassword: hunter2-prod")), [("plaintext-secret", 5)])

    def test_suppression_comment(self):
        text = (FX / "azure-pipelines-suppressed.yml").read_text(encoding="utf-8")
        self.assertEqual(review(text), [])
        stripped = "\n".join(l.split("  # pipeline-doctor")[0] for l in text.splitlines() if "# pipeline-doctor" not in l.strip()[:20]) + "\n"
        self.assertEqual(sorted(r for r, _ in review(stripped)), ["floating-image", "missing-timeout"])


class Cli(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "pipeline_yaml_review.py"), *args],
                              capture_output=True, text=True, encoding="utf-8", timeout=60)

    def test_json_deterministic_and_shape(self):
        a, b = self.cli(str(FX), "--json"), self.cli(str(FX), "--json")
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        doc = json.loads(a.stdout)
        self.assertEqual(set(doc), {"files", "summary", "findings"})
        self.assertEqual(set(doc["findings"][0]), {"rule", "severity", "category", "file", "line", "platform", "evidence", "why", "fix"})

    def test_fail_on(self):
        self.assertEqual(self.cli(str(FX / "azure-pipelines-bad.yml"), "--fail-on", "high").returncode, 1)
        self.assertEqual(self.cli(str(FX / "azure-pipelines-good.yml"), "--fail-on", "low").returncode, 0)
        self.assertEqual(self.cli(str(FX / "azure-pipelines-list-vars.yml")).returncode, 0)


if __name__ == "__main__":
    unittest.main()

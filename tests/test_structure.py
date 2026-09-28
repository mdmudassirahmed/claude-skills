"""Repository-level checks: marketplace/plugins are consistent, every skill is self-contained
and works when installed on its own, builds and analysers are idempotent, and the
repository stays generic."""
import filecmp
import json
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGINS = ROOT / "plugins"
FX = ROOT / "tests" / "fixtures"
MARKET = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
SKILLS = sorted(p.name for p in (ROOT / "src" / "skills").iterdir() if p.is_dir())
CLOUD_SKILLS = {"cloud-cost-scout", "log-detective", "pipeline-doctor"}

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def frontmatter(path):
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, f"{path}: missing YAML frontmatter"
    if yaml:
        return yaml.safe_load(m.group(1)), text[m.end():]
    meta = dict(line.split(":", 1) for line in m.group(1).splitlines() if ":" in line)
    return {k.strip(): v.strip() for k, v in meta.items()}, text[m.end():]


class Marketplace(unittest.TestCase):
    def test_bundle_plus_one_plugin_per_skill(self):
        self.assertEqual(sorted(e["name"] for e in MARKET["plugins"]), sorted(["ops-toolkit", *SKILLS]))

    def test_entries_match_plugin_json(self):
        for e in MARKET["plugins"]:
            with self.subTest(e["name"]):
                self.assertEqual(e["source"], f"./plugins/{e['name']}")
                pj = json.loads((ROOT / e["source"] / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
                self.assertEqual(pj["name"], e["name"])
                self.assertEqual(pj["version"], e["version"])
                self.assertEqual(pj["description"], e["description"])
                self.assertEqual(pj["version"], (ROOT / "VERSION").read_text().strip())

    def test_hooks_only_where_the_cloud_is_touched(self):
        for e in MARKET["plugins"]:
            has_hooks = (ROOT / e["source"] / "hooks" / "hooks.json").exists()
            skills = {p.name for p in (ROOT / e["source"] / "skills").iterdir()}
            self.assertEqual(has_hooks, bool(skills & CLOUD_SKILLS), e["name"])

    def test_build_is_up_to_date_and_idempotent(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "build.py"), "--check"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class Skills(unittest.TestCase):
    def skill_dirs(self):
        return sorted(PLUGINS.glob("*/skills/*"))

    def test_frontmatter(self):
        for d in self.skill_dirs():
            with self.subTest(str(d.relative_to(ROOT))):
                meta, body = frontmatter(d / "SKILL.md")
                self.assertIsInstance(meta, dict, "frontmatter must be valid YAML")
                self.assertEqual(meta["name"], d.name)
                self.assertRegex(meta["name"], r"^[a-z0-9-]{1,64}$")
                self.assertTrue(80 < len(meta["description"]) <= 1024)
                self.assertGreater(len(body.split()), 200)

    def test_referenced_files_exist_inside_the_skill(self):
        for d in self.skill_dirs():
            _, body = frontmatter(d / "SKILL.md")
            for ref in set(re.findall(r"`((?:references|scripts)/[\w./-]+)`", body)):
                with self.subTest(skill=d.name, ref=ref):
                    self.assertTrue((d / ref).exists(), f"{d.name}: {ref} referenced but missing")
            for script in set(re.findall(r"<skill-dir>/scripts/([\w.-]+\.py)", body)):
                self.assertTrue((d / "scripts" / script).exists(), f"{d.name}: scripts/{script} missing")

    def test_scripts_only_import_stdlib_or_siblings(self):
        stdlib = {"argparse", "csv", "io", "json", "os", "re", "sys", "statistics", "datetime", "pathlib"}
        for f in PLUGINS.glob("*/skills/*/scripts/*.py"):
            mods = set(re.findall(r"^\s*(?:from|import) (\w+)", f.read_text(encoding="utf-8"), re.M))
            siblings = {p.stem for p in f.parent.glob("*.py")}
            self.assertEqual(mods - stdlib - siblings, set(), f"{f.relative_to(ROOT)}")

    def test_python_compiles(self):
        for f in list(PLUGINS.rglob("*.py")) + list((ROOT / "tools").glob("*.py")):
            py_compile.compile(str(f), doraise=True)


class StandaloneInstall(unittest.TestCase):
    """Copy ONE skill folder somewhere else (as a manual install would) and run it."""

    def run_alone(self, skill, script, args):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / skill
            shutil.copytree(PLUGINS / skill / "skills" / skill, dest)
            return subprocess.run([sys.executable, str(dest / "scripts" / script), *args],
                                  capture_output=True, text=True, encoding="utf-8", timeout=120)

    def test_cost_scout_alone(self):
        r = self.run_alone("cloud-cost-scout", "cost_scout.py",
                           [str(FX / "cost" / "aws-account"), "--json", "--as-of", "2026-09-27"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["finding_count"], 5)  # needs references/aws-approx-prices.json

    def test_log_detective_alone(self):
        r = self.run_alone("log-detective", "log_detective.py", [str(FX / "logs" / "text-python-traceback"), "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["verdict_hint"], "error-spike")

    def test_pipeline_doctor_alone(self):
        r = self.run_alone("pipeline-doctor", "pipeline_triage.py",
                           [str(FX / "pipelines" / "ado-npm-eresolve.log"), "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)[0]["diagnosis"]["id"], "npm-eresolve")


class Idempotency(unittest.TestCase):
    """Same input, run twice into the same output directory -> byte-identical results."""

    def twice(self, script, args):
        with tempfile.TemporaryDirectory() as tmp:
            snaps = []
            for i in range(2):
                out = Path(tmp) / "report"
                r = subprocess.run([sys.executable, str(script), *args, "--out-dir", str(out)],
                                   capture_output=True, text=True, encoding="utf-8", timeout=120)
                self.assertEqual(r.returncode, 0, r.stderr)
                snap = Path(tmp) / f"run{i}"
                shutil.copytree(out, snap)
                snaps.append(snap)
            cmp = filecmp.dircmp(snaps[0], snaps[1])
            self.assertEqual(cmp.diff_files, [], "second run produced different output")
            self.assertEqual(cmp.left_only + cmp.right_only, [])

    def test_cost_scout(self):
        s = PLUGINS / "ops-toolkit" / "skills" / "cloud-cost-scout" / "scripts" / "cost_scout.py"
        self.twice(s, [str(FX / "cost" / "azure-dev-subscription"), "--as-of", "2026-09-27"])

    def test_log_detective(self):
        s = PLUGINS / "ops-toolkit" / "skills" / "log-detective" / "scripts" / "log_detective.py"
        d = FX / "logs" / "appinsights-nullref-after-deploy"
        self.twice(s, [str(d), "--deploys", str(d / "deploys.txt")])


class Hygiene(unittest.TestCase):
    FORBIDDEN = re.compile(r"deloitte|concerto|\bS20\b|GP&S|\bOGC\b|mudmohammad", re.I)
    # AI-tool attribution lines, the robot emoji, and em dashes don't belong in this repo's text
    WATERMARKS = re.compile("generated with|co-authored-by|noreply@anthropic|\U0001F916|—", re.I)

    def repo_files(self):
        skip = {".git", "__pycache__", ".pytest_cache", "node_modules"}
        for p in ROOT.rglob("*"):
            if p.is_file() and not skip & set(p.parts) and p.suffix != ".pyc":
                yield p

    def test_generic_no_employer_or_internal_names(self):
        hits = []
        for p in self.repo_files():
            if p.name == "test_structure.py":
                continue
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if self.FORBIDDEN.search(line):
                    hits.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:80]}")
        self.assertEqual(hits, [])

    def test_no_ai_watermarks_or_em_dashes(self):
        hits = []
        for p in self.repo_files():
            if p.name == "test_structure.py" or "fixtures" in p.parts:
                continue
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if self.WATERMARKS.search(line):
                    hits.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:80]}")
        self.assertEqual(hits, [])

    def test_no_hidden_control_characters(self):
        for p in list(PLUGINS.rglob("*.py")) + list((ROOT / "src").rglob("*.py")) + list((ROOT / "tools").glob("*.py")):
            bad = [i for i, ch in enumerate(p.read_text(encoding="utf-8")) if ord(ch) < 32 and ch not in "\n\t\r"]
            self.assertEqual(bad, [], f"{p.relative_to(ROOT)} has control characters")

    def test_readme_images_exist(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        images = re.findall(r'src="(docs/images/[^"]+)"', readme)
        self.assertGreaterEqual(len(images), 4)
        for img in images:
            self.assertTrue((ROOT / img).exists(), img)

    def test_shell_scripts_forced_to_lf(self):
        attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertRegex(attrs, r"\*\.sh\s+text\s+eol=lf")
        for sh in PLUGINS.rglob("*.sh"):
            self.assertNotIn(b"\r\n", sh.read_bytes(), sh.name)

    def test_no_private_keys_or_tokens_in_repo(self):
        for p in self.repo_files():
            t = p.read_text(encoding="utf-8", errors="ignore")
            # a real key has a long base64 body; test inputs use short fakes
            self.assertIsNone(re.search(r"PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{100,}", t), p.name)
            self.assertIsNone(re.search(r"\bgh[pousr]_[A-Za-z0-9]{36}\b", t), p.name)


if __name__ == "__main__":
    unittest.main()

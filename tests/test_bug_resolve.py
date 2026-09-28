"""bug-resolve helpers: find_similar.py (same bug elsewhere) and fix_report.py (report + proof check)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "plugins" / "ops-toolkit" / "skills" / "bug-resolve"
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))
import find_similar as fs  # noqa: E402
import fix_report as fr  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "bugs"
REPO = FX / "repo"
OUT = FX / "outputs"


def line_of(rel, snippet, nth=1):
    """1-based line number of the nth line in a fixture file containing snippet."""
    seen = 0
    for i, line in enumerate((REPO / rel).read_text(encoding="utf-8").split("\n"), 1):
        if snippet in line:
            seen += 1
            if seen == nth:
                return i
    raise AssertionError(f"{snippet!r} not in {rel}")


def hits(report):
    return {(f["path"], m["line"]) for f in report["files"] for m in f["matches"]}


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


def out(name):
    return (OUT / name).read_text(encoding="utf-8")


# =============================================================================================
# find_similar: presets, positive and negative
# =============================================================================================

class Presets(unittest.TestCase):
    def scan(self, preset, **kw):
        return fs.search(str(REPO), preset=preset, **kw)

    def assertExactly(self, report, expected):
        self.assertEqual(hits(report), set(expected))
        self.assertEqual(report["summary"]["match_count"], len(expected))

    def test_python_dict_key_access(self):
        r = self.scan("python-dict-key-access")
        self.assertExactly(r, {
            ("src/pricing.py", line_of("src/pricing.py", 'market["currency"]')),
            ("src/pricing.py", line_of("src/pricing.py", 'if order["region"]')),
            ("src/reports.py", line_of("src/reports.py", 'data["title"]')),
            ("src/reports.py", line_of("src/reports.py", 'os.environ["HOME"]')),
            ("src/reports.py", line_of("src/reports.py", 'data["currency"]')),
        })
        # negatives: Literal[...] typing, assignment target, .get(), list literal, comment line
        got = hits(r)
        for path, snippet in (("src/pricing.py", 'Literal["fast"]'), ("src/pricing.py", 'order["status"] ='),
                              ("src/pricing.py", "market.get("), ("src/reports.py", 'items = ["a"'),
                              ("src/pricing.py", '# order["comment"]')):
            self.assertNotIn((path, line_of(path, snippet)), got, snippet)

    def test_python_bare_except(self):
        r = self.scan("python-bare-except")
        self.assertExactly(r, {("src/pricing.py", line_of("src/pricing.py", "except:"))})
        self.assertEqual(r["files"][0]["matches"][0]["match"], "except:")

    def test_python_mutable_default_arg(self):
        r = self.scan("python-mutable-default-arg")
        self.assertExactly(r, {("src/pricing.py", line_of("src/pricing.py", "basket=[]")),
                               ("src/reports.py", line_of("src/reports.py", "store={}"))})
        self.assertEqual(sorted(m["match"] for f in r["files"] for m in f["matches"]), ["basket=[]", "store={}"])
        # None / tuple defaults are fine
        self.assertNotIn(("src/pricing.py", line_of("src/pricing.py", "basket=None")), hits(r))

    def test_csharp_nullable_value(self):
        r = self.scan("csharp-nullable-value")
        cs, inv = "src/Orders/OrderService.cs", "src/Billing/Invoice.cs"
        self.assertExactly(r, {
            (cs, line_of(cs, "order.Discount.Value;")),
            (inv, line_of(inv, "other.PaidOn.Value")),
            (inv, line_of(inv, "days.Value")),
        })
        got = hits(r)
        self.assertNotIn((cs, line_of(cs, "price - order.Discount.Value")), got, "guarded by HasValue above")
        self.assertNotIn((cs, line_of(cs, "pair.Value")), got, "KeyValuePair.Value is not Nullable")
        self.assertNotIn((inv, line_of(inv, "(n != null)")), got, "guarded on the same line")
        self.assertNotIn((inv, line_of(inv, "lazy.Value")), got)

    def test_csharp_async_void(self):
        cs = "src/Orders/OrderService.cs"
        self.assertExactly(self.scan("csharp-async-void"), {(cs, line_of(cs, "async void Refresh"))})

    def test_csharp_first_without_default(self):
        cs, inv = "src/Orders/OrderService.cs", "src/Billing/Invoice.cs"
        self.assertExactly(self.scan("csharp-first-without-default"), {
            (cs, line_of(cs, "order.Tags.First()", 1)),
            (inv, line_of(inv, "list.Single(")),
        })

    def test_ts_non_null_assertion(self):
        ts = "src/web/user.ts"
        r = self.scan("js-ts-non-null-assertion")
        self.assertExactly(r, {(ts, line_of(ts, "user!.name")), (ts, line_of(ts, "name!;")),
                               (ts, line_of(ts, "parseInt(user!.age"))})
        self.assertNotIn((ts, line_of(ts, "let later!")), hits(r), "definite assignment is not an assertion")
        self.assertNotIn((ts, line_of(ts, "!==")), hits(r))

    def test_js_loose_equality(self):
        ts, js = "src/web/user.ts", "src/web/legacy.js"
        r = self.scan("js-loose-equality")
        self.assertExactly(r, {(ts, line_of(ts, "user.age == 18")), (js, line_of(js, "n == 0"))})
        matches = {m["match"] for f in r["files"] for m in f["matches"]}
        self.assertIn("user.age == 18", matches)
        self.assertNotIn("user != null", matches)
        self.assertNotIn((ts, line_of(ts, "typeof user ==")), hits(r))
        self.assertNotIn((js, line_of(js, "input == null")), hits(r))

    def test_js_parseint_no_radix(self):
        ts, js = "src/web/user.ts", "src/web/legacy.js"
        self.assertExactly(self.scan("js-parseInt-no-radix"), {
            (ts, line_of(ts, "parseInt(user!.age")),
            (ts, line_of(ts, "Number.parseInt(String")),
            (js, line_of(js, "parseInt(input);")),
        })

    def test_java_optional_get(self):
        j = "src/main/java/shop/UserService.java"
        r = self.scan("java-optional-get")
        self.assertExactly(r, {(j, line_of(j, "findNickname(id).get()")), (j, line_of(j, "findById(id).get()")),
                               (j, line_of(j, "other.get()"))})
        self.assertNotIn((j, line_of(j, "nick.get()")), hits(r), "guarded by isPresent()")
        self.assertNotIn((j, line_of(j, "supplier.get()")), hits(r), "Supplier.get is not Optional")

    def test_java_equals_on_strings(self):
        j = "src/main/java/shop/UserService.java"
        r = self.scan("java-equals-on-strings")
        self.assertExactly(r, {(j, line_of(j, 'role == "admin"')), (j, line_of(j, "name == role"))})
        self.assertNotIn((j, line_of(j, "return a == b")), hits(r))
        self.assertNotIn("role != null", {m["match"] for f in r["files"] for m in f["matches"]})

    def test_sql_string_concat(self):
        r = self.scan("sql-string-concat")
        cs, j, py = "src/Orders/OrderService.cs", "src/main/java/shop/UserService.java", "src/reports.py"
        self.assertExactly(r, {
            ("db/procs/search.sql", line_of("db/procs/search.sql", "    SET @sql")),
            ("db/procs/oracle_search.sql", line_of("db/procs/oracle_search.sql", "|| p_name ||")),
            (cs, line_of(cs, "            var sql = ")), (cs, line_of(cs, "var sql2 = $")),
            (j, line_of(j, "String sql = ")), (j, line_of(j, "String.format(")),
            (py, line_of(py, '" + str(user_id)')), (py, line_of(py, "f\"SELECT")), (py, line_of(py, '" % user_id')),
            ("src/web/db.ts", line_of("src/web/db.ts", "${id}")),
        })
        got = hits(r)
        for path, snippet in ((py, '%s", (user_id,)'), (py, "Tell us where"), (cs, "new SqlCommand("),
                              (j, "prepareStatement("), ("src/web/db.ts", "$1"),
                              ("db/procs/search.sql", "sp_executesql"), ("db/procs/search.sql", "-- dynamic"),
                              ("db/procs/oracle_search.sql", "USING p_name"), (cs, "// var sql")):
            self.assertNotIn((path, line_of(path, snippet)), got, snippet)

    def test_every_preset_is_documented(self):
        self.assertEqual(len(fs.PRESETS), 12)
        for p in fs.PRESETS:
            d = p.describe()
            self.assertTrue(d["languages"] and len(d["catches"]) > 30 and len(d["false_positives"]) > 10, p.name)
        r = run("find_similar.py", "--list-presets", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([p["name"] for p in json.loads(r.stdout)], [p.name for p in fs.PRESETS])
        md = run("find_similar.py", "--list-presets").stdout
        self.assertIn("| `sql-string-concat` |", md)

    def test_presets_are_documented_in_skill_md(self):
        body = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for p in fs.PRESETS:
            self.assertIn(f"`{p.name}`", body)


# =============================================================================================
# find_similar: exclusions, tests, languages
# =============================================================================================

class Exclusions(unittest.TestCase):
    VENDOR = ("node_modules/", "bin/", "obj/", "dist/", "build/", "target/")

    def all_paths(self, include_tests):
        paths = set()
        for p in fs.PRESETS:
            paths |= {f["path"] for f in fs.search(str(REPO), preset=p.name, include_tests=include_tests)["files"]}
        paths |= {f["path"] for f in fs.search(str(REPO), pattern=r".", include_tests=include_tests)["files"]}
        return paths

    def test_vendor_and_build_dirs_are_never_scanned(self):
        for include_tests in (False, True):
            for path in self.all_paths(include_tests):
                self.assertFalse(path.startswith(self.VENDOR), path)

    def test_fixture_vendor_dirs_really_contain_bugs(self):
        # guard against a vacuous test: the ignored folders do contain matching code
        self.assertIn("parseInt(n)", (REPO / "node_modules/leftpad/index.js").read_text(encoding="utf-8"))
        self.assertIn("Discount.Value", (REPO / "bin/Debug/Generated.cs").read_text(encoding="utf-8"))

    def test_tests_excluded_by_default_and_included_on_request(self):
        test_files = {"tests/pricing_checks.py", "tests/Shop.Tests/OrderServiceTests.cs", "src/web/user.test.ts",
                      "src/test/java/shop/UserServiceTest.java"}
        self.assertEqual(self.all_paths(False) & test_files, set())
        self.assertEqual(self.all_paths(True) & test_files, test_files)
        r = fs.search(str(REPO), preset="python-dict-key-access", include_tests=True)
        self.assertIn(("tests/pricing_checks.py", 6), hits(r))
        self.assertEqual(r["summary"]["match_count"], 6)

    def test_is_test_path(self):
        for p in ("tests/a.py", "tests/pricing_checks.py", "src/test_x.py", "src/x_test.py", "conftest.py", "a/b.spec.ts", "a/b.test.jsx",
                  "Shop.Tests/Foo.cs", "Shop.UnitTests/Foo.cs", "src/FooTests.cs", "src/FooTest.java",
                  "pkg/x_test.go", "web/__tests__/x.js", "src/FooIT.java"):
            self.assertTrue(fs.is_test_path(p), p)
        for p in ("src/pricing.py", "src/contest.py", "src/Latest.cs", "src/protest.ts", "src/attestation.py",
                  "src/Manifest.java"):
            self.assertFalse(fs.is_test_path(p), p)

    def test_dynamic_ignored_dirs_and_extra_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (".venv/lib/x.py", "venv/y.py", "__pycache__/z.py", ".terraform/m.py", ".git/hooks/h.py",
                        "generated/g.py", "app/main.py"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text('v = d["k"]\n', encoding="utf-8")
            r = fs.search(tmp, preset="python-dict-key-access", exclude_dirs=["generated"])
            self.assertEqual([f["path"] for f in r["files"]], ["app/main.py"])
            r = run("find_similar.py", tmp, "--preset", "python-dict-key-access", "--json",
                    "--exclude-dir", "generated")
            self.assertEqual([f["path"] for f in json.loads(r.stdout)["files"]], ["app/main.py"])

    def test_language_detection_and_filter(self):
        r = fs.search(str(REPO), pattern=r"SELECT \* FROM", include_tests=False)
        langs = {f["path"]: f["language"] for f in r["files"]}
        self.assertEqual(langs["src/reports.py"], "python")
        self.assertEqual(langs["src/Orders/OrderService.cs"], "csharp")
        self.assertEqual(langs["src/web/db.ts"], "typescript")
        self.assertEqual(langs["src/main/java/shop/UserService.java"], "java")
        self.assertEqual(langs["db/procs/search.sql"], "sql")
        only = fs.search(str(REPO), pattern=r"SELECT \* FROM", languages=["sql"])
        self.assertEqual({f["language"] for f in only["files"]}, {"sql"})
        with self.assertRaises(ValueError):
            fs.search(str(REPO), pattern="x", languages=["cobol"])

    def test_binary_and_crlf_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "win.py").write_bytes(b'a = 1\r\nb = d["k"]\r\nc = 2\r\n')
            Path(tmp, "blob.py").write_bytes(b'\x00\x01d["k"]')
            r = fs.search(tmp, preset="python-dict-key-access")
            self.assertEqual(hits(r), {("win.py", 2)})
            self.assertEqual(r["files"][0]["matches"][0]["text"], 'b = d["k"]')
            self.assertEqual(r["summary"]["files_skipped"], 1)


# =============================================================================================
# find_similar: --pattern and --like
# =============================================================================================

class PatternAndLike(unittest.TestCase):
    def test_pattern_scans_comments_but_presets_do_not(self):
        cs = "src/Orders/OrderService.cs"
        comment = (cs, line_of(cs, "// var sql"))
        self.assertIn(comment, hits(fs.search(str(REPO), pattern=r"SELECT \* FROM Customers")))
        self.assertNotIn(comment, hits(fs.search(str(REPO), preset="sql-string-concat")))

    def test_pattern_with_lookaround_matches_line_by_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text("x = foo\nbar\ny = foo\nbaz\n", encoding="utf-8")
            r = fs.search(tmp, pattern=r"foo(?!\s*bar)")
            self.assertEqual(hits(r), {("a.py", 1), ("a.py", 3)}, "each line is matched on its own")
            r = fs.search(tmp, pattern=r"foo\s*$")
            self.assertEqual(hits(r), {("a.py", 1), ("a.py", 3)})

    def test_pattern_ignore_case_and_bad_regex(self):
        self.assertTrue(fs.search(str(REPO), pattern=r"select \* from", ignore_case=True)["files"])
        self.assertFalse(fs.search(str(REPO), pattern=r"select \* from customers where")["files"])
        r = run("find_similar.py", REPO, "--pattern", "([")
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid --pattern", r.stderr)

    def test_like_python_dict_key(self):
        ln = line_of("src/pricing.py", 'market["currency"]')
        r = fs.search(str(REPO), like=f"src/pricing.py:{ln}")
        self.assertEqual(r["like"]["bug_class"], "python-dict-key-access")
        self.assertEqual(r["like"]["expression"], 'market["currency"]')
        self.assertEqual(r["query"]["preset"], "python-dict-key-access")
        self.assertEqual(r["summary"]["match_count"], 5)
        self.assertEqual(r["summary"]["elsewhere_count"], 4)
        origin = [(f["path"], m["line"]) for f in r["files"] for m in f["matches"] if m["origin"]]
        self.assertEqual(origin, [("src/pricing.py", ln)])

    def test_like_python_strict_same_key_only(self):
        ln = line_of("src/pricing.py", 'market["currency"]')
        r = fs.search(str(REPO), like=f"src/pricing.py:{ln}", strict=True)
        self.assertTrue(r["like"]["strict_applied"])
        self.assertIn("currency", r["like"]["pattern"])
        self.assertEqual(hits(r), {("src/pricing.py", ln), ("src/reports.py", line_of("src/reports.py", 'data["currency"]'))})
        with_tests = fs.search(str(REPO), like=f"src/pricing.py:{ln}", strict=True, include_tests=True)
        self.assertIn(("tests/pricing_checks.py", 6), hits(with_tests))

    def test_like_csharp_nullable_value(self):
        cs = "src/Orders/OrderService.cs"
        ln = line_of(cs, "order.Discount.Value;")
        r = fs.search(str(REPO), like=f"{cs}:{ln}")
        self.assertEqual(r["like"]["bug_class"], "csharp-nullable-value")
        self.assertEqual(r["like"]["expression"], "Discount.Value")
        self.assertEqual(r["summary"]["match_count"], 3)
        strict = fs.search(str(REPO), like=f"{cs}:{ln}", strict=True)
        self.assertEqual(hits(strict), {(cs, ln), (cs, line_of(cs, "price - order.Discount.Value"))})

    def test_like_csharp_first_and_async_void(self):
        cs = "src/Orders/OrderService.cs"
        r = fs.search(str(REPO), like=f"{cs}:{line_of(cs, 'order.Tags.First()')}")
        self.assertEqual(r["like"]["bug_class"], "csharp-first-without-default")
        r = fs.search(str(REPO), like=f"{cs}:{line_of(cs, 'async void Refresh')}")
        self.assertEqual(r["like"]["bug_class"], "csharp-async-void")

    def test_like_typescript_non_null(self):
        ts = "src/web/user.ts"
        ln = line_of(ts, "user!.name")
        r = fs.search(str(REPO), like=f"{ts}:{ln}")
        self.assertEqual(r["like"]["bug_class"], "js-ts-non-null-assertion")
        self.assertEqual(r["like"]["expression"], "user!")
        self.assertEqual(r["summary"]["match_count"], 3)
        strict = fs.search(str(REPO), like=f"{ts}:{ln}", strict=True)
        self.assertEqual(hits(strict), {(ts, ln), (ts, line_of(ts, "parseInt(user!.age"))})

    def test_like_js_loose_equality_and_parseint(self):
        js = "src/web/legacy.js"
        r = fs.search(str(REPO), like=f"{js}:{line_of(js, 'n == 0')}")
        self.assertEqual((r["like"]["bug_class"], r["like"]["expression"]), ("js-loose-equality", "n == 0"))
        self.assertEqual(r["query"]["languages"], ["javascript", "typescript"])
        r = fs.search(str(REPO), like=f"{js}:{line_of(js, 'parseInt(input);')}")
        self.assertEqual(r["like"]["bug_class"], "js-parseInt-no-radix")
        self.assertEqual(r["summary"]["match_count"], 3)

    def test_like_java_optional_and_sql(self):
        j = "src/main/java/shop/UserService.java"
        r = fs.search(str(REPO), like=f"{j}:{line_of(j, 'findNickname(id).get()')}")
        self.assertEqual(r["like"]["bug_class"], "java-optional-get")
        self.assertEqual(r["summary"]["match_count"], 3)
        r = fs.search(str(REPO), like=f"db/procs/search.sql:{line_of('db/procs/search.sql', '    SET @sql')}")
        self.assertEqual(r["like"]["bug_class"], "sql-string-concat")
        self.assertEqual(r["summary"]["match_count"], 10, "SQL concatenation is searched across all languages")
        self.assertFalse(r["like"]["strict_applied"])

    def test_like_learns_receivers_the_preset_could_not_know(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "A.cs").write_text("class A {\n  int F(Box b) { return b.Count.Value; }\n"
                                         "  int G(Box c) { return c.Count.Value; }\n}\n", encoding="utf-8")
            self.assertEqual(fs.search(tmp, preset="csharp-nullable-value")["summary"]["match_count"], 0)
            r = fs.search(tmp, like="A.cs:2")
            self.assertEqual(hits(r), {("A.cs", 2), ("A.cs", 3)})

    def test_like_literal_fallback(self):
        ln = line_of("src/pricing.py", "return amount * rate, currency")
        r = fs.search(str(REPO), like=f"src/pricing.py:{ln}")
        self.assertEqual(r["like"]["bug_class"], "literal")
        self.assertIn(r"\s+", r["like"]["pattern"])
        self.assertEqual(hits(r), {("src/pricing.py", ln)})

    def test_like_accepts_path_relative_to_cwd(self):
        ln = line_of("src/pricing.py", 'market["currency"]')
        r = fs.search(str(REPO), like=f"{REPO / 'src' / 'pricing.py'}:{ln}")
        self.assertEqual(r["like"]["file"], "src/pricing.py")
        self.assertEqual(r["summary"]["elsewhere_count"], 4)

    def test_like_errors(self):
        for spec in ("src/pricing.py", "src/nope.py:3", "src/pricing.py:9999", "db/procs/x.txt:1"):
            r = run("find_similar.py", REPO, "--like", spec)
            self.assertEqual(r.returncode, 2, spec)
            self.assertTrue(r.stderr.startswith("find_similar:"), r.stderr)
        r = run("find_similar.py", REPO, "--preset", "no-such-preset")
        self.assertEqual(r.returncode, 2)
        r = run("find_similar.py", REPO)
        self.assertEqual(r.returncode, 2)


# =============================================================================================
# find_similar: output shape, caps, determinism, markdown
# =============================================================================================

class Output(unittest.TestCase):
    def test_json_shape(self):
        r = json.loads(run("find_similar.py", REPO, "--preset", "sql-string-concat", "--json").stdout)
        self.assertEqual(set(r), {"tool", "root", "query", "like", "preset_info", "summary", "files"})
        self.assertEqual(set(r["summary"]), {"files_scanned", "files_skipped", "files_with_matches", "match_count",
                                             "elsewhere_count", "files_shown", "files_not_shown"})
        self.assertEqual(r["query"]["mode"], "preset")
        paths = [f["path"] for f in r["files"]]
        self.assertEqual(paths, sorted(paths))
        for f in r["files"]:
            self.assertEqual(set(f), {"path", "language", "count", "shown", "matches"})
            self.assertEqual(f["count"], len(f["matches"]))
            for m in f["matches"]:
                self.assertEqual(set(m), {"line", "col", "match", "text", "origin"})
                self.assertGreaterEqual(m["col"], 1)
                self.assertNotIn("\n", m["text"])
            self.assertEqual([m["line"] for m in f["matches"]], sorted(m["line"] for m in f["matches"]))
        self.assertNotIn(str(Path.home()), json.dumps(r["files"]))

    def test_caps_per_file_and_file_count(self):
        full = fs.search(str(REPO), pattern=r"\w")
        capped = fs.search(str(REPO), pattern=r"\w", max_per_file=2, max_files=3)
        self.assertEqual(capped["summary"]["match_count"], full["summary"]["match_count"], "counts are never capped")
        self.assertEqual(len(capped["files"]), 3)
        self.assertEqual(capped["summary"]["files_not_shown"], full["summary"]["files_with_matches"] - 3)
        for f in capped["files"]:
            self.assertLessEqual(len(f["matches"]), 2)
            self.assertEqual(f["shown"], len(f["matches"]))
        md = fs.to_markdown(capped)
        self.assertIn("(showing 2)", md)
        self.assertIn("more files with matches not shown", md)

    def test_origin_line_survives_the_per_file_cap(self):
        ln = line_of("src/reports.py", 'data["currency"]')
        r = fs.search(str(REPO), like=f"src/reports.py:{ln}", max_per_file=1)
        reports = [f for f in r["files"] if f["path"] == "src/reports.py"][0]
        self.assertEqual([(m["line"], m["origin"]) for m in reports["matches"]], [(ln, True)])

    def test_deterministic_and_out_dir(self):
        a = run("find_similar.py", REPO, "--like", f"src/pricing.py:{line_of('src/pricing.py', 'market[')}",
                "--json")
        b = run("find_similar.py", REPO, "--like", f"src/pricing.py:{line_of('src/pricing.py', 'market[')}",
                "--json")
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            snaps = []
            for _ in range(2):
                r = run("find_similar.py", REPO, "--preset", "csharp-nullable-value", "--out-dir", tmp)
                self.assertEqual(r.returncode, 0, r.stderr)
                snaps.append((Path(tmp, "similar.json").read_bytes(), Path(tmp, "similar.md").read_bytes()))
            self.assertEqual(snaps[0], snaps[1])
            self.assertEqual(json.loads(snaps[0][0])["summary"]["match_count"], 3)

    def test_markdown_content(self):
        ln = line_of("src/pricing.py", 'market["currency"]')
        md = run("find_similar.py", REPO, "--like", f"src/pricing.py:{ln}").stdout
        self.assertTrue(md.startswith("# Similar-bug scan: more like `src/pricing.py:"))
        self.assertIn("recognised as **python-dict-key-access**", md)
        self.assertIn("**5 matches in 2 files** (4 besides the original line)", md)
        self.assertIn("## `src/reports.py` (3)", md)
        self.assertIn('currency = market["currency"]  <- original', md)
        self.assertIn("False positives:", md)
        self.assertIn("test files excluded", md)
        self.assertIn("Ask before widening", md)
        empty = run("find_similar.py", REPO, "--pattern", "zzz_never_there").stdout
        self.assertIn("No matches.", empty)

    def test_scripts_are_read_only(self):
        before = {p: p.stat().st_mtime_ns for p in REPO.rglob("*") if p.is_file()}
        for p in fs.PRESETS:
            fs.search(str(REPO), preset=p.name, include_tests=True)
        after = {p: p.stat().st_mtime_ns for p in REPO.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        for script in ("find_similar.py", "fix_report.py"):
            src = (SCRIPTS / script).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"^\s*(?:import|from) (?:subprocess|urllib|http|socket|requests)\b", src,
                                        re.M), script)

    def test_fast_enough_on_a_generated_medium_repo(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            body = "".join(f"def f{i}(x, y=None):\n    return x.get('k{i}') or y\n" for i in range(200))
            for i in range(400):
                d = Path(tmp, f"pkg{i % 20}")
                d.mkdir(exist_ok=True)
                (d / f"m{i}.py").write_text(body + ('v = data["key"]\n' if i % 50 == 0 else ""), encoding="utf-8")
            # first pass warms the OS file cache (freshly written files may be scanned by antivirus)
            self.assertEqual(fs.search(tmp, preset="python-dict-key-access")["summary"]["match_count"], 8)
            t = time.time()
            r = fs.search(tmp, preset="python-dict-key-access")
            self.assertEqual(r["summary"]["match_count"], 8)
            self.assertLess(time.time() - t, 5, "400 files x 400 lines should take well under 5 s")


# =============================================================================================
# fix_report: proof checks and report content
# =============================================================================================

def base(**over):
    d = {"bug": "Pricing crashes for markets without a currency",
         "root_cause": "price_in_currency assumed every market has a currency key",
         "fix": "default the currency to EUR", "files_changed": ["src/pricing.py"], "branch": "fix/missing-currency",
         "test_name": "test_missing_currency_defaults_to_eur",
         "test_command": "pytest tests/test_pricing.py -q",
         "before_output": out("pytest-before-fail.txt"), "after_output": out("pytest-after-pass.txt"),
         "suite_output": out("pytest-suite-pass.txt"), "suite_command": "pytest -q",
         "follow_ups": ["reports.py reads data['currency'] too"], "guardrail": "TypedDict for market payloads"}
    d.update(over)
    return d


class ProofChecks(unittest.TestCase):
    def ids(self, data):
        return {p["id"] for p in fr.check_proof(data)["problems"]}

    def test_verified_pytest(self):
        r = fr.build(base())
        self.assertEqual(r["proof"]["status"], "verified")
        self.assertEqual(r["proof"]["problems"], [])
        self.assertIn("New test test_missing_currency_defaults_to_eur: FAILED before (KeyError: 'currency') -> "
                      "PASSED after", r["report_text"])
        self.assertIn("Suite: 80 passed in 1.73s (pytest -q)", r["report_text"])

    def test_verified_other_stacks(self):
        cases = [("dotnet-before-fail.txt", "dotnet-after-pass.txt"), ("jest-before-fail.txt", "jest-after-pass.txt"),
                 ("pytest-before-fail.txt", "junit-after-pass.txt"), ("pytest-before-fail.txt", "go-after-pass.txt")]
        for before, after in cases:
            with self.subTest(after):
                p = fr.check_proof(base(before_output=out(before), after_output=out(after), test_name=None))
                self.assertTrue(p["test_verified"], p["problems"])

    def test_before_that_passed_is_not_a_reproduction(self):
        d = base(before_output=out("pytest-after-pass.txt"), after_output=out("pytest-after-pass.txt") + "\n")
        self.assertIn("before-no-failure", self.ids(d))
        r = fr.build(d)
        self.assertEqual(r["proof"]["status"], "unverified")
        self.assertNotIn("PASSED after", r["report_text"])
        self.assertIn("NOT VERIFIED", r["report_text"])

    def test_before_failing_on_import_or_compile_error_is_flagged(self):
        self.assertIn("before-setup-error", self.ids(base(before_output=out("pytest-before-import-error.txt"))))
        self.assertIn("before-setup-error", self.ids(base(before_output=out("dotnet-before-compile-error.txt"))))
        r = fr.build(base(before_output=out("dotnet-before-compile-error.txt")))
        self.assertEqual(r["proof"]["status"], "unverified")
        self.assertIn("compile error (C#)", r["comment_markdown"])

    def test_after_without_a_pass_line_is_refused(self):
        d = base(after_output=out("just-words.txt"))
        self.assertIn("after-no-pass-indicator", self.ids(d))
        r = fr.build(d)
        self.assertNotIn("PASSED", r["report_text"])
        self.assertIn("> **Proof incomplete.**", r["comment_markdown"])
        self.assertIn("**Proof check:** NOT VERIFIED.", r["comment_markdown"])

    def test_after_still_failing_is_refused(self):
        self.assertIn("after-failed", self.ids(base(after_output=out("pytest-suite-fail.txt"))))
        self.assertIn("after-failed", self.ids(base(after_output=out("jest-before-fail.txt"))))

    def test_after_with_no_tests_run_is_refused(self):
        self.assertIn("after-no-tests", self.ids(base(after_output=out("pytest-no-tests.txt"))))

    def test_missing_outputs(self):
        ids = self.ids(base(before_output=None, after_output="   "))
        self.assertTrue({"before-missing", "after-missing"} <= ids)
        r = fr.build(base(before_output=None, after_output=None))
        self.assertNotIn("PASSED", r["report_text"])

    def test_identical_before_and_after_is_refused(self):
        same = out("pytest-before-fail.txt")
        self.assertIn("identical-output", self.ids(base(before_output=same, after_output=same)))

    def test_suite_checks(self):
        self.assertIn("suite-failed", self.ids(base(suite_output=out("pytest-suite-fail.txt"))))
        r = fr.build(base(suite_output=out("pytest-suite-fail.txt")))
        self.assertIn("Suite: FAILING: 1 failed, 79 passed in 1.80s", r["report_text"])
        self.assertIn("suite-no-pass-indicator", self.ids(base(suite_output=out("just-words.txt"))))
        partial = fr.build(base(suite_output=None))
        self.assertEqual(partial["proof"]["status"], "partial")
        self.assertIn("Suite: not run (no output provided)", partial["report_text"])
        self.assertIn("PASSED after", partial["report_text"], "the new test itself was proven")

    def test_test_name_not_in_before_output_is_a_warning(self):
        p = fr.check_proof(base(test_name="test_something_else"))
        self.assertEqual([(x["id"], x["severity"]) for x in p["problems"]], [("before-test-not-named", "warning")])
        self.assertEqual(p["status"], "verified")

    def test_zero_counts_are_not_failures(self):
        c = fr.classify("Passed!  - Failed:     0, Passed:    42, Skipped:     0\n")
        self.assertEqual(c["fail_signals"], [])
        c = fr.classify("Tests run: 5, Failures: 0, Errors: 0, Skipped: 0\n0 failed\n")
        self.assertEqual(c["fail_signals"], [])
        self.assertTrue(c["pass_signals"])


class ReportContent(unittest.TestCase):
    def similar(self):
        ln = line_of("src/pricing.py", 'market["currency"]')
        return fs.search(str(REPO), like=f"src/pricing.py:{ln}")

    def test_comment_markdown(self):
        r = fr.build(base(similar=self.similar(), work_item="AB#1234"))
        c = r["comment_markdown"]
        self.assertEqual(r["pr_title"], "fix: Pricing crashes for markets without a currency")
        self.assertTrue(c.startswith("## fix: Pricing crashes"))
        for needle in ("Work item: AB#1234", "**Root cause:**", "**Files changed:**", "- `src/pricing.py`",
                       "**Branch:** `fix/missing-currency`",
                       "**Regression test:** `test_missing_currency_defaults_to_eur` (`pytest tests/test_pricing.py -q`)",
                       "<summary>Before the fix</summary>", "<summary>After the fix</summary>",
                       "**Suite:** 80 passed in 1.73s (pytest -q)", "**Prevention:** TypedDict for market payloads",
                       "- reports.py reads data['currency'] too",
                       "**Proof check:** verified (fail before, pass after, suite passing)."):
            self.assertIn(needle, c)

    def test_similar_matches_table(self):
        r = fr.build(base(similar=self.similar()))
        c = r["comment_markdown"]
        self.assertIn("**Same pattern elsewhere (python-dict-key-access):** 4 other match(es) in 2 file(s).", c)
        self.assertIn("| `src/reports.py:7` | `cur = data[\"currency\"]` | not changed, review |", c)
        self.assertIn("| `src/pricing.py:16` |", c)
        self.assertIn("in a file changed here", c)
        self.assertNotIn(f"`src/pricing.py:{line_of('src/pricing.py', 'market[')}`", c, "origin is not 'elsewhere'")
        self.assertIn("Same pattern elsewhere: 4 other match(es) of python-dict-key-access in 2 file(s); "
                      "1 in files changed by this fix", r["report_text"])

    def test_long_output_is_trimmed_and_fences_are_safe(self):
        noisy = "\n".join(f"line {i}" for i in range(100)) + "\n```\n" + out("pytest-after-pass.txt")
        c = fr.build(base(after_output=noisy))["comment_markdown"]
        self.assertIn("(last 20 of", c)
        self.assertIn("~~~text", c)
        self.assertNotIn("line 5\n", c)

    def test_cli_json_input_similar_path_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sim = Path(tmp, "similar.json")
            sim.write_text(json.dumps(self.similar()), encoding="utf-8")
            data = base(similar=str(sim))
            Path(tmp, "fix.json").write_text(json.dumps(data), encoding="utf-8")
            r = run("fix_report.py", "--input", Path(tmp, "fix.json"), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            rep = json.loads(r.stdout)
            self.assertEqual(rep["proof"]["status"], "verified")
            self.assertIn("4 other match(es)", rep["report_text"])
            # command-line options override JSON and files are read from disk
            r = run("fix_report.py", "--input", Path(tmp, "fix.json"), "--after", OUT / "just-words.txt")
            self.assertEqual(r.returncode, 3)
            self.assertIn("NOT VERIFIED", r.stdout)
            self.assertIn("# Work item / PR comment", r.stdout)

    def test_cli_args_only_and_out_dir_is_deterministic(self):
        args = ["--bug", "Null discount crashes Total", "--root-cause", "Discount is optional for guests",
                "--file", "src/Orders/OrderService.cs", "--test-name", "Total_WithoutDiscount_DoesNotThrow",
                "--before", OUT / "dotnet-before-fail.txt", "--after", OUT / "dotnet-after-pass.txt",
                "--suite", OUT / "dotnet-after-pass.txt", "--suite-command", "dotnet test",
                "--follow-up", "enable <Nullable>", "--follow-up", "check Invoice.PaidOn"]
        with tempfile.TemporaryDirectory() as tmp:
            snaps = []
            for _ in range(2):
                r = run("fix_report.py", *args, "--out-dir", tmp)
                self.assertEqual(r.returncode, 0, r.stderr)
                snaps.append(Path(tmp, "fix-report.md").read_text(encoding="utf-8"))
            self.assertEqual(snaps[0], snaps[1])
            md = snaps[0]
            self.assertIn("FAILED before (System.InvalidOperationException : Nullable object must have a value.) "
                          "-> PASSED after", md)
            self.assertIn("Risk / follow-ups: enable <Nullable>; check Invoice.PaidOn", md)
            self.assertTrue(Path(tmp, "fix-report.json").exists())

    def test_missing_input_file_is_a_clean_error(self):
        r = run("fix_report.py", "--before", "no/such/file.txt")
        self.assertEqual(r.returncode, 2)
        self.assertTrue(r.stderr.startswith("fix_report:"))


class SkillDocs(unittest.TestCase):
    def test_skill_md_workflow(self):
        body = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for needle in ("failing test", "<skill-dir>/scripts/find_similar.py", "<skill-dir>/scripts/fix_report.py",
                       "references/prevention-catalog.md", "references/regression-test-templates.md",
                       "ask before widening", "security-defect process", "fix/<ticket-or-slug>",
                       "don't invent business rules", "git identity", "NOT VERIFIED"):
            self.assertIn(needle.lower(), body.lower(), needle)

    def test_references_cover_every_stack_and_class(self):
        cat = (SKILL / "references" / "prevention-catalog.md").read_text(encoding="utf-8")
        for needle in ("<Nullable>enable</Nullable>", "TreatWarningsAsErrors", "CS8602", "CS8629", "strictNullChecks",
                       "noUncheckedIndexedAccess", "eqeqeq", "radix", "@typescript-eslint/no-non-null-assertion",
                       "B006", "E722", "BLE001", "S608", "SpotBugs", "Error Prone", "sp_executesql",
                       "Property-based", "Boundary"):
            self.assertIn(needle, cat)
        for p in fs.PRESETS:
            self.assertIn(p.name, cat)
        tpl = (SKILL / "references" / "regression-test-templates.md").read_text(encoding="utf-8")
        for needle in ("pytest", "[Fact]", "[Test]", "[TestMethod]", "describe(", "vitest", "@Test",
                       "func Test", "fail before", "fix_report.py"):
            self.assertIn(needle.lower(), tpl.lower(), needle)


if __name__ == "__main__":
    unittest.main()

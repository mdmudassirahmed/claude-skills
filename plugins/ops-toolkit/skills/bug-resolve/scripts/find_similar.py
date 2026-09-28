#!/usr/bin/env python3
"""find_similar - after fixing a bug, find the same bug shape elsewhere in the repository.

Three ways to say what to look for (pick one):
  --preset NAME         a documented bug class (see --list-presets)
  --pattern REGEX       your own regular expression (Python `re` syntax, one line at a time)
  --like FILE:LINE      "more like this one": the offending expression is read from that line,
                        its bug class is recognised, and a safe pattern is built from it.
                        Add --strict to narrow it to the same key / member / receiver.

Read-only: it never modifies files. Output is deterministic (sorted by path, no timestamps).
Vendor and build folders are skipped (.git, node_modules, bin, obj, dist, build, .venv, venv,
__pycache__, target, .terraform, ...) and so are test files unless --include-tests is given.
Presets skip whole-line comments; --pattern does not.

Usage:
  python find_similar.py <repo> --preset python-dict-key-access [--json] [--out-dir report]
  python find_similar.py <repo> --like src/pricing.py:42 [--strict]
  python find_similar.py <repo> --pattern "\\.Result\\b" --lang csharp
  python find_similar.py --list-presets
Standard library only; Python 3.8+.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

LANG_BY_EXT = {
    ".py": "python", ".cs": "csharp", ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".cts": "typescript", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java", ".sql": "sql", ".go": "go", ".kt": "kotlin", ".kts": "kotlin", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".swift": "swift", ".scala": "scala", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".vb": "vb", ".fs": "fsharp", ".ps1": "powershell",
    ".sh": "shell",
}
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bin", "obj", "dist", "build", ".venv", "venv", "__pycache__",
    "target", ".terraform", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vs",
    ".next", ".nuxt", "coverage", "bower_components", ".gradle",
}
TEST_DIRS = {"test", "tests", "__tests__", "__test__", "spec", "specs", "testing", "unittests", "e2e"}
TEST_FILE_RE = re.compile(
    r"(^test_.*\.py$|_test\.py$|^conftest\.py$|\.(test|spec)\.[cm]?[jt]sx?$|Tests?\.(cs|java|kt)$"
    r"|_test\.go$|IT\.java$)")
TEST_PROJECT_RE = re.compile(r"\.(?:Unit|Integration)?Tests?$|Tests$")
COMMENT_PREFIXES = {
    "python": ("#",), "sql": ("--",), "shell": ("#",), "powershell": ("#",), "ruby": ("#",),
}
C_LIKE_COMMENTS = ("//", "/*", "* ", "*/")
MAX_FILE_BYTES = 2000000
MAX_LINE_CHARS = 4000
TEXT_CHARS = 200


# ---------------------------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------------------------

class Preset(object):
    """A bug class: which languages, how to find it, and what the reader should know about it."""

    def __init__(self, name, languages, catches, false_positives, regex=None, accept=None,
                 hint=None, finder=None, file_context=None, repo_collect=None, group=0, hint_lower=False):
        self.name = name
        self.group = group
        self.languages = languages
        self.catches = catches
        self.false_positives = false_positives
        self.regex = regex
        self.accept = accept
        # hint: a cheap regex run over the whole file; only lines it hits get the full check. It must
        # match on every line the full check could match on and must not cross lines. It starts with a
        # literal where possible (fast in `re`); hint_lower runs it on the lower-cased text instead of
        # using re.I, which is an order of magnitude slower.
        self.hint = re.compile(hint, re.M) if hint else None
        self.hint_lower = hint_lower
        self.finder = finder
        self.file_context = file_context
        self.repo_collect = repo_collect

    def describe(self):
        return {"name": self.name, "languages": sorted(self.languages), "catches": self.catches,
                "false_positives": self.false_positives}


def _near(lines, i, needle_re, back=3):
    """True if needle_re appears on line i or up to `back` lines above it."""
    for j in range(max(0, i - back), i + 1):
        if needle_re.search(lines[j]):
            return True
    return False


# python ------------------------------------------------------------------------------------------
PY_DICT_KEY = re.compile(
    r"\b[A-Za-z_][\w.]*(?:\(\))?(?<!Literal)(?<!Annotated)(?<!ClassVar)(?<!Final)"
    r"\[\s*(?:'[^'\n]*'|\"[^\"\n]*\")\s*\](?!\s*=(?!=))")
PY_BARE_EXCEPT = re.compile(r"^\s*(except\s*:)")
PY_MUTABLE_DEFAULT = re.compile(
    r"\bdef\s+\w+\s*\(.*?(\b\w+\s*(?::[^=()]*?)?=\s*"
    r"(?:\[[^\]]*\]?|\{[^}]*\}?"
    r"|(?:list|dict|set|defaultdict|OrderedDict|collections\.defaultdict|collections\.OrderedDict)\(\s*\)))")

# csharp ------------------------------------------------------------------------------------------
CS_NULLABLE_DECL = re.compile(
    r"(?:\bNullable<\s*[\w.]+\s*>|\b(?:int|uint|long|ulong|short|ushort|byte|sbyte|decimal|double|float|bool"
    r"|char|[A-Z]\w*)\?)\s+(\w+)\s*(?=[;=,)({]|=>|$)")
CS_VALUE_USE = re.compile(r"\b(\w+)(\s*\([^()]*\))?\s*\.\s*Value\b(?!\s*=(?!=))(?!\s*\()")
CS_ASYNC_VOID = re.compile(r"\basync\s+void\s+(\w+)\s*\(([^)]*)")
CS_FIRST = re.compile(r"(\b\w+)(?:\([^()]*\))?\s*\.\s*(First|Last|Single)\s*\(")


def cs_collect(text, acc):
    acc.setdefault("cs_nullable", set()).update(CS_NULLABLE_DECL.findall(text))


def cs_accept_value(m, lines, i, ctx):
    name = m.group(1)
    if name not in ctx.get("cs_nullable", ()):
        return False
    guard = re.compile(r"\b" + re.escape(name) + r"\s*(?:\??\.\s*HasValue\b|!=\s*null\b|is\s+not\s+null\b|is\s*\{)")
    return not _near(lines, i, guard)


def cs_accept_async_void(m, lines, i, ctx):
    return not re.search(r"EventArgs\b", m.group(2))


def cs_accept_first(m, lines, i, ctx):
    recv = re.escape(m.group(1))
    guard = re.compile(r"\b" + recv + r"\s*\.\s*(?:Any\s*\(|Count\s*(?:\(\s*\))?\s*(?:>|!=)\s*0|Length\s*(?:>|!=)\s*0)")
    return not _near(lines, i, guard)


# javascript / typescript -------------------------------------------------------------------------
TS_NON_NULL = re.compile(
    r"(?<![\w$.])([\w$]+(?:\??\.[\w$]+|\([^()]*\)|\[[^\[\]]*\])*)!(?=[.;,)\[\]}])")
JS_LOOSE_EQ = re.compile(r"(?<![=!<>])([=!]=)(?!=)")
JS_PARSEINT = re.compile(r"\b(?:Number\.)?parseInt\s*\(((?:[^(),]|\([^()]*\))*)\)")


def js_loose_finder(line, lines, i, ctx):
    out = []
    for m in JS_LOOSE_EQ.finditer(line):
        before, after = line[:m.start()], line[m.end():]
        if re.search(r"\bnull\s*$", before) or re.match(r"\s*null\b", after):
            continue  # x == null is the accepted "null or undefined" idiom (eslint eqeqeq "smart")
        if re.search(r"\btypeof\s+[\w$.\[\]]+\s*$", before) or re.match(r"\s*typeof\b", after):
            continue  # typeof always returns a string, so == and === behave the same
        left = re.search(r"[\w$.\]\)'\"`]+\s*$", before)
        right = re.match(r"\s*[\w$.'\"`(\[!-]+", after)
        if not left or not right:
            continue
        out.append((left.start(), (left.group(0) + m.group(1) + right.group(0)).strip()))
    return out


# java --------------------------------------------------------------------------------------------
JAVA_OPT_METHOD_DECL = re.compile(r"\bOptional(?:Int|Long|Double)?(?:<[^;{}()]*>)?\s+(\w+)\s*\(")
JAVA_OPT_VAR_DECL = re.compile(r"\bOptional(?:Int|Long|Double)?(?:<[^;{}()]*>)?\s+(\w+)\s*(?=[=;,)]|$)")
JAVA_OPT_BUILTIN = {"findFirst", "findAny", "max", "min", "reduce", "ofNullable", "of", "empty", "findById",
                    "findOne", "average"}
JAVA_OPT_GET = re.compile(
    r"\b(\w+)\s*(\((?:[^()]|\([^()]*\))*\))?\s*\.\s*(get(?:AsInt|AsLong|AsDouble)?)\s*\(\s*\)")
JAVA_STRING_DECL = re.compile(r"\bString\s+(\w+)\s*(?=[=;,)]|$)")
JAVA_OPERAND = r"(\"(?:[^\"\\]|\\.)*\"|[A-Za-z_]\w*(?:\s*\.\s*\w+(?:\s*\([^()]*\))?)*)"
JAVA_EQ = re.compile(JAVA_OPERAND + r"\s*([!=]=)(?!=)\s*" + JAVA_OPERAND)


def java_collect(text, acc):
    acc.setdefault("java_opt_methods", set()).update(JAVA_OPT_METHOD_DECL.findall(text))


def java_file_ctx(text):
    return {"java_opt_vars": set(JAVA_OPT_VAR_DECL.findall(text)),
            "java_strings": set(JAVA_STRING_DECL.findall(text))}


def java_accept_opt(m, lines, i, ctx):
    name, call = m.group(1), m.group(2)
    if call:
        ok = name in JAVA_OPT_BUILTIN or name in ctx.get("java_opt_methods", ())
    else:
        ok = name in ctx.get("java_opt_vars", ())
    if not ok:
        return False
    if not call:
        guard = re.compile(r"\b" + re.escape(name) + r"\s*\.\s*isPresent\s*\(\s*\)")
        return not _near(lines, i, guard)
    return True


def java_accept_eq(m, lines, i, ctx):
    a, b = m.group(1), m.group(3)
    if "null" in (a, b):
        return False
    if a.startswith('"') or b.startswith('"'):
        return True
    strings = ctx.get("java_strings", ())
    return a in strings or b in strings


# sql (any language) ------------------------------------------------------------------------------
STRING_LIT = re.compile(r"(\b[rRfFbBuU]{1,2}|\$@|@\$|\$|@)?(\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`[^`]*`)")
SQL_IN_STRING = re.compile(
    r"\bselect\b.*?\bfrom\b|\binsert\s+into\b|\bupdate\s+[\w.\[\]\"]+\s+set\b|\bdelete\s+from\b"
    r"|\b(?:where|and|or)\s+[\w.\[\]\"`]+\s*(?:=|<>|!=|<=|>=|<|>|like\b|in\b)|\border\s+by\b", re.I)


def sql_finder(line, lines, i, ctx):
    if "'" not in line and '"' not in line and "`" not in line:
        return []
    lang = ctx.get("language")
    lits = list(STRING_LIT.finditer(line))
    if not lits or not any(SQL_IN_STRING.search(m.group(2)) for m in lits):
        return []
    concat = r"(?:\+|\|\|)" if lang == "sql" else r"\+"
    for m in lits:
        prefix, body = (m.group(1) or ""), m.group(2)
        before, after = line[:m.start()], line[m.end():]
        dynamic = (
            (("f" in prefix.lower() or "$" in prefix) and "{" in body)
            or (body.startswith("`") and "${" in body)
            or re.match(r"\s*" + concat + r"\s*(?![\s\"'`])\S", after) is not None
            or re.search(r"[\w)\]@]\s*" + concat + r"\s*$", before) is not None
            or re.match(r"\s*\.\s*format\s*\(", after) is not None
            or re.match(r"\s*%\s*[\w(]", after) is not None
            or (re.search(r"\b(?:String\.format|string\.Format)\s*\(\s*$", before) is not None)
        )
        if dynamic:
            return [(len(line) - len(line.lstrip()), line.strip())]
    return []


PRESETS = [
    Preset("python-dict-key-access", {"python"},
           'Subscript reads with a literal string key (`data["currency"]`) that raise KeyError when the '
           "key is missing; `.get()` or an explicit check was probably intended.",
           "Keys that are guaranteed by a schema, dataclass-like dicts you built yourself, pandas columns. "
           "Assignments (`d[\"k\"] = v`) and typing forms such as `Literal[\"a\"]` are not reported.",
           regex=PY_DICT_KEY, hint=r"\[[ \t]*['\"]"),
    Preset("python-bare-except", {"python"},
           "`except:` with no exception type, which also swallows KeyboardInterrupt and SystemExit and hides "
           "the real error.",
           "Rare; a bare except that immediately re-raises is legitimate. Broad `except Exception:` is not "
           "reported by this preset.",
           regex=PY_BARE_EXCEPT, hint=r"except[ \t]*:", group=1),
    Preset("python-mutable-default-arg", {"python"},
           "Function defaults that are mutable (`=[]`, `={}`, `=list()`, `=dict()`, `=set()`): one object is "
           "shared by every call, so state leaks between calls.",
           "Deliberate memoisation caches. Only single-line `def` headers are seen; parameters on "
           "continuation lines of a multi-line signature are missed.",
           regex=PY_MUTABLE_DEFAULT, hint=r"def\b", group=1),
    Preset("csharp-nullable-value", {"csharp"},
           "`.Value` on a Nullable<T> / `T?` member or local (declared anywhere in the scanned repo) with no "
           "HasValue / null check on that line or the three lines above: InvalidOperationException when null.",
           "Name-based: an unrelated member with the same name as a nullable one elsewhere is reported too; a "
           "guard further away than three lines is not seen. KeyValuePair/Lazy/IOptions .Value are ignored "
           "unless the name was declared nullable.",
           regex=CS_VALUE_USE, accept=cs_accept_value, hint=r"\.[ \t]*Value\b", repo_collect=cs_collect),
    Preset("csharp-async-void", {"csharp"},
           "`async void` methods: exceptions cannot be awaited or caught by the caller and can crash the process.",
           "Event handlers (parameters ending in EventArgs) are skipped because async void is required there.",
           regex=CS_ASYNC_VOID, accept=cs_accept_async_void, hint=r"async[ \t]+void\b"),
    Preset("csharp-first-without-default", {"csharp"},
           "`.First(` / `.Last(` / `.Single(` on sequences that may be empty (InvalidOperationException: "
           "Sequence contains no elements).",
           "Sequences that are never empty by construction. A same-receiver `.Any()` / `Count > 0` check on the "
           "line or the three lines above suppresses the hit.",
           regex=CS_FIRST, accept=cs_accept_first, hint=r"\.[ \t]*(?:First|Last|Single)[ \t]*\("),
    Preset("js-ts-non-null-assertion", {"typescript"},
           "TypeScript non-null assertions (`user!.name`, `value!;`, `fn(x!)`) that silence the compiler and "
           "fail at runtime with 'cannot read properties of undefined'.",
           "Values proven non-null a few lines earlier. `!` inside string literals can be misreported. "
           "Definite-assignment declarations (`let x!: T`) are not reported.",
           regex=TS_NON_NULL, hint=r"!(?=[.;,)\[\]}])"),
    Preset("js-loose-equality", {"javascript", "typescript"},
           "`==` / `!=` where `===` / `!==` was meant: type coercion makes `0 == \"\"` and `\"1\" == 1` true.",
           "Mirrors eslint eqeqeq 'smart': comparisons with `null` and `typeof` checks are skipped. `==` inside "
           "strings or regex literals can be misreported.",
           finder=js_loose_finder, hint=r"[=!]="),
    Preset("js-parseInt-no-radix", {"javascript", "typescript"},
           "`parseInt(x)` without a radix; the radix should always be explicit (`parseInt(x, 10)`) so input "
           "such as '0x1A' is not silently read as hexadecimal.",
           "None known; calls split across lines are missed.",
           regex=JS_PARSEINT, hint=r"parseInt\b"),
    Preset("java-optional-get", {"java"},
           "`.get()` (or getAsInt/Long/Double) on an Optional: NoSuchElementException when empty. Optional "
           "receivers are recognised from `Optional<...>` locals and fields in the file, methods declared "
           "anywhere in the repo as returning Optional, and stream/repository methods such as findFirst, "
           "findById, max, min.",
           "A guard with `isPresent()` on the same variable within three lines suppresses the hit. Other "
           "types with a no-argument get() (Supplier, AtomicInteger, Future) are ignored unless declared "
           "Optional.",
           regex=JAVA_OPT_GET, accept=java_accept_opt, hint=r"get(?:AsInt|AsLong|AsDouble)?[ \t]*\([ \t]*\)",
           file_context=java_file_ctx,
           repo_collect=java_collect),
    Preset("java-equals-on-strings", {"java"},
           "`==` / `!=` between Strings (a literal, or a variable declared String in the same file): compares "
           "references, not text.",
           "Only same-file String declarations are known; comparisons of two method results are missed. "
           "Deliberate identity checks on interned constants are reported.",
           regex=JAVA_EQ, accept=java_accept_eq, hint=r"[=!]=", file_context=java_file_ctx),
    Preset("sql-string-concat", {"python", "csharp", "java", "javascript", "typescript", "sql"},
           "SQL built from a string literal plus user data: `+` concatenation, f-strings, C# `$\"...\"`, JS "
           "template literals, `.format()`, `%` formatting, String.format, and `+`/`||` with @variables in "
           "T-SQL/PL/SQL. SQL injection risk and quoting bugs; parameterise instead.",
           "Concatenation of trusted constants (table names from an allow-list) is reported too. Queries split "
           "over many lines are only caught on the line that joins data in. This is a lead: if it is "
           "exploitable, route it to the security process.",
           finder=sql_finder, hint=r"(?:select|insert|update|delete|where|and|or|order)\b",
           hint_lower=True),
]
PRESET_BY_NAME = {p.name: p for p in PRESETS}


# ---------------------------------------------------------------------------------------------
# matchers
# ---------------------------------------------------------------------------------------------

class Matcher(object):
    def __init__(self, preset=None, regex=None, languages=None, skip_comments=True, extra_ctx=None):
        self.preset = preset
        self.regex = regex
        self.languages = set(languages) if languages else set()
        self.skip_comments = skip_comments
        self.repo_ctx = dict(extra_ctx or {})

    def candidate_lines(self, text, count):
        """Indexes of the lines worth a full per-line check, found with one pass over the file."""
        if self.preset is not None and self.preset.hint is not None:
            rx = self.preset.hint
            if self.preset.hint_lower:
                text = text.lower()
        elif self.regex is not None and not re.search(r"\(\?[=!<]|\\[AZz]", self.regex.pattern):
            # safe to pre-scan the whole file: no lookaround or absolute anchors that could behave
            # differently across a line break
            rx = re.compile(self.regex.pattern, self.regex.flags | re.M)
        else:
            return range(count)
        out = []
        line, last, pos = 0, 0, 0
        while True:
            m = rx.search(text, pos)
            if not m:
                return out
            line += text.count("\n", last, m.start())
            last = m.start()
            out.append(line)
            nl = text.find("\n", m.start())
            if nl < 0:
                return out
            line += 1
            last = pos = nl + 1

    def collect(self, text):
        if self.preset and self.preset.repo_collect:
            self.preset.repo_collect(text, self.repo_ctx)

    def find(self, text, lang):
        lines = text.split("\n")
        candidates = self.candidate_lines(text, len(lines))
        if not candidates:
            return []
        ctx = dict(self.repo_ctx)
        if self.preset and self.preset.file_context:
            for k, v in self.preset.file_context(text).items():
                ctx[k] = (ctx[k] | v) if k in ctx else v
        ctx["language"] = lang
        prefixes = COMMENT_PREFIXES.get(lang, C_LIKE_COMMENTS)
        out = []
        for i in candidates:
            line = lines[i]
            if len(line) > MAX_LINE_CHARS:
                continue
            stripped = line.lstrip()
            if self.skip_comments and (stripped.startswith(prefixes) or stripped == "*"):
                continue
            if self.preset and self.preset.finder:
                hits = self.preset.finder(line, lines, i, ctx)
            else:
                rx = self.regex if self.regex is not None else self.preset.regex
                hits = []
                for m in rx.finditer(line):
                    if self.preset and self.preset.accept and not self.preset.accept(m, lines, i, ctx):
                        continue
                    grp = self.preset.group if (self.preset and self.regex is None) else 0
                    hits.append((m.start(grp), m.group(grp).strip()))
            for col, text_match in hits:
                out.append((i + 1, col + 1, text_match, line))
        return out


# ---------------------------------------------------------------------------------------------
# walking
# ---------------------------------------------------------------------------------------------

def is_test_path(rel):
    parts = rel.split("/")
    for d in parts[:-1]:
        if d.lower() in TEST_DIRS or TEST_PROJECT_RE.search(d):
            return True
    return bool(TEST_FILE_RE.search(parts[-1]))


def iter_files(root, languages, include_tests, extra_excludes):
    """Yield (relative posix path, absolute path, language) in sorted order."""
    excluded = EXCLUDED_DIRS | set(extra_excludes or ())
    root = os.path.abspath(root)
    if os.path.isfile(root):
        lang = LANG_BY_EXT.get(os.path.splitext(root)[1].lower())
        if lang and (not languages or lang in languages):
            yield os.path.basename(root), root, lang
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            lang = LANG_BY_EXT.get(os.path.splitext(name)[1].lower())
            if not lang or (languages and lang not in languages):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if not include_tests and is_test_path(rel):
                continue
            yield rel, full, lang


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------------------------
# --like: recognise the offending expression
# ---------------------------------------------------------------------------------------------

LIKE_RULES = {
    "python": [
        ("python-dict-key-access", re.compile(r"\b[A-Za-z_][\w.]*(?:\(\))?\[\s*(['\"])([^'\"\n]+)\1\s*\]")),
        ("python-bare-except", PY_BARE_EXCEPT),
        ("python-mutable-default-arg", PY_MUTABLE_DEFAULT),
    ],
    "csharp": [
        ("csharp-nullable-value", re.compile(r"\b(\w+)(\s*\([^()]*\))?\s*!?\s*\.\s*Value\b(?!\s*\()")),
        ("csharp-async-void", CS_ASYNC_VOID),
        ("csharp-first-without-default", CS_FIRST),
    ],
    "typescript": [
        ("js-ts-non-null-assertion", TS_NON_NULL),
        ("js-parseInt-no-radix", JS_PARSEINT),
    ],
    "javascript": [
        ("js-parseInt-no-radix", JS_PARSEINT),
    ],
    "java": [
        ("java-optional-get", JAVA_OPT_GET),
        ("java-equals-on-strings", JAVA_EQ),
    ],
    "sql": [],
}


def _last_segment(expr):
    seg = re.split(r"\??\.", re.sub(r"\([^()]*\)|\[[^\[\]]*\]", "", expr))
    return seg[-1] if seg else expr


def derive_like(line, lang, strict):
    """Return (bug_class, expression, preset_or_None, regex_or_None, extra_ctx)."""
    for name, rx in LIKE_RULES.get(lang, []):
        m = rx.search(line)
        if not m:
            continue
        expr = m.group(0).strip()
        if name == "python-dict-key-access":
            key = m.group(2)
            if strict:
                return name, expr, None, re.compile(
                    r"\[\s*['\"]" + re.escape(key) + r"['\"]\s*\](?!\s*=(?!=))"), {}
            return name, expr, PRESET_BY_NAME[name], None, {}
        if name == "csharp-nullable-value":
            recv = m.group(1)
            if strict:
                return name, expr, None, re.compile(
                    r"\b" + re.escape(recv) + r"(?:\s*\([^()]*\))?\s*!?\s*\.\s*Value\b(?!\s*\()"), {}
            return name, expr, PRESET_BY_NAME[name], None, {"cs_nullable": {recv}}
        if name == "csharp-first-without-default":
            if strict:
                return name, expr, None, re.compile(
                    r"\b" + re.escape(m.group(1)) + r"(?:\([^()]*\))?\s*\.\s*" + m.group(2) + r"\s*\("), {}
            return name, expr, PRESET_BY_NAME[name], None, {}
        if name == "js-ts-non-null-assertion":
            seg = _last_segment(m.group(1))
            if strict:
                return name, expr, None, re.compile(r"(?<![\w$])" + re.escape(seg) + r"!(?=[.;,)\[\]}])"), {}
            return name, expr, PRESET_BY_NAME[name], None, {}
        if name == "java-optional-get":
            recv = m.group(1)
            if strict:
                return name, expr, None, re.compile(
                    r"\b" + re.escape(recv) + r"\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*\.\s*get\s*\(\s*\)"), {}
            extra = {"java_opt_methods": {recv}} if m.group(2) else {"java_opt_vars": {recv}}
            return name, expr, PRESET_BY_NAME[name], None, extra
        if name == "java-equals-on-strings" and not java_accept_eq(m, [line], 0, {}):
            continue
        return name, expr, PRESET_BY_NAME[name], None, {}
    if lang in ("javascript", "typescript") and js_loose_finder(line, [line], 0, {}):
        expr = js_loose_finder(line, [line], 0, {})[0][1]
        return "js-loose-equality", expr, PRESET_BY_NAME["js-loose-equality"], None, {}
    if lang in PRESET_BY_NAME["sql-string-concat"].languages and sql_finder(line, [line], 0, {"language": lang}):
        return "sql-string-concat", line.strip(), PRESET_BY_NAME["sql-string-concat"], None, {}
    literal = line.strip()
    if not literal:
        return None, "", None, None, {}
    pattern = r"\s+".join(re.escape(tok) for tok in literal.split())
    return "literal", literal, None, re.compile(pattern), {}


def parse_like(spec, root):
    path, _, num = spec.rpartition(":")
    if not path or not num.isdigit():
        raise ValueError("--like expects FILE:LINE, for example src/app.py:42")
    candidates = [Path(root) / path, Path(path)]
    for c in candidates:
        if c.is_file():
            return c, int(num)
    raise ValueError(f"--like file not found: {path}")


# ---------------------------------------------------------------------------------------------
# main analysis
# ---------------------------------------------------------------------------------------------

def search(root, preset=None, pattern=None, like=None, strict=False, languages=None, include_tests=False,
           max_per_file=20, max_files=100, exclude_dirs=None, ignore_case=False):
    """Run one search and return the report dict (shape documented in SKILL.md)."""
    query = {"mode": None, "preset": None, "pattern": None, "languages": [], "include_tests": include_tests,
             "strict": bool(strict)}
    like_info = None
    extra_ctx = {}
    regex = None
    chosen = None
    origin = None
    if like:
        path, line_no = parse_like(like, root)
        lang = LANG_BY_EXT.get(path.suffix.lower())
        if not lang:
            raise ValueError(f"--like: unsupported file type {path.suffix}")
        lines = (read_text(str(path)) or "").split("\n")
        if not 1 <= line_no <= len(lines):
            raise ValueError(f"--like: {path} has {len(lines)} lines, no line {line_no}")
        bug_class, expr, chosen, regex, extra_ctx = derive_like(lines[line_no - 1], lang, strict)
        if bug_class is None:
            raise ValueError(f"--like: line {line_no} of {path} is empty")
        try:
            rel = os.path.relpath(os.path.abspath(str(path)), os.path.abspath(root)).replace(os.sep, "/")
        except ValueError:  # different drive on Windows
            rel = path.name
        origin = (rel, line_no)
        like_info = {"file": rel, "line": line_no, "language": lang, "expression": expr[:TEXT_CHARS],
                     "bug_class": bug_class, "pattern": regex.pattern if regex is not None else None,
                     "strict_applied": bool(strict and regex is not None and bug_class != "literal")}
        query["mode"] = "like"
        query["preset"] = chosen.name if chosen else None
        query["pattern"] = regex.pattern if regex is not None else None
        if not languages:
            languages = sorted(chosen.languages) if chosen else [lang]
            if bug_class == "literal" or (regex is not None):
                languages = [lang]
    elif preset:
        if preset not in PRESET_BY_NAME:
            raise ValueError(f"unknown preset {preset!r}; try --list-presets")
        chosen = PRESET_BY_NAME[preset]
        query["mode"] = "preset"
        query["preset"] = preset
        languages = languages or sorted(chosen.languages)
    elif pattern:
        try:
            regex = re.compile(pattern, re.I if ignore_case else 0)
        except re.error as e:
            raise ValueError(f"invalid --pattern: {e}")
        query["mode"] = "pattern"
        query["pattern"] = pattern
    else:
        raise ValueError("give one of --preset, --pattern or --like")
    unknown = set(languages or []) - set(LANG_BY_EXT.values())
    if unknown:
        raise ValueError(f"unknown language(s): {', '.join(sorted(unknown))}")
    query["languages"] = sorted(languages or [])

    matcher = Matcher(preset=chosen if regex is None else None, regex=regex, languages=languages,
                      skip_comments=query["mode"] != "pattern", extra_ctx=extra_ctx)
    files = list(iter_files(root, set(languages or []), include_tests, exclude_dirs))
    texts = []
    skipped = 0
    for rel, full, lang in files:
        text = read_text(full)
        if text is None:
            skipped += 1
            continue
        texts.append((rel, lang, text))
        matcher.collect(text)

    results = []
    total = 0
    for rel, lang, text in texts:
        hits = matcher.find(text, lang)
        if not hits:
            continue
        total += len(hits)
        shown = [{"line": ln, "col": col, "match": mt[:TEXT_CHARS], "text": ltxt.strip()[:TEXT_CHARS],
                  "origin": origin == (rel, ln)} for ln, col, mt, ltxt in hits]
        pinned = [s for s in shown if s["origin"]]
        rest = [s for s in shown if not s["origin"]]
        keep = (pinned + rest)[:max_per_file]
        keep.sort(key=lambda s: (s["line"], s["col"]))
        results.append({"path": rel, "language": lang, "count": len(hits), "shown": len(keep), "matches": keep})

    results.sort(key=lambda r: r["path"])
    origin_hits = sum(1 for r in results for m in r["matches"] if m["origin"])
    shown_files = results[:max_files]
    return {
        "tool": "find_similar",
        "root": Path(root).as_posix(),
        "query": query,
        "like": like_info,
        "preset_info": chosen.describe() if chosen else None,
        "summary": {
            "files_scanned": len(texts),
            "files_skipped": skipped,
            "files_with_matches": len(results),
            "match_count": total,
            "elsewhere_count": total - origin_hits,
            "files_shown": len(shown_files),
            "files_not_shown": len(results) - len(shown_files),
        },
        "files": shown_files,
    }


def _fence_safe(s):
    return s.replace("```", "'''")


def to_markdown(r):
    q = r["query"]
    if q["mode"] == "like":
        title = f"Similar-bug scan: more like `{r['like']['file']}:{r['like']['line']}`"
    elif q["mode"] == "preset":
        title = f"Similar-bug scan: preset `{q['preset']}`"
    else:
        title = "Similar-bug scan: custom pattern"
    s = r["summary"]
    L = [f"# {title}", ""]
    if r["like"]:
        lk = r["like"]
        L.append(f"- Expression: `{_fence_safe(lk['expression'])}` ({lk['language']}), recognised as "
                 f"**{lk['bug_class']}**" + (" (strict)" if q["strict"] else ""))
    if q["pattern"]:
        L.append(f"- Pattern: `{q['pattern']}`")
    if r["preset_info"]:
        L.append(f"- Catches: {r['preset_info']['catches']}")
        L.append(f"- False positives: {r['preset_info']['false_positives']}")
    L.append(f"- Languages: {', '.join(q['languages']) or 'all known source types'}; test files "
             f"{'included' if q['include_tests'] else 'excluded'}")
    L.append(f"- Scanned {s['files_scanned']} files: **{s['match_count']} matches in "
             f"{s['files_with_matches']} files**" +
             (f" ({s['elsewhere_count']} besides the original line)" if r["like"] else ""))
    L.append("")
    if not r["files"]:
        L += ["No matches.", ""]
    for f in r["files"]:
        more = f" (showing {f['shown']})" if f["shown"] < f["count"] else ""
        L += [f"## `{f['path']}` ({f['count']}){more}", "", "```text"]
        for m in f["matches"]:
            mark = "  <- original" if m["origin"] else ""
            L.append(f"{m['line']:>5}  {_fence_safe(m['text'])}{mark}")
        L += ["```", ""]
    if s["files_not_shown"]:
        L += [f"_{s['files_not_shown']} more files with matches not shown (raise --max-files)._", ""]
    L += ["---", "Leads, not verdicts: read each hit before changing it. Ask before widening the fix beyond a "
          "few files."]
    return "\n".join(L) + "\n"


def presets_markdown():
    L = ["| Preset | Languages | Catches | False positives |", "|---|---|---|---|"]
    for p in PRESETS:
        L.append(f"| `{p.name}` | {', '.join(sorted(p.languages))} | {p.catches} | {p.false_positives} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find the same bug shape elsewhere in a repository (read-only).")
    ap.add_argument("root", nargs="?", default=".", help="repository folder (default: current folder)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--preset", help="bug-class preset, see --list-presets")
    g.add_argument("--pattern", help="regular expression applied to each line")
    g.add_argument("--like", help="FILE:LINE of the bug you just fixed")
    g.add_argument("--list-presets", action="store_true")
    ap.add_argument("--strict", action="store_true", help="with --like: same key/member only")
    ap.add_argument("--lang", help="comma-separated languages (python,csharp,typescript,javascript,java,sql,...)")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--exclude-dir", action="append", default=[], help="extra folder name to skip (repeatable)")
    ap.add_argument("-i", "--ignore-case", action="store_true", help="with --pattern")
    ap.add_argument("--max-per-file", type=int, default=20)
    ap.add_argument("--max-files", type=int, default=100)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out-dir")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if a.list_presets:
        sys.stdout.write(json.dumps([p.describe() for p in PRESETS], indent=2) + "\n" if a.json
                         else presets_markdown())
        return 0
    langs = [x.strip() for x in a.lang.split(",") if x.strip()] if a.lang else None
    try:
        rep = search(a.root, preset=a.preset, pattern=a.pattern, like=a.like, strict=a.strict, languages=langs,
                     include_tests=a.include_tests, max_per_file=max(1, a.max_per_file),
                     max_files=max(1, a.max_files), exclude_dirs=a.exclude_dir, ignore_case=a.ignore_case)
    except ValueError as e:
        sys.stderr.write(f"find_similar: {e}\n")
        return 2
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "similar.json").write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
        Path(a.out_dir, "similar.md").write_text(to_markdown(rep), encoding="utf-8")
        print(f"wrote {a.out_dir}/similar.md and .json ({rep['summary']['match_count']} matches)")
    else:
        sys.stdout.write(json.dumps(rep, indent=2) + "\n" if a.json else to_markdown(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())

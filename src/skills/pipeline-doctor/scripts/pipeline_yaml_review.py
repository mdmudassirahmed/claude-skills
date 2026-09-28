#!/usr/bin/env python3
"""pipeline_yaml_review - security and reliability hygiene check for pipeline YAML.

Scans Azure Pipelines (azure-pipelines*.yml, .azure-pipelines/, pipelines/) and GitHub
Actions (.github/workflows/*.yml) files with line-based checks, no YAML library, and
reports rule id, severity, file, line, why and fix. Secret values are never printed.

Rules: unpinned-action, pr-target-checkout, script-injection, secret-echo,
secret-in-command-line, plaintext-secret, write-all-permissions, missing-permissions,
az-login-secret, continue-on-error, swallowed-failure, set-plus-e, legacy-peer-deps,
no-verify, missing-timeout, floating-image.
Silence one finding with a comment on the line (or the line above):
  # pipeline-doctor: ignore <rule-id>

Usage:
  python pipeline_yaml_review.py <files or repo folder...> [--json] [--fail-on high|medium|low]
Deterministic, redacted output. Standard library only; Python 3.8+.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from redact import Redactor  # noqa: E402

SEVERITY = {"high": 3, "medium": 2, "low": 1}
KEY = re.compile(r"^(?P<key>\$\{\{.*?\}\}|\"[^\"]+\"|'[^']+'|[A-Za-z_][\w.\-/]*)\s*:(?:\s+(?P<value>.*)|\s*)$")
BLOCK = re.compile(r"^[|>][+-]?\d*$")
SCRIPT_KEYS = {"run", "script", "bash", "pwsh", "powershell", "inline", "inlinescript", "customcommand", "arguments"}
TEST_SEC = re.compile(r"\btests?\b|pytest|\bjest\b|vitest|mocha|dotnet test|VSTest|\bmvnw? .*\b(test|verify)\b|"
                      r"gradlew? .*\b(test|check)\b|\bgo test\b|cargo test|coverage|\blint\b|eslint|flake8|ruff|mypy|"
                      r"\baudit\b|security|codeql|sonar|trivy|snyk|checkov|tfsec|semgrep|gitleaks|trufflehog|"
                      r"dependency-check|owasp|\bsast\b|\bdast\b|credscan|\bzap\b|bandit|grype", re.I)
PUBLISH_ONLY = re.compile(r"PublishTestResults|PublishCodeCoverageResults", re.I)
SECRET_REF_GH = re.compile(r"\$\{\{\s*secrets\.[\w-]+\s*\}\}")
SECRET_WORDS = r"password|passwd|pwd|secret|token|apikey|api_key|accesskey|access_key|privatekey|private_key|connectionstring|credential|\bpat\b"
SECRET_REF_AZ = re.compile(r"\$\(\s*[\w.]*(" + SECRET_WORDS + r")[\w.]*\s*\)|\$\(\s*[\w.]*pat\s*\)", re.I)
SECRET_REF_ENV = re.compile(r"\$(env:)?\{?[A-Za-z_]*(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|_PAT)\b\}?")
ECHO = re.compile(r"(^|[;&|]\s*|\s)(echo|Write-Host|Write-Output|printf|print)\b", re.I)
MASKING = re.compile(r"issecret=true|::add-mask::", re.I)
INJECTION = re.compile(r"\$\{\{\s*(github\.event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|"
                       r"comment\.body|review\.body|review_comment\.body|head_commit\.(message|author\.(name|email))|"
                       r"commits\b[^}]*\.(message|name|email)|pages\b[^}]*page_name|discussion\.(title|body))|github\.head_ref)\s*\}\}")
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/")
SHA = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = {"actions", "github"}
MOVING_REFS = {"main", "master", "dev", "develop", "latest", "head", "trunk"}

RULES = {
    "unpinned-action": ("security",
        "A tag or branch can be moved to different code at any time (as in the 2025 tj-actions/changed-files compromise); "
        "only a full commit SHA is immutable.",
        "Pin to the full 40-character commit SHA and keep the tag as a comment: `uses: {action}@<sha> # {ref}`; let Dependabot/Renovate update it."),
    "pr-target-checkout": ("security",
        "`pull_request_target` runs with a write token and repository secrets; checking out and building the PR head runs untrusted fork code with them.",
        "Use `pull_request` for building/testing PR code. If `pull_request_target` is needed (labels, comments), never check out or run the PR head; "
        "split untrusted work into a `pull_request` workflow and pass results via `workflow_run`."),
    "script-injection": ("security",
        "User-controlled text (PR title/body, branch name, comments) is pasted into the shell script before it runs, so a crafted title can run commands with the job's token.",
        "Pass it through an environment variable and quote it: `env: TITLE: ${{ github.event.pull_request.title }}` then use \"$TITLE\" in the script."),
    "secret-echo": ("security",
        "The script prints a secret. Masking is best-effort (it fails for transformed, split or encoded values) and the value can end up in logs and artifacts.",
        "Remove the echo. If a value must be checked, print its length or a hash prefix, never the value. Rotate the secret if it has already been logged."),
    "secret-in-command-line": ("security",
        "The secret is pasted into the command line, where it is visible in the process list, shell history, `set -x` traces and tool error messages.",
        "Map it into the step's environment (`env:`) and read it from the variable, or pipe it (`--password-stdin`)."),
    "plaintext-secret": ("security",
        "A secret-looking value is committed in the YAML in plain text: anyone with read access to the repository (and its history) has it.",
        "Move it to a secret store (Azure Key Vault-linked variable group or secret variable; GitHub encrypted secret or environment secret), "
        "reference it as $(Name) / ${{ secrets.NAME }}, and rotate the exposed value."),
    "write-all-permissions": ("security",
        "`write-all` gives the GITHUB_TOKEN write access to everything (contents, packages, deployments...), so any compromised step can push code or releases.",
        "Declare only what the job needs, e.g. `permissions: contents: read` at the top and `pull-requests: write` on the one job that comments."),
    "missing-permissions": ("security",
        "Without a top-level `permissions:` block the GITHUB_TOKEN gets the repository/organisation default, which is often read-write for everything.",
        "Add `permissions: contents: read` at the top of the workflow and grant extra scopes per job."),
    "az-login-secret": ("security",
        "Logging in with a client secret means a long-lived secret must be stored, rotated and can leak; it also expires and breaks deployments.",
        "Use workload identity federation: an Azure Resource Manager service connection with federation (AzureCLI@2 with that connection), "
        "or azure/login with client-id, tenant-id and subscription-id plus `permissions: id-token: write` (OIDC)."),
    "continue-on-error": ("reliability",
        "The test/security step can fail without failing the run, so broken tests or findings reach main unnoticed.",
        "Remove continueOnError / continue-on-error. If the check is new and noisy, make it a separate, clearly non-blocking job with an owner and a date to enforce it."),
    "swallowed-failure": ("reliability",
        "`|| true` (or `|| exit 0`) after a test/lint/scan command turns every failure into success.",
        "Remove the `|| true`. If only some exit codes are acceptable, handle them explicitly."),
    "set-plus-e": ("reliability",
        "Turning off fail-on-error means later failing commands in the script are ignored and the step still passes.",
        "Keep `set -e` (and `set -o pipefail`); for a command that may fail, handle it explicitly (`if ! cmd; then ...; fi`)."),
    "legacy-peer-deps": ("reliability",
        "`--legacy-peer-deps` skips peer-dependency checks, so incompatible versions install silently and fail later at runtime.",
        "Resolve the conflict (align the versions) and commit the regenerated lockfile; if a workaround is unavoidable, document it with an owner and a removal date."),
    "no-verify": ("reliability",
        "`--no-verify` skips git hooks (lint, secret scanning, signing checks) for commits or pushes made by the pipeline.",
        "Remove `--no-verify`, or run the same checks explicitly in the pipeline before committing."),
    "missing-timeout": ("reliability",
        "Without a timeout a hung job holds an agent until the platform limit (360 minutes on GitHub; 60 minutes on Microsoft-hosted, unlimited on self-hosted Azure agents).",
        "Set `timeout-minutes:` on each GitHub job / `timeoutInMinutes:` on each Azure job, a little above the normal duration."),
    "floating-image": ("reproducibility",
        "`*-latest` images move to a new OS version without notice, changing preinstalled tools and breaking builds on a date you do not choose.",
        "Pin the image version (e.g. ubuntu-24.04, windows-2022) and upgrade deliberately."),
}
SEV = {"pr-target-checkout": "high", "script-injection": "high", "secret-echo": "high", "secret-in-command-line": "high",
       "plaintext-secret": "high", "write-all-permissions": "medium", "missing-permissions": "medium",
       "az-login-secret": "medium", "continue-on-error": "medium", "swallowed-failure": "medium", "set-plus-e": "medium",
       "legacy-peer-deps": "medium", "no-verify": "medium", "missing-timeout": "low", "floating-image": "low"}


def strip_comment(s):
    quote = None
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def unquote(v):
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def model(text):
    """One dict per line: no, raw, kind (blank|comment|key|item|cont|block), indent, col, key, value,
    parents (tuple of enclosing keys), owner (key owning a block/continuation), script (bool)."""
    out, stack, block = [], [], None  # stack: [(col, key)]; block: (owner_col, owner_key, parents)
    for no, raw in enumerate(text.splitlines(), 1):
        raw = raw.rstrip("\r").replace("\t", "    ")
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        rec = {"no": no, "raw": raw, "indent": indent, "col": indent, "key": None, "value": None,
               "parents": tuple(k for _, k in stack), "owner": None, "script": False, "kind": "blank"}
        if block is not None:
            if not body or indent > block[0]:
                rec.update(kind="block", text=body, owner=block[1], parents=block[2],
                           script=block[1].lower() in SCRIPT_KEYS)
                out.append(rec)
                continue
            block = None
        if not body:
            out.append(rec)
            continue
        if body.startswith("#"):
            rec["kind"] = "comment"
            out.append(rec)
            continue
        code = strip_comment(body)
        is_item = code == "-" or code.startswith("- ")
        rest = code[1:].lstrip() if is_item else code
        col = indent + (len(code) - len(rest)) if is_item else indent
        m = KEY.match(rest)
        if is_item:
            while stack and stack[-1][0] > indent:
                stack.pop()
        elif m:
            while stack and stack[-1][0] >= col:
                stack.pop()
        else:  # continuation of a multi-line plain scalar, or a flow sequence line
            owner = stack[-1][1] if stack and indent > stack[-1][0] else None
            rec.update(kind="cont", text=code, owner=owner, script=bool(owner and owner.lower() in SCRIPT_KEYS))
            out.append(rec)
            continue
        parents = tuple(k for _, k in stack)
        rec.update(kind="item" if is_item else "key", col=col, parents=parents, text=code)
        if m:
            key, value = unquote(m.group("key")), (m.group("value") or "").strip()
            rec.update(key=key, value=value, script=key.lower() in SCRIPT_KEYS and not BLOCK.match(value))
            stack.append((col, key))
            if BLOCK.match(value):
                block = (col, key, parents + (key,))
        else:
            rec["value"] = rest
        out.append(rec)
    return out


def spans(lines, parent_key):
    """[(start_index, end_index_exclusive)] for list items directly under `parent_key:`."""
    res = []
    for i, l in enumerate(lines):
        if l["kind"] == "item" and l["parents"] and l["parents"][-1] == parent_key:
            j = i + 1
            while j < len(lines):
                n = lines[j]
                if n["kind"] not in ("blank", "comment", "block") and n["indent"] <= l["indent"]:
                    break
                j += 1
            res.append((i, j))
    return res


def gh_jobs(lines):
    """GitHub jobs: [(start, end)] for keys directly under the top-level `jobs:`."""
    res = []
    for i, l in enumerate(lines):
        if l["kind"] == "key" and l["parents"] == ("jobs",):
            j = i + 1
            while j < len(lines) and not (lines[j]["kind"] in ("key", "item") and lines[j]["indent"] <= l["indent"]):
                j += 1
            res.append((i, j))
    return res


def span_code(lines, a, b):
    return "\n".join(l.get("text") or "" for l in lines[a:b] if l["kind"] not in ("blank", "comment"))


def enclosing(spans_list, idx):
    best = None
    for a, b in spans_list:
        if a <= idx < b and (best is None or a > best[0]):
            best = (a, b)
    return best


def is_secret_name(name):
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    if "connectionstring" in n:
        return True
    if re.search(r"(^|[_\-.])pat$|[a-z]Pat$|^pat$", name, re.I):
        return True
    return n.endswith(("password", "passwd", "pwd", "secret", "token", "apikey", "accesskey", "privatekey",
                       "clientsecret", "sastoken", "credential", "credentials"))


def is_literal(value):
    v = unquote(value)
    if not v or BLOCK.match(v) or v.startswith(("$", "<", "{", "[")) or "$(" in v or "${{" in v or "$[" in v:
        return False
    return v.lower() not in ("true", "false", "yes", "no", "null", "~", "none", "''", '""') and len(v) >= 4


def detect_platform(path, lines):
    p = path.as_posix()
    if "/.github/workflows/" in "/" + p:
        return "github"
    top = {l["key"] for l in lines if l["kind"] == "key" and not l["parents"]}
    if "runs-on" in {l["key"] for l in lines if l["key"]} or ("on" in top and "jobs" in top):
        return "github"
    return "azure"


def review_text(text, path, redactor=None, display=None):
    red = redactor or Redactor()
    path = Path(path)
    shown = display or path.as_posix()
    lines = model(text)
    platform = detect_platform(path, lines)
    findings = []

    def ignored(idx, rule):
        for l in lines[max(0, idx - 1):idx + 1]:
            m = re.search(r"pipeline-doctor:\s*ignore\b(?P<ids>[\w\s,-]*)", l["raw"])
            if m and (not m.group("ids").strip() or rule in re.split(r"[\s,]+", m.group("ids").strip())):
                return True
        return False

    def add(rule, idx, evidence=None, severity=None, **fmt):
        if ignored(idx, rule):
            return
        cat, why, fix = RULES[rule]
        for k, v in fmt.items():
            fix = fix.replace("{" + k + "}", v)
        l = lines[idx]
        ev = evidence if evidence is not None else l["raw"].strip()
        findings.append({"rule": rule, "severity": severity or SEV[rule], "category": cat,
                         "file": shown, "line": l["no"], "platform": platform,
                         "evidence": red.redact(ev)[:200], "why": why, "fix": fix})

    steps = spans(lines, "steps")
    jobs = gh_jobs(lines) if platform == "github" else spans(lines, "jobs")
    script_lines = [(i, l) for i, l in enumerate(lines) if l["script"]]

    # ---- actions pinning, triggers, permissions (GitHub)
    if platform == "github":
        for i, l in enumerate(lines):
            if l["key"] == "uses":
                v = unquote(l["value"])
                m = re.match(r"^(?P<action>(?P<owner>[\w.-]+)/[\w./-]+)@(?P<ref>[\w./-]+)$", v)
                if m and not SHA.match(m.group("ref")):
                    sev = "low" if m.group("owner").lower() in FIRST_PARTY and m.group("ref").lower() not in MOVING_REFS else "medium"
                    add("unpinned-action", i, severity=sev, action=m.group("action"), ref=m.group("ref"))
        on_target = any(
            (l["key"] == "on" and "pull_request_target" in (l["value"] or ""))
            or (l["key"] == "pull_request_target" and l["parents"][:1] == ("on",))
            or (l["kind"] == "item" and l["parents"] == ("on",) and "pull_request_target" in (l["value"] or ""))
            for l in lines)
        if on_target:
            for i, l in enumerate(lines):
                code = l.get("text") or ""
                if HEAD_REF.search(code) and ((l["key"] == "ref" and "with" in l["parents"]) or l["script"]):
                    add("pr-target-checkout", i)
        top = [l for l in lines if l["kind"] == "key" and not l["parents"]]
        if not any(l["key"] == "permissions" for l in top):
            job_perms = [any(lines[k]["key"] == "permissions" and lines[k]["parents"][-1:] == (lines[a]["key"],)
                             for k in range(a, b)) for a, b in jobs]
            if not (jobs and all(job_perms)):
                anchor = next((k for k, l in enumerate(lines) if l["key"] == "on" and not l["parents"]), 0)
                add("missing-permissions", anchor, evidence="(no top-level permissions: block)")
        for i, l in enumerate(lines):
            if l["key"] == "permissions" and unquote(l["value"]).lower() == "write-all":
                add("write-all-permissions", i)
            if l["key"] == "creds" and "with" in l["parents"]:
                step = enclosing(steps, i)
                if step and re.search(r"azure/login@", span_code(lines, *step), re.I):
                    add("az-login-secret", i, evidence="creds: <service principal secret JSON>")

    # ---- scripts
    for i, l in script_lines:
        code = l["text"] if l["kind"] != "key" else l["value"]
        if platform == "github" and INJECTION.search(code):
            add("script-injection", i)
        refs = SECRET_REF_GH.search(code) or SECRET_REF_AZ.search(code) or SECRET_REF_ENV.search(code)
        if refs and not MASKING.search(code):
            if ECHO.search(code):
                add("secret-echo", i)
            elif SECRET_REF_GH.search(code) or SECRET_REF_AZ.search(code):
                add("secret-in-command-line", i)
        if re.search(r"--legacy-peer-deps\b", code):
            add("legacy-peer-deps", i)
        if re.search(r"\|\|\s*(true|:|exit 0)\b", code) and TEST_SEC.search(code):
            add("swallowed-failure", i)
        if re.search(r"(?<![\w-])--no-verify\b", code):
            add("no-verify", i)
        if re.search(r"(^|[;&]\s*)set \+e\b|set \+o errexit|\$ErrorActionPreference\s*=\s*['\"]?(SilentlyContinue|Continue|Ignore)\b", code, re.I):
            add("set-plus-e", i)
        if re.search(r"\baz login\b", code) and "--service-principal" in code \
                and re.search(r"(\s-p\s|\s-p=|--password|--client-secret)", code + " "):
            add("az-login-secret", i)
        if re.search(r"Connect-AzAccount\b.*-ServicePrincipal\b.*-Credential\b|Connect-AzAccount\b.*-Credential\b.*-ServicePrincipal\b", code, re.I):
            add("az-login-secret", i)

    # ---- continue on error for tests / security
    for i, l in enumerate(lines):
        if l["key"] in ("continueOnError", "continue-on-error") and unquote(l["value"]).lower() == "true":
            unit = enclosing(steps, i) or enclosing(jobs, i)
            code = span_code(lines, *unit) if unit else ""
            if TEST_SEC.search(code) and not PUBLISH_ONLY.search(code):
                add("continue-on-error", i)

    # ---- plain-text secrets in variables / env / inputs
    holders = {"variables", "env", "with", "inputs"}
    for i, l in enumerate(lines):
        if not l["parents"] or l["kind"] not in ("key", "item"):
            continue
        if l["kind"] == "key" and l["parents"][-1] in holders and l["key"] and is_secret_name(l["key"]) and is_literal(l["value"]):
            add("plaintext-secret", i, evidence=f"{l['key']}: <redacted>")
        # Azure list form:  - name: DbPassword  /  value: literal
        if l["key"] == "value" and l["kind"] == "key" and l["parents"][-1] == "variables" and is_literal(l["value"]):
            item = next((lines[k] for k in range(i - 1, max(-1, i - 6), -1) if lines[k]["kind"] == "item"), None)
            if item and item["key"] == "name" and item["parents"] == l["parents"] and is_secret_name(unquote(item["value"])):
                add("plaintext-secret", i, evidence=f"{unquote(item['value'])} value: <redacted>")

    # ---- timeouts
    if platform == "github":
        for a, b in jobs:
            keys = {lines[k]["key"] for k in range(a, b) if lines[k]["parents"][-1:] == (lines[a]["key"],)}
            if "uses" not in keys and "timeout-minutes" not in keys:
                add("missing-timeout", a)
    else:
        top = {l["key"]: k for k, l in enumerate(lines) if l["kind"] == "key" and not l["parents"]}
        az_jobs = [(a, b) for a, b in jobs if lines[a]["key"] in ("job", "deployment")]
        for a, b in az_jobs:
            keys = {lines[k]["key"] for k in range(a, b) if lines[k]["indent"] <= lines[a]["col"] and lines[k]["key"]}
            if "timeoutInMinutes" not in keys:
                add("missing-timeout", a)
        is_template = "steps" in top and not ({"trigger", "pr", "pool", "schedules", "resources", "name"} & set(top))
        if "steps" in top and "jobs" not in top and "stages" not in top and not is_template:
            add("missing-timeout", top["steps"], evidence="steps: (single implicit job, no timeoutInMinutes)")

    # ---- floating images
    for i, l in enumerate(lines):
        if l["key"] in ("vmImage", "runs-on") and re.search(r"-latest\b", l["value"] or ""):
            add("floating-image", i)
        elif l["kind"] == "item" and l["parents"][-1:] == ("runs-on",) and re.search(r"-latest\b", l["value"] or ""):
            add("floating-image", i)

    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    return findings


def discover(paths):
    files = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            files.append(p)
            continue
        for f in sorted(p.rglob("*")):
            parts = set(f.parts)
            if not f.is_file() or f.suffix.lower() not in (".yml", ".yaml") or parts & {".git", "node_modules"}:
                continue
            rel = f.relative_to(p).as_posix()
            if "/.github/workflows/" in "/" + rel or f.name.lower().startswith("azure-pipelines") \
                    or re.search(r"(^|/)\.?(azure-)?pipelines/", rel):
                files.append(f)
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def review(paths, redactor=None, base=None):
    red = redactor or Redactor()
    results, files, shown = [], discover(paths), []
    for f in files:
        name = (f.relative_to(base) if base and Path(base) in f.parents else f).as_posix()
        shown.append(name)
        results += review_text(f.read_text(encoding="utf-8-sig", errors="replace"), f, red, display=name)
    results.sort(key=lambda r: (r["file"], r["line"], r["rule"]))
    counts = {s: sum(1 for r in results if r["severity"] == s) for s in ("high", "medium", "low")}
    return {"files": shown, "summary": counts, "findings": results}


def to_markdown(res):
    c = res["summary"]
    L = ["# Pipeline Doctor - YAML health check", "",
         f"Files: {len(res['files'])}. Findings: **{c['high']} high, {c['medium']} medium, {c['low']} low**.", ""]
    if not res["findings"]:
        L.append("No findings.")
    else:
        L += ["| Severity | Rule | Where | Evidence |", "|---|---|---|---|"]
        for f in res["findings"]:
            L.append(f"| {f['severity']} | `{f['rule']}` | {f['file']}:{f['line']} | `{f['evidence'][:90]}` |")
        L += ["", "## Why and how to fix", ""]
        worst = {}
        for f in res["findings"]:
            worst[f["rule"]] = max(worst.get(f["rule"], 0), SEVERITY[f["severity"]])
        names = {v: k for k, v in SEVERITY.items()}
        for rule in sorted(worst, key=lambda r: (-worst[r], r)):
            hits = [f for f in res["findings"] if f["rule"] == rule]
            fixes = sorted({f["fix"] for f in hits})
            L += [f"### `{rule}` ({names[worst[rule]]}, {len(hits)}x): " + ", ".join(f"{f['file']}:{f['line']}" for f in hits), "",
                  f"- Why: {hits[0]['why']}"] + [f"- Fix: {x}" for x in fixes] + [""]
    L += ["---", "Secret values are never shown. Read-only review: propose the fixes as a pull request."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Security and reliability review of pipeline YAML.")
    ap.add_argument("paths", nargs="+", help="pipeline YAML files or a repository folder")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 1 if a finding at or above this severity exists")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    base = a.paths[0] if len(a.paths) == 1 and Path(a.paths[0]).is_dir() else None
    res = review(a.paths, base=base)
    sys.stdout.write(json.dumps(res, indent=2) + "\n" if a.json else to_markdown(res))
    if a.fail_on and any(SEVERITY[f["severity"]] >= SEVERITY[a.fail_on] for f in res["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

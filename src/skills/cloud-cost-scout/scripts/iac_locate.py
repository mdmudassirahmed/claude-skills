#!/usr/bin/env python3
"""iac_locate - find where each Cloud Cost Scout finding is defined in infrastructure-as-code.

Takes the report JSON written by cost_scout.py and a repository folder, and lists per finding
the Bicep, ARM template, Terraform and CloudFormation files (with line numbers) that mention the
resource name. Use it to prepare a pull request that changes the IaC; it never applies anything.

Matching is by whole name (case-insensitive): "vm-web-dev" matches `name: 'vm-web-dev'` but not
"vm-web-dev-2". Names built from variables (e.g. 'vm-${app}-dev') cannot be found this way; the
report lists those findings under "not found" so a person can look.

Usage:
  python iac_locate.py cost-scout-report/cost-scout-report.json path/to/repo          # markdown
  python iac_locate.py cost-scout-report/ path/to/repo --json                         # JSON
  python iac_locate.py report.json repo --out-dir cost-scout-report                   # iac-locations.md + .json
Standard library only; Python 3.8+.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

EXCLUDED_DIRS = {".git", "node_modules", ".terraform", "bin", "obj", "__pycache__", ".venv", "venv"}
MAX_BYTES = 2 * 1024 * 1024
MIN_NAME_LEN = 3


def iac_kind(path, text):
    """'bicep' | 'arm' | 'terraform' | 'cloudformation' | None."""
    suffix = path.suffix.lower()
    if suffix in (".bicep", ".bicepparam"):
        return "bicep"
    if suffix in (".tf", ".tfvars") or path.name.lower().endswith(".tf.json"):
        return "terraform"
    if suffix == ".json":
        if re.search(r'"\$schema"\s*:\s*"[^"]*deploymentTemplate', text, re.I):
            return "arm"
        if re.search(r'"AWSTemplateFormatVersion"|"Type"\s*:\s*"AWS::', text):
            return "cloudformation"
        return None
    if suffix in (".yaml", ".yml", ".template"):
        if re.search(r"^\s*AWSTemplateFormatVersion\s*:|^\s*Type\s*:\s*['\"]?AWS::", text, re.M):
            return "cloudformation"
    return None


def iac_files(repo):
    """Yield (relative posix path, kind, lines) for IaC files, skipping excluded folders."""
    repo = Path(repo)
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d.lower() not in EXCLUDED_DIRS)
        for name in sorted(files):
            p = Path(root) / name
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            kind = iac_kind(p, text)
            if kind:
                yield p.relative_to(repo).as_posix(), kind, text.splitlines()


def search_terms(finding):
    terms = []
    for t in (finding.get("name"), (finding.get("evidence") or {}).get("workspace")):
        t = str(t or "").strip()
        if "/" in t:  # e.g. "law-dev/ContainerLogV2": the workspace and the table
            terms += [x for x in t.split("/") if x]
        elif t:
            terms.append(t)
    out = []
    for t in terms:
        if len(t) >= MIN_NAME_LEN and t.lower() not in [x.lower() for x in out]:
            out.append(t)
    return out


def term_regex(term):
    return re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(term) + r"(?![A-Za-z0-9_-])", re.I)


def load_report(path):
    p = Path(path)
    if p.is_dir():
        p = p / "cost-scout-report.json"
    data = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{p}: not a cost_scout report (no findings list)")
    return data


def locate(report, repo):
    files = list(iac_files(repo))
    results, not_found = [], []
    for f in report["findings"]:
        terms = search_terms(f)
        regexes = [(t, term_regex(t)) for t in terms]
        matches = []
        for rel, kind, lines in files:
            hit_lines, hit_terms = [], set()
            for i, line in enumerate(lines, 1):
                for t, rx in regexes:
                    if rx.search(line):
                        hit_lines.append(i)
                        hit_terms.add(t)
                        break
            if hit_lines:
                matches.append({"file": rel, "kind": kind, "lines": hit_lines, "terms": sorted(hit_terms)})
        entry = {"name": f.get("name"), "resource_id": f.get("resource_id"), "category": f.get("category"),
                 "check": f.get("check"), "title": f.get("title"), "action": f.get("action"),
                 "search_terms": terms, "matches": matches}
        results.append(entry)
        if not matches:
            not_found.append(f.get("name"))
    kinds = {}
    for _, kind, _ in files:
        kinds[kind] = kinds.get(kind, 0) + 1
    return {"repo": str(repo), "iac_files_scanned": len(files), "iac_files_by_kind": dict(sorted(kinds.items())),
            "excluded_dirs": sorted(EXCLUDED_DIRS), "results": results, "not_found": not_found,
            "note": "Locations only. Prepare the change as a pull request for the owning team; never apply it "
                    "from here."}


def to_markdown(r):
    lines = ["# Where the findings live in IaC", "",
             f"_{r['iac_files_scanned']} IaC file(s) scanned in `{r['repo']}` "
             f"({', '.join(f'{k}: {v}' for k, v in r['iac_files_by_kind'].items()) or 'none'})._", ""]
    found = [x for x in r["results"] if x["matches"]]
    if found:
        lines += ["| Resource | Finding | File | Lines | Kind |", "|---|---|---|---|---|"]
        for x in found:
            for m in x["matches"]:
                lines.append(f"| `{x['name']}` | {x['title']} | `{m['file']}` | "
                             f"{', '.join(str(n) for n in m['lines'])} | {m['kind']} |")
    else:
        lines.append("No finding's resource name appears in the IaC files.")
    if r["not_found"]:
        lines += ["", "Not found (the name may be built from variables, or the resource was created outside IaC): "
                  + ", ".join(f"`{n}`" for n in r["not_found"])]
    lines += ["", "---", "Use these locations to prepare a pull request with the IaC change for the owning team. "
                  "Nothing was changed."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find the IaC files that define each cost finding's resource.")
    ap.add_argument("report", help="cost-scout-report.json (or the folder that contains it)")
    ap.add_argument("repo", help="repository folder to search")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--out-dir", help="write iac-locations.md and iac-locations.json here")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not Path(a.repo).is_dir():
        sys.stderr.write(f"repository folder not found: {a.repo}\n")
        return 2
    try:
        report = load_report(a.report)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"cannot read report: {e}\n")
        return 2
    result = locate(report, a.repo)
    if a.out_dir:
        os.makedirs(a.out_dir, exist_ok=True)
        Path(a.out_dir, "iac-locations.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        Path(a.out_dir, "iac-locations.md").write_text(to_markdown(result), encoding="utf-8")
        print(f"wrote {a.out_dir}/iac-locations.md and .json")
    else:
        sys.stdout.write(json.dumps(result, indent=2) + "\n" if a.json else to_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())

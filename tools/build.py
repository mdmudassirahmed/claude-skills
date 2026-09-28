#!/usr/bin/env python3
"""Build the installable plugins in plugins/ and the marketplace manifest from src/.

src/ is the single source of truth:
  src/skills/<skill>/     SKILL.md, references/, scripts/   (one folder per skill)
  src/shared/redact.py    copied into the scripts/ of every skill that needs it
  src/hooks/              read-only guard hook, added to plugins whose skills touch the cloud

Generated (committed, so the marketplace can install straight from git):
  plugins/ops-toolkit/       bundle: every skill + guard hook
  plugins/<skill>/           one plugin per skill, so each can be installed on its own
  .claude-plugin/marketplace.json

Idempotent: files are only written when their content changes, and stale files are
removed. `--check` writes nothing and exits 1 if anything is out of date (used in CI).

Usage:  python tools/build.py [--check]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
OUT = ROOT / "plugins"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

MARKETPLACE = "claude-skills"
BUNDLE = "ops-toolkit"
OWNER = {"name": "Mudassir Ahmed Mohammad", "url": "https://github.com/mdmudassirahmed"}
HOMEPAGE = "https://github.com/mdmudassirahmed/claude-skills"

NEEDS_REDACT = {"log-detective", "pipeline-doctor"}
TOUCHES_CLOUD = {"cloud-cost-scout", "log-detective", "pipeline-doctor"}

SKILL_BLURBS = {
    "cloud-cost-scout": "Find cloud waste and cost optimisations in Azure or AWS from read-only exports: idle resources, right-sizing, non-prod schedules, logging costs, cheaper rates, storage tiering, why the bill changed, untagged spend, and where to change it in your IaC. Never changes resources.",
    "log-detective": "Diagnose incidents from App Insights / Log Analytics / CloudWatch / GCP or log files: when it started, new errors, latency, the deploy or infrastructure change just before, platform outages, blast radius, a suggested alert and a postmortem draft. Read-only.",
    "pipeline-doctor": "Diagnose and improve Azure Pipelines / GitHub Actions: the root error behind a red run, flaky vs regression vs recurring failures, slow steps and caching, and a security and reliability review of the pipeline YAML. Read-only on CI.",
    "bug-resolve": "Fix an ordinary bug properly: failing test first, root cause not symptom, smallest fix, fail-before / pass-after proof, the same bug found elsewhere, and a guardrail so it can't come back.",
    "ops-digest": "Turn the reports from the other skills into one short weekly summary for a manager, as markdown and a single HTML page. Every number comes from a report; nothing is invented.",
}
BUNDLE_DESC = ("All five ops skills in one install: cloud cost scan and optimisation, incident diagnosis from logs, "
               "CI/CD triage and health checks, bug fixing with proof, and a weekly digest. Read-only, with a guard "
               "hook that blocks cloud changes and secret reads.")
GUARD_NOTE = " Includes the read-only guard hook."


def plan():
    """Return {relative_path: bytes} for everything the build owns."""
    files = {}
    skills = sorted(p.name for p in (SRC / "skills").iterdir() if p.is_dir())
    unknown = set(skills) ^ set(SKILL_BLURBS)
    if unknown:
        sys.exit(f"skills and SKILL_BLURBS disagree: {sorted(unknown)}")

    def add_skill(plugin, skill):
        base = SRC / "skills" / skill
        for f in sorted(base.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                files[f"plugins/{plugin}/skills/{skill}/{f.relative_to(base).as_posix()}"] = f.read_bytes()
        if skill in NEEDS_REDACT:
            files[f"plugins/{plugin}/skills/{skill}/scripts/redact.py"] = (SRC / "shared" / "redact.py").read_bytes()

    def add_hooks(plugin):
        for f in sorted(p for p in (SRC / "hooks").iterdir() if p.is_file() and p.suffix != ".pyc"):
            files[f"plugins/{plugin}/hooks/{f.name}"] = f.read_bytes()

    def manifest(plugin, description):
        doc = {"name": plugin, "description": description, "version": VERSION,
               "author": OWNER, "homepage": HOMEPAGE, "license": "MIT", "skills": ["./skills/"]}
        files[f"plugins/{plugin}/.claude-plugin/plugin.json"] = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode()

    entries = []
    # bundle
    for s in skills:
        add_skill(BUNDLE, s)
    add_hooks(BUNDLE)
    manifest(BUNDLE, BUNDLE_DESC)
    entries.append({"name": BUNDLE, "source": f"./plugins/{BUNDLE}", "description": BUNDLE_DESC, "version": VERSION})
    # one plugin per skill
    for s in skills:
        desc = SKILL_BLURBS[s] + (GUARD_NOTE if s in TOUCHES_CLOUD else "")
        add_skill(s, s)
        if s in TOUCHES_CLOUD:
            add_hooks(s)
        manifest(s, desc)
        entries.append({"name": s, "source": f"./plugins/{s}", "description": desc, "version": VERSION})

    market = {"name": MARKETPLACE, "owner": OWNER,
              "metadata": {"description": "Practical Claude Code skills for keeping live systems healthy: cost, logs, pipelines and bugs.",
                           "version": VERSION},
              "plugins": entries}
    files[".claude-plugin/marketplace.json"] = (json.dumps(market, indent=2, ensure_ascii=False) + "\n").encode()
    return files


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if generated files are out of date")
    a = ap.parse_args(argv)
    want = plan()
    existing = ({p.relative_to(ROOT).as_posix() for p in OUT.rglob("*")
                 if p.is_file() and "__pycache__" not in p.parts} if OUT.exists() else set())
    changed = [p for p, data in want.items() if not (ROOT / p).exists() or (ROOT / p).read_bytes() != data]
    stale = sorted(existing - {p for p in want if p.startswith("plugins/")})
    if a.check:
        for p in changed:
            print(f"out of date: {p}")
        for p in stale:
            print(f"stale: {p}")
        if changed or stale:
            print("Run: python tools/build.py")
            return 1
        print(f"plugins up to date ({len(want)} files, version {VERSION})")
        return 0
    for p in changed:
        dest = ROOT / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(want[p])
    for p in stale:
        (ROOT / p).unlink()
    for d in sorted((x for x in OUT.rglob("*") if x.is_dir() and "__pycache__" not in x.parts),
                    key=lambda x: -len(x.parts)):
        if not any(d.iterdir()):
            d.rmdir()
    print(f"built {len(want)} files: {len(changed)} written, {len(stale)} removed (version {VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

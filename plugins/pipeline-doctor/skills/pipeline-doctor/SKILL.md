---
name: pipeline-doctor
description: Diagnoses failed CI/CD runs in Azure Pipelines or GitHub Actions - reads the failed log, finds the root error (not the "exit code 1" cascade), explains it in plain words, says who can fix it (developer, pipeline admin, platform team), and proposes the fix as a pull request when it is in the repo. Use when the user says "the pipeline/build is red", "why did the build fail", "fix the failing pipeline", "CI is broken", "release failed", or pastes a pipeline log or run URL. Read-only - never re-runs, cancels, approves or edits pipelines, service connections or variables.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Pipeline Doctor

Red pipeline → one plain-English cause → the right person fixes it (usually via a small PR).

## Non-negotiable rules

1. **Read-only on the CI system.** Never queue/re-run/cancel runs, approve stages, edit variables, variable groups, service connections, or environments. The bundled guard hook blocks `az pipelines run`, mutating `az devops invoke`, and write calls to the DevOps/GitHub APIs.
2. **Secrets stay secret.** Logs are redacted before analysis. If a log shows a secret in clear text, flag it as a **security issue** (it must be rotated) - don't repeat the value.
3. **Fix in code, not in the pipeline UI.** Repo-side fixes (YAML, lockfiles, code, tests) become a pull request. Anything needing admin rights (service connections, feed permissions, agent images) becomes a clear request to the named owner.

## Step 1 - Get the failed log

- **Pasted log / downloaded file** - use it directly.
- **Azure Pipelines (Tier 1, read-only identity):**
  ```bash
  az pipelines runs list --pipeline-ids <id> --result failed --top 5 -o table      # find the run
  az devops invoke --area build --resource logs --route-parameters project=<project> buildId=<runId> \
      --api-version 7.1 -o json > logs-index.json                                    # list logs
  az devops invoke --area build --resource logs --route-parameters project=<project> buildId=<runId> logId=<n> \
      --api-version 7.1 --accept-media-type text/plain > run.log                     # the failing step's log
  ```
  Or in the UI: run → ⋯ → **Download logs** (zip; use the failing step's file).
- **GitHub Actions:** `gh run list --status failure -L 5` then `gh run view <run-id> --log-failed > run.log`.

## Step 2 - Diagnose

```bash
python "<skill-dir>/scripts/pipeline_triage.py" run.log
```

(`<skill-dir>` = this skill's base directory, shown when the skill loads.) It reports the **diagnosis** (id, category, confidence, fix owner), the **failing step and log line**, **failing test names** when tests failed, other signals, and a redacted excerpt. The failure library is `references/failure-signatures.json` (~40 known causes).

When the diagnosis is **unknown** or **low confidence**, read the excerpt and the first real error yourself, reason about it, and say so explicitly.

## Step 3 - Confirm against the repo

Before proposing a fix, check the diagnosis against the code:

- **Dependency / lockfile / toolchain:** open `package.json` + lockfile, `.csproj` / `Directory.Packages.props`, `global.json`, `.nvmrc`, `requirements.txt`, and the pipeline YAML. What changed in the last commits (`git log -5 -- <file>`)?
- **Compile errors:** open the file and line from the diagnosis.
- **Test failures:** is it a **regression** or **flaky**? Check the same test in the last few runs (Tier 1: `az pipelines runs list` / `gh run list` + their logs). Passing and failing on the same commit = flaky; failing since a specific commit = regression → hand to **bug-resolve** with the test name.
- **Auth / service connection / feed / agent image:** not fixable in the repo - prepare the request for the owner.

## Step 4 - Fix or route

| Owner in diagnosis | What you do |
|---|---|
| **developer** | Make the minimal fix in a branch (YAML pin, lockfile regenerate, code/test fix), run the relevant command locally if possible (`npm ci`, `dotnet build`, `pytest`), and open a PR titled `fix(ci): <diagnosis title>` explaining cause + evidence (log line). |
| **pipeline-admin** | Write a short, copy-paste request: what failed, the exact error code (e.g. AADSTS7000222), which service connection/feed, and the fix (prefer **workload identity federation** over secrets). |
| **platform-team** | Same, for agent images, Docker mirrors, firewall/DNS, disk, RBAC roles - include the least-privilege role needed. |

Never "fix" by weakening a gate (disabling tests, lowering coverage, `--force`, `continueOnError: true`) unless the user explicitly decides to, and then record it as a follow-up.

## Step 5 - Report

```
Pipeline: <name> run <id> - FAILED at step "<step>"
Cause (<confidence>): <diagnosis title> - <one-sentence why>
Evidence: log line <n>: `<redacted line>`
Fix owner: <developer | pipeline-admin | platform-team>
Fix: <PR link/branch, or the request text for the owner>
Prevent: <e.g. pin tool version, add retry for network step, federation instead of secret>
```

## Extending the library

When you meet a new recurring failure, add an entry to `references/failure-signatures.json` (id, category, weight, confidence, pattern, title, why, fix, owner) with a test log under the repository's `tests/fixtures/pipelines/` - the test suite checks every placeholder and field.

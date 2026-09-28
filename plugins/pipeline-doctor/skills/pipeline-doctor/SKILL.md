---
name: pipeline-doctor
description: Diagnoses failed CI/CD runs in Azure Pipelines or GitHub Actions - reads the failed log, finds the root error (not the "exit code 1" cascade), explains it in plain words, says who can fix it (developer, pipeline admin, platform team), and proposes the fix as a pull request when it is in the repo. Uses run history to tell a flaky test from a real regression (first bad and last good commit) or a recurring cause, and runs a health check even on green pipelines - slowest steps with estimated minutes saved (caching, shallow checkout, sharding) and a YAML security and reliability review (unpinned actions, secrets in YAML, pull_request_target, missing timeouts). Use when the user says "the pipeline/build is red", "why did the build fail", "is this test flaky", "fix the failing pipeline", "CI is broken", "release failed", "why is the pipeline slow", "review our pipeline YAML", or pastes a pipeline log or run URL. Read-only - never re-runs, cancels, approves or edits pipelines, service connections or variables.
user-invocable: true
compatibility: Claude Code (agent skills SKILL.md format). Helper scripts need Python 3.8+ and run on Windows, macOS and Linux.
---

# Pipeline Doctor

Red pipeline → one plain-English cause → the right person fixes it (usually via a small PR).
Green pipeline → a health check: what makes it slow, and what in the YAML is risky.

## Non-negotiable rules

1. **Read-only on the CI system.** Never queue/re-run/cancel runs, approve stages, edit variables, variable groups, service connections, or environments. The bundled guard hook blocks `az pipelines run`, mutating `az devops invoke`, and write calls to the DevOps/GitHub APIs. Every command in this skill only reads (`runs list`, `runs show`, `run view`, and `az devops invoke` with its default GET).
2. **Secrets stay secret.** Logs and YAML excerpts are redacted before analysis. If a log or YAML file shows a secret in clear text, flag it as a **security issue** (it must be rotated) - don't repeat the value.
3. **Fix in code, not in the pipeline UI.** Repo-side fixes (YAML, lockfiles, code, tests) become a pull request. Anything needing admin rights (service connections, feed permissions, agent images, parallel jobs) becomes a clear request to the named owner.

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

(`<skill-dir>` = this skill's base directory, shown when the skill loads.) It reports the **diagnosis** (id, category, confidence, fix owner), the **failing step and log line**, **failing test names** when tests failed, other signals, and a redacted excerpt. The failure library is `references/failure-signatures.json` (~60 known causes, including Maven/npm/Go/Cargo dependency errors, Key Vault and Kubernetes auth, ARM quota, Helm locks, parallel-job limits, GITHUB_TOKEN permissions and missing Playwright/Cypress browsers).

When the diagnosis is **unknown** or **low confidence**, read the excerpt and the first real error yourself, reason about it, and say so explicitly.

## Step 3 - Check history before fixing (tests and repeat failures)

When the diagnosis is a **test failure** (category `test`), or the user says "it failed again", decide **flaky vs regression vs recurring** before touching code:

```bash
# Azure Pipelines: last 30 runs of the pipeline (add --branch <branch> to focus)
az pipelines runs list --pipeline-ids <id> --top 30 -o json > runs.json
# GitHub Actions
gh run list --workflow <workflow file or name> -L 30 \
    --json databaseId,conclusion,status,headSha,headBranch,createdAt,updatedAt,name > runs.json
```

Save the logs of the failed runs into one folder, named by run id: `logs/<runId>.log` (GitHub: `gh run view <runId> --log-failed > logs/<runId>.log`; Azure: the logs `az devops invoke` from Step 1, or an unzipped "Download logs" folder renamed to the run id). Then:

```bash
python "<skill-dir>/scripts/pipeline_history.py" runs.json --logs logs/
```

It classifies every failing test and reports failure rate, mean time between failures and mean time to green:

| Verdict | Meaning | What you do |
|---|---|---|
| **flaky** | failed and passed on the same commit (or passed in a later run of that commit) | Do not change product code first. Find the timing/order/shared-state cause in the test, fix or quarantine it with a ticket. |
| **regression** | fails on every run since one commit; the run before was green | Hand to **bug-resolve** with the test name, the first bad and last good commit (`git log --oneline <good>..<bad>`). |
| **intermittent** | failed, recovered, failed again on different commits | Probably flaky: confirm by running it in a loop locally. |
| **persistent** | failing through the whole window | Fetch a longer window (`--top 100`) to find the start. |
| **recurring** (diagnosis) | same root cause in 3+ runs | Fix the cause once (or send the owner request); stop re-running. |

Failed runs without a log are listed, not guessed.

## Step 4 - Confirm against the repo

Before proposing a fix, check the diagnosis against the code:

- **Dependency / lockfile / toolchain:** open `package.json` + lockfile, `.csproj` / `Directory.Packages.props`, `global.json`, `.nvmrc`, `requirements.txt`, and the pipeline YAML. What changed in the last commits (`git log -5 -- <file>`)?
- **Compile errors:** open the file and line from the diagnosis.
- **Test failures:** use the Step 3 verdict. Regression → **bug-resolve**; flaky → fix the test, not the product code.
- **Auth / service connection / feed / agent image:** not fixable in the repo - prepare the request for the owner.

## Step 5 - Fix or route

| Owner in diagnosis | What you do |
|---|---|
| **developer** | Make the minimal fix in a branch (YAML pin, lockfile regenerate, code/test fix), run the relevant command locally if possible (`npm ci`, `dotnet build`, `pytest`), and open a PR titled `fix(ci): <diagnosis title>` explaining cause + evidence (log line). |
| **pipeline-admin** | Write a short, copy-paste request: what failed, the exact error code (e.g. AADSTS7000222), which service connection/feed, and the fix (prefer **workload identity federation** over secrets). |
| **platform-team** | Same, for agent images, Docker mirrors, firewall/DNS, disk, RBAC roles, quotas - include the least-privilege role needed. |

Never "fix" by weakening a gate (disabling tests, lowering coverage, `--force`, `continueOnError: true`) unless the user explicitly decides to, and then record it as a follow-up.

## Health check (offer it even when the pipeline is green)

After a fix, or when asked "why is CI slow" / "review our pipelines", offer both checks.

**Speed and cost.** Get one recent run's timings:

```bash
# Azure Pipelines: per-task start/finish times, plus queue time from the run itself
az devops invoke --area build --resource timeline --route-parameters project=<project> buildId=<runId> \
    --api-version 7.1 -o json > timeline.json
az pipelines runs show --id <runId> -o json > run.json
# GitHub Actions: per-step times and the full log (for cache hits and git fetch depth)
gh run view <runId> --json jobs,createdAt,startedAt,updatedAt,name > run.json
gh run view <runId> --log > run.log

python "<skill-dir>/scripts/pipeline_speed.py" timeline.json run.json [run.log] [--per-minute-rate <your cost>]
```

It lists the slowest steps and rule-based tips: dependency installs over 60 s with no cache hit (Cache@2 / actions/cache or setup-* `cache:` keyed on the lockfile), a cache that misses every run, Docker builds without layer cache, full-history checkouts (`fetchDepth: 1`), long test steps (sharding), long queue waits, and big artifact uploads. Savings are **estimates** from the measured step times and the ratios in `references/speed-tips.json`; always say so and suggest comparing the next few runs.

**YAML security and reliability review:**

```bash
python "<skill-dir>/scripts/pipeline_yaml_review.py" .      # scans azure-pipelines*.yml, pipelines/ and .github/workflows/
```

Findings carry rule id, severity, file:line, why and fix. High: `pull_request_target` checking out PR code, script injection from PR titles/branch names, secrets echoed or pasted on the command line, plain-text secrets in `variables:`/`env:` (value never shown). Medium: actions not pinned to a commit SHA (third-party or branch refs), `permissions: write-all` or no top-level `permissions:`, `continueOnError`/`|| true`/`set +e` on tests or scans, `--legacy-peer-deps`, `--no-verify`, `az login` with a client secret. Low: first-party actions on tags, missing job timeouts, `*-latest` images. A reviewed exception is silenced with `# pipeline-doctor: ignore <rule-id>` on or above the line.

Propose the repo-side fixes as **one pull request** (`ci: pipeline hygiene`), high severity first. Plain-text secrets additionally need rotation by their owner right away; moving a service connection to workload identity federation is a pipeline-admin request.

## Report

```
Pipeline: <name> run <id> - FAILED at step "<step>"
Cause (<confidence>): <diagnosis title> - <one-sentence why>
Evidence: log line <n>: `<redacted line>`
History: <flaky | regression since <commit> (last good <commit>) | recurring in N of M runs>; failure rate <x%>, time to green <t>
Fix owner: <developer | pipeline-admin | platform-team>
Fix: <PR link/branch, or the request text for the owner>
Prevent: <e.g. pin tool version, add retry for network step, federation instead of secret>
Health: slowest <step> (<t>); est. <m> min/run saved by <top tips>; YAML <h> high / <m> medium / <l> low findings
```

Leave out the History or Health line when that check was not run.

## Extending the library

When you meet a new recurring failure, add an entry to `references/failure-signatures.json` (id, category, weight, confidence, pattern, title, why, fix, owner) with a test log under the repository's `tests/fixtures/pipelines/` - the test suite checks every placeholder and field. Put specific patterns before generic ones: the first matching entry wins on a line, and the highest weight wins across lines.

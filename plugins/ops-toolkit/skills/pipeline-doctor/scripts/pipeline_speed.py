#!/usr/bin/env python3
"""pipeline_speed - where does a CI run spend its time, and what would make it faster/cheaper?

Measures step durations and suggests rule-based speed-ups with an ESTIMATE of time saved
per run (ratios and thresholds in ../references/speed-tips.json, verify them).

Inputs (auto-detected, any mix; folders are scanned for .log/.txt/.json):
  Azure Pipelines log     lines start with ISO timestamps; steps from ##[section]Starting:/Finishing:
  GitHub Actions log      gh run view <id> --log > run.log    (job<TAB>step<TAB>timestamp lines)
  Azure timeline JSON     az devops invoke --area build --resource timeline
                            --route-parameters project=<p> buildId=<id> --api-version 7.1 -o json
  Azure run JSON          az pipelines runs show --id <id> -o json          (queue time)
  GitHub run/jobs JSON    gh run view <id> --json jobs,createdAt,startedAt,updatedAt,name
When a timeline or jobs JSON is given, its step times are used and logs only add content
(cache hits, git fetch depth, docker cache flags).

Usage:
  python pipeline_speed.py <inputs...> [--json] [--top 10] [--platform azure|github]
                           [--per-minute-rate 0.008] [--tips custom.json]
Deterministic, redacted output. Standard library only; Python 3.8+.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pipeline_common import human, iso, parse_ts  # noqa: E402
from redact import Redactor  # noqa: E402

DEFAULT_TIPS = HERE.parent / "references" / "speed-tips.json"
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TS = re.compile(r"^﻿?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ?")
GHA = re.compile(r"^(?P<job>[^\t]+)\t(?P<step>[^\t]+)\t﻿?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ?")
START = re.compile(r"^##\[section\]Starting: (?P<name>.+)$")
FINISH = re.compile(r"^##\[section\]Finishing: (?P<name>.+)$")
GROUP_RUN = re.compile(r"^##\[group\]Run (?P<name>.+)$")

# (ecosystem, regex on the step name / command lines)
INSTALLERS = [
    ("pnpm", r"\bpnpm (i|install)\b"),
    ("yarn", r"\byarn install\b|\byarn --(frozen-lockfile|immutable)|^(Run )?yarn\s*$"),
    ("npm", r"\bnpm (ci|install|i)\b|\bNpm@1\b"),
    ("nuget", r"\bdotnet restore\b|\bnuget(\.exe)? restore\b|NuGetCommand@2|DotNetCoreCLI@2.*restore|^restore$"),
    ("poetry", r"\bpoetry install\b"),
    ("pip", r"\bpip3? install\b|\bpython -m pip install\b"),
    ("maven", r"\bmvnw?\b|Maven@\d"),
    ("gradle", r"\bgradlew?\b|Gradle@\d"),
    ("go", r"\bgo mod download\b|\bgo build\b"),
    ("cargo", r"\bcargo (build|fetch)\b"),
    ("bundler", r"\bbundle install\b"),
    ("composer", r"\bcomposer install\b"),
]
ECO_WORDS = {"npm": r"\bnpm\b|\.npm\b|node", "yarn": r"yarn", "pnpm": r"pnpm", "nuget": r"nuget|dotnet",
             "pip": r"\bpip\b|python|requirements", "poetry": r"poetry|python", "maven": r"maven|\.m2|\bmvn",
             "gradle": r"gradle", "go": r"\bgo\b|gomod|go\.sum", "cargo": r"cargo|rust", "bundler": r"bundle|gem|ruby",
             "composer": r"composer|php"}
CACHE_STEP = re.compile(r"^(Cache|Restore cache)\b|Cache@2|actions/cache|\bcache\b", re.I)
CACHE_HIT = re.compile(r"Cache restored from key|There is a cache hit|Cache hit\b|cache-hit=true|Restored from cache|"
                       r"Cache restored successfully", re.I)
CACHE_MISS = re.compile(r"Cache not found for input keys|There is a cache miss|Cache miss\b|cache-hit=false|"
                        r"cache is not found", re.I)
DOCKER = re.compile(r"\bdocker (buildx )?build\b|Docker@2|docker/build-push-action|buildAndPush|^(Build|Build and push)( image)?$", re.I)
DOCKER_CACHED = re.compile(r"--cache-from|cache-from:|type=gha|type=registry|--cache-to|^#\d+ CACHED|---> Using cache", re.I)
CHECKOUT = re.compile(r"^Checkout\b|actions/checkout|^Get sources$", re.I)
SHALLOW = re.compile(r"--depth[= ]\d+|fetchDepth|fetch-depth: ?[1-9]", re.I)
TESTS = re.compile(r"\btests?\b|pytest|\bjest\b|vitest|mocha|dotnet test|VSTest|\bmvnw? .*\b(test|verify)\b|"
                   r"gradlew? .*\btest|\bgo test\b|cargo test|playwright test|cypress run", re.I)
SHARDED = re.compile(r"--shard|\s-n (auto|\d+)|xdist|distributionBatchType|--parallel\b", re.I)
ARTIFACT = re.compile(r"PublishPipelineArtifact|PublishBuildArtifacts|upload-artifact|Upload artifact|Publish (pipeline |build )?artifact", re.I)
ARTIFACT_SIZE = [(re.compile(r"Total Content:\s*(?P<n>[\d,.]+)\s*(?P<u>KB|MB|GB)", re.I), None),
                 (re.compile(r"(Final size is|Artifact size is|Uploaded) (?P<n>\d+) bytes", re.I), "B")]
UNITS = {"B": 1.0 / 1048576, "KB": 1.0 / 1024, "MB": 1.0, "GB": 1024.0}

FIX = {
    "npm": ("Cache@2 before `npm ci` with key: 'npm | \"$(Agent.OS)\" | package-lock.json' and path: $(npm_config_cache), "
            "plus variable npm_config_cache: $(Pipeline.Workspace)/.npm (cache the download cache, not node_modules).",
            "actions/setup-node with `cache: npm` (keyed on package-lock.json), or actions/cache on ~/.npm with key "
            "`${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}`."),
    "yarn": ("Cache@2 with key: 'yarn | \"$(Agent.OS)\" | yarn.lock' and path: $(YARN_CACHE_FOLDER) "
             "(variable YARN_CACHE_FOLDER: $(Pipeline.Workspace)/.yarn).",
             "actions/setup-node with `cache: yarn` (keyed on yarn.lock)."),
    "pnpm": ("Cache@2 with key: 'pnpm | \"$(Agent.OS)\" | pnpm-lock.yaml' and path: $(pnpm_config_store_dir) "
             "(variable pnpm_config_store_dir: $(Pipeline.Workspace)/.pnpm-store).",
             "pnpm/action-setup, then actions/setup-node with `cache: pnpm`."),
    "nuget": ("Cache@2 with key: 'nuget | \"$(Agent.OS)\" | **/packages.lock.json' and path: $(NUGET_PACKAGES) "
              "(variable NUGET_PACKAGES: $(Pipeline.Workspace)/.nuget/packages; set RestorePackagesWithLockFile=true so the lock files exist).",
              "actions/setup-dotnet with `cache: true` (needs packages.lock.json), or actions/cache on ~/.nuget/packages "
              "keyed on `hashFiles('**/packages.lock.json')`."),
    "pip": ("Cache@2 with key: 'python | \"$(Agent.OS)\" | requirements.txt' and path: $(PIP_CACHE_DIR) "
            "(variable PIP_CACHE_DIR: $(Pipeline.Workspace)/.pip).",
            "actions/setup-python with `cache: pip` (keyed on requirements files)."),
    "poetry": ("Cache@2 with key: 'poetry | \"$(Agent.OS)\" | poetry.lock' on the Poetry cache directory.",
               "actions/setup-python with `cache: poetry` (after installing Poetry)."),
    "maven": ("Cache@2 with key: 'maven | \"$(Agent.OS)\" | **/pom.xml' and path: $(MAVEN_CACHE_FOLDER), "
              "passing -Dmaven.repo.local=$(MAVEN_CACHE_FOLDER) to Maven.",
              "actions/setup-java with `cache: maven` (keyed on pom.xml files)."),
    "gradle": ("Cache@2 with key: 'gradle | \"$(Agent.OS)\" | **/*.gradle* | **/gradle-wrapper.properties' "
               "and path: $(GRADLE_USER_HOME)/caches.",
               "gradle/actions/setup-gradle (caches dependencies and wrapper), or actions/setup-java with `cache: gradle`."),
    "go": ("Cache@2 with key: 'go | \"$(Agent.OS)\" | **/go.sum' on the module cache (`go env GOMODCACHE`).",
           "actions/setup-go (v4+ caches modules by default, keyed on go.sum)."),
    "cargo": ("Cache@2 with key: 'cargo | \"$(Agent.OS)\" | Cargo.lock' on ~/.cargo/registry and target/.",
              "Swatinem/rust-cache (or actions/cache on ~/.cargo/registry and target keyed on Cargo.lock)."),
    "bundler": ("Cache@2 with key: 'gems | \"$(Agent.OS)\" | Gemfile.lock' on vendor/bundle.",
                "ruby/setup-ruby with `bundler-cache: true`."),
    "composer": ("Cache@2 with key: 'composer | \"$(Agent.OS)\" | composer.lock' on the Composer cache directory.",
                 "actions/cache on the Composer cache directory keyed on composer.lock."),
    "cache_miss": ("A Cache@2 step ran but missed. A miss right after the lockfile changes is normal; if it misses on every run the key "
                   "contains something that changes each run (Build.BuildId, commit, date). Key on the lockfile only.",
                   "A cache step ran but found nothing. If it misses on every run the key contains something that changes each "
                   "run (github.sha, run_id, date) or the post-job save failed; key on hashFiles(lockfile) only."),
    "docker_build": ("Build with BuildKit and a registry cache: `docker buildx build --cache-from type=registry,ref=<registry>/<image>:buildcache "
                     "--cache-to type=registry,ref=<registry>/<image>:buildcache,mode=max` (Docker@2 buildAndPush has no cache inputs, so use a script step); "
                     "copy dependency manifests and restore before copying the source in the Dockerfile.",
                     "docker/setup-buildx-action, then docker/build-push-action with `cache-from: type=gha` and `cache-to: type=gha,mode=max`; "
                     "copy dependency manifests and restore before copying the source in the Dockerfile."),
    "shallow_checkout": ("`- checkout: self` with `fetchDepth: 1` (and `fetchTags: false`); keep full history only in jobs that need it "
                         "(versioning from tags, Sonar blame).",
                         "actions/checkout defaults to `fetch-depth: 1`; remove `fetch-depth: 0` unless this job needs full history or tags."),
    "test_sharding": ("Split tests across agents: `strategy: parallel: N` with VSTest `distributionBatchType: basedOnExecutionTime`, "
                      "or `--shard=$(System.JobPositionInPhase)/$(System.TotalJobsInPhase)` for jest/playwright; pytest-xdist `-n auto` "
                      "on one agent. List the slowest tests first (`pytest --durations=20`).",
                      "Matrix sharding (`strategy.matrix.shard: [1, 2, 3, 4]` with `--shard=${{ matrix.shard }}/4` for jest/playwright), "
                      "or pytest-xdist `-n auto`. List the slowest tests first (`pytest --durations=20`)."),
    "queue": ("The run waited for an agent: add parallel jobs or agents to the pool, move scheduled/non-urgent pipelines off peak, "
              "and check for jobs holding agents for long.",
              "Jobs waited for a runner: check the plan's concurrency limit, larger or self-hosted runner pools, and a "
              "`concurrency:` group with `cancel-in-progress: true` so superseded runs stop."),
    "artifact": ("Publish only what later stages need (exclude node_modules, obj, test output) using a .artifactignore; "
                 "compress before upload.",
                 "Narrow the upload-artifact `path:` to what later jobs need, exclude dependencies, and set `retention-days`."),
}
WHY = {
    "install": "Dependency install took {dur} and no cache hit for {eco} was seen, so every run downloads the same packages again.",
    "cache_miss": "Dependency install took {dur} although a cache step ran: the cache missed.",
    "docker_build": "Docker build took {dur} with no layer cache (no --cache-from / cache-from, no CACHED layers seen).",
    "shallow_checkout": "Checkout took {dur} and the git fetch shows no --depth, so it downloads the full history.",
    "test_sharding": "Tests took {dur} in one job with no sharding or parallel workers seen.",
    "queue": "The run waited {dur} before an agent/runner picked it up.",
    "artifact": "Artifact upload took {dur}{size}.",
}
AFFECTS_WALL = "wall-clock only (agent minutes unchanged or higher)"
AFFECTS_BOTH = "wall-clock and agent minutes"


def load_tips(path=None):
    return json.loads(Path(path or DEFAULT_TIPS).read_text(encoding="utf-8"))


def new_step(job, name, start, source, platform, depth=0):
    return {"job": job, "name": name, "start": start, "end": None, "source": source, "platform": platform,
            "text": [], "children": 0, "depth": depth}


def parse_log(text, source):
    """Steps with start/end times from one log file. Returns (steps, first_ts, last_ts)."""
    lines = [ANSI.sub("", l).rstrip("\r") for l in text.splitlines()]
    steps, first, last = [], None, None
    if any(GHA.match(l) for l in lines[:50]):
        cur = None
        for l in lines:
            m = GHA.match(l)
            if not m:
                if cur is not None:
                    cur["text"].append(l)
                continue
            t = parse_ts(m.group("ts"))
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
            job, step = m.group("job").strip(), m.group("step").strip()
            if cur is None or (cur["job"], cur["name"]) != (job, step):
                cur = new_step(job, step, t, source, "github")
                steps.append(cur)
            cur["end"] = t
            cur["text"].append(l[m.end():])
        for i, s in enumerate(steps):  # a step ends when the next step of the same job starts
            nxt = next((n for n in steps[i + 1:] if n["job"] == s["job"]), None)
            if nxt is not None:
                s["end"] = nxt["start"]
        return steps, first, last
    azure = any(START.match(TS.sub("", l)) for l in lines)
    stack = []
    for l in lines:
        m = TS.match(l)
        t = parse_ts(m.group("ts")) if m else None
        body = l[m.end():] if m else l
        if t is not None:
            first = t if first is None else min(first, t)
            last = t if last is None else max(last, t)
        if azure:
            s, f = START.match(body), FINISH.match(body)
            if s and t is not None:
                if stack:
                    stack[-1]["children"] += 1
                step = new_step(stack[0]["name"] if stack else None, s.group("name").strip(), t, source, "azure", len(stack))
                stack.append(step)
                steps.append(step)
                continue
            if f and t is not None:
                name = f.group("name").strip()
                if any(x["name"] == name for x in stack):
                    while stack:
                        x = stack.pop()
                        x["end"] = t
                        if x["name"] == name:
                            break
                continue
            if stack:
                stack[-1]["text"].append(body)
        else:
            g = GROUP_RUN.match(body)
            if g and t is not None:
                if steps:
                    steps[-1]["end"] = t
                steps.append(new_step(None, "Run " + g.group("name").strip(), t, source, "github"))
                continue
            if steps:
                steps[-1]["text"].append(body)
    for s in steps:
        if s["end"] is None:
            s["end"] = last
    return [s for s in steps if s["children"] == 0], first, last


def parse_timeline(data, source):
    recs = [r for r in data.get("records", []) if isinstance(r, dict)]
    by_id = {r.get("id"): r for r in recs}

    def ancestor(rec, kinds):
        seen = 0
        while rec is not None and seen < 20:
            rec = by_id.get(rec.get("parentId"))
            if rec is not None and rec.get("type") in kinds:
                return rec
            seen += 1
        return None

    steps, jobs = [], []
    for r in sorted(recs, key=lambda r: (parse_ts(r.get("startTime")) or 0, r.get("order") or 0, r.get("name") or "")):
        start, end = parse_ts(r.get("startTime")), parse_ts(r.get("finishTime"))
        if start is None or end is None:
            continue
        if r.get("type") == "Task":
            job = ancestor(r, ("Job",))
            s = new_step(job.get("name") if job else None, r.get("name") or "?", start, source, "azure")
            s["end"] = end
            steps.append(s)
        elif r.get("type") == "Job":
            parent = ancestor(r, ("Phase", "Stage"))
            pstart = parse_ts(parent.get("startTime")) if parent else None
            wait = start - pstart if pstart is not None and start > pstart else 0.0
            jobs.append({"name": r.get("name"), "seconds": round(end - start, 1), "wait_seconds": round(wait, 1),
                         "start": start, "end": end})
    return steps, jobs


def parse_gh_jobs(data, source):
    steps, jobs = [], []
    for j in data.get("jobs") or []:
        js, je = parse_ts(j.get("startedAt")), parse_ts(j.get("completedAt"))
        if js is not None and je is not None:
            jobs.append({"name": j.get("name"), "seconds": round(je - js, 1), "wait_seconds": 0.0, "start": js, "end": je})
        for st in j.get("steps") or []:
            a, b = parse_ts(st.get("startedAt")), parse_ts(st.get("completedAt"))
            if a is not None and b is not None:
                s = new_step(j.get("name"), st.get("name") or "?", a, source, "github")
                s["end"] = b
                steps.append(s)
    return steps, jobs


def queue_from_run(data, jobs):
    """(seconds, method) or None."""
    q, s = parse_ts(data.get("queueTime")), parse_ts(data.get("startTime"))
    if q is not None and s is not None:
        return max(0.0, s - q), "run startTime - queueTime"
    created = parse_ts(data.get("createdAt"))
    if created is not None and jobs:
        first = min(j["start"] for j in jobs)
        return max(0.0, first - created), "first job start - run createdAt"
    return None


def iter_inputs(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".log", ".txt", ".json")):
                yield f
        else:
            yield p


def command_text(step):
    """Step name plus command lines: what the step RAN, not everything it printed."""
    cmds = [l for l in step["text"] if "[command]" in l or l.startswith("##[group]Run ")]
    return "\n".join([step["name"]] + (cmds or step["text"][:8]))


def norm(name):
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def analyse(paths, tips=None, top=10, platform=None, rate=None, redactor=None):
    tips = tips or load_tips()
    red = redactor or Redactor()
    th, ratio = tips["thresholds_seconds"], tips["saving_ratio"]
    log_steps, struct_steps, jobs, sources, spans, queue = [], [], [], [], [], None
    for f in iter_inputs(paths):
        sources.append(f.name)
        if f.suffix.lower() == ".json":
            data = json.loads(f.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and "records" in data:
                s, j = parse_timeline(data, f.name)
            elif isinstance(data, dict) and "jobs" in data:
                s, j = parse_gh_jobs(data, f.name)
            else:
                s, j = [], []
            struct_steps += s
            jobs += j
            if isinstance(data, dict):
                q = queue_from_run(data, j)
                if q and (queue is None or q[0] > queue[0]):
                    queue = q
            continue
        s, a, b = parse_log(f.read_text(encoding="utf-8-sig", errors="replace"), f.name)
        log_steps += s
        if a is not None and b is not None:
            spans.append((a, b))

    if struct_steps:  # structured times win; logs only add content, matched by step name
        texts = {}
        for s in log_steps:
            texts.setdefault(norm(s["name"]), []).extend(s["text"])
        for s in struct_steps:
            s["text"] = texts.get(norm(s["name"]), [])
        steps = struct_steps
    else:
        steps = log_steps
    for s in steps:
        s["seconds"] = round(max(0.0, (s["end"] or s["start"]) - s["start"]), 1)
    if queue is None:
        waits = [j["wait_seconds"] for j in jobs if j["wait_seconds"] > 0]
        if waits:
            queue = (max(waits), "timeline: gap between the parent stage/phase start and the job start (approximate, includes checks and approvals)")

    plat = platform or (", ".join(sorted({s["platform"] for s in steps})) if steps else None)

    # which ecosystems have a cache hit / a cache step that missed
    hit_ecos, miss_ecos = set(), set()
    for s in steps + ([] if steps is log_steps else log_steps):
        hits = [l for l in s["text"] if CACHE_HIT.search(l)]
        misses = [l for l in s["text"] if CACHE_MISS.search(l)]
        is_cache = bool(CACHE_STEP.search(s["name"]))
        if not (hits or misses or is_cache):
            continue
        context = " ".join([s["name"]] + [l for l in s["text"] if re.search(r"key|Resolved to|path", l, re.I)] + hits + misses)
        ecos = {e for e, rx in ECO_WORDS.items() if re.search(rx, context, re.I)} or {"*"}
        if hits:
            hit_ecos |= ecos
        elif misses or is_cache:
            miss_ecos |= ecos

    def fix_for(key):
        az, gh = FIX[key]
        if plat == "azure":
            return ["Azure Pipelines: " + az]
        if plat == "github":
            return ["GitHub Actions: " + gh]
        return ["Azure Pipelines: " + az, "GitHub Actions: " + gh]

    found = []

    def tip(rule, step, key, why_key, affects, **fmt):
        secs = step["seconds"] if step else queue[0]
        est = round(secs * ratio[key], 1)
        found.append({"_step": next(i for i, x in enumerate(steps) if x is step) if step else None, "rule": rule, "job": red.redact(step["job"]) if step and step["job"] else None,
                      "step": red.redact(step["name"]) if step else None, "seconds": secs, "duration": human(secs),
                      "estimate_seconds": est, "estimate": human(est), "affects": affects,
                      "assumption": f"{int(ratio[key] * 100)}% of the measured {human(secs)} (saving_ratio.{key} in references/speed-tips.json)",
                      "why": WHY[why_key].format(dur=human(secs), **fmt), "fix": fix_for(key)})

    for s in steps:
        cmd = command_text(s)
        body = "\n".join(s["text"])
        docker = bool(DOCKER.search(cmd))  # a Dockerfile's RUN npm ci is not a pipeline install step
        eco = None if docker else next((e for e, rx in INSTALLERS if re.search(rx, cmd, re.I | re.M)), None)
        if eco and s["seconds"] >= th["install"] and not CACHE_STEP.search(s["name"]):
            if "*" in hit_ecos or eco in hit_ecos:
                pass
            elif "*" in miss_ecos or eco in miss_ecos:
                tip("cache-miss", s, "cache_miss", "cache_miss", AFFECTS_BOTH)
            else:
                tip("dependency-cache", s, eco, "install", AFFECTS_BOTH, eco=eco)
        if docker and s["seconds"] >= th["docker_build"] and s["text"] and not DOCKER_CACHED.search(body):
            tip("docker-layer-cache", s, "docker_build", "docker_build", AFFECTS_BOTH)
        if CHECKOUT.search(s["name"]) and s["seconds"] >= th["checkout"] and s["text"] and not SHALLOW.search(body) \
                and re.search(r"\bgit\b.*\bfetch\b", body):
            tip("shallow-checkout", s, "shallow_checkout", "shallow_checkout", AFFECTS_BOTH)
        if TESTS.search(cmd) and not ARTIFACT.search(s["name"]) and s["seconds"] >= th["tests"] and not SHARDED.search(cmd + body):
            tip("test-sharding", s, "test_sharding", "test_sharding", AFFECTS_WALL)
        if ARTIFACT.search(cmd):
            size = None
            for rx, unit in ARTIFACT_SIZE:
                m = rx.search(body)
                if m:
                    size = round(float(m.group("n").replace(",", "")) * UNITS[unit or m.group("u").upper()], 1)
                    break
            if s["seconds"] >= th["artifact_upload"] or (size or 0) >= tips.get("artifact_size_mb", 500):
                tip("large-artifact", s, "artifact", "artifact", AFFECTS_BOTH,
                    size=f" for about {size} MB" if size is not None else "")
    if queue and queue[0] >= th["queue"]:
        tip("queue-wait", None, "queue", "queue", "wall-clock only (no agent minutes are used while waiting)")
    found.sort(key=lambda t: (-t["estimate_seconds"], t["rule"], t["job"] or "", t["step"] or ""))

    ordered = sorted(steps, key=lambda s: (-s["seconds"], s["job"] or "", s["name"], s["source"]))
    step_total = round(sum(s["seconds"] for s in steps), 1)
    agent = round(sum(j["seconds"] for j in jobs), 1) if jobs else step_total
    if jobs:
        wall = round(max(j["end"] for j in jobs) - min(j["start"] for j in jobs), 1)
    elif spans and len({s["source"] for s in steps}) <= 1:
        wall = round(max(b for _, b in spans) - min(a for a, _ in spans), 1)
    else:
        wall = None  # several log files may be parallel jobs: wall clock unknown
    total_saved = round(sum(t["estimate_seconds"] for t in found if t["_step"] is None), 1)
    agent_saved = 0.0
    for idx in sorted({t["_step"] for t in found if t["_step"] is not None}):
        mine = [t for t in found if t["_step"] == idx]
        cap = steps[idx]["seconds"]  # several tips on one step never save more than the step takes
        total_saved += min(cap, sum(t["estimate_seconds"] for t in mine))
        agent_saved += min(cap, sum(t["estimate_seconds"] for t in mine if t["affects"] == AFFECTS_BOTH))
    total_saved, agent_saved = round(total_saved, 1), round(agent_saved, 1)
    for t in found:
        del t["_step"]

    res = {
        "sources": sources, "platform": plat,
        "wall_clock_seconds": wall, "wall_clock": human(wall),
        "agent_seconds": agent, "agent_time": human(agent),
        "step_seconds": step_total, "step_count": len(steps),
        "queue": {"seconds": round(queue[0], 1), "duration": human(queue[0]), "method": queue[1]} if queue else None,
        "jobs": [{"name": red.redact(j["name"] or "?"), "seconds": j["seconds"], "duration": human(j["seconds"]),
                  "wait_seconds": j["wait_seconds"]} for j in sorted(jobs, key=lambda j: (j["start"], j["name"] or ""))],
        "slowest_steps": [{"job": red.redact(s["job"]) if s["job"] else None, "step": red.redact(s["name"]),
                           "seconds": s["seconds"], "duration": human(s["seconds"]),
                           "share": round(s["seconds"] / step_total, 3) if step_total else 0.0,
                           "start": iso(s["start"]), "source": s["source"]} for s in ordered[:top]],
        "tips": found,
        "estimated_saving_seconds": total_saved, "estimated_saving": human(total_saved),
        "estimated_agent_seconds_saved": agent_saved,
        "assumptions": [tips.get("_note", ""),
                        "Estimates use only the step times measured in these inputs; one run is a sample, compare several runs.",
                        "Wall-clock savings from sharding and queue fixes do not reduce agent minutes."],
    }
    if rate:
        res["cost"] = {"per_minute_rate": rate, "run_cost": round(agent / 60.0 * rate, 4),
                       "estimated_saving_per_run": round(agent_saved / 60.0 * rate, 4),
                       "note": "agent minutes x the rate you supplied; hosted-agent pricing differs by plan and OS."}
    return res


def to_markdown(res):
    L = ["# Pipeline Doctor - speed and cost review", "",
         f"Sources: {', '.join(res['sources'])} ({res['platform'] or 'unknown platform'})", "",
         f"- Wall clock: **{res['wall_clock']}**; agent time: **{res['agent_time']}** across {res['step_count']} steps"]
    if res["queue"]:
        L.append(f"- Waiting for an agent: **{res['queue']['duration']}** ({res['queue']['method']})")
    if res.get("cost"):
        c = res["cost"]
        L.append(f"- Cost at {c['per_minute_rate']}/agent-minute: {c['run_cost']} per run; tips below could save about "
                 f"{c['estimated_saving_per_run']} per run (estimate)")
    L += ["", "## Slowest steps", "", "| # | Job | Step | Time | Share |", "|---|---|---|---|---|"]
    for i, s in enumerate(res["slowest_steps"], 1):
        L.append(f"| {i} | {s['job'] or ''} | {s['step']} | {s['duration']} | {s['share'] * 100:.0f}% |")
    L += ["", "## Speed-ups (estimates)", ""]
    if not res["tips"]:
        L.append("No rule fired: installs are cached (or fast), checkout is shallow, tests and uploads are under the thresholds.")
    for t in res["tips"]:
        where = f" - step **{t['step']}**" if t["step"] else ""
        L += [f"### `{t['rule']}`{where}: save about {t['estimate']} per run (estimate)", "",
              f"- Why: {t['why']}", f"- Saves: {t['affects']}. Assumption: {t['assumption']}."]
        L += [f"- Fix: {f}" for f in t["fix"]]
        L.append("")
    L += [f"**Total estimated saving: about {res['estimated_saving']} per run** (wall clock; agent time saved about "
          f"{human(res['estimated_agent_seconds_saved'])}). These are estimates from one run's measured step times; "
          "verify on the next runs after the change.", "", "---",
          "Read-only review. Names redacted where needed. No pipeline or run was changed."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Step timings and rule-based speed/cost tips for a CI run.")
    ap.add_argument("inputs", nargs="+", help="log files, timeline/run JSON files, or folders")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--platform", choices=["azure", "github"])
    ap.add_argument("--per-minute-rate", type=float, help="your cost per agent minute, to express savings as money")
    ap.add_argument("--tips", help="alternative speed-tips JSON (thresholds and saving ratios)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    res = analyse(a.inputs, load_tips(a.tips), a.top, a.platform, a.per_minute_rate)
    sys.stdout.write(json.dumps(res, indent=2) + "\n" if a.json else to_markdown(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())

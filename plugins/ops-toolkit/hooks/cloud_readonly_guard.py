#!/usr/bin/env python3
"""ops-toolkit read-only guard (Claude Code PreToolUse hook).

Reads the hook payload on stdin. If the Bash/PowerShell command would change a
cloud resource or read a secret, exits 2 with the reason on stderr (Claude Code
blocks the call and shows the reason to the model). Otherwise exits 0.

This is a seatbelt, not the lock. The real control is a read-only cloud identity
(see the plugin README, "Access model"). A determined script or SDK call can get
past any command filter; the identity's RBAC cannot be bypassed.

Human-approved exception: launch Claude Code with OPS_TOOLKIT_ALLOW_CLOUD_WRITES=1.
Standard library only; Python 3.8+.
"""
import json
import os
import re
import sys

OVERRIDE_ENV = "OPS_TOOLKIT_ALLOW_CLOUD_WRITES"

GUIDANCE = (
    "These skills are read-only. They never change cloud resources or reads secrets directly. "
    "Propose the change as a pull request (IaC or code) or hand the exact command to a human to run. "
    f"(A human-approved exception requires relaunching Claude Code with {OVERRIDE_ENV}=1.)"
)

CLIS = {"az", "aws", "gcloud", "kubectl", "terraform", "tofu", "helm", "pulumi"}
HTTP_CLIS = {"curl", "wget", "invoke-restmethod", "invoke-webrequest", "irm", "iwr", "http", "https"}

# ---------------------------------------------------------------- Azure CLI
AZ_LOCAL_GROUPS = {"login", "logout", "extension", "config", "cache", "version", "find",
                   "upgrade", "bicep", "interactive", "feedback", "init", "self-test", "survey"}
AZ_MUTATING = {
    "create", "delete", "update", "set", "remove", "add", "start", "stop", "restart", "deallocate",
    "purge", "import", "swap", "scale", "reset", "regenerate", "rotate", "move", "invoke", "deploy",
    "apply", "upgrade", "attach", "detach", "enable", "disable", "renew", "revoke", "grant", "lock",
    "unlock", "put", "approve", "reject", "cancel", "redeploy", "reimage", "resize", "restore",
    "failover", "sync", "upload", "recover", "assign", "unassign", "config-zip", "up", "run",
    "trigger", "queue", "abort", "clear", "flush", "reboot", "power-off", "shutdown", "convert",
    "migrate", "publish", "push", "promote", "patch", "replace", "rollback", "rollout", "backup",
    "generalize", "capture", "simulate-eviction", "reconcile", "repair", "force-delete", "wipe",
    "install", "uninstall", "renew", "resume", "suspend", "pause", "stop-continuous", "undelete",
}
AZ_READONLY_OVERRIDES = {"what-if", "validate"}  # e.g. `az deployment group what-if`
AZ_SECRET_PATTERNS = [
    r"\bkeys? list\b", r"\blist-keys\b", r"\bkeys? renew\b", r"\bcredential show\b",
    r"\bcredential list\b", r"\bget-credentials\b", r"\bsecret show\b", r"\bsecret download\b",
    r"\bcertificate download\b", r"\bappsettings list\b", r"\bconnection-string show\b",
    r"\bshow-connection-string\b", r"\blist-connection-strings\b", r"\bgenerate-sas\b",
    r"\blist-publishing-profiles\b", r"\blist-publishing-credentials\b", r"\bget-access-token\b",
    r"\bfunction keys\b", r"\bhost keys\b", r"\bkeys show\b", r"\bshow-keys\b",
]
AZ_REST_SECRET_URL = re.compile(r"/(listkeys|listsecrets|listcredentials|listconnectionstrings|"
                                r"regeneratekey|listaccountsas|listservicesas|config/list)", re.I)

# ---------------------------------------------------------------- AWS CLI
AWS_GLOBAL_OPTS_WITH_VALUE = {"--profile", "--region", "--output", "--query", "--endpoint-url",
                              "--cli-read-timeout", "--cli-connect-timeout", "--color", "--ca-bundle"}
AWS_LOCAL = {"configure", "sso", "help", "--version"}
AWS_MUT_PREFIXES = (
    "create", "delete", "put", "update", "modify", "terminate", "stop", "start", "reboot", "run",
    "attach", "detach", "associate", "disassociate", "authorize", "revoke", "enable", "disable",
    "register", "deregister", "invoke", "publish", "send", "reset", "restore", "copy", "import",
    "tag", "untag", "set", "add", "remove", "cancel", "replace", "release", "allocate", "apply",
    "execute", "upload", "rotate", "purchase", "accept", "reject", "deploy", "restart", "promote",
    "failover", "batch-write", "batch-delete", "change", "schedule", "rollback", "resume",
    "suspend", "activate", "deactivate", "move", "merge", "swap", "sync", "recover", "request",
    "package", "test-invoke", "confirm", "initiate", "complete", "abort", "increase", "decrease",
    "reject", "retry", "redrive", "purge", "flush", "reboot", "reload", "resize",
)
AWS_READ_EXCEPTIONS = {("logs", "start-query"), ("logs", "stop-query")}
AWS_SECRET_OPS = {
    ("secretsmanager", "get-secret-value"), ("secretsmanager", "batch-get-secret-value"),
    ("kms", "decrypt"), ("sts", "assume-role"), ("sts", "assume-role-with-web-identity"),
    ("sts", "assume-role-with-saml"), ("ecr", "get-login-password"), ("ecr", "get-authorization-token"),
    ("eks", "get-token"), ("rds", "generate-db-auth-token"), ("iam", "get-credential-report"),
}
AWS_DATA_READS = {  # data-plane content, not configuration (ViewOnly model excludes these)
    ("dynamodb", "scan"), ("dynamodb", "query"), ("dynamodb", "get-item"),
    ("dynamodb", "batch-get-item"), ("dynamodb", "execute-statement"),
    ("s3api", "get-object"), ("s3api", "select-object-content"),
}
AWS_S3_MUT = {"cp", "mv", "rm", "sync", "mb", "rb", "website", "presign"}

# ---------------------------------------------------------------- gcloud
GCLOUD_LOCAL_GROUPS = {"config", "auth", "components", "info", "version", "help", "init", "topic"}
GCLOUD_MUTATING = {
    "create", "delete", "update", "deploy", "set-iam-policy", "add-iam-policy-binding",
    "remove-iam-policy-binding", "start", "stop", "reset", "resize", "patch", "import", "submit",
    "set", "add", "remove", "enable", "disable", "restore", "rollback", "suspend", "resume",
    "upgrade", "migrate", "attach", "detach", "move", "promote", "failover", "apply", "cancel",
    "run", "execute", "publish", "undelete", "rotate", "destroy", "restart", "scale", "replace",
    "add-labels", "remove-labels", "update-labels", "add-tags", "remove-tags",
}
GCLOUD_SECRET_PATTERNS = [r"\bsecrets versions access\b", r"\bprint-access-token\b",
                          r"\bprint-identity-token\b", r"\bgenerate-login-token\b", r"\bget-credentials\b"]

# ---------------------------------------------------------------- kubectl etc.
KUBECTL_MUTATING = {"apply", "create", "delete", "patch", "replace", "scale", "edit", "set", "drain",
                    "cordon", "uncordon", "taint", "label", "annotate", "exec", "cp", "run", "expose",
                    "autoscale", "attach", "debug", "port-forward", "proxy", "certificate", "kustomize"}
KUBECTL_ROLLOUT_READ = {"status", "history"}
TERRAFORM_MUTATING = {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh"}
TERRAFORM_STATE_MUTATING = {"rm", "mv", "push", "replace-provider"}
HELM_MUTATING = {"install", "upgrade", "uninstall", "delete", "rollback", "push"}
PULUMI_MUTATING = {"up", "update", "destroy", "import", "refresh", "cancel"}

# ---------------------------------------------------------------- PowerShell modules
PS_AZ_MUTATING = re.compile(
    r"\b(New|Set|Remove|Update|Start|Stop|Restart|Invoke|Add|Move|Import|Publish|Register|"
    r"Unregister|Enable|Disable|Reset|Restore|Suspend|Resume|Grant|Revoke|Clear|Sync|Switch|"
    r"Undo|Backup|Deploy)-Az[A-Za-z]+", re.I)
PS_AZ_SECRET = re.compile(r"\bGet-Az(KeyVaultSecret|StorageAccountKey|WebAppPublishingProfile|"
                          r"CosmosDBAccountKey|RedisCacheKey|AccessToken)\b", re.I)
PS_AWS_MUTATING = re.compile(
    r"\b(New|Remove|Set|Update|Stop|Start|Restart|Invoke|Register|Unregister|Publish|Write|"
    r"Add|Edit|Reset|Restore|Send|Copy|Import)-(EC2|S3|IAM|RDS|LM|CFN|ECS|EKS|SSM|SEC|KMS|CW|CWL|"
    r"DDB|SNS|SQS|ELB2|ASG|R53|CF|ECR|EB)[A-Za-z]*\b", re.I)

# ---------------------------------------------------------------- raw HTTP
MGMT_HOSTS = re.compile(
    r"(management\.azure\.com|management\.core\.windows\.net|\.vault\.azure\.net|graph\.microsoft\.com|"
    r"dev\.azure\.com|\.visualstudio\.com|api\.github\.com|\.amazonaws\.com|googleapis\.com)", re.I)
HTTP_MUTATING = re.compile(
    r"(-X\s*(POST|PUT|PATCH|DELETE)\b|--request\s+(POST|PUT|PATCH|DELETE)\b|"
    r"-Method\s+(Post|Put|Patch|Delete)\b|\s(-d|--data[a-z-]*|-F|--form|-T|--upload-file|-Body)\s)",
    re.I)

SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n\r()`]|\$\(")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'')
# A quoted string right after one of these is code a shell will execute, so inspect it.
SHELL_RUNNER_BEFORE = re.compile(r"(?:^|\s)(-c|-lc|-ic|-command|/c|eval|-e)\s*$", re.I)


def flatten(command):
    """Unquote single-word values, inspect quoted code passed to a shell, and treat any
    other quoted multi-word text (commit messages, echo/grep strings, KQL) as inert data."""
    out, pos = [], 0
    for m in QUOTED.finditer(command):
        out.append(command[pos:m.start()])
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        if not re.search(r"\s", inner):
            out.append(inner)
        elif SHELL_RUNNER_BEFORE.search(command[:m.start()]):
            out.append(" ; " + inner + " ; ")
        else:
            out.append(" QUOTED_TEXT ")
        pos = m.end()
    out.append(command[pos:])
    return "".join(out)


def norm_token(tok):
    tok = tok.strip().strip("\"'")
    base = re.split(r"[\\/]", tok)[-1]
    base = re.sub(r"\.(exe|cmd|bat|ps1)$", "", base, flags=re.I)
    return base.lower()


def positional(args, opts_with_value=frozenset()):
    """Leading non-option words, skipping known global options (and their values)."""
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if a in opts_with_value and "=" not in a:
                i += 2
                continue
            if out:  # first flag after positional words ends the command path
                break
            i += 1
            continue
        out.append(a.lower())
        i += 1
    return out


def flag_value(args, *names):
    for i, a in enumerate(args):
        low = a.lower()
        for n in names:
            if low == n and i + 1 < len(args):
                return args[i + 1].lower()
            if low.startswith(n + "="):
                return low.split("=", 1)[1]
    return None


def check_az(args):
    pos = positional(args)
    if not pos:
        return None
    joined = " ".join(pos)
    if pos[0] in AZ_LOCAL_GROUPS:
        return None
    if pos[0] == "account":
        if "get-access-token" in pos:
            return "az account get-access-token (raw token could bypass read-only tooling)"
        return None
    for pat in AZ_SECRET_PATTERNS:
        if re.search(pat, joined):
            return f"secret-reading Azure command (`az {joined}`)"
    if pos[0] == "rest":
        method = flag_value(args, "--method", "-m") or "get"
        url = flag_value(args, "--url", "--uri", "-u") or " ".join(args)
        if AZ_REST_SECRET_URL.search(url):
            return "az rest call to a secret-listing endpoint"
        if method not in ("get", "head") or flag_value(args, "--body", "-b") is not None:
            return f"az rest with method {method.upper()} (mutating management-API call)"
        return None
    if pos[0] == "devops" and "invoke" in pos:  # generic ADO REST call, GET by default
        method = flag_value(args, "--http-method") or "get"
        if method not in ("get", "head") or flag_value(args, "--in-file") is not None:
            return f"az devops invoke with {method.upper()} (mutating Azure DevOps call)"
        return None
    if any(p in AZ_READONLY_OVERRIDES for p in pos):
        return None
    hits = [p for p in pos[1:] if p in AZ_MUTATING]
    if hits:
        return f"cloud-mutating Azure command (`az {joined}`)"
    return None


def check_aws(args):
    pos = positional(args, AWS_GLOBAL_OPTS_WITH_VALUE)
    if not pos or pos[0] in AWS_LOCAL:
        return None
    service = pos[0]
    op = pos[1] if len(pos) > 1 else ""
    if service == "s3":
        return f"`aws s3 {op}` writes or transfers data" if op in AWS_S3_MUT else None
    if (service, op) in AWS_SECRET_OPS:
        return f"secret/credential-issuing AWS call (`aws {service} {op}`)"
    if service == "ssm" and op.startswith("get-parameter") and "--with-decryption" in [a.lower() for a in args]:
        return "`aws ssm get-parameter --with-decryption` reads secret values"
    if (service, op) in AWS_DATA_READS:
        return f"data-content read (`aws {service} {op}`) is outside the view-only model"
    if (service, op) in AWS_READ_EXCEPTIONS:
        return None
    if op.startswith(AWS_MUT_PREFIXES):
        return f"cloud-mutating AWS call (`aws {service} {op}`)"
    return None


def check_gcloud(args):
    pos = [p for p in positional(args) if p not in ("alpha", "beta")]
    if not pos or pos[0] in GCLOUD_LOCAL_GROUPS:
        if pos and pos[0] == "auth" and any(re.search(p, " ".join(pos)) for p in GCLOUD_SECRET_PATTERNS):
            return f"token-printing gcloud command (`gcloud {' '.join(pos)}`)"
        return None
    joined = " ".join(pos)
    for pat in GCLOUD_SECRET_PATTERNS:
        if re.search(pat, joined):
            return f"secret-reading gcloud command (`gcloud {joined}`)"
    if any(p in GCLOUD_MUTATING for p in pos[1:]):
        return f"cloud-mutating gcloud command (`gcloud {joined}`)"
    return None


def check_kubectl(args):
    pos = positional(args, {"-n", "--namespace", "--context", "--kubeconfig", "-o", "--output", "-l"})
    if not pos:
        return None
    verb = pos[0]
    if verb == "rollout":
        return None if len(pos) > 1 and pos[1] in KUBECTL_ROLLOUT_READ else "kubectl rollout (restart/undo changes workloads)"
    if verb in KUBECTL_MUTATING:
        return f"cluster-mutating kubectl command (`kubectl {verb}`)"
    if verb in ("get", "describe") and len(pos) > 1 and re.match(r"^(secret|secrets)(/|$)", pos[1]):
        return "reading Kubernetes secrets"
    return None


def check_terraform(cli, args):
    pos = positional(args)
    if not pos:
        return None
    if pos[0] in TERRAFORM_MUTATING:
        return f"`{cli} {pos[0]}` changes infrastructure or state"
    if pos[0] == "state" and len(pos) > 1 and pos[1] in TERRAFORM_STATE_MUTATING:
        return f"`{cli} state {pos[1]}` changes state"
    if pos[0] == "workspace" and len(pos) > 1 and pos[1] in ("new", "delete"):
        return f"`{cli} workspace {pos[1]}` changes state"
    return None


def check_simple(cli, args, mutating):
    pos = positional(args)
    if pos and pos[0] in mutating:
        return f"`{cli} {pos[0]}` changes deployed resources"
    if cli == "pulumi" and len(pos) > 1 and pos[0] == "stack" and pos[1] == "rm":
        return "`pulumi stack rm` deletes a stack"
    return None


def check_segment(tokens):
    for i, raw in enumerate(tokens):
        cli = norm_token(raw)
        args = [t.strip("\"'") for t in tokens[i + 1:]]
        reason = None
        if cli == "az":
            reason = check_az(args)
        elif cli == "aws":
            reason = check_aws(args)
        elif cli == "gcloud":
            reason = check_gcloud(args)
        elif cli == "kubectl":
            reason = check_kubectl(args)
        elif cli in ("terraform", "tofu"):
            reason = check_terraform(cli, args)
        elif cli == "helm":
            reason = check_simple(cli, args, HELM_MUTATING)
        elif cli == "pulumi":
            reason = check_simple(cli, args, PULUMI_MUTATING)
        elif cli in HTTP_CLIS:
            seg = " " + " ".join(tokens[i:]) + " "
            if MGMT_HOSTS.search(seg) and HTTP_MUTATING.search(seg):
                reason = "mutating HTTP call to a cloud / DevOps management API"
        if reason:
            return reason
    return None


def evaluate(command):
    """Return a block reason, or None if the command is allowed."""
    if not command or not command.strip():
        return None
    flat = flatten(command.replace("\\\n", " "))
    for rx, why in ((PS_AZ_SECRET, "secret-reading Az PowerShell cmdlet"),
                    (PS_AZ_MUTATING, "cloud-mutating Az PowerShell cmdlet"),
                    (PS_AWS_MUTATING, "cloud-mutating AWS PowerShell cmdlet")):
        m = rx.search(flat)
        if m:
            return f"{why} ({m.group(0)})"
    for seg in SEGMENT_SPLIT.split(flat):
        tokens = [t for t in re.split(r"\s+", seg.replace('"', " ").replace("'", " ")) if t]
        reason = check_segment(tokens)
        if reason:
            return reason
    return None


def main():
    if os.environ.get(OVERRIDE_ENV) == "1":
        return 0
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return 0
    command = (payload.get("tool_input") or {}).get("command", "")
    if not isinstance(command, str):
        return 0
    reason = evaluate(command)
    if reason:
        sys.stderr.write(f"BLOCKED by the ops-toolkit read-only guard: {reason}. {GUIDANCE}\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

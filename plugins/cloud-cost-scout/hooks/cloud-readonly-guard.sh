#!/usr/bin/env bash
# ops-toolkit PreToolUse wrapper. Runs the precise Python guard; if no usable
# Python 3.8+ is found, falls back to a conservative grep check (may over-block,
# never silently allows an obvious cloud write). Exit 2 = block, 0 = allow.
set -u

[ "${OPS_TOOLKIT_ALLOW_CLOUD_WRITES:-}" = "1" ] && exit 0

# On Windows the hook path can arrive with backslashes (D:\...\hook.sh); normalise it.
SRC="${BASH_SOURCE[0]//\\//}"
case "$SRC" in */*) DIR="${SRC%/*}" ;; *) DIR="." ;; esac
GUARD="$DIR/cloud_readonly_guard.py"
INPUT="$(cat)"

# OPS_TOOLKIT_PYTHON lets tests (or locked-down machines) pin the interpreter list.
if [ -f "$GUARD" ]; then
  for PY in ${OPS_TOOLKIT_PYTHON:-python3 python py}; do
    # The version probe also rejects the Windows Store "python3" alias stub.
    if command -v "$PY" >/dev/null 2>&1 \
       && "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
      printf '%s' "$INPUT" | "$PY" "$GUARD"
      RC=$?
      # Only 0 (allow) and 2 (block) are decisions. Anything else is a guard crash:
      # fall through to the conservative check rather than allowing or blocking blindly.
      if [ "$RC" -eq 0 ] || [ "$RC" -eq 2 ]; then exit "$RC"; fi
      break
    fi
  done
fi

# Fallback: no Python. Match only inside the "command" value to avoid tripping on descriptions.
CMD=$(printf '%s' "$INPUT" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\(\([^"\\]\|\\.\)*\)".*/\1/p' | head -1)
[ -z "$CMD" ] && CMD="$INPUT"
if printf '%s' "$CMD" | grep -Eiq '(^|[^[:alnum:]_-])(az|aws|gcloud|kubectl|terraform|tofu|helm|pulumi)([^[:alnum:]_-][^;&|]*)?[^[:alnum:]_-](delete|create|update|set|deploy|apply|destroy|terminate|remove|put|modify|scale|restart|stop|start|purge|install|uninstall|patch|replace|get-secret-value|get-access-token|list-keys)([^[:alnum:]_-]|$)'; then
  echo "BLOCKED by the ops-toolkit read-only guard (fallback mode - Python 3.8+ not found, so matching is conservative and may over-block): this looks like a cloud-mutating or secret-reading command. These skills are read-only, so propose the change as a pull request or hand the exact command to a human. Install Python 3.8+ for precise checks. Human-approved exception: relaunch Claude Code with OPS_TOOLKIT_ALLOW_CLOUD_WRITES=1." >&2
  exit 2
fi
exit 0

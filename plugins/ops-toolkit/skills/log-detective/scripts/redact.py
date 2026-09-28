#!/usr/bin/env python3
"""Redact secrets and personal data from logs / exports before an AI reads them.

Replacements are *consistent pseudonyms* (the same email always becomes <email-1>),
so correlation across log lines still works after redaction.

What it covers: secrets and tokens (JWT, bearer, Azure keys / SAS, connection-string
passwords, AWS access keys, private keys, GitHub/ADO tokens, generic key=value
secrets), emails, IPv4/IPv6, card numbers (Luhn-checked), phone numbers (international
+ format only, to avoid eating ordinary numbers).
What it cannot cover: free-text personal names, addresses, or business-confidential
content. Apply data-classification rules before sharing client logs at all.

Usage:
    python redact.py input.log > clean.log
    python redact.py --stats input.json          # also print counts to stderr
    cat file | python redact.py -
Standard library only; Python 3.8+.
"""
import argparse
import re
import sys

# Order matters: secrets first (they may contain email-/IP-like fragments).
# Where a rule has a named group `v`, only that part is replaced (the key name stays,
# e.g. "Password=<conn-password-1>"), which keeps the line readable for diagnosis.
RULES = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,})")),
    ("azure-key", re.compile(r"(?i)\b(AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/=]{20,})")),
    ("sas-sig", re.compile(r"(?i)[?&]sig=(?P<v>[A-Za-z0-9%+/=]{16,})")),
    ("conn-password", re.compile(r"(?i)\b(password|pwd)=(?P<v>[^;\"'\s]+)")),
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("aws-secret", re.compile(r"(?i)aws_secret_access_key[\"'\s:=]{1,4}(?P<v>[A-Za-z0-9/+=]{40})")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("instrumentation-key", re.compile(r"(?i)InstrumentationKey=(?P<v>[0-9a-f-]{36})")),
    # Well-known token formats are secrets whatever key they sit under.
    ("known-token", re.compile(
        r"\b(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"      # Stripe
        r"|xox[abprs]-[A-Za-z0-9-]{10,}"                         # Slack
        r"|AIza[0-9A-Za-z_-]{35}"                                # Google API key
        r"|glpat-[A-Za-z0-9_-]{20,}"                             # GitLab
        r"|npm_[A-Za-z0-9]{36}"                                  # npm
        r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})")),       # SendGrid
    ("secret-value", re.compile(
        # key names ending in token/secret/password/apikey/...key: _authToken, client_secret,
        # DB_PASSWORD, PaymentGateway__ApiKey, SubscriptionKey. Quotes may be backslash-escaped,
        # as in JSON embedded in a JSON string (Activity Log request bodies).
        r"(?i)\b\w*?(api[_-]?key|apikey|secret|token|passwd|password|pwd"
        r"|(?:access|subscription|shared|private|signing|master|primary|secondary|account)[_-]?key)"
        r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?"
        r"(?P<v>[^\s\"'\\,;&]{6,})")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("ipv6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("phone", re.compile(r"(?<![\w+])\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}\b")),
]

# Values that look like IPs/cards but are not personal data.
SAFE_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class Redactor:
    def __init__(self):
        self.maps = {}
        self.counts = {}

    def _token(self, kind, value):
        m = self.maps.setdefault(kind, {})
        if value not in m:
            m[value] = f"<{kind}-{len(m) + 1}>"
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return m[value]

    def redact(self, text):
        for kind, rx in RULES:
            def repl(match, kind=kind):
                whole = match.group(0)
                if "v" in match.re.groupindex:
                    val = match.group("v")
                    if val.startswith("<") and val.endswith(">"):  # already redacted
                        return whole
                    start = match.start("v") - match.start(0)
                    return whole[:start] + self._token(kind, val) + whole[start + len(val):]
                if kind == "ipv4" and whole in SAFE_IPS:
                    return whole
                if kind == "card":
                    digits = re.sub(r"\D", "", whole)
                    if not (13 <= len(digits) <= 19 and luhn_ok(digits)):
                        return whole
                return self._token(kind, whole)
            text = rx.sub(repl, text)
        return text


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", help="file to redact, or - for stdin")
    ap.add_argument("--stats", action="store_true", help="print redaction counts to stderr")
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    data = sys.stdin.read() if args.path == "-" else open(args.path, encoding="utf-8", errors="replace").read()
    r = Redactor()
    sys.stdout.write(r.redact(data))
    if args.stats:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(r.counts.items())) or "nothing found"
        sys.stderr.write(f"redacted: {summary}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Small helpers shared by the pipeline-doctor scripts: timestamp parsing, duration
formatting and JSON loading. Standard library only; Python 3.8+.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ISO = re.compile(r"(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[T ](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
                 r"(?:\.(?P<frac>\d+))?\s*(?P<tz>Z|[+-]\d{2}:?\d{2})?")


def parse_ts(value):
    """Parse an ISO-8601 timestamp (Azure DevOps uses 7 fractional digits, GitHub uses 'Z').
    Returns seconds since the epoch as a float, or None. Timestamps without a zone are UTC."""
    if not value or not isinstance(value, str):
        return None
    m = ISO.search(value)
    if not m:
        return None
    frac = (m.group("frac") or "0")[:6].ljust(6, "0")
    dt = datetime(int(m.group("y")), int(m.group("mo")), int(m.group("d")), int(m.group("h")),
                  int(m.group("mi")), int(m.group("s")), int(frac), tzinfo=timezone.utc)
    tz = m.group("tz")
    if tz and tz != "Z":
        sign = -1 if tz[0] == "-" else 1
        digits = tz[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return dt.timestamp()


def iso(seconds):
    """Seconds since the epoch -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC), or None."""
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def human(seconds):
    """Duration in seconds -> '2d 03h', '1h 05m', '12m 30s', '45s'."""
    if seconds is None:
        return "n/a"
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d {(s % 86400) // 3600:02d}h"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def mean(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None

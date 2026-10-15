#!/usr/bin/env python3
"""
Simulated SIEM replay for MayaTrail workflow runs.

Posts one alert per Sigma rule an emulation ships to a workflow alert endpoint,
signed exactly as a real SIEM must sign them. It stands in for a SIEM when none
is connected, so the workflow's detection scorecard can be shown end to end.

Every alert is SIMULATED. Nothing here observes the attack: the alerts are
built from the emulation's rule files, not from logs. Each alert carries
"source": "simulated-replay" and "simulated": true so it can never be mistaken
for real telemetry, and this script says so on every run. Present any result
produced with it as a simulation.

Rules can be withheld with --silent so the scorecard shows them as missed, and
--none sends nothing at all, which the platform reports as "not integrated" for
that run.

Usage:
    export MAYATRAIL_ALERT_SECRET='<endpoint secret>'
    python replay.py --endpoint https://app.mayatrail.tech/api/workflows/alerts/<id>/ \\
        --emulation codefinger --silent T1490 --silent T1530
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

SECRET_ENV = "MAYATRAIL_ALERT_SECRET"
SOURCE = "simulated-replay"
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_BANNER = (
    "SIMULATED ALERTS: these are generated from the emulation's rule files, not\n"
    "detected from logs. Present any scorecard they produce as a simulation."
)


def repo_root() -> Path:
    """
    Return the repository root: two levels above this script when it sits in
    tools/siem_replay/ of a checkout, otherwise the current directory.
    """
    here = Path(__file__).resolve()
    if len(here.parents) > 2 and (here.parents[2] / "emulations").is_dir():
        return here.parents[2]
    return Path.cwd()


def load_rules(emulation_dir: Path) -> list[dict]:
    """
    Read every Sigma rule the emulation ships.

    Args:
        emulation_dir: The emulation's folder under emulations/.

    Returns:
        One dict per rule with ruleId, ruleName, technique, severity and the
        file stem, in file order.
    """
    rules = []
    for path in sorted((emulation_dir / "detections").glob("sigma_*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not isinstance(doc, dict) or not doc.get("id"):
                continue
            techniques = [
                m.group(1).upper()
                for tag in doc.get("tags", [])
                if (m := _TECHNIQUE_TAG.match(str(tag)))
            ]
            rules.append({
                "ruleId": str(doc["id"]),
                "ruleName": str(doc.get("title", "")),
                "technique": techniques[0] if techniques else "",
                "severity": str(doc.get("level", "")),
                "file": path.stem,
                "detection": doc.get("detection") or {},
            })
    return rules


def is_withheld(rule: dict, silent: list[str]) -> bool:
    """
    Decide whether a rule was named in --silent.

    A --silent value matches a rule's Sigma id, its technique (T1490 also
    matches T1490.001) or its file stem (sigma_t1490).
    """
    for value in silent:
        v = value.strip().lower()
        technique = rule["technique"].lower()
        if v in (rule["ruleId"].lower(), rule["file"].lower(), technique):
            return True
        if technique.startswith(v + "."):
            return True
    return False


# CloudTrail fields copied from a rule's own selections into the alert's event.
# Only fields the rule itself matches on are used; nothing is invented.
_EVENT_FIELDS = ("eventSource", "eventName")


def _first_value(value):
    """A selection value may be a scalar or a list of alternatives; take the first."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def rule_event(rule: dict, region: str, when: str) -> dict:
    """
    Build a CloudTrail-shaped record for the alert to carry, the way a SIEM
    attaches the event that triggered a detection.

    eventSource and eventName are taken from the first selection in the rule
    that names them, using plain field equality only (modifiers such as
    |contains are skipped). Identity, address and request details are left out
    rather than made up.
    """
    event = {"eventVersion": "1.08", "eventTime": when, "awsRegion": region, "eventType": "AwsApiCall"}
    for name, selection in rule["detection"].items():
        if name == "condition" or not isinstance(selection, dict):
            continue
        for field in _EVENT_FIELDS:
            if field in selection and field not in event:
                value = _first_value(selection[field])
                if isinstance(value, str):
                    event[field] = value
    return event


def build_alert(rule: dict, region: str) -> dict:
    """
    Build one alert in a SIEM-like shape: rule metadata plus the CloudTrail
    record that triggered it. Marked as simulated in every payload.
    """
    when = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "ruleId": rule["ruleId"],
        "ruleName": rule["ruleName"],
        "technique": rule["technique"],
        "severity": rule["severity"],
        "firedAt": when,
        "source": SOURCE,
        "simulated": True,
        "event": rule_event(rule, region, when),
    }


def post_alert(endpoint: str, secret: str, alert: dict) -> int:
    """
    Sign and post one alert.

    The signature is HMAC-SHA256 over "<timestamp>.<body>" with the endpoint's
    secret, sent as "sha256=<hex>", which is what the platform verifies.

    Returns:
        The HTTP status code (202 when accepted).
    """
    body = json.dumps(alert, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-MayaTrail-Timestamp": timestamp,
            "X-MayaTrail-Signature": f"sha256={digest}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


def parse_args() -> argparse.Namespace:
    """Define and parse the command line."""
    parser = argparse.ArgumentParser(description="Post simulated SIEM alerts to a MayaTrail workflow endpoint.")
    parser.add_argument("--endpoint", required=True, help="Full alert endpoint URL from the Workflows page.")
    parser.add_argument("--emulation", required=True, help="Emulation folder name, e.g. codefinger.")
    parser.add_argument("--silent", action="append", default=[],
                        help="Withhold a rule (Sigma id, technique or file stem). Repeatable.")
    parser.add_argument("--none", action="store_true",
                        help="Send nothing; the run is reported as not integrated.")
    parser.add_argument("--region", default="us-east-1", help="awsRegion for the simulated CloudTrail record.")
    parser.add_argument("--spacing", type=float, default=3.0, help="Seconds between alerts (default 3).")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be sent without posting.")
    parser.add_argument("--repo", type=Path, default=None, help="Repository root (default: auto).")
    return parser.parse_args()


def main() -> int:
    """Run the replay and report what was sent."""
    args = parse_args()
    print(_BANNER, end="\n\n")

    emulation_dir = (args.repo or repo_root()) / "emulations" / args.emulation
    rules = load_rules(emulation_dir)
    if not rules:
        print(f"No Sigma rules found under {emulation_dir}/detections.", file=sys.stderr)
        return 2

    if args.none:
        print(f"{args.emulation}: sending nothing ({len(rules)} rules). The run will read as not integrated.")
        return 0

    secret = os.environ.get(SECRET_ENV, "")
    if not secret and not args.dry_run:
        print(f"Set {SECRET_ENV} to the endpoint's secret.", file=sys.stderr)
        return 2

    failed = 0
    for index, rule in enumerate(rules):
        label = f"{rule['technique'] or '-':<10} {rule['ruleName']}"
        if is_withheld(rule, args.silent):
            print(f"  silent    {label}")
            continue
        alert = build_alert(rule, args.region)
        if args.dry_run:
            print(f"  would send {label}\n             {json.dumps(alert)}")
            continue
        status = post_alert(args.endpoint, secret, alert)
        ok = status == 202
        failed += 0 if ok else 1
        print(f"  {'sent' if ok else 'FAILED'}      {label}  (HTTP {status})")
        if index < len(rules) - 1:
            time.sleep(args.spacing)

    if failed:
        print(f"\n{failed} alert(s) rejected. 401 means a wrong secret, a wrong endpoint id, or a clock more "
              "than 5 minutes off.", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

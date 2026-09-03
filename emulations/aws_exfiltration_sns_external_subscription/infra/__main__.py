import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import pathlib
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants (single source of truth) ──────────────────────────
# Load from resource_names.json when present (local dev); fall back to the
# embedded defaults when the backend worker copies only Pulumi.yaml+__main__.py.
_DEFAULT_RESOURCES = {
    "target_topic_name":  "atomic-sns-ext-sub-topic",
    "bait_topic_name":    "atomic-sns-ext-sub-bait",
    "sink_queue_name":    "atomic-sns-ext-sub-sink",
    "victim_role_name":   "atomic-sns-external-subscription-victim-role",
    "victim_policy_name": "atomic-sns-ext-sub-victim-policy",
}
_p = pathlib.Path(__file__).parent / "resource_names.json"
_R = json.loads(_p.read_text())["resources"] if _p.exists() else _DEFAULT_RESOURCES

TARGET_TOPIC_NAME   = _R["target_topic_name"]
BAIT_TOPIC_NAME     = _R["bait_topic_name"]
SINK_QUEUE_NAME     = _R["sink_queue_name"]
VICTIM_ROLE_NAME    = _R["victim_role_name"]
VICTIM_POLICY_NAME  = _R["victim_policy_name"]

# Common tags
TAGS = {
    "MayaTrail": "true",
    "Purpose":   "adversary-emulation",
    "AtomicId":  "aws.exfiltration.sns-external-subscription",
    "Technique": "T1567",
}

# Account identity (synchronous; .id per pulumi-aws v7)
account_id = aws.get_caller_identity().account_id

# ── Target SNS Topic ──────────────────────────────────────────────────────────
# Carries seeded sensitive notifications; attacker subscribes an external
# endpoint to this topic as the exfil channel (T1567).
target_topic = aws.sns.Topic(
    "target-topic",
    name=TARGET_TOPIC_NAME,
    display_name="prod-order-events-notifications",
    tags=TAGS,
)

# ── Bait SNS Topic ────────────────────────────────────────────────────────────
# Decoy topic so sns:ListTopics returns multiple plausible targets.
bait_topic = aws.sns.Topic(
    "bait-topic",
    name=BAIT_TOPIC_NAME,
    display_name="billing-invoice-stream",
    fifo_topic=False,
    tags=TAGS,
)

# ── SQS Sink Queue ────────────────────────────────────────────────────────────
# Stands in for the attacker-controlled external endpoint. SNS auto-confirms
# SQS subscriptions without a handshake; delivery stays within the account.
sink_queue = aws.sqs.Queue(
    "sink-queue",
    name=SINK_QUEUE_NAME,
    message_retention_seconds=3600,
    visibility_timeout_seconds=30,
    tags=TAGS,
)

# ── SQS Queue Policy ──────────────────────────────────────────────────────────
# Allows sns.amazonaws.com to call sqs:SendMessage on the sink queue, scoped
# to the target topic ARN. Without this, delivery silently drops.
sink_queue_policy = aws.sqs.QueuePolicy(
    "sink-queue-policy",
    queue_url=sink_queue.id,
    policy=pulumi.Output.all(
        sink_queue_arn=sink_queue.arn,
        target_topic_arn=target_topic.arn,
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "AllowSNSDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action":   "sqs:SendMessage",
                "Resource": args["sink_queue_arn"],
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": args["target_topic_arn"],
                    }
                },
            }
        ],
    })),
)

# ── Victim IAM Role ───────────────────────────────────────────────────────────
# Trust policy uses current account root so any principal in the account
# can assume the role (self-trust). Never a placeholder account ID.
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    description="Atomic emulation victim role - over-permissioned SNS service account",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect":    "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action":    "sts:AssumeRole",
            }
        ],
    }),
    max_session_duration=3600,
    tags=TAGS,
)

# ── Victim Inline Policy ──────────────────────────────────────────────────────
# Intentionally over-permissioned (sns:Subscribe on *) to simulate a
# developer/service account that accumulated excess SNS rights.
victim_policy = aws.iam.RolePolicy(
    "victim-policy",
    name=VICTIM_POLICY_NAME,
    role=victim_role.name,
    policy=pulumi.Output.all(
        sink_queue_arn=sink_queue.arn,
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "SNSBroadPermissions",
                "Effect": "Allow",
                "Action": [
                    "sns:ListTopics",
                    "sns:GetTopicAttributes",
                    "sns:ListSubscriptionsByTopic",
                    "sns:Subscribe",
                    "sns:Unsubscribe",
                    "sns:Publish",
                ],
                "Resource": "*",
            },
            {
                "Sid":    "SQSSinkReadBack",
                "Effect": "Allow",
                "Action": [
                    "sqs:GetQueueUrl",
                    "sqs:GetQueueAttributes",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                ],
                "Resource": args["sink_queue_arn"],
            },
            {
                "Sid":    "STSIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
        ],
    })),
)

# ── Pulumi Exports ────────────────────────────────────────────────────────────
# Static name exports (attack.py resolves these without depending on ARN Output)
pulumi.export("target_topic_name", TARGET_TOPIC_NAME)
pulumi.export("bait_topic_name",   BAIT_TOPIC_NAME)
pulumi.export("sink_queue_name",   SINK_QUEUE_NAME)
pulumi.export("victim_role_name",  VICTIM_ROLE_NAME)

# Dynamic ARN / URL exports (known only after pulumi up)
pulumi.export("target_topic_arn", target_topic.arn)
pulumi.export("bait_topic_arn",   bait_topic.arn)
pulumi.export("sink_queue_url",   sink_queue.id)
pulumi.export("sink_queue_arn",   sink_queue.arn)
pulumi.export("victim_role_arn",  victim_role.arn)

# Aliases: attack.py's own names for these same resources
pulumi.export("topic_arn",        target_topic.arn)
pulumi.export("sqs_sink_arn",     sink_queue.arn)
pulumi.export("sqs_sink_url",     sink_queue.id)

"""
Infra for aws_persistence_sqs_open_queue_policy (atomic technique T1098).

Ported from the pipeline emulation ATOMIC_SQS_OPEN_QUEUE_POLICY. The backend
worker copies only Pulumi.yaml + __main__.py into the run dir, so the original
resource_names.json has been inlined below as constants.

Provisions a target SQS queue (plus DLQ and a decoy queue), a victim IAM role
and a victim IAM user with a static access key. attack.py builds its boto3
session from the exported victim access key and injects a wildcard resource
policy on the target queue via SetQueueAttributes.
"""

import json

import pulumi
import pulumi_aws as aws

# --------------------------------------------------------------------------- #
# Resource name constants (inlined from infra/resource_names.json)
# --------------------------------------------------------------------------- #
ORDERS_INGEST_PROD  = "orders-ingest-prod"
ORDERS_INGEST_DLQ   = "orders-ingest-dlq"
PAYMENTS_PROCESSING = "payments-processing-prod"
VICTIM_ROLE_NAME    = "atomic-sqs-victim-role"
VICTIM_USER_NAME    = "atomic-sqs-victim-user"
LOG_GROUP_NAME      = "/mayatrail/atomic-sqs-open-queue-policy"

# Resolve current account synchronously - used in trust policy
caller     = aws.get_caller_identity()
account_id = caller.account_id

# --------------------------------------------------------------------------- #
# Shared tags
# --------------------------------------------------------------------------- #
TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-sqs-open-queue-policy",
    "Technique":   "T1098",
}

# --------------------------------------------------------------------------- #
# 1. CloudWatch Log Group (no dependencies)
# --------------------------------------------------------------------------- #
log_group = aws.cloudwatch.LogGroup(
    "emulation-log-group",
    name=LOG_GROUP_NAME,
    retention_in_days=7,
    tags=TAGS,
)

# --------------------------------------------------------------------------- #
# 2. Dead-letter queue (no dependencies)
# --------------------------------------------------------------------------- #
orders_dlq = aws.sqs.Queue(
    "orders-ingest-dlq",
    name=ORDERS_INGEST_DLQ,
    message_retention_seconds=345600,
    tags=TAGS,
)

# --------------------------------------------------------------------------- #
# 3. Decoy queue - recon bait, no dependencies
# --------------------------------------------------------------------------- #
payments_queue = aws.sqs.Queue(
    "payments-processing-prod",
    name=PAYMENTS_PROCESSING,
    message_retention_seconds=86400,
    tags=TAGS,
)

# --------------------------------------------------------------------------- #
# 4. Primary target queue (depends on DLQ for redrive)
# --------------------------------------------------------------------------- #
redrive_policy_str = orders_dlq.arn.apply(
    lambda arn: json.dumps({"deadLetterTargetArn": arn, "maxReceiveCount": 3})
)

orders_queue = aws.sqs.Queue(
    "orders-ingest-prod",
    name=ORDERS_INGEST_PROD,
    visibility_timeout_seconds=30,
    message_retention_seconds=86400,
    redrive_policy=redrive_policy_str,
    tags=TAGS,
)

# --------------------------------------------------------------------------- #
# 5. Victim IAM role - self-account trust so AssumeRole works in the lab
# --------------------------------------------------------------------------- #
trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
})

victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=trust_policy,
    description="Atomic emulation victim role - sqs open queue policy T1098",
    tags=TAGS,
)

# --------------------------------------------------------------------------- #
# 6. Inline policy - sqs:* on orders-ingest-prod (depends on queue + role)
#    Intentionally broad: mirrors real-world workload roles so the detection
#    fires on the anomalous queue policy content, not a principal anomaly.
#    sqs:ListQueues / sqs:GetQueueUrl do not support resource-level permissions
#    and must be granted on "*" (attack Step 1 enumerates queues).
# --------------------------------------------------------------------------- #
victim_inline_policy = orders_queue.arn.apply(
    lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SQSWorkloadAccess",
                "Effect": "Allow",
                "Action": ["sqs:*"],
                "Resource": arn,
            },
            {
                "Sid": "SQSListEnumerate",
                "Effect": "Allow",
                "Action": ["sqs:ListQueues", "sqs:GetQueueUrl"],
                "Resource": "*",
            },
        ],
    })
)

victim_role_policy = aws.iam.RolePolicy(
    "victim-role-policy",
    role=victim_role.name,
    policy=victim_inline_policy,
)

# --------------------------------------------------------------------------- #
# 7. Victim IAM user with static access key (attack_surface)
# attack.py never does AssumeRole -- it builds its boto3 session directly from
# a static access key. A Role cannot hold an access key, so this is a separate
# IAM User carrying the identical SQS policy content as victim_role.
# --------------------------------------------------------------------------- #
victim_user = aws.iam.User(
    "victim-user",
    name=VICTIM_USER_NAME,
    tags=TAGS,
)

victim_access_key = aws.iam.AccessKey(
    "victim-access-key",
    user=victim_user.name,
)

victim_user_policy = aws.iam.UserPolicy(
    "victim-user-policy",
    user=victim_user.name,
    policy=victim_inline_policy,
)

# --------------------------------------------------------------------------- #
# Pulumi exports - consumed by attack.run(outputs, region)
# --------------------------------------------------------------------------- #
pulumi.export("orders_ingest_prod_url",  orders_queue.url)
pulumi.export("orders_ingest_prod_arn",  orders_queue.arn)
pulumi.export("orders_ingest_prod_name", ORDERS_INGEST_PROD)
pulumi.export("orders_ingest_dlq_url",   orders_dlq.url)
pulumi.export("orders_ingest_dlq_name",  ORDERS_INGEST_DLQ)
pulumi.export("payments_processing_url", payments_queue.url)
pulumi.export("payments_processing_name", PAYMENTS_PROCESSING)
pulumi.export("victim_role_arn",         victim_role.arn)
pulumi.export("victim_role_name",        VICTIM_ROLE_NAME)
pulumi.export("account_id",             account_id)
pulumi.export("victim_access_key_id",     victim_access_key.id)
pulumi.export("victim_secret_access_key", pulumi.Output.secret(victim_access_key.secret))

import json
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
TARGET_ROLE_NAME = "stratus-red-team-backdoor-role-target"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.persistence.iam-backdoor-role",
}

# ── IAM role with a simple same-account trust policy ─────────────────────────
# The attack script will modify this trust policy to add an external account.
current_account = aws.get_caller_identity().account_id

trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": f"arn:aws:iam::{current_account}:root"
            },
            "Action": "sts:AssumeRole",
        }
    ],
})

role = aws.iam.Role(
    "target-role",
    name=TARGET_ROLE_NAME,
    assume_role_policy=trust_policy,
    tags=TAGS,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("role_name",            TARGET_ROLE_NAME)
pulumi.export("role_arn",             role.arn)
pulumi.export("original_trust_policy", trust_policy)

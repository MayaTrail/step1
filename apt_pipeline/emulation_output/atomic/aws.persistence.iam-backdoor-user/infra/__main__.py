import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
TARGET_USER_NAME = "stratus-red-team-backdoor-user-target"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.persistence.iam-backdoor-user",
}

# ── IAM user with no existing access keys ─────────────────────────────────────
# The attack will create a second access key for this user.
user = aws.iam.User(
    "target-user",
    name=TARGET_USER_NAME,
    force_destroy=True,
    tags=TAGS,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("user_name", TARGET_USER_NAME)
pulumi.export("user_arn",  user.arn)

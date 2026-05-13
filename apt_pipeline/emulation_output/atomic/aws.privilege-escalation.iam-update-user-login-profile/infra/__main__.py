import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
TARGET_USER_NAME = "stratus-red-team-update-login-profile-user"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.privilege-escalation.iam-update-user-login-profile",
}

# ── IAM user with a console login profile ────────────────────────────────────
# Simulates a legitimate user whose console password an attacker will hijack.
user = aws.iam.User(
    "target-user",
    name=TARGET_USER_NAME,
    force_destroy=True,
    tags=TAGS,
)

aws.iam.UserLoginProfile(
    "target-user-login-profile",
    user=user.name,
    password_length=20,
    password_reset_required=False,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("target_user_name", TARGET_USER_NAME)

import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
TARGET_USER_NAME = "stratus-red-team-no-mfa-user"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.initial-access.console-login-without-mfa",
}

# ── IAM user with console access but no MFA ───────────────────────────────────
user = aws.iam.User(
    "no-mfa-user",
    name=TARGET_USER_NAME,
    force_destroy=True,
    tags=TAGS,
)

# Login profile — the user can log in to the console without MFA
aws.iam.UserLoginProfile(
    "no-mfa-login-profile",
    user=user.name,
    password_length=20,
    password_reset_required=False,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("user_name", TARGET_USER_NAME)
pulumi.export("user_arn",  user.arn)

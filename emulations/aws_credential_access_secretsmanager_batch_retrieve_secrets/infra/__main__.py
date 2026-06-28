import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
SECRET_PREFIX = "stratus-red-team-batch-retrieve-secret"
SECRET_COUNT  = 20

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.credential-access.secretsmanager-batch-retrieve-secrets",
}

# ── Secrets Manager secrets (20) ──────────────────────────────────────────────
for i in range(SECRET_COUNT):
    name = f"{SECRET_PREFIX}-{i}"
    secret = aws.secretsmanager.Secret(
        f"secret-{i}",
        name=name,
        recovery_window_in_days=0,
        tags=TAGS,
    )
    aws.secretsmanager.SecretVersion(
        f"secret-version-{i}",
        secret_id=secret.id,
        secret_string=f"stratus-red-team-fake-secret-value-{i}",
    )

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("secret_prefix", SECRET_PREFIX)
pulumi.export("secret_count",  SECRET_COUNT)
pulumi.export("tag_key",       "StratusRedTeam")
pulumi.export("tag_value",     "true")

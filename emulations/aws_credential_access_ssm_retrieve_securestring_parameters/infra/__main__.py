import secrets as pysecrets
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PARAM_PREFIX = "/credentials/stratus-red-team"
PARAM_COUNT  = 42

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.credential-access.ssm-retrieve-securestring-parameters",
}

# ── SSM SecureString parameters (42) ──────────────────────────────────────────
for i in range(PARAM_COUNT):
    aws.ssm.Parameter(
        f"param-{i}",
        name=f"{PARAM_PREFIX}/{i}",
        type="SecureString",
        value=pysecrets.token_hex(8),
        tags=TAGS,
    )

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("param_prefix", PARAM_PREFIX)
pulumi.export("param_count",  PARAM_COUNT)

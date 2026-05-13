import base64
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX      = "stratus-red-team-sm-lc"
CONFIG_NAME = f"{PREFIX}-config"

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.execution.sagemaker-update-lifecycle-config",
}

# ── Benign OnStart script (will be overwritten by the attack) ─────────────────
BENIGN_SCRIPT_B64 = base64.b64encode(
    b"#!/bin/bash\n"
    b"echo 'SageMaker notebook instance starting...'\n"
).decode("utf-8")

# ── SageMaker Notebook Instance Lifecycle Configuration ───────────────────────
# Note: on_start takes a single base64-encoded script string in pulumi-aws.
lifecycle_config = aws.sagemaker.NotebookInstanceLifecycleConfiguration(
    f"{PREFIX}-config",
    name=CONFIG_NAME,
    on_start=BENIGN_SCRIPT_B64,
    tags=TAGS,
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("lifecycle_config_name", lifecycle_config.name)

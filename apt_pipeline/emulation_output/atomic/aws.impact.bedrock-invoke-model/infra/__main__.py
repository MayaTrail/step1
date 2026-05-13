import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack calls bedrock:InvokeModel directly.
# Bedrock model access must be enabled for the account in us-east-1 or us-west-2.

pulumi.export("note", "No infrastructure required — enable Bedrock model access in us-east-1 or us-west-2")

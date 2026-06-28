import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# sts:GetFederationToken requires IAM user credentials (not a role).
# Run this script with IAM user access keys in the environment.
# The federated token expires naturally; no cleanup is needed.

pulumi.export("note", "No infrastructure required — run with IAM user credentials")

import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack script creates its own IAM role and cleans it up on exit.
# No Pulumi-managed resources are needed.

pulumi.export("note", "No infrastructure required for this technique")

import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack reads userData from existing EC2 instances in the account.
# No Pulumi resources are needed.

pulumi.export("note", "No infrastructure required — reads existing EC2 instances")

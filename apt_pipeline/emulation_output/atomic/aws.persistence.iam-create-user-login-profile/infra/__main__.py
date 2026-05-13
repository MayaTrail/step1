import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack script creates its own IAM user + login profile, then cleans up.

pulumi.export("note", "No infrastructure required for this technique")

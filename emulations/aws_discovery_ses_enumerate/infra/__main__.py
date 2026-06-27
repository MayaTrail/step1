import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack reads existing SES configuration — no resources need to be created.

pulumi.export("note", "No infrastructure required — reads existing SES configuration")

import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack script launches and immediately terminates its own EC2 instance.

pulumi.export("note", "No infrastructure required — attack creates and terminates its own instance")

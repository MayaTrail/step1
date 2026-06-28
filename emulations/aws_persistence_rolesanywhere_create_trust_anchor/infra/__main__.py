import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack script generates a self-signed certificate and creates the trust
# anchor in-script, then cleans up on exit.

pulumi.export("note", "No infrastructure required for this technique")

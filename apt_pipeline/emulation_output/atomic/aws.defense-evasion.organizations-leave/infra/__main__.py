import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# The attack calls organizations:LeaveOrganization directly.
# It will be denied in most environments, but the CloudTrail event
# is the detection signal regardless of success or failure.

pulumi.export("note", "No infrastructure required for this technique")

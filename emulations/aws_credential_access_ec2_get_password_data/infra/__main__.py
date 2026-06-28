import pulumi

# ── No infrastructure required ────────────────────────────────────────────────
# This technique generates CloudTrail noise by calling ec2:GetPasswordData
# against fake instance IDs — no AWS resources need to be created first.

pulumi.export("note", "No infrastructure required for this technique")

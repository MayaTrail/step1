import pulumi

# No AWS resources required as prerequisites.
# The attack script (emulation_scripts/attack.py) creates and cleans up
# its own resources (IAM user, policy attachment, access key).

pulumi.export("note", "No prerequisites — attack.py manages its own resources")

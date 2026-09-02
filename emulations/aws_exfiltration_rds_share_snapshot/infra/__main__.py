"""
Infrastructure for aws.exfiltration.rds-share-snapshot.

Provisions a small MySQL instance and a manual snapshot, plus a scoped attacker
role holding only the snapshot-attribute actions the technique needs. Sharing a
snapshot to an external account is destructive, so the attack assumes that role
rather than running as the tenant's cross-account role. IAM, not the script,
bounds which snapshots can be shared.
"""

import json

import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX          = "stratus-red-team-rds-snap"
ATTACKER_ROLE_NAME   = f"{PREFIX}-attacker-role"
ATTACKER_POLICY_NAME = f"{PREFIX}-attacker-policy"

account_id = aws.get_caller_identity().account_id
DB_IDENTIFIER   = f"{PREFIX}-db"
SNAP_IDENTIFIER = f"{PREFIX}-snap"
DB_USERNAME     = "stratusadmin"
DB_PASSWORD     = "StratusR3dT3am1!"   # Used only in test infra — not a real secret

TAGS = {
    "StratusRedTeam": "true",
    "Purpose":        "adversary-emulation",
    "Technique":      "aws.exfiltration.rds-share-snapshot",
}

# ── RDS DB Instance (MySQL db.t3.micro — minimal cost) ───────────────────────
db = aws.rds.Instance(
    f"{PREFIX}-db",
    identifier=DB_IDENTIFIER,
    allocated_storage=20,
    engine="mysql",
    engine_version="8.0",
    instance_class="db.t3.micro",
    db_name="stratusdb",
    username=DB_USERNAME,
    password=DB_PASSWORD,
    publicly_accessible=False,
    multi_az=False,
    skip_final_snapshot=True,
    apply_immediately=True,
    tags={**TAGS, "Name": DB_IDENTIFIER},
)

# ── Manual RDS Snapshot ───────────────────────────────────────────────────────
snapshot = aws.rds.Snapshot(
    f"{PREFIX}-snapshot",
    db_instance_identifier=db.identifier,   # .id returns DbiResourceId; .identifier is the user-defined name
    db_snapshot_identifier=SNAP_IDENTIFIER,
    tags=TAGS,
)

# ── Attacker role (scoped to this snapshot only) ──────────────────────────────
# Trusts the account root so the tenant's cross-account role can assume it.
# ModifyDBSnapshotAttribute does support resource-level permissions, so the
# policy is pinned to this emulation's own snapshot ARN. The role cannot share
# any other snapshot in the account.
attacker_role = aws.iam.Role(
    "attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "attacker-role-policy",
    name=ATTACKER_POLICY_NAME,
    role=attacker_role.id,
    policy=snapshot.db_snapshot_arn.apply(
        lambda snapshot_arn: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    # The destructive action. Pinned to this emulation's own
                    # snapshot, so the role cannot share anything else.
                    "Sid": "ShareThisSnapshotOnly",
                    "Effect": "Allow",
                    "Action": "rds:ModifyDBSnapshotAttribute",
                    "Resource": snapshot_arn,
                },
                {
                    # Read-only verification step. Kept on "*" because RDS
                    # Describe actions do not reliably support resource-level
                    # permissions; scoping it risks AccessDenied at attack time
                    # for no blast-radius gain, since the call only reports who
                    # a snapshot is already shared with.
                    "Sid": "ReadSnapshotAttributes",
                    "Effect": "Allow",
                    "Action": "rds:DescribeDBSnapshotAttributes",
                    "Resource": "*",
                },
            ],
        })
    ),
)

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("snapshot_id",    snapshot.id)
pulumi.export("db_instance_id", db.id)
pulumi.export("attacker_role_arn",  attacker_role.arn)
pulumi.export("attacker_role_name", ATTACKER_ROLE_NAME)

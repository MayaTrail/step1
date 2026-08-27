import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ────────────────────────────────────────────────────
PREFIX          = "stratus-red-team-rds-snap"
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

# ── Outputs ───────────────────────────────────────────────────────────────────
pulumi.export("snapshot_id",    snapshot.id)
pulumi.export("db_instance_id", db.id)

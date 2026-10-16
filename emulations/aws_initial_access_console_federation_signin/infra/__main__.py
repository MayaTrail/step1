# FILE: __main__.py
import json
import pathlib
import sys

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource Name Constants -- single source of truth via resource_names.json
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC-console-federation-signin',
 'csp': 'aws',
 'resources': {'victim_iam_user': 'atomic-console-federation-victim-user',
               'bait_secret_name': 'prod/database/master_credentials'},
 'pulumi_export_keys': {'victim_iam_user': 'victim_iam_user',
                        'victim_access_key_id': 'victim_access_key_id',
                        'victim_secret_access_key': 'victim_secret_access_key',
                        'target_bucket_name': 'target_bucket_name',
                        'bait_secret_name': 'bait_secret_name'}}
_R = _NAMES["resources"]

VICTIM_IAM_USER  = _R["victim_iam_user"]
BAIT_SECRET_NAME = _R["bait_secret_name"]

# ---------------------------------------------------------------------------
# Account / region
# ---------------------------------------------------------------------------
account_id = aws.get_caller_identity().account_id
region     = aws.get_region().id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-console-federation-signin",
    "Technique":   "T1538",
}

# ---------------------------------------------------------------------------
# Target S3 bucket  (no dependencies)
# bucket_prefix gives a unique production-looking name with a random suffix
# ---------------------------------------------------------------------------
target_bucket = aws.s3.BucketV2(
    "atomic-console-federation-target-bucket",
    force_destroy=True,  # lab bucket: CloudTrail/log objects must not block destroy
    bucket_prefix="acme-prod-app-configs-",
    tags=TAGS,
)

aws.s3.BucketPublicAccessBlock(
    "atomic-console-federation-target-bucket-pab",
    bucket=target_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# ---------------------------------------------------------------------------
# Bait Secrets Manager secret  (no dependencies)
# recovery_window_in_days=0 so re-runs after destroy never hit deletion-schedule conflict
# No deny resource policy -- avoids locking out the Pulumi deployer principal
# ---------------------------------------------------------------------------
bait_secret = aws.secretsmanager.Secret(
    "atomic-console-federation-bait-secret",
    name=BAIT_SECRET_NAME,
    description="Production database master credentials (emulation bait - synthetic data only)",
    recovery_window_in_days=0,
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# Victim IAM user  (no dependencies -- IAM is global)
# Must be an IAM user, NOT a role: sts:GetFederationToken is only callable by IAM users
# ---------------------------------------------------------------------------
victim_user = aws.iam.User(
    "atomic-console-federation-victim-user",
    name=VICTIM_IAM_USER,
    path="/emulation/",
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# Victim inline policy  (depends on victim_user + target_bucket ARN)
# Grants minimum permissions for GetFederationToken + console browsing of lab resources.
# secretsmanager:GetSecretValue intentionally excluded -- bait is discoverable, not readable.
# ---------------------------------------------------------------------------
victim_policy_doc = target_bucket.arn.apply(
    lambda bucket_arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetFederationToken",
                "Effect": "Allow",
                "Action": ["sts:GetFederationToken"],
                "Resource": "*",
            },
            {
                "Sid": "AllowS3ListAll",
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets"],
                "Resource": "*",
            },
            {
                "Sid": "AllowS3TargetBucketList",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": bucket_arn,
            },
            {
                "Sid": "AllowS3TargetBucketRead",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": f"{bucket_arn}/*",
            },
            {
                "Sid": "AllowSecretsDiscovery",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:ListSecrets",
                    "secretsmanager:DescribeSecret",
                ],
                "Resource": "*",
            },
        ],
    })
)

aws.iam.UserPolicy(
    "atomic-console-federation-victim-policy",
    user=victim_user.name,
    name="victim-inline-policy",
    policy=victim_policy_doc,
)

# ---------------------------------------------------------------------------
# Victim access key  (depends on victim_user)
# Exported as secrets so attack.py can read them from stack outputs
# ---------------------------------------------------------------------------
victim_access_key = aws.iam.AccessKey(
    "atomic-console-federation-victim-access-key",
    user=victim_user.name,
)

# ---------------------------------------------------------------------------
# S3 objects -- realistic-looking sensitive data (synthetic, no real creds/PII)
# Depends on target_bucket
# ---------------------------------------------------------------------------
aws.s3.BucketObjectv2(
    "atomic-console-federation-obj-app-config",
    bucket=target_bucket.id,
    key="internal-configs/app-config.json",
    content=json.dumps({
        "db_host": "prod-db.cluster-xxxx.us-east-1.rds.amazonaws.com",
        "db_user": "appuser",
        "db_pass": "PLACEHOLDER",
    }),
    content_type="application/json",
)

aws.s3.BucketObjectv2(
    "atomic-console-federation-obj-users-csv",
    bucket=target_bucket.id,
    key="backups/users-2026-Q3.csv",
    content="id,email,created_at\n1,REDACTED,2026-07-01",
    content_type="text/csv",
)

# ---------------------------------------------------------------------------
# Bait secret version  (depends on bait_secret)
# All values synthetic -- retrieval blocked by policy (GetSecretValue not granted)
# ---------------------------------------------------------------------------
aws.secretsmanager.SecretVersion(
    "atomic-console-federation-bait-secret-version",
    secret_id=bait_secret.id,
    secret_string=json.dumps({
        "username": "dbadmin",
        "password": "Sup3rS3cr3t-FAKE",
        "engine":   "mysql",
        "host":     "prod-aurora.cluster-xxxx.us-east-1.rds.amazonaws.com",
        "port":     3306,
        "dbname":   "production",
    }),
)

# ---------------------------------------------------------------------------
# Pulumi exports -- attack.py reads these via `pulumi stack output`
# Keys must match pulumi_export_keys in resource_names.json exactly
# ---------------------------------------------------------------------------
pulumi.export("victim_iam_user",          VICTIM_IAM_USER)
pulumi.export("victim_access_key_id",     victim_access_key.id)
pulumi.export("victim_secret_access_key", victim_access_key.secret)
pulumi.export("target_bucket_name",       target_bucket.bucket)
pulumi.export("bait_secret_name",         BAIT_SECRET_NAME)

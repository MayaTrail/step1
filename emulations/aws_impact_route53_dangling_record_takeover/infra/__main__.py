import json
import pathlib
import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource name constants - loaded from resource_names.json (single source of truth)
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC-route53-dangling-record-takeover',
 'csp': 'aws',
 'resources': {'hosted_zone_name': 'corp-victim-lab.internal',
               'hosted_zone_comment': 'MayaTrail emulation zone',
               'dangling_record_name': 'app.corp-victim-lab.internal',
               'dangling_record_target': 'app-corp-victim-lab.s3-website-us-east-1.amazonaws.com',
               'bait_www_record_name': 'www.corp-victim-lab.internal',
               'bait_www_record_target': 'www-corp-victim-lab.s3-website-us-east-1.amazonaws.com',
               'bait_www_bucket': 'www-corp-victim-lab',
               'attacker_role_name': 'atomic-route53-dangling-attacker-role',
               'unclaimed_bucket_name': 'app-corp-victim-lab'},
 'pulumi_export_keys': {'hosted_zone_id': 'hosted_zone_id',
                        'attacker_role_arn': 'attacker_role_arn',
                        'dangling_record_fqdn': 'dangling_record_fqdn',
                        'bait_www_bucket_name': 'bait_www_bucket_name'}}
_R = _NAMES["resources"]

HOSTED_ZONE_NAME       = _R["hosted_zone_name"]
HOSTED_ZONE_COMMENT    = _R["hosted_zone_comment"]
DANGLING_RECORD_NAME   = _R["dangling_record_name"]
DANGLING_RECORD_TARGET = _R["dangling_record_target"]
BAIT_WWW_RECORD_NAME   = _R["bait_www_record_name"]
BAIT_WWW_RECORD_TARGET = _R["bait_www_record_target"]
BAIT_WWW_BUCKET        = _R["bait_www_bucket"]
ATTACKER_ROLE_NAME     = _R["attacker_role_name"]
UNCLAIMED_BUCKET_NAME  = _R["unclaimed_bucket_name"]

# Export static name constants so attack.py can read them from stack outputs
pulumi.export("hosted_zone_name",       HOSTED_ZONE_NAME)
pulumi.export("dangling_record_name",   DANGLING_RECORD_NAME)
pulumi.export("dangling_record_target", DANGLING_RECORD_TARGET)
pulumi.export("bait_www_bucket",        BAIT_WWW_BUCKET)
pulumi.export("attacker_role_name",     ATTACKER_ROLE_NAME)
pulumi.export("unclaimed_bucket_name",  UNCLAIMED_BUCKET_NAME)

# ---------------------------------------------------------------------------
# Current account - used for self-account backdoor trust (never a placeholder)
# ---------------------------------------------------------------------------
account_id = aws.get_caller_identity().account_id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-route53-dangling-record-takeover",
    "Technique":   "T1491.002",
}

# ---------------------------------------------------------------------------
# Attacker IAM Role
# Trust principal: current account root - self-account backdoor pattern per
# platform requirement (never a placeholder like 111111111111).
# ---------------------------------------------------------------------------
attacker_trust_policy = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect":    "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action":    "sts:AssumeRole",
    }],
})

attacker_role = aws.iam.Role(
    "atomic-route53-dangling-attacker-role",
    name=ATTACKER_ROLE_NAME,
    assume_role_policy=attacker_trust_policy,
    description="MayaTrail emulation - Route53 subdomain takeover attacker",
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# Attacker inline policy
# Scoped: Route53 actions (cannot be further scoped by AWS), S3 only for the
# unclaimed bucket name so blast radius is minimal.
# ---------------------------------------------------------------------------
attacker_policy_doc = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":    "Route53Enumerate",
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "route53:TestDNSAnswer",
            ],
            "Resource": "*",
        },
        {
            "Sid":    "S3ClaimBucket",
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:PutBucketWebsite",
                "s3:PutBucketPolicy",
                "s3:PutBucketPublicAccessBlock",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:DeleteBucket",
            ],
            "Resource": [
                f"arn:aws:s3:::{UNCLAIMED_BUCKET_NAME}",
                f"arn:aws:s3:::{UNCLAIMED_BUCKET_NAME}/*",
            ],
        },
    ],
})

attacker_role_policy = aws.iam.RolePolicy(
    "atomic-route53-dangling-attacker-role-policy",
    role=attacker_role.id,
    policy=attacker_policy_doc,
)

# ---------------------------------------------------------------------------
# Route53 Hosted Zone
# Public zone on an unregistered TLD - no VPC association.
# Never delegated from a real registrar so it is fully isolated from the
# public DNS tree while still being queryable via the Route53 API.
# ---------------------------------------------------------------------------
hosted_zone = aws.route53.Zone(
    "atomic-route53-dangling-hosted-zone",
    name=HOSTED_ZONE_NAME,
    comment=HOSTED_ZONE_COMMENT,
    tags=TAGS,
)

# ---------------------------------------------------------------------------
# Dangling CNAME record (app -> unclaimed S3 static-website endpoint)
# CRITICAL: the bucket 'app-corp-victim-lab' is intentionally NOT created.
# The unclaimed endpoint is the attack surface for T1491.002 subdomain takeover.
# ---------------------------------------------------------------------------
dangling_record = aws.route53.Record(
    "atomic-route53-dangling-record",
    zone_id=hosted_zone.zone_id,
    name=DANGLING_RECORD_NAME,
    type="CNAME",
    ttl=300,
    records=[DANGLING_RECORD_TARGET],
)

# ---------------------------------------------------------------------------
# Bait www CNAME record (backed by a real bucket - makes zone look live)
# Only the 'app' subdomain is dangling; 'www' resolves correctly.
# ---------------------------------------------------------------------------
bait_www_record = aws.route53.Record(
    "atomic-route53-dangling-bait-www-record",
    zone_id=hosted_zone.zone_id,
    name=BAIT_WWW_RECORD_NAME,
    type="CNAME",
    ttl=300,
    records=[BAIT_WWW_RECORD_TARGET],
)

# ---------------------------------------------------------------------------
# Bait www S3 bucket (real bucket backing the www record)
# ---------------------------------------------------------------------------
bait_www_bucket = aws.s3.BucketV2(
    "atomic-route53-dangling-bait-www-bucket",
    bucket=BAIT_WWW_BUCKET,
    force_destroy=True,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[bait_www_record]),
)

# All four block_public_* set to False to permit the S3 website policy
bait_www_public_access = aws.s3.BucketPublicAccessBlock(
    "atomic-route53-dangling-bait-www-public-access",
    bucket=bait_www_bucket.id,
    block_public_acls=False,
    block_public_policy=False,
    ignore_public_acls=False,
    restrict_public_buckets=False,
)

bait_www_website = aws.s3.BucketWebsiteConfigurationV2(
    "atomic-route53-dangling-bait-www-website",
    bucket=bait_www_bucket.id,
    index_document=aws.s3.BucketWebsiteConfigurationV2IndexDocumentArgs(
        suffix="index.html",
    ),
    opts=pulumi.ResourceOptions(depends_on=[bait_www_public_access]),
)

# Public-read bucket policy - must wait for public-access-block to be applied
bait_www_bucket_policy = aws.s3.BucketPolicy(
    "atomic-route53-dangling-bait-www-bucket-policy",
    bucket=bait_www_bucket.id,
    policy=bait_www_bucket.bucket.apply(lambda b: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid":       "PublicReadGetObject",
            "Effect":    "Allow",
            "Principal": "*",
            "Action":    "s3:GetObject",
            "Resource":  f"arn:aws:s3:::{b}/*",
        }],
    })),
    opts=pulumi.ResourceOptions(depends_on=[bait_www_public_access]),
)

INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Corp Victim Lab - Corporate Portal</title>
  <style>body{font-family:Arial,sans-serif;max-width:800px;margin:60px auto;color:#333}</style>
</head>
<body>
  <h1>Corp Victim Lab - Corporate Portal</h1>
  <p>Welcome to the internal corporate portal. Please authenticate to access company resources.</p>
  <p>For technical support contact <a href="mailto:support@corp-victim-lab.internal">support@corp-victim-lab.internal</a>.</p>
</body>
</html>
"""

bait_www_index = aws.s3.BucketObjectv2(
    "atomic-route53-dangling-bait-www-index",
    bucket=bait_www_bucket.id,
    key="index.html",
    content=INDEX_HTML,
    content_type="text/html",
    opts=pulumi.ResourceOptions(depends_on=[bait_www_bucket_policy]),
)

# ---------------------------------------------------------------------------
# Pulumi exports - dynamic values known only after deploy
# ---------------------------------------------------------------------------
pulumi.export("hosted_zone_id",       hosted_zone.zone_id)
pulumi.export("attacker_role_arn",    attacker_role.arn)
pulumi.export("dangling_record_fqdn", dangling_record.fqdn)
pulumi.export("bait_www_bucket_name", bait_www_bucket.bucket)

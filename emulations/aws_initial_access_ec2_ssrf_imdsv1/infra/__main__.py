import json
import hashlib
import pathlib
import pulumi
import pulumi_aws as aws

# ── Resource Name Constants ───────────────────────────────────────────────────
_NAMES = {'campaign': 'ATOMIC-ec2-ssrf-imdsv1',
 'csp': 'aws',
 'resources': {'iam_instance_role': 'atomic-ec2-ssrf-imdsv1-instance-role',
               'iam_instance_profile': 'atomic-ec2-ssrf-imdsv1-instance-profile',
               'iam_instance_policy': 'atomic-ec2-ssrf-imdsv1-instance-policy'},
 'pulumi_export_keys': {'vpc_id': 'vpc_id',
                        'ec2_public_ip': 'ec2_public_ip',
                        'ec2_instance_id': 'ec2_instance_id',
                        'iam_role_arn': 'iam_role_arn',
                        'iam_role_name': 'iam_role_name',
                        'iam_instance_role_name': 'iam_instance_role_name',
                        'iam_instance_profile_name': 'iam_instance_profile_name',
                        's3_bait_bucket_name': 's3_bait_bucket_name',
                        'flowlog_bucket_name': 'flowlog_bucket_name'}}
_R = _NAMES["resources"]

IAM_INSTANCE_ROLE_NAME    = _R["iam_instance_role"]
IAM_INSTANCE_PROFILE_NAME = _R["iam_instance_profile"]
IAM_INSTANCE_POLICY_NAME  = _R["iam_instance_policy"]

# ── Config and AWS metadata ───────────────────────────────────────────────────
config      = pulumi.Config()


def _worker_cidr() -> str:
    """CIDR allowed to reach the lab's deliberately vulnerable app. The backend sets
    no Pulumi config, so fall back to the public IP this program runs from (the worker
    that also probes readiness and runs the attack). Never default to 0.0.0.0/0."""
    configured = config.get("workerCidr")
    if configured:
        return configured
    import urllib.request
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as resp:
        return resp.read().decode().strip() + "/32"


worker_cidr = _worker_cidr()

region     = aws.get_region().id
account_id = aws.get_caller_identity().account_id

# Stable 8-char hex suffix so bucket names survive pulumi destroy/up cycles
_suffix = hashlib.sha256(account_id.encode()).hexdigest()[:8]

FLOWLOG_BUCKET_NAME = f"atomic-ec2-ssrf-imdsv1-flowlogs-{_suffix}"
S3_BAIT_BUCKET_NAME = f"atomic-ec2-ssrf-imdsv1-prod-data-archive-{_suffix}"

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-ec2-ssrf-imdsv1",
    "Technique":   "T1190",
}

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc = aws.ec2.Vpc(
    "vpc",
    cidr_block="10.99.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-vpc"},
)

subnet_public = aws.ec2.Subnet(
    "subnet-public",
    vpc_id=vpc.id,
    cidr_block="10.99.1.0/24",
    map_public_ip_on_launch=True,
    availability_zone=f"{region}a",
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-subnet-public"},
)

igw = aws.ec2.InternetGateway(
    "igw",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-igw"},
)

# No inline routes= here - separate aws.ec2.Route avoids perpetual diff
route_table = aws.ec2.RouteTable(
    "route-table",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-rt"},
)

route_default = aws.ec2.Route(
    "route-default",
    route_table_id=route_table.id,
    destination_cidr_block="0.0.0.0/0",
    gateway_id=igw.id,
)

rt_assoc = aws.ec2.RouteTableAssociation(
    "rt-assoc",
    subnet_id=subnet_public.id,
    route_table_id=route_table.id,
)

# ── Security Group ────────────────────────────────────────────────────────────
# Ingress locked to emulation worker CIDR only - 0.0.0.0/0 is never used
sg_vulnerable_app = aws.ec2.SecurityGroup(
    "sg-vulnerable-app",
    name="atomic-ec2-ssrf-imdsv1-app-sg",
    vpc_id=vpc.id,
    description="SSRF lab app port 8080 restricted to emulation worker IP only",
    ingress=[{
        "from_port":   8080,
        "to_port":     8080,
        "protocol":    "tcp",
        "cidr_blocks": [worker_cidr],
        "description": "SSRF app access from emulation worker only",
    }],
    egress=[{
        "from_port":   0,
        "to_port":     0,
        "protocol":    "-1",
        "cidr_blocks": ["0.0.0.0/0"],
        "description": "Outbound unrestricted for package installs during bootstrap",
    }],
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-sg-app"},
)

# ── Flow Log Bucket ───────────────────────────────────────────────────────────
flowlog_bucket = aws.s3.BucketV2(
    "flowlog-bucket",
    bucket=FLOWLOG_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

flowlog = aws.ec2.FlowLog(
    "flowlog",
    vpc_id=vpc.id,
    traffic_type="ALL",
    log_destination_type="s3",
    log_destination=flowlog_bucket.arn,
    max_aggregation_interval=60,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[flowlog_bucket]),
)

# ── S3 Bait Bucket ────────────────────────────────────────────────────────────
s3_bait_bucket = aws.s3.BucketV2(
    "s3-bait-bucket",
    bucket=S3_BAIT_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

bucket_pab = aws.s3.BucketPublicAccessBlock(
    "bucket-pab",
    bucket=s3_bait_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# ── IAM Instance Role ─────────────────────────────────────────────────────────
iam_instance_role = aws.iam.Role(
    "iam-instance-role",
    name=IAM_INSTANCE_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

iam_instance_policy = aws.iam.RolePolicy(
    "iam-instance-policy",
    name=IAM_INSTANCE_POLICY_NAME,
    role=iam_instance_role.name,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   ["s3:ListAllMyBuckets"],
            "Resource": "*",
        }],
    }),
)

iam_instance_profile = aws.iam.InstanceProfile(
    "iam-instance-profile",
    name=IAM_INSTANCE_PROFILE_NAME,
    role=iam_instance_role.name,
    tags=TAGS,
)

# ── AMI Lookup ────────────────────────────────────────────────────────────────
# Amazon Linux 2 reached EOL 2025-06-30 - using Amazon Linux 2023 (dnf package manager)
ami = aws.ec2.get_ami(
    owners=["amazon"],
    most_recent=True,
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name",  values=["al2023-ami-*-x86_64"]),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)

# ── User Data: Flask SSRF-Vulnerable App ──────────────────────────────────────
# [EMULATED] T1190: Exploit Public-Facing Application
# Deploys a Flask app with an unvalidated /fetch?url= endpoint; IMDSv1 reachable
# at 169.254.169.254 from the app process because http_tokens=optional on the instance.
USER_DATA = """#!/bin/bash
dnf install -y python3 python3-pip
pip3 install flask requests
mkdir -p /opt/ssrf_app

cat > /opt/ssrf_app/app.py << 'APPEOF'
from flask import Flask, request
import requests as req
app = Flask(__name__)

@app.route('/health')
def health():
    return 'ok', 200

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    r = req.get(url, timeout=3)
    return r.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
APPEOF

history -cw

cat > /etc/systemd/system/ssrf-app.service << 'SVCEOF'
[Unit]
Description=SSRF Vulnerable App
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/ssrf_app/app.py
Restart=always
[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload && systemctl enable ssrf-app && systemctl start ssrf-app
history -cw
"""

# ── EC2 Instance ──────────────────────────────────────────────────────────────
# http_tokens=optional enables IMDSv1 - raw GET to 169.254.169.254 returns credentials
ec2_victim = aws.ec2.Instance(
    "ec2-victim",
    ami=ami.id,
    instance_type="t3.micro",
    iam_instance_profile=iam_instance_profile.name,
    subnet_id=subnet_public.id,
    vpc_security_group_ids=[sg_vulnerable_app.id],
    associate_public_ip_address=True,
    metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
        http_endpoint="enabled",
        http_tokens="optional",
        http_put_response_hop_limit=1,
    ),
    user_data=USER_DATA,
    tags={**TAGS, "Name": "atomic-ec2-ssrf-imdsv1-ec2-victim"},
    opts=pulumi.ResourceOptions(
        depends_on=[subnet_public, sg_vulnerable_app, iam_instance_profile,
                    route_default, rt_assoc],
    ),
)

# ── Exports ───────────────────────────────────────────────────────────────────
pulumi.export("vpc_id",                    vpc.id)
pulumi.export("ec2_public_ip",             ec2_victim.public_ip)
pulumi.export("ec2_instance_id",           ec2_victim.id)
pulumi.export("iam_role_arn",              iam_instance_role.arn)
pulumi.export("iam_role_name",             iam_instance_role.name)
pulumi.export("iam_instance_role_name",    IAM_INSTANCE_ROLE_NAME)
pulumi.export("iam_instance_profile_name", IAM_INSTANCE_PROFILE_NAME)
pulumi.export("s3_bait_bucket_name",       s3_bait_bucket.bucket)
pulumi.export("flowlog_bucket_name",       flowlog_bucket.bucket)

"""
SCARLETEEL — Adversary Emulation Infrastructure
Provisions a deliberately vulnerable AWS environment for red team emulation.

Attack execution lives in ../emulation_scripts/attack.py.
Run `pulumi up` here first, then run attack.py separately.

MITRE techniques covered:
  T1190  — Exploit Public-Facing Application (Flask RCE container)
  T1552.005 — Cloud Instance Metadata API (IMDSv1 on container host)
  T1078.004 — Valid Accounts: Cloud Accounts (stolen IMDS creds)
  T1526  — Cloud Service Discovery (IAM, S3, Lambda enumeration)
  T1562.008 — Disable or Modify Cloud Logs (CloudTrail StopLogging)
  T1530  — Data from Cloud Storage (S3 bucket exfiltration + terraform.tfstate)
  T1005  — Data from Local System (Lambda source code via GetFunction)
  T1496  — Resource Hijacking (simulated XMRig cryptominer)
"""
import pulumi
import pulumi_aws as aws
import pulumi.asset as asset
import json

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Zero-Permission Bait User (Lateral Movement Target)
# ═══════════════════════════════════════════════════════════════════════════════
bait_user = aws.iam.User("scarleteel-secondary-user", force_destroy=True)
bait_key  = aws.iam.AccessKey("scarleteel-secondary-key", user=bait_user.name)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Over-Privileged Compute Role (The Initial Target)
# ═══════════════════════════════════════════════════════════════════════════════
vuln_role = aws.iam.Role(
    "scarleteel-vuln-ec2-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"}
        }]
    }),
)

# SSM for debug access (not part of the attack path)
aws.iam.RolePolicyAttachment(
    "ssm-core",
    role=vuln_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

# Over-privileged inline policy — mirrors real SCARLETEEL permissions
vuln_policy = aws.iam.RolePolicy(
    "scarleteel-vuln-policy",
    role=vuln_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets", "s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:ListFunctions", "lambda:GetFunction",
                    "lambda:ListVersionsByFunction", "lambda:GetPolicy",
                    "lambda:ListAliases", "lambda:ListTags",
                    "lambda:ListEventSourceMappings"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": ["cloudtrail:StopLogging", "cloudtrail:DescribeTrails"],
                "Resource": "*"
            },
        ]
    }),
)

vuln_profile = aws.iam.InstanceProfile("scarleteel-vuln-profile", role=vuln_role.name)

# ═══════════════════════════════════════════════════════════════════════════════
# 3. S3 Context: Dummy Buckets + Terraform State Bait
# ═══════════════════════════════════════════════════════════════════════════════
dummy_logs    = aws.s3.Bucket("scarleteel-dummy-logs",    force_destroy=True)
dummy_scripts = aws.s3.Bucket("scarleteel-dummy-scripts", force_destroy=True)
tf_state      = aws.s3.Bucket("scarleteel-tf-state",      force_destroy=True)

# Bait terraform.tfstate containing zero-permission user creds (lateral movement pivot)
tf_state_obj = aws.s3.BucketObject(
    "state",
    bucket=tf_state.id,
    key="terraform.tfstate",
    content=pulumi.Output.all(bait_key.id, bait_key.secret).apply(
        lambda args: json.dumps({
            "version": 4,
            "resources": [{
                "type": "aws_iam_access_key",
                "name": "example_access_key",
                "instances": [{"attributes": {"id": args[0], "secret": args[1]}}]
            }]
        })
    ),
)

# Mock data in dummy buckets
aws.s3.BucketObject(
    "customer_db_script",
    bucket=dummy_scripts.id,
    key="db_loader.sh",
    content="#!/bin/bash\necho 'Loading proprietary customer data...'\n",
)
aws.s3.BucketObject(
    "syslogs",
    bucket=dummy_logs.id,
    key="syslog-1.log",
    content="Dec 10 12:00:00 ip-10-0-0-1 sudo: pam_unix(sudo:session): session opened for user root\n",
)

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Proprietary Lambda Function (IP theft target)
# ═══════════════════════════════════════════════════════════════════════════════
lambda_role = aws.iam.Role(
    "proprietary-lambda-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"}
        }]
    }),
)

prop_lambda = aws.lambda_.Function(
    "ProprietaryAlgoFunc",
    role=lambda_role.arn,
    handler="index.handler",
    runtime="python3.9",
    code=asset.AssetArchive({
        "index.py": asset.StringAsset(
            "import os\n"
            "def handler(event, context):\n"
            "    print('Proprietary ALGO execution')\n"
            "    return {'statusCode': 200, 'body': os.environ['DB_PASS']}\n"
        )
    }),
    environment={"variables": {"DB_PASS": "SuperSecretCustomerPass123"}},
)

# ═══════════════════════════════════════════════════════════════════════════════
# 5. CloudTrail Trail (defense evasion target — attack Phase 4 disables this)
# ═══════════════════════════════════════════════════════════════════════════════
trail_bucket = aws.s3.Bucket("scarleteel-trail-logs", force_destroy=True)
trail_bucket_policy = aws.s3.BucketPolicy(
    "scarleteel-trail-bucket-policy",
    bucket=trail_bucket.id,
    policy=pulumi.Output.all(trail_bucket.arn).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": args[0],
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{args[0]}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    })),
)

trail = aws.cloudtrail.Trail(
    "scarleteel-trail",
    s3_bucket_name=trail_bucket.id,
    is_multi_region_trail=False,
    enable_logging=True,
    opts=pulumi.ResourceOptions(depends_on=[trail_bucket_policy]),
)

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Vulnerable Container Host (Docker + Flask RCE app + IMDSv1 enabled)
# ═══════════════════════════════════════════════════════════════════════════════
USER_DATA = """#!/bin/bash
set -ex

# Install Docker on Amazon Linux 2023
dnf install -y docker
systemctl enable docker
systemctl start docker

# Create the vulnerable web application (T1190 — command injection endpoint)
mkdir -p /opt/vuln-app

cat > /opt/vuln-app/app.py << 'PYEOF'
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/health')
def health():
    return 'ok'

@app.route('/cmd', methods=['POST'])
def cmd():
    command = request.form.get('cmd', '')
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, timeout=30
        )
        return output.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8', errors='replace'), 500
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
PYEOF

cat > /opt/vuln-app/Dockerfile << 'DKEOF'
FROM python:3.9-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl wget && rm -rf /var/lib/apt/lists/*
RUN pip install flask
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python", "app.py"]
DKEOF

cd /opt/vuln-app
docker build -t vuln-webapp .
docker run -d --name vuln-webapp -p 8080:8080 vuln-webapp
"""

ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[{"name": "name", "values": ["al2023-ami-2023.*-x86_64"]}],
)

vuln_sg = aws.ec2.SecurityGroup(
    "scarleteel-vuln-sg",
    description="Allow inbound HTTP to vulnerable container",
    ingress=[{
        "protocol": "tcp", "from_port": 8080, "to_port": 8080,
        "cidr_blocks": ["0.0.0.0/0"], "description": "Vulnerable webapp access",
    }],
    egress=[{
        "protocol": "-1", "from_port": 0, "to_port": 0,
        "cidr_blocks": ["0.0.0.0/0"], "description": "Allow all outbound",
    }],
)

# IMDSv1 ENABLED (http_tokens=optional) — the core vulnerability
# hop_limit=2 allows Docker bridge containers to reach 169.254.169.254
vuln_instance = aws.ec2.Instance(
    "scarleteel-vuln-container-host",
    ami=ami.id,
    instance_type="t3.micro",
    iam_instance_profile=vuln_profile.name,
    vpc_security_group_ids=[vuln_sg.id],
    associate_public_ip_address=True,
    user_data=USER_DATA,
    metadata_options={
        "http_tokens": "optional",      # IMDSv1 ENABLED — credential theft vector
        "http_endpoint": "enabled",
        "http_put_response_hop_limit": 2,  # Docker bridge can reach IMDS
    },
    tags={"Name": "Scarleteel Container Host", "Purpose": "SCARLETEEL_Emulation"},
)

# ═══════════════════════════════════════════════════════════════════════════════
# Outputs — consumed by ../emulation_scripts/attack.py
# ═══════════════════════════════════════════════════════════════════════════════
pulumi.export("vuln_instance_ip", vuln_instance.public_ip)
pulumi.export("vuln_instance_id", vuln_instance.id)
pulumi.export("bait_user",        bait_user.name)
pulumi.export("trail_name",       trail.name)
pulumi.export("tf_state_bucket",  tf_state.id)

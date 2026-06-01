"""
SCARLETEEL 2.0 — Pulumi infrastructure program.

Provisions the intentionally vulnerable AWS environment needed to run the
SCARLETEEL emulation.  Infrastructure only — no attack logic lives here.

The trigger_attack() hook present in earlier sample code has been removed
deliberately.  Attack execution is handled by a separate Celery task
(run_emulation_attack) which calls emulations/scarleteel/attack.py.
Keeping infra and attack separate means:
  - Django can track the attack in EmulationRun
  - The Celery worker (not the Pulumi container) captures stdout/stderr
  - The user can re-trigger the attack without re-deploying infra
  - The frontend can receive real-time phase progress

Resources created:
  - VPC with public subnet (for EC2 internet access)
  - Security group (8080 inbound for /health + RCE endpoint)
  - EC2 t3.micro running the vulnerable web application via UserData
  - S3 bucket (Terraform state target, seed objects pre-uploaded)
  - Secrets Manager secret (lateral movement target)
  - CloudTrail trail (toggled off in Phase 4)
  - Lambda execution role (used in Phase 6 backdoor)
  - IAM role for the EC2 instance (IMDSv1 enabled, over-privileged)

Stack outputs used by attack.py:
  - vuln_instance_ip      (EC2 public IP)
  - target_bucket_name    (S3 bucket)
  - cloudtrail_arn        (CloudTrail trail ARN)
  - secrets_manager_arn   (Secrets Manager secret ARN)
  - lambda_role_arn       (Lambda execution role ARN)

Resource naming follows the mayatrail-*-{stack_name} convention
where stack_name comes from pulumi.get_stack().
"""

import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

# ---------------------------------------------------------------------------
# VPC and networking
# ---------------------------------------------------------------------------

vpc = aws.ec2.Vpc(
    f"mayatrail-scarleteel-vpc-{stack_name}",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    tags={"Name": f"mayatrail-scarleteel-vpc-{stack_name}", "MayaTrail": "scarleteel"},
)

igw = aws.ec2.InternetGateway(
    f"mayatrail-scarleteel-igw-{stack_name}",
    vpc_id=vpc.id,
    tags={"Name": f"mayatrail-scarleteel-igw-{stack_name}"},
)

public_subnet = aws.ec2.Subnet(
    f"mayatrail-scarleteel-subnet-{stack_name}",
    vpc_id=vpc.id,
    cidr_block="10.0.1.0/24",
    map_public_ip_on_launch=True,
    availability_zone=f"{region}a",
    tags={"Name": f"mayatrail-scarleteel-subnet-{stack_name}"},
)

route_table = aws.ec2.RouteTable(
    f"mayatrail-scarleteel-rt-{stack_name}",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)],
    tags={"Name": f"mayatrail-scarleteel-rt-{stack_name}"},
)

aws.ec2.RouteTableAssociation(
    f"mayatrail-scarleteel-rta-{stack_name}",
    subnet_id=public_subnet.id,
    route_table_id=route_table.id,
)

security_group = aws.ec2.SecurityGroup(
    f"mayatrail-scarleteel-sg-{stack_name}",
    vpc_id=vpc.id,
    description="SCARLETEEL vulnerable instance - allow 8080 inbound",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=8080,
            to_port=8080,
            cidr_blocks=["0.0.0.0/0"],
            description="Vulnerable web app + /health endpoint",
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
        ),
    ],
    tags={"Name": f"mayatrail-scarleteel-sg-{stack_name}"},
)

# ---------------------------------------------------------------------------
# IAM role for the EC2 instance (deliberately over-privileged)
# ---------------------------------------------------------------------------

ec2_assume_role_policy = aws.iam.get_policy_document(statements=[
    aws.iam.GetPolicyDocumentStatementArgs(
        actions=["sts:AssumeRole"],
        principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
            type="Service",
            identifiers=["ec2.amazonaws.com"],
        )],
    )
])

ec2_role = aws.iam.Role(
    f"mayatrail-scarleteel-ec2-role-{stack_name}",
    assume_role_policy=ec2_assume_role_policy.json,
    tags={"MayaTrail": "scarleteel"},
)

aws.iam.RolePolicyAttachment(
    f"mayatrail-scarleteel-ec2-policy-{stack_name}",
    role=ec2_role.name,
    policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
)

instance_profile = aws.iam.InstanceProfile(
    f"mayatrail-scarleteel-profile-{stack_name}",
    role=ec2_role.name,
)

# ---------------------------------------------------------------------------
# EC2 — vulnerable web application (IMDSv1 required, no hop limit)
# ---------------------------------------------------------------------------

# Amazon Linux 2023 — latest AMI resolved at deploy time.
ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-*-x86_64"]),
        aws.ec2.GetAmiFilterArgs(name="state", values=["available"]),
    ],
)

# UserData: install Docker, then BUILD the vulnerable web app on the instance
# and run it.  The image is built locally (no registry pull) — it is a tiny
# Flask app exposing:
#   GET  /health  -> 200 readiness probe (gates ready_for_attack)
#   POST /cmd     -> command-injection RCE (form field "cmd"), used by attack.py
# The container image installs curl/wget because Phase 2 of the attack runs
# `curl http://169.254.169.254/...` from INSIDE the container to steal the
# instance-role credentials via IMDSv1 (the instance allows a 2-hop IMDS PUT).
user_data = """#!/bin/bash
set -ex

# Install and start Docker (Amazon Linux 2023).
dnf install -y docker
systemctl enable --now docker

# Write the intentionally vulnerable Flask application.
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

# Write the Dockerfile.  curl/wget are required by the IMDSv1 theft phase.
cat > /opt/vuln-app/Dockerfile << 'DKEOF'
FROM python:3.9-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl wget && rm -rf /var/lib/apt/lists/*
RUN pip install flask
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["python", "app.py"]
DKEOF

# Build the image locally and run it.
cd /opt/vuln-app
docker build -t vuln-webapp .
docker run -d --name vuln-webapp -p 8080:8080 --restart unless-stopped vuln-webapp

echo "SCARLETEEL vulnerable app built and started"
"""

instance = aws.ec2.Instance(
    f"mayatrail-scarleteel-ec2-{stack_name}",
    instance_type="t3.micro",
    ami=ami.id,
    subnet_id=public_subnet.id,
    vpc_security_group_ids=[security_group.id],
    iam_instance_profile=instance_profile.name,
    user_data=user_data,
    # IMDSv1 enabled — required for the credential theft phase.
    metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
        http_endpoint="enabled",
        http_tokens="optional",   # optional = IMDSv1 allowed
        http_put_response_hop_limit=2,
    ),
    tags={"Name": f"mayatrail-scarleteel-ec2-{stack_name}", "MayaTrail": "scarleteel"},
)

# ---------------------------------------------------------------------------
# S3 — Terraform state target bucket (seed objects pre-uploaded)
# ---------------------------------------------------------------------------

terraform_state_bucket = aws.s3.BucketV2(
    f"mayatrail-scarleteel-tfstate-{stack_name}",
    force_destroy=True,
    tags={"MayaTrail": "scarleteel"},
)

aws.s3.BucketObjectv2(
    f"mayatrail-scarleteel-tfstate-object-{stack_name}",
    bucket=terraform_state_bucket.id,
    key="terraform.tfstate",
    content='{"version": 4, "serial": 1, "outputs": {}}',
    content_type="application/json",
)

# ---------------------------------------------------------------------------
# Secrets Manager — lateral movement target
# ---------------------------------------------------------------------------

secret = aws.secretsmanager.Secret(
    f"mayatrail-scarleteel-secret-{stack_name}",
    name=f"mayatrail-scarleteel-secret-{stack_name}",
    tags={"MayaTrail": "scarleteel"},
)

aws.secretsmanager.SecretVersion(
    f"mayatrail-scarleteel-secret-version-{stack_name}",
    secret_id=secret.id,
    secret_string='{"api_key": "super-secret-scarleteel-key", "db_password": "s3cret!"}',
)

# ---------------------------------------------------------------------------
# CloudTrail — disabled in Phase 4
# ---------------------------------------------------------------------------

cloudtrail_bucket = aws.s3.BucketV2(
    f"mayatrail-scarleteel-ct-bucket-{stack_name}",
    force_destroy=True,
    tags={"MayaTrail": "scarleteel"},
)

ct_bucket_policy = aws.s3.BucketPolicy(
    f"mayatrail-scarleteel-ct-bucket-policy-{stack_name}",
    bucket=cloudtrail_bucket.id,
    policy=pulumi.Output.all(
        cloudtrail_bucket.arn,
        cloudtrail_bucket.id,
    ).apply(lambda args: f"""{{
        "Version": "2012-10-17",
        "Statement": [
            {{
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                "Action": "s3:GetBucketAcl",
                "Resource": "{args[0]}"
            }},
            {{
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {{"Service": "cloudtrail.amazonaws.com"}},
                "Action": "s3:PutObject",
                "Resource": "{args[0]}/AWSLogs/*",
                "Condition": {{"StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}}}}
            }}
        ]
    }}"""),
)

trail = aws.cloudtrail.Trail(
    f"mayatrail-scarleteel-trail-{stack_name}",
    s3_bucket_name=cloudtrail_bucket.id,
    include_global_service_events=True,
    is_multi_region_trail=False,
    tags={"MayaTrail": "scarleteel"},
    opts=pulumi.ResourceOptions(depends_on=[cloudtrail_bucket, ct_bucket_policy]),
)

# ---------------------------------------------------------------------------
# Lambda execution role — used in Phase 6 for the backdoor
# ---------------------------------------------------------------------------

lambda_assume_policy = aws.iam.get_policy_document(statements=[
    aws.iam.GetPolicyDocumentStatementArgs(
        actions=["sts:AssumeRole"],
        principals=[aws.iam.GetPolicyDocumentStatementPrincipalArgs(
            type="Service",
            identifiers=["lambda.amazonaws.com"],
        )],
    )
])

lambda_role = aws.iam.Role(
    f"mayatrail-scarleteel-lambda-role-{stack_name}",
    assume_role_policy=lambda_assume_policy.json,
    tags={"MayaTrail": "scarleteel"},
)

aws.iam.RolePolicyAttachment(
    f"mayatrail-scarleteel-lambda-policy-{stack_name}",
    role=lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
)

# ---------------------------------------------------------------------------
# Stack outputs consumed by attack.py via stack.outputs
# ---------------------------------------------------------------------------

pulumi.export("vuln_instance_ip", instance.public_ip)
pulumi.export("target_bucket_name", terraform_state_bucket.id)
pulumi.export("cloudtrail_arn", trail.arn)
pulumi.export("secrets_manager_arn", secret.arn)
pulumi.export("lambda_role_arn", lambda_role.arn)

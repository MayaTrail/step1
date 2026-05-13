"""
SCARLETEEL 2.0 — Adversary Emulation Infrastructure
Provisions a deliberately vulnerable AWS environment for red team emulation.

Attack execution lives in ../emulation_scripts/attack.py.
Run `pulumi up` here first, then run attack.py separately.

Resolves: GAP-1, GAP-4, GAP-5, GAP-6, GAP-8, GAP-12, GAP-14, Bug#1-4

MITRE techniques covered:
  T1190  — Exploit Public-Facing Application (Flask RCE container)
  T1552.005 — Cloud Instance Metadata API (IMDSv1, hop-limit=2 for Docker)
  T1078.004 — Valid Accounts: Cloud Accounts (stolen IMDS creds)
  T1526  — Cloud Service Discovery (IAM, S3, Lambda)
  T1580  — Cloud Infrastructure Discovery (Pacu-style recon)
  T1562.008 — Disable or Modify Cloud Logs (CloudTrail StopLogging)
  T1530  — Data from Cloud Storage (S3 + terraform.tfstate)
  T1005  — Data from Local System (Lambda GetFunction source code)
  T1098.001 — Account Manipulation (AdminJoe naming-convention bypass)
  T1528  — Steal Application Access Token (SecretsManager harvest)
  T1048  — Exfiltration Over Alternative Protocol (/dev/tcp, Russian S3 endpoint)
  T1496  — Resource Hijacking (XMRig + Pandora simulated)
"""
import pulumi
import pulumi_aws as aws
import pulumi_tls as tls
import pulumi.asset as asset
import json

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Zero-Permission Bait User (Lateral Movement Target)
# ═══════════════════════════════════════════════════════════════════════════════
bait_user = aws.iam.User("scarleteel-bait-user", force_destroy=True)
bait_key  = aws.iam.AccessKey("scarleteel-bait-key", user=bait_user.name)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Over-Privileged Compute Role (The Initial Target)
#    GAP-5: Added iam:CreateUser/CreateAccessKey so priv esc attempts generate
#    real CloudTrail events (not just AccessDenied from missing permissions)
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

aws.iam.RolePolicyAttachment(
    "ssm-core",
    role=vuln_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
)

# GAP-5: Over-privileged inline policy — mirrors real SCARLETEEL permissions
vuln_policy = aws.iam.RolePolicy(
    "scarleteel-vuln-policy",
    role=vuln_role.id,
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ReadAll",
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets", "s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            },
            {
                "Sid": "LambdaReadAll",
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
                "Sid": "CloudTrailDisable",
                "Effect": "Allow",
                "Action": ["cloudtrail:StopLogging", "cloudtrail:DescribeTrails"],
                "Resource": "*"
            },
            {
                "Sid": "IAMPrivEscAttempts",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateUser", "iam:CreateAccessKey",
                    "iam:ListUsers", "iam:ListRoles",
                    "iam:ListAttachedRolePolicies", "iam:ListAccessKeys"
                ],
                "Resource": "*"
            },
            {
                "Sid": "SecretsManagerRead",
                "Effect": "Allow",
                "Action": ["secretsmanager:ListSecrets", "secretsmanager:GetSecretValue"],
                "Resource": "*"
            },
        ]
    }),
)

# GAP-5: Permission boundary that blocks CreateAccessKey for lowercase admin* users.
# "adminJoe" is blocked but "AdminJoe" (capital A) bypasses the condition.
admin_deny_boundary = aws.iam.Policy(
    "scarleteel-admin-deny-boundary",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {
                "Sid": "DenyAdminLowercase",
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "arn:aws:iam::*:user/admin*"
            },
        ]
    }),
)

aws.iam.RolePolicyAttachment(
    "scarleteel-boundary-attach",
    role=vuln_role.name,
    policy_arn=admin_deny_boundary.arn,
)

vuln_profile = aws.iam.InstanceProfile("scarleteel-vuln-profile", role=vuln_role.name)

# ═══════════════════════════════════════════════════════════════════════════════
# 3. S3 Context: Dummy Buckets + Terraform State Bait
# ═══════════════════════════════════════════════════════════════════════════════
dummy_logs    = aws.s3.Bucket("scarleteel-dummy-logs",    force_destroy=True)
dummy_scripts = aws.s3.Bucket("scarleteel-dummy-scripts", force_destroy=True)
tf_state_bucket = aws.s3.Bucket("scarleteel-tf-state",   force_destroy=True)

# Bait state file — contains the bait IAM user's access keys (lateral movement pivot)
tf_state_obj = aws.s3.BucketObject(
    "state",
    bucket=tf_state_bucket.id,
    key="terraform.tfstate",
    content=pulumi.Output.all(bait_key.id, bait_key.secret).apply(
        lambda args: json.dumps({
            "version": 4,
            "resources": [{
                "type": "aws_iam_access_key",
                "name": "lateral_movement_key",
                "instances": [{"attributes": {"id": args[0], "secret": args[1]}}]
            }]
        })
    ),
)

aws.s3.BucketObject(
    "customer_db_script",
    bucket=dummy_scripts.id,
    key="db_loader.sh",
    content=(
        "#!/bin/bash\n"
        "echo 'Loading proprietary customer data...'\n"
        "aws s3 cp s3://internal-data/customers.csv /tmp/\n"
    ),
)
aws.s3.BucketObject(
    "syslogs",
    bucket=dummy_logs.id,
    key="syslog-2026-03.log",
    content=(
        "Mar 31 12:00:00 ip-10-0-0-1 sudo: pam_unix(sudo:session): session opened for user root\n"
        "Mar 31 12:01:00 ip-10-0-0-1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22\n"
    ),
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
# 5. Secrets Manager Bait Secret (GAP-4 — Phase 6 secondary pivot harvests this)
# ═══════════════════════════════════════════════════════════════════════════════
bait_secret = aws.secretsmanager.Secret(
    "scarleteel-bait-secret",
    name="prod/database/master_credentials",
    description="Production database master credentials",
)

aws.secretsmanager.SecretVersion(
    "scarleteel-bait-secret-version",
    secret_id=bait_secret.id,
    secret_string=json.dumps({
        "username": "db_admin",
        "password": "Pr0d-M4st3r-P@ss!2026",
        "host": "prod-db.internal.corp.com",
        "port": 5432,
    }),
)

# ═══════════════════════════════════════════════════════════════════════════════
# 6. CloudTrail Trail (defense evasion target — Phase 4 disables this)
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
# 7. Vulnerable Container Host (GAP-1, GAP-8, GAP-12, GAP-14, Bug#1-4)
#    Docker + Flask RCE app + IMDSv1 enabled + XMRig + Pandora simulation
# ═══════════════════════════════════════════════════════════════════════════════

# Bug#1/#2: Use dnf with --allowerasing for AL2023 curl-minimal conflict
# GAP-8: docker inspect env var sweep
# GAP-12: Pandora (Mirai) payload drop
# GAP-14: history -cw after each stage (notraces pattern)
# Bug#3: Miner payload is executable bash script with shebang
USER_DATA = r"""#!/bin/bash
# SCARLETEEL 2.0 Host-Level Emulation — UserData script
# NOTE: Do NOT use set -e — individual command failures must not abort the chain

# T1562.004: Flush firewall rules for permissive network
dnf install -y iptables 2>/dev/null || true
iptables -F 2>/dev/null || true
history -cw

# T1552.001: Credential harvesting from filesystem
find /tmp /var/log /root -type f \( -name "*credentials*" -o -name "*secret*" -o -name "*.pem" -o -name "*config*" \) 2>/dev/null || true
history -cw

# Install Docker (--allowerasing handles curl-minimal conflict on AL2023)
dnf install -y docker --allowerasing 2>/dev/null || dnf install -y docker 2>/dev/null || true
systemctl enable docker
systemctl start docker
history -cw

# T1552.004: Docker container credential sweep (GAP-8)
if command -v docker &>/dev/null; then
    docker ps -a || true
    for cid in $(docker ps -aq 2>/dev/null); do
        docker inspect "$cid" 2>/dev/null | grep -i "env\|secret\|key\|pass\|token" || true
    done
fi
history -cw

# Vulnerable Web Application (T1190 — command injection endpoint)
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
history -cw

# XMRig miner simulation (T1496)
mkdir -p /root/.configure

cat > /root/.configure/containerd << 'MINEREOF'
#!/bin/bash
# XMRig miner simulation — SCARLETEEL 2.0 emulation (not real mining)
while true; do
    echo "[$(date)] XMRig v6.21.0 — mining simulation active"
    echo "[$(date)] Pool: stratum+tcp://pool.c3pool.com:13333"
    echo "[$(date)] Wallet: 43Lfq18TycJHVR3AMews5C9f6SEfenZoQMcrsEeFXZTWcFW9jW7VeCySDm1L9n4d2JEoHjcDpWZFq6QzqN4QGHYZVaALj3U"
    sleep 60
done
MINEREOF
chmod +x /root/.configure/containerd

cat > /etc/systemd/system/containered.service << 'SVCEOF'
[Unit]
Description=Containerd core service
After=network.target

[Service]
ExecStart=/root/.configure/containerd
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable containered.service
systemctl start containered.service
history -cw

# Pandora (Mirai variant) simulation (GAP-12)
cat > /root/.configure/pandora << 'PANDORAEOF'
#!/bin/bash
# Pandora/Mirai DDoS bot simulation — SCARLETEEL 2.0 emulation (not real botnet)
while true; do
    echo "[$(date)] Pandora (Mirai variant) — DDoS-as-a-Service bot simulation"
    echo "[$(date)] C2: 45.9.148.221 — awaiting commands (simulated)"
    sleep 120
done
PANDORAEOF
chmod +x /root/.configure/pandora

history -cw
clear
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

# Bug#4: Explicitly set IMDSv1 enabled (http_tokens=optional)
# GAP-15: hop_limit=2 so Docker bridge containers can reach IMDS
vuln_instance = aws.ec2.Instance(
    "scarleteel-vuln-container-host",
    ami=ami.id,
    instance_type="t3.micro",
    iam_instance_profile=vuln_profile.name,
    vpc_security_group_ids=[vuln_sg.id],
    associate_public_ip_address=True,
    user_data=USER_DATA,
    metadata_options={
        "http_tokens": "optional",         # IMDSv1 ENABLED — the core vulnerability
        "http_endpoint": "enabled",
        "http_put_response_hop_limit": 2,  # Allows container access via Docker bridge
    },
    tags={"Name": "Scarleteel Container Host", "Purpose": "SCARLETEEL2_Emulation"},
)

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Fallback SSH KeyPair (Phase 6 — secondary pivot persistence)
# ═══════════════════════════════════════════════════════════════════════════════
fallback_privkey = tls.PrivateKey("scarleteel-fallback-privkey", algorithm="RSA", rsa_bits=4096)
aws.ec2.KeyPair(
    "scarleteel-fallback-keypair",
    key_name="scarleteel_fallback_key",
    public_key=fallback_privkey.public_key_openssh,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Outputs — consumed by ../emulation_scripts/attack.py
# ═══════════════════════════════════════════════════════════════════════════════
pulumi.export("vuln_instance_ip",  vuln_instance.public_ip)
pulumi.export("vuln_instance_id",  vuln_instance.id)
pulumi.export("bait_user",         bait_user.name)
pulumi.export("trail_name",        trail.name)
pulumi.export("bait_secret_name",  bait_secret.name)
pulumi.export("tf_state_bucket",   tf_state_bucket.id)

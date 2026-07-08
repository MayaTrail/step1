import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

TAGS = {"MayaTrail": "true", "ThreatActor": "K8S_IMPERSONATION"}

vpc = aws.ec2.Vpc(f"mayatrail-k8s-imp-vpc-{stack_name}", cidr_block="10.110.0.0/16", enable_dns_hostnames=True, enable_dns_support=True, tags=TAGS)
igw = aws.ec2.InternetGateway(f"mayatrail-k8s-imp-igw-{stack_name}", vpc_id=vpc.id, tags=TAGS)
subnet = aws.ec2.Subnet(f"mayatrail-k8s-imp-subnet-{stack_name}", vpc_id=vpc.id, cidr_block="10.110.1.0/24", map_public_ip_on_launch=True, availability_zone=f"{region}a", tags=TAGS)
rt = aws.ec2.RouteTable(f"mayatrail-k8s-imp-rt-{stack_name}", vpc_id=vpc.id, routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)], tags=TAGS)
aws.ec2.RouteTableAssociation(f"mayatrail-k8s-imp-rta-{stack_name}", subnet_id=subnet.id, route_table_id=rt.id)

sg = aws.ec2.SecurityGroup(f"mayatrail-k8s-imp-sg-{stack_name}", vpc_id=vpc.id, ingress=[
    aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=8080, to_port=8080, cidr_blocks=["0.0.0.0/0"])
], egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])], tags=TAGS)

ami = aws.ec2.get_ami(most_recent=True, owners=["amazon"], filters=[aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-*-x86_64"])])

user_data = """#!/bin/bash
dnf install -y docker
systemctl enable --now docker
mkdir -p /opt/app
cat > /opt/app/app.py << 'PYEOF'
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/health')
def health():
    return 'ok'

@app.route('/apis/authorization.k8s.io/v1/selfsubjectrulesreviews', methods=['POST'])
def ssrr():
    auth = request.headers.get("Authorization", "")
    if "stolen-dev-token" not in auth:
        return "Unauthorized", 401
    
    # Return rules for dev
    rules = [
        {"apiGroups": ["*"], "resources": ["serviceaccounts"], "verbs": ["impersonate"]},
        {"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectrulesreviews"], "verbs": ["create"]}
    ]
    return jsonify({"status": {"resourceRules": rules}})

@app.route('/api/v1/secrets', methods=['GET'])
def get_secrets():
    # Enforce Impersonation header checks
    auth = request.headers.get("Authorization", "")
    imp_user = request.headers.get("Impersonate-User", "")
    imp_group = request.headers.get("Impersonate-Group", "")

    if "stolen-dev-token" not in auth:
        return "Unauthorized", 401

    if imp_user == "admin-sa" and imp_group == "system:masters":
        # Elevated access
        return jsonify({
            "items": [
                {"metadata": {"name": "db-credential"}, "data": {"password": "c3VwZXItc2VjcmV0LWszcw=="}}
            ]
        })
    return "Forbidden", 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
PYEOF

cat > /opt/app/Dockerfile << 'DKEOF'
FROM python:3.9-slim
RUN pip install flask
COPY app.py /app/app.py
CMD ["python", "/app/app.py"]
DKEOF

cd /opt/app
docker build -t k8s-imp .
docker run -d --name k8s-imp -p 8080:8080 --restart unless-stopped k8s-imp
"""

instance = aws.ec2.Instance(f"mayatrail-k8s-imp-ec2-{stack_name}", instance_type="t3.micro", ami=ami.id, subnet_id=subnet.id, vpc_security_group_ids=[sg.id], user_data=user_data, tags=TAGS)

pulumi.export("vuln_instance_ip", instance.public_ip)

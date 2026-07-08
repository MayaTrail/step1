import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

TAGS = {"MayaTrail": "true", "ThreatActor": "K8S_LOG_ESCAPE"}

vpc = aws.ec2.Vpc(f"mayatrail-k8s-log-vpc-{stack_name}", cidr_block="10.120.0.0/16", enable_dns_hostnames=True, enable_dns_support=True, tags=TAGS)
igw = aws.ec2.InternetGateway(f"mayatrail-k8s-log-igw-{stack_name}", vpc_id=vpc.id, tags=TAGS)
subnet = aws.ec2.Subnet(f"mayatrail-k8s-log-subnet-{stack_name}", vpc_id=vpc.id, cidr_block="10.120.1.0/24", map_public_ip_on_launch=True, availability_zone=f"{region}a", tags=TAGS)
rt = aws.ec2.RouteTable(f"mayatrail-k8s-log-rt-{stack_name}", vpc_id=vpc.id, routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)], tags=TAGS)
aws.ec2.RouteTableAssociation(f"mayatrail-k8s-log-rta-{stack_name}", subnet_id=subnet.id, route_table_id=rt.id)

sg = aws.ec2.SecurityGroup(f"mayatrail-k8s-log-sg-{stack_name}", vpc_id=vpc.id, ingress=[
    aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=8080, to_port=8080, cidr_blocks=["0.0.0.0/0"])
], egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])], tags=TAGS)

ami = aws.ec2.get_ami(most_recent=True, owners=["amazon"], filters=[aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-*-x86_64"])])

user_data = """#!/bin/bash
dnf install -y docker
systemctl enable --now docker
mkdir -p /opt/app
cat > /opt/app/app.py << 'PYEOF'
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

# Simulated host filesystem
HOST_FILESYSTEM = {
    "/etc/shadow": "root:$6$vulnerable_root_hash:19500:0:99999:7:::",
    "/etc/kubernetes/admin.conf": "apiVersion: v1\nkind: Config\nclusters:\n- name: minikube\nusers:\n- name: minikube-admin\n  token: stolen-admin-token"
}

SYMLINKS = {}

@app.route('/health')
def health():
    return 'ok'

@app.route('/cmd', methods=['POST'])
def cmd():
    # RCE endpoint representing command execution inside the pod container
    command = request.form.get("cmd", "")
    if "ln -s" in command:
        # e.g., ln -s /etc/shadow /var/log/pods/webapp.log
        parts = command.split()
        target = parts[2]
        link = parts[3]
        SYMLINKS[link] = target
        return f"Created symlink: {link} -> {target}"
    return "Command executed successfully"

@app.route('/api/v1/nodes/worker-1/proxy/logs', methods=['GET'])
def get_logs():
    path = request.args.get("path", "")
    if path in SYMLINKS:
        target = SYMLINKS[path]
        return Response(HOST_FILESYSTEM.get(target, "Not found"), mimetype="text/plain")
    return "Log file empty or not found", 404

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
docker build -t k8s-log .
docker run -d --name k8s-log -p 8080:8080 --restart unless-stopped k8s-log
"""

instance = aws.ec2.Instance(f"mayatrail-k8s-log-ec2-{stack_name}", instance_type="t3.micro", ami=ami.id, subnet_id=subnet.id, vpc_security_group_ids=[sg.id], user_data=user_data, tags=TAGS)

pulumi.export("vuln_instance_ip", instance.public_ip)

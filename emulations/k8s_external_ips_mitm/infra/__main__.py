import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

TAGS = {"MayaTrail": "true", "ThreatActor": "K8S_MITM_CVE"}

vpc = aws.ec2.Vpc(f"mayatrail-k8s-mitm-vpc-{stack_name}", cidr_block="10.140.0.0/16", enable_dns_hostnames=True, enable_dns_support=True, tags=TAGS)
igw = aws.ec2.InternetGateway(f"mayatrail-k8s-mitm-igw-{stack_name}", vpc_id=vpc.id, tags=TAGS)
subnet = aws.ec2.Subnet(f"mayatrail-k8s-mitm-subnet-{stack_name}", vpc_id=vpc.id, cidr_block="10.140.1.0/24", map_public_ip_on_launch=True, availability_zone=f"{region}a", tags=TAGS)
rt = aws.ec2.RouteTable(f"mayatrail-k8s-mitm-rt-{stack_name}", vpc_id=vpc.id, routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)], tags=TAGS)
aws.ec2.RouteTableAssociation(f"mayatrail-k8s-mitm-rta-{stack_name}", subnet_id=subnet.id, route_table_id=rt.id)

sg = aws.ec2.SecurityGroup(f"mayatrail-k8s-mitm-sg-{stack_name}", vpc_id=vpc.id, ingress=[
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

RESOURCES = {
    "services": []
}

@app.route('/health')
def health():
    return 'ok'

@app.route('/api/v1/namespaces/default/services', methods=['POST'])
def create_service():
    data = request.json or {}
    name = data.get("metadata", {}).get("name", "")
    external_ips = data.get("spec", {}).get("externalIPs", [])
    selector = data.get("spec", {}).get("selector", {})
    if not name or not external_ips:
        return "Bad request", 400
    service = {"name": name, "externalIPs": external_ips, "selector": selector}
    RESOURCES["services"].append(service)
    return jsonify({"status": "Created", "service": service}), 201

@app.route('/simulate/victim-traffic', methods=['POST'])
def simulate_victim_traffic():
    data = request.json or {}
    destination = data.get("destination", "")
    payload = data.get("payload", "")
    hijacked_service = next(
        (s for s in RESOURCES["services"] if destination in s.get("externalIPs", [])),
        None
    )
    if not hijacked_service:
        return jsonify({"note": "No hijack active for this destination", "destination": destination}), 200
    return jsonify({
        "intended_destination": destination,
        "actual_receiver": hijacked_service["selector"].get("app", "attacker-pod"),
        "intercepted_payload": payload,
        "hijacking_service": hijacked_service["name"],
        "note": "kube-proxy redirected traffic via externalIPs rule (CVE-2020-8554)"
    }), 200

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
docker build -t k8s-mitm .
docker run -d --name k8s-mitm -p 8080:8080 --restart unless-stopped k8s-mitm
"""

instance = aws.ec2.Instance(f"mayatrail-k8s-mitm-ec2-{stack_name}", instance_type="t3.micro", ami=ami.id, subnet_id=subnet.id, vpc_security_group_ids=[sg.id], user_data=user_data, tags=TAGS)

pulumi.export("vuln_instance_ip", instance.public_ip)

import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

TAGS = {"MayaTrail": "true", "ThreatActor": "K8S_STATUS_MITM"}

vpc = aws.ec2.Vpc(f"mayatrail-k8s-stat-vpc-{stack_name}", cidr_block="10.150.0.0/16", enable_dns_hostnames=True, enable_dns_support=True, tags=TAGS)
igw = aws.ec2.InternetGateway(f"mayatrail-k8s-stat-igw-{stack_name}", vpc_id=vpc.id, tags=TAGS)
subnet = aws.ec2.Subnet(f"mayatrail-k8s-stat-subnet-{stack_name}", vpc_id=vpc.id, cidr_block="10.150.1.0/24", map_public_ip_on_launch=True, availability_zone=f"{region}a", tags=TAGS)
rt = aws.ec2.RouteTable(f"mayatrail-k8s-stat-rt-{stack_name}", vpc_id=vpc.id, routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)], tags=TAGS)
aws.ec2.RouteTableAssociation(f"mayatrail-k8s-stat-rta-{stack_name}", subnet_id=subnet.id, route_table_id=rt.id)

sg = aws.ec2.SecurityGroup(f"mayatrail-k8s-stat-sg-{stack_name}", vpc_id=vpc.id, ingress=[
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

ATTACKER_IP = "10.244.9.99"

RESOURCES = {
    "pod_status": {
        "name": "victim-pod",
        "podIP": "10.244.1.20",
        "podIPs": [{"ip": "10.244.1.20"}]
    }
}

@app.route('/health')
def health():
    return 'ok'

@app.route('/api/v1/namespaces/default/pods/victim-pod/status', methods=['PATCH'])
def patch_status():
    data = request.json or {}
    new_ip = data.get("status", {}).get("podIP")
    if not new_ip:
        return "Bad request: missing status.podIP", 400
    RESOURCES["pod_status"]["podIP"] = new_ip
    RESOURCES["pod_status"]["podIPs"] = [{"ip": new_ip}]
    return jsonify({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "victim-pod", "namespace": "default"},
        "status": RESOURCES["pod_status"]
    })

@app.route('/simulate/service-traffic', methods=['POST'])
def simulate_service_traffic():
    data = request.json or {}
    service = data.get("service", "victim-svc")
    payload = data.get("client_payload", "")
    current_pod_ip = RESOURCES["pod_status"]["podIP"]
    intercepted = (current_pod_ip == ATTACKER_IP)
    return jsonify({
        "service": service,
        "routed_to_ip": current_pod_ip,
        "attacker_ip": ATTACKER_IP,
        "intercepted": intercepted,
        "intercepted_payload": payload if intercepted else None,
        "note": (
            "Traffic hijacked: endpoint now points to attacker-controlled IP"
            if intercepted else
            "Traffic flowing normally to legitimate pod IP"
        )
    })

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
docker build -t k8s-stat .
docker run -d --name k8s-stat -p 8080:8080 --restart unless-stopped k8s-stat
"""

instance = aws.ec2.Instance(f"mayatrail-k8s-stat-ec2-{stack_name}", instance_type="t3.micro", ami=ami.id, subnet_id=subnet.id, vpc_security_group_ids=[sg.id], user_data=user_data, tags=TAGS)

pulumi.export("vuln_instance_ip", instance.public_ip)

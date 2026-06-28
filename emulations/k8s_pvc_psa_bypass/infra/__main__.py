import pulumi
import pulumi_aws as aws

stack_name = pulumi.get_stack()
region = aws.config.region or "ap-south-1"

TAGS = {"MayaTrail": "true", "ThreatActor": "K8S_PSA_BYPASS"}

vpc = aws.ec2.Vpc(f"mayatrail-k8s-pvc-vpc-{stack_name}", cidr_block="10.130.0.0/16", enable_dns_hostnames=True, enable_dns_support=True, tags=TAGS)
igw = aws.ec2.InternetGateway(f"mayatrail-k8s-pvc-igw-{stack_name}", vpc_id=vpc.id, tags=TAGS)
subnet = aws.ec2.Subnet(f"mayatrail-k8s-pvc-subnet-{stack_name}", vpc_id=vpc.id, cidr_block="10.130.1.0/24", map_public_ip_on_launch=True, availability_zone=f"{region}a", tags=TAGS)
rt = aws.ec2.RouteTable(f"mayatrail-k8s-pvc-rt-{stack_name}", vpc_id=vpc.id, routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)], tags=TAGS)
aws.ec2.RouteTableAssociation(f"mayatrail-k8s-pvc-rta-{stack_name}", subnet_id=subnet.id, route_table_id=rt.id)

sg = aws.ec2.SecurityGroup(f"mayatrail-k8s-pvc-sg-{stack_name}", vpc_id=vpc.id, ingress=[
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

HOST_FILESYSTEM = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "/etc/shadow": "root:$6$vulnerable_root_hash:19500:0:99999:7:::",
    "/etc/kubernetes/admin.conf": "apiVersion: v1\\nkind: Config\\nclusters:\\n- name: minikube"
}

RESOURCES = {
    "pv": [],
    "pvc": [],
    "pods": []
}

@app.route('/health')
def health():
    return 'ok'

@app.route('/api/v1/persistentvolumes', methods=['POST'])
def create_pv():
    data = request.json or {}
    name = data.get("metadata", {}).get("name", "")
    host_path = data.get("spec", {}).get("hostPath", {}).get("path", "")
    if not name or not host_path:
        return "Bad request", 400
    pv = {"name": name, "hostPath": host_path, "status": "Available"}
    RESOURCES["pv"].append(pv)
    return jsonify({"status": "Created", "pv": pv}), 201

@app.route('/api/v1/namespaces/default/persistentvolumeclaims', methods=['POST'])
def create_pvc():
    data = request.json or {}
    name = data.get("metadata", {}).get("name", "")
    volume_name = data.get("spec", {}).get("volumeName", "")
    if not name:
        return "Bad request", 400
    bound_host_path = None
    for pv in RESOURCES["pv"]:
        if pv["name"] == volume_name or not volume_name:
            bound_host_path = pv["hostPath"]
            pv["status"] = "Bound"
            break
    pvc = {"name": name, "volumeName": volume_name, "boundHostPath": bound_host_path, "status": "Bound"}
    RESOURCES["pvc"].append(pvc)
    return jsonify({"status": "Created", "pvc": pvc}), 201

@app.route('/api/v1/namespaces/default/pods', methods=['POST'])
def create_pod():
    data = request.json or {}
    name = data.get("metadata", {}).get("name", "")
    if not name:
        return "Bad request", 400
    volumes = data.get("spec", {}).get("volumes", [])
    pvc_claim = None
    for vol in volumes:
        pvc_ref = vol.get("persistentVolumeClaim", {}).get("claimName")
        if pvc_ref:
            pvc_claim = pvc_ref
            break
    bound_host_path = None
    for pvc in RESOURCES["pvc"]:
        if pvc["name"] == pvc_claim:
            bound_host_path = pvc.get("boundHostPath")
            break
    pod = {"name": name, "pvcClaim": pvc_claim, "mountedHostPath": bound_host_path, "status": "Running"}
    RESOURCES["pods"].append(pod)
    return jsonify({"status": "Created", "pod": pod}), 201

@app.route('/pod-exec', methods=['POST'])
def pod_exec():
    data = request.json or {}
    pod_name = data.get("pod", "")
    cmd = data.get("cmd", "")
    pod = next((p for p in RESOURCES["pods"] if p["name"] == pod_name), None)
    if not pod:
        return "Pod not found", 404
    host_path = pod.get("mountedHostPath", "")
    if "passwd" in cmd and host_path == "/etc":
        output = HOST_FILESYSTEM.get("/etc/passwd", "")
        return jsonify({"pod": pod_name, "cmd": cmd, "output": output, "note": "Read from host path /etc via PVC mount"})
    if "shadow" in cmd and host_path == "/etc":
        output = HOST_FILESYSTEM.get("/etc/shadow", "")
        return jsonify({"pod": pod_name, "cmd": cmd, "output": output, "note": "Read from host path /etc via PVC mount"})
    return jsonify({"pod": pod_name, "cmd": cmd, "output": "command executed", "mountedHostPath": host_path})

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
docker build -t k8s-pvc .
docker run -d --name k8s-pvc -p 8080:8080 --restart unless-stopped k8s-pvc
"""

instance = aws.ec2.Instance(f"mayatrail-k8s-pvc-ec2-{stack_name}", instance_type="t3.micro", ami=ami.id, subnet_id=subnet.id, vpc_security_group_ids=[sg.id], user_data=user_data, tags=TAGS)

pulumi.export("vuln_instance_ip", instance.public_ip)

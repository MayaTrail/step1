"""
Readiness contract for emulation stacks.

Every emulation's MANIFEST MUST declare a `readiness` block describing how the
backend decides a freshly-deployed stack is ready for the attack phase:

    {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"}
        Poll http://<outputs[ip_output]>:<port><path> until 200 (the scarleteel
        model).  The author declares which Pulumi stack output holds the instance
        IP (ip_output) and the static port/path of the in-instance service — all
        three are known at authoring time because the author writes both the
        infra export and the service.  The IP *value* is resolved at runtime from
        the stack outputs; the manifest only names where to find it.

    {"type": "none"}
        No probe — the stack is ready immediately after deploy (e.g. IAM /
        credential-abuse emulations with no vulnerable web service).

This block is a required, CI-validated field: validate_readiness() is folded
into the emulation test suite (apps/emulations/test_readiness.py), so a missing
or malformed block fails CI at PR time rather than surfacing as a mysterious
FAILED stack at deploy time on the worker.  Requiring an explicit declaration
means "I need no probe" ({"type": "none"}) and "I forgot to declare" (field
absent) are distinct states: the former passes, the latter fails loudly.
"""

from __future__ import annotations

from typing import Any

# Readiness type identifiers.
READINESS_NONE = "none"
READINESS_EC2_HTTP = "ec2_http"
KNOWN_TYPES = frozenset({READINESS_NONE, READINESS_EC2_HTTP})

# The manifest keys each readiness type requires.
_REQUIRED_KEYS: dict[str, frozenset[str]] = {
    READINESS_EC2_HTTP: frozenset({"ip_output", "port", "path"}),
    READINESS_NONE: frozenset(),
}

# Legacy default, retained ONLY as a defensive runtime fallback for a manifest
# that somehow reaches deploy without a readiness block.  The contract
# (validate_readiness) requires the field, so for any CI-compliant emulation
# this fallback is unreachable — it is not a documented authoring path.
DEFAULT_READINESS: dict[str, Any] = {
    "type": READINESS_EC2_HTTP,
    "ip_output": "vuln_instance_ip",
    "port": 8080,
    "path": "/health",
}


def resolve_readiness(manifest: dict[str, Any]) -> dict[str, Any]:
    """
    Return the manifest's readiness block, or the legacy default if absent.

    Presence is guaranteed by validate_readiness() at CI time; the fallback
    exists purely so a non-compliant manifest degrades to the historical
    EC2-HTTP behaviour instead of raising at runtime.

    Args:
        manifest: The emulation MANIFEST dict (or registry catalogue entry).

    Returns:
        The readiness block dict.
    """
    return manifest.get("readiness") or DEFAULT_READINESS


def requires_http_probe(readiness: dict[str, Any]) -> bool:
    """
    True when the stack must pass an HTTP readiness probe before the attack.

    Positive dispatch on the known type: only `ec2_http` triggers a probe.
    Any other value (including an unknown/typo type that slipped past
    validation) is treated as "no probe" rather than silently polling a
    possibly-missing output — validate_readiness() is the layer that rejects
    unknown types at CI time.

    Args:
        readiness: A readiness block as returned by resolve_readiness().

    Returns:
        True if an HTTP probe is required, False otherwise.
    """
    return readiness.get("type") == READINESS_EC2_HTTP


def validate_readiness(manifest: dict[str, Any]) -> list[str]:
    """
    Validate a manifest's readiness block against the contract.

    The function never raises so callers can aggregate errors across every
    emulation in one pass (mirrors apps/metrics/contracts.validate_manifest).

    Args:
        manifest: The emulation MANIFEST dict (or registry catalogue entry).

    Returns:
        A list of human-readable error strings.  An empty list means the
        readiness block is contract-compliant.
    """
    name = manifest.get("name") or "<unnamed>"
    readiness = manifest.get("readiness")

    if readiness is None:
        return [
            f"{name}: 'readiness' is required — declare {{'type': 'none'}} for an "
            f"emulation with no bootable service, or a full 'ec2_http' block "
            f"with {sorted(_REQUIRED_KEYS[READINESS_EC2_HTTP])}."
        ]
    if not isinstance(readiness, dict):
        return [f"{name}: 'readiness' must be an object (got {type(readiness).__name__})"]

    rtype = readiness.get("type")
    if rtype not in KNOWN_TYPES:
        return [
            f"{name}: readiness.type must be one of {sorted(KNOWN_TYPES)} "
            f"(got {rtype!r})"
        ]

    errors: list[str] = []
    for key in sorted(_REQUIRED_KEYS[rtype]):
        if key not in readiness:
            errors.append(f"{name}: readiness.{key} is required for type '{rtype}'")

    # Shape checks for the ec2_http probe target (only meaningful once the
    # required keys are present).
    if rtype == READINESS_EC2_HTTP:
        ip_output = readiness.get("ip_output")
        if "ip_output" in readiness and (not isinstance(ip_output, str) or not ip_output.strip()):
            errors.append(f"{name}: readiness.ip_output must be a non-empty string")

        port = readiness.get("port")
        if "port" in readiness and not isinstance(port, int):
            errors.append(f"{name}: readiness.port must be an int")

        path = readiness.get("path")
        if "path" in readiness and (not isinstance(path, str) or not path.startswith("/")):
            errors.append(f"{name}: readiness.path must be a string beginning with '/'")

    return errors

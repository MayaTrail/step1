"""MANIFEST for k8s_pod_status_mitm."""
MANIFEST = {
    "schema_version": 2,
    "name": "k8s_pod_status_mitm",
    "display_name": "K8s MITM via Pod status.podIP Mutation",
    "description": (
        "Simulates a traffic interception attack where the attacker patches the "
        "status.podIP of a target pod to redirect service traffic to an attacker-controlled endpoint."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "Adversary-in-the-Middle", "Status Subresource", "RBAC Abuse"],
    "technique_count": 1,
    "severity": "HIGH",
    "aliases": "podIP Hijack",
    "attribution": "Advanced K8s lateral movement campaigns",
    "active_since": "2021",
    "targets": "K8s clusters allowing patch verbs on the pods/status subresource",
    "incidents": ["Internal service impersonation"],
    "attack_path": [
        {
            "phase": 1,
            "name": "Adversary-in-the-Middle",
            "techniques": [{"id": "T1557", "name": "Adversary-in-the-Middle"}],
        },
        {
            "phase": 2,
            "name": "Traffic Redirect Verification",
            "techniques": [{"id": "T1557", "name": "Adversary-in-the-Middle"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1557",
            "name": "Adversary-in-the-Middle",
            "tactic": "Credential Access",
            "platform": "Kubernetes",
            "description": "Modifying pods/status subresource to spoof the pod's IP and intercept incoming traffic."
        }
    ],
    "references": [
        {"icon": "#", "title": "Kubernetes Pod status subresource", "source": "Kubernetes", "type": "DOCUMENTATION", "color": "yellow"}
    ],
    "phase_count": 2,
    "estimated_duration_minutes": 8,
    "estimated_cost_per_hour_usd": 0.015,
    "default_ttl_hours": 2,
    "total_resources": 6,
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t3.micro"],
        "uses_lambda": False,
        "uses_secrets_manager": False,
        "uses_cloudtrail": False,
        "uses_guardduty": False,
    },
    "resource_costs": [
        {"name": "EC2 Host", "count": 1, "cost_per_hour_usd": 0.015}
    ]
}

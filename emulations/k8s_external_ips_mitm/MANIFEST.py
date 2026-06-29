"""MANIFEST for k8s_external_ips_mitm."""
MANIFEST = {
    "schema_version": 3,
    "name": "k8s_external_ips_mitm",
    "display_name": "K8s External IPs Hijacking (CVE-2020-8554)",
    "description": (
        "Emulates traffic interception utilizing CVE-2020-8554 where an attacker "
        "creates a Service with arbitrary externalIPs, forcing traffic to route "
        "to a container under their control."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "services": ["Kubernetes API", "kube-proxy"],
    "readiness": {"type": "none"},
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "Adversary-in-the-Middle", "External IPs", "Vulnerability"],
    "technique_count": 1,
    "severity": "MEDIUM",
    "aliases": "ExternalIPs MITM",
    "attribution": "Common Kubernetes misconfiguration scenarios",
    "active_since": "2020",
    "targets": "K8s clusters using vulnerable versions of kube-proxy (CVE-2020-8554)",
    "incidents": ["Cluster-internal traffic diversion"],
    "attack_path": [
        {
            "phase": 1,
            "name": "Traffic Interception",
            "techniques": [{"id": "T1557", "name": "Adversary-in-the-Middle"}],
        },
        {
            "phase": 2,
            "name": "Traffic Interception Verification",
            "techniques": [{"id": "T1557", "name": "Adversary-in-the-Middle"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1557",
            "name": "Adversary-in-the-Middle",
            "tactic": "Credential Access",
            "platform": "Kubernetes",
            "description": "Intercepting traffic meant for external/internal destinations via service externalIPs routing."
        }
    ],
    "references": [
        {
            "icon": "#",
            "title": "CVE-2020-8554: Man in the middle using LoadBalancer or ExternalIPs",
            "source": "Kubernetes · github.com",
            "type": "ADVISORY",
            "color": "red",
            "url": "https://github.com/kubernetes/kubernetes/issues/97076",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1557: Adversary-in-the-Middle",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
            "url": "https://attack.mitre.org/techniques/T1557/",
        },
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

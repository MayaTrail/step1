"""MANIFEST for k8s_pvc_psa_bypass."""
MANIFEST = {
    "schema_version": 2,
    "name": "k8s_pvc_psa_bypass",
    "display_name": "K8s PSA Bypass via PV Abuse",
    "description": (
        "Demonstrates how an attacker bypasses baseline Pod Security Admission (PSA) "
        "by mounting host-paths using raw PersistentVolume and Claims, then reads "
        "sensitive host files from inside an otherwise unprivileged pod."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "Pod Security Admission", "Bypass", "PersistentVolume", "Host Escape"],
    "technique_count": 2,
    "severity": "HIGH",
    "aliases": "PV Abuse Bypass",
    "attribution": "Various cloud exploitation frameworks",
    "active_since": "2022",
    "targets": "K8s clusters relying solely on PSA baseline configurations without storage admission restrictions",
    "incidents": ["Generic cloud infrastructure compromise"],
    "attack_path": [
        {
            "phase": 1,
            "name": "PSA Bypass via HostPath PV",
            "techniques": [{"id": "T1211", "name": "Exploitation for Defense Evasion"}],
        },
        {
            "phase": 2,
            "name": "Host Filesystem Read from Pod",
            "techniques": [{"id": "T1611", "name": "Escape to Host"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1211",
            "name": "Exploitation for Defense Evasion",
            "tactic": "Defense Evasion",
            "platform": "Kubernetes",
            "description": "Circumventing container file restrictions by creating hostPath-backed PVs that PSA does not inspect."
        },
        {
            "id": "T1611",
            "name": "Escape to Host",
            "tactic": "Privilege Escalation",
            "platform": "Kubernetes",
            "description": "Mounting the hostPath PV inside a pod to read sensitive host files (e.g. /etc/passwd) from an otherwise unprivileged container."
        }
    ],
    "references": [
        {"icon": "#", "title": "Bypassing PSA via Storage", "source": "Kubernetes Docs", "type": "DOCUMENTATION", "color": "purple"}
    ],
    "phase_count": 2,
    "estimated_duration_minutes": 10,
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

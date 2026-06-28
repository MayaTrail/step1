"""MANIFEST for k8s_writable_log_escape."""
MANIFEST = {
    "schema_version": 2,
    "name": "k8s_writable_log_escape",
    "display_name": "K8s Writable /var/log Host Escape",
    "description": (
        "Simulates host escape by utilizing a writable host log directory mount "
        "combined with Kubelet log-retrieval permissions to read arbitrary host files."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "Host Escape", "Symlink Abuse", "Writable Mount"],
    "technique_count": 2,
    "severity": "HIGH",
    "aliases": "Log Symlink Escape",
    "attribution": "Various malware campaigns (e.g. Siloscape)",
    "active_since": "2021",
    "targets": "K8s clusters mounting host /var/log inside containers",
    "incidents": ["Siloscape Campaign (2021)"],
    "attack_path": [
        {
            "phase": 1,
            "name": "Pod Command Execution",
            "techniques": [{"id": "T1609", "name": "Container Administration Command"}],
        },
        {
            "phase": 2,
            "name": "Escape to Host Node",
            "techniques": [{"id": "T1611", "name": "Escape to Host"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1609",
            "name": "Container Administration Command",
            "tactic": "Execution",
            "platform": "Kubernetes",
            "description": "Executing code in target pod container to create symlink."
        },
        {
            "id": "T1611",
            "name": "Escape to Host",
            "tactic": "Privilege Escalation",
            "platform": "Kubernetes",
            "description": "Exfiltrating sensitive host files via log endpoint following symlink creation."
        }
    ],
    "references": [
        {"icon": "#", "title": "Writable /var/log Host Escape", "source": "Sysdig Threat Research", "type": "DOCUMENTATION", "color": "orange"}
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

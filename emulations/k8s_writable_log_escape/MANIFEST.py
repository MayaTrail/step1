"""MANIFEST for k8s_writable_log_escape."""
MANIFEST = {
    "schema_version": 3,
    "name": "k8s_writable_log_escape",
    "display_name": "K8s Writable /var/log Host Escape",
    "description": (
        "Simulates host escape by utilizing a writable host log directory mount "
        "combined with Kubelet log-retrieval permissions to read arbitrary host files."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "services": ["Kubelet", "Container Runtime"],
    "readiness": {"type": "none"},
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
        {
            "icon": ">",
            "title": "How to mitigate kubelet's CVE-2021-25741: Symlink exchange can allow host filesystem access",
            "source": "Sysdig · sysdig.com",
            "type": "REPORT",
            "color": "orange",
            "url": "https://sysdig.com/blog/cve-2021-25741-kubelet-falco/",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1609: Container Administration Command",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
            "url": "https://attack.mitre.org/techniques/T1609/",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1611: Escape to Host",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
            "url": "https://attack.mitre.org/techniques/T1611/",
        },
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

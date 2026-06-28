"""MANIFEST for k8s_rbac_impersonation."""
MANIFEST = {
    "schema_version": 2,
    "name": "k8s_rbac_impersonation",
    "display_name": "K8s RBAC Impersonation Privilege Escalation",
    "description": (
        "Simulates a Kubernetes attacker exploiting service accounts with "
        "impersonate access rights to gain admin privileges."
    ),
    "tier": "enterprise",
    "platform": "k8s",
    "added": "2026-06",
    "origin": "unknown",
    "origin_label": "K8S EMULATION",
    "tags": ["Kubernetes", "RBAC", "Impersonation", "Privilege Escalation"],
    "technique_count": 2,
    "severity": "HIGH",
    "aliases": "RBAC Impersonation",
    "attribution": "Scattered Spider / LUCR-3 (abusing cloud/SAML/K8s roles)",
    "active_since": "2020",
    "targets": "Kubernetes API Server with loose impersonation policies",
    "incidents": ["MGM Resorts Breach (2023)"],
    "attack_path": [
        {
            "phase": 1,
            "name": "Permission Enumeration",
            "techniques": [{"id": "T1069", "name": "Permission Groups Discovery"}],
        },
        {
            "phase": 2,
            "name": "Privilege Escalation",
            "techniques": [{"id": "T1548", "name": "Abuse Elevation Control"}],
        }
    ],
    "mitre_mappings": [
        {
            "id": "T1069",
            "name": "Permission Groups Discovery",
            "tactic": "Discovery",
            "platform": "Kubernetes",
            "description": "Enumerating RBAC rules to identify impersonate permissions."
        },
        {
            "id": "T1548",
            "name": "Abuse Elevation Control",
            "tactic": "Privilege Escalation",
            "platform": "Kubernetes",
            "description": "Using request-time impersonate headers to borrow admin permissions."
        }
    ],
    "references": [
        {"icon": "#", "title": "K8s User Impersonation Docs", "source": "Kubernetes", "type": "DOCUMENTATION", "color": "blue"}
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

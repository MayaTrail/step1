"""
MANIFEST for the SCARLETEEL 2.0 enterprise emulation.

schema_version 1 — first versioned format.  Increment this when adding fields
that older registry or view code cannot safely ignore.

All cost values are static estimates authored here — no AWS Pricing API calls
are made.  The estimate endpoint reads resource_costs directly.

UI metadata fields (origin, attack_path, mitre_mappings, references, etc.) are
consumed by EmulationListView which serialises them to camelCase for the
frontend.
"""

MANIFEST = {
    "schema_version": 1,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "scarleteel",
    "display_name": "SCARLETEEL 2.0",
    "description": (
        "6-phase APT emulation based on the real-world SCARLETEEL campaign: "
        "container RCE, IMDSv1 credential theft, lateral movement to AWS, "
        "Terraform state exfiltration, and persistence via Lambda backdoor."
    ),
    "tier": "enterprise",

    # Readiness: explicit default, identical to the legacy ec2_http behavior.
    "readiness": {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"},

    # ── UI catalogue metadata ─────────────────────────────────────────────────
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "Container RCE",
        "IMDSv1 Exploitation",
        "Credential Theft",
        "Lateral Movement",
        "Lambda Backdoor",
        "Defense Evasion",
    ],
    "technique_count": 8,
    "severity": "CRITICAL",
    "aliases": "SCARLETEEL 2.0 · Cloud Container Attack · Terraform State Theft",
    "attribution": "Unknown (Financially Motivated) — Cryptomining + IP Theft",
    "active_since": "2023 — Active",
    "targets": "Kubernetes / ECS clusters on AWS with IMDSv1 enabled",
    "incidents": [
        "SCARLETEEL Campaign (Sysdig TRT, Feb 2023)",
        "SCARLETEEL 2.0 — Extended Campaign (Sysdig TRT, Jul 2023)",
    ],

    # ── Kill-chain phases (maps to frontend attackPath) ───────────────────────
    "attack_path": [
        {
            "phase": 1,
            "name": "Initial Access",
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
            ],
        },
        {
            "phase": 2,
            "name": "Credential Access",
            "techniques": [
                {"id": "T1552.005", "name": "Cloud Instance Metadata API"},
            ],
        },
        {
            "phase": 3,
            "name": "Discovery",
            "techniques": [
                {"id": "T1087.004", "name": "Cloud Account Discovery"},
                {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
            ],
        },
        {
            "phase": 4,
            "name": "Defense Evasion",
            "techniques": [
                {"id": "T1562.008", "name": "Disable Cloud Logs"},
            ],
        },
        {
            "phase": 5,
            "name": "Lateral Movement",
            "techniques": [
                {"id": "T1548.005", "name": "Abuse Elevation Control — AssumeRole"},
                {"id": "T1550.001", "name": "Application Access Token"},
            ],
        },
        {
            "phase": 6,
            "name": "Persistence",
            "techniques": [
                {"id": "T1098", "name": "Account Manipulation — Lambda Backdoor"},
            ],
        },
    ],

    # ── Full MITRE ATT&CK mappings (maps to frontend mitreMappings) ───────────
    "mitre_mappings": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "platform": "Container / EC2",
            "description": (
                "Container RCE via an exposed Jupyter notebook or web shell on a "
                "misconfigured EC2 instance — the attacker's first foothold."
            ),
        },
        {
            "id": "T1552.005",
            "name": "Cloud Instance Metadata API",
            "tactic": "Credential Access",
            "platform": "AWS EC2 IMDS",
            "description": (
                "HTTP GET to 169.254.169.254/latest/meta-data/iam/security-credentials/ "
                "from inside the compromised container.  IMDSv1 requires no PUT "
                "pre-flight, making it reachable from any process inside the instance."
            ),
        },
        {
            "id": "T1087.004",
            "name": "Cloud Account Discovery",
            "tactic": "Discovery",
            "platform": "AWS IAM",
            "description": (
                "Enumerate IAM users, roles, and attached policies using the stolen "
                "IMDSv1 credentials to map the blast radius of the compromised role."
            ),
        },
        {
            "id": "T1580",
            "name": "Cloud Infrastructure Discovery",
            "tactic": "Discovery",
            "platform": "AWS S3 / Secrets Manager",
            "description": (
                "List S3 buckets and Secrets Manager secrets to locate the Terraform "
                "state bucket and any embedded credentials or sensitive configuration."
            ),
        },
        {
            "id": "T1562.008",
            "name": "Disable Cloud Logs",
            "tactic": "Defense Evasion",
            "platform": "AWS CloudTrail",
            "description": (
                "cloudtrail:StopLogging on the active trail before performing lateral "
                "movement — blinds CloudTrail-based detections for the attack window."
            ),
        },
        {
            "id": "T1548.005",
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
            "platform": "AWS STS / IAM",
            "description": (
                "sts:AssumeRole to pivot to a target role with S3 read access on the "
                "Terraform state bucket in the victim account."
            ),
        },
        {
            "id": "T1550.001",
            "name": "Application Access Token",
            "tactic": "Lateral Movement",
            "platform": "AWS STS",
            "description": (
                "Temporary STS credentials from AssumeRole are used to access the "
                "Terraform state bucket and extract plaintext secrets from the state file."
            ),
        },
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "tactic": "Persistence",
            "platform": "AWS Lambda",
            "description": (
                "Lambda backdoor deployed with the exfiltrated role ARN for persistent "
                "access that survives container restarts and cluster remediation."
            ),
        },
    ],

    # ── References (maps to frontend references) ──────────────────────────────
    "references": [
        {
            "icon": ">",
            "title": "SCARLETEEL: Operation Leveraging Terraform, Kubernetes, and AWS for Data Theft",
            "source": "Sysdig TRT · sysdig.com · Feb 2023",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": ">",
            "title": "SCARLETEEL 2.0: Fargate, IAM, and Crypto Under the Covers",
            "source": "Sysdig TRT · sysdig.com · Jul 2023",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1552.005: Cloud Instance Metadata API",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1562.008: Disable Cloud Logs",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "~",
            "title": "AWS Security Best Practices: Require IMDSv2 on All EC2 Instances",
            "source": "AWS Security Blog · 2024",
            "type": "DOCUMENTATION",
            "color": "orange",
        },
    ],

    # ── Infrastructure and cost metadata ──────────────────────────────────────
    "phase_count": 6,
    "estimated_duration_minutes": 20,
    "estimated_cost_per_hour_usd": 0.05,
    "default_ttl_hours": 4,
    "total_resources": 19,
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t3.micro"],
        "uses_lambda": True,
        "uses_secrets_manager": True,
        "uses_cloudtrail": True,
    },
    "resource_costs": [
        {"name": "EC2 t3.micro",           "count": 1, "cost_per_hour_usd": 0.0104},
        {"name": "Secrets Manager secret", "count": 1, "cost_per_hour_usd": 0.00055},
        {"name": "Lambda function",        "count": 1, "cost_per_hour_usd": 0.0},
        {"name": "S3 buckets",             "count": 4, "cost_per_hour_usd": 0.0},
        {"name": "CloudTrail trail",       "count": 1, "cost_per_hour_usd": 0.0},
    ],
}

"""
MANIFEST for the DANGERDEV enterprise emulation.

schema_version 1.  Static cost estimates only — no AWS Pricing API calls.
Based on the real DangerDev@protonmail.me campaign (Invictus IR).
"""

MANIFEST = {
    "schema_version": 1,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "dangerdev",
    "display_name": "DangerDev",
    "description": (
        "17-step AWS adversary emulation based on the real DangerDev "
        "(DangerDev@protonmail.me) campaign: a leaked IAM admin key seeds backdoor "
        "user creation, cross-account trust backdoors, account hijacking, "
        "GPU-cryptomining reconnaissance, defense evasion, and documented "
        "SES/Route53 phishing infrastructure."
    ),
    "tier": "enterprise",

    # ── Readiness (compatibility-critical) ───────────────────────────────────
    # No vulnerable web service — go straight to READY_FOR_ATTACK after deploy.
    "readiness": {"type": "none"},

    # ── UI catalogue metadata ─────────────────────────────────────────────────
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "Leaked Credentials",
        "IAM Abuse",
        "Account Manipulation",
        "Cross-Account Backdoor",
        "Masquerading",
        "Cryptomining Recon",
        "Defense Evasion",
        "Phishing Infrastructure",
    ],
    "technique_count": 17,
    "severity": "HIGH",
    "aliases": "DangerDev@protonmail.me",
    "attribution": "DangerDev (Indonesia, financially motivated) — Cryptomining + SES/PayPal phishing",
    "active_since": "Documented by Invictus IR",
    "targets": "AWS accounts with leaked long-term IAM admin access keys",
    "incidents": [
        "The Curious Case of DangerDev@protonmail.me (Invictus IR)",
    ],

    # ── Kill-chain phases (frontend attackPath) ───────────────────────────────
    "attack_path": [
        {
            "phase": 1,
            "name": "Initial Access & Persistence Establishment",
            "techniques": [
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
                {"id": "T1526", "name": "Cloud Service Discovery"},
                {"id": "T1087.004", "name": "Account Discovery: Cloud Account"},
                {"id": "T1136.003", "name": "Create Account: Cloud Account"},
                {"id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles"},
            ],
        },
        {
            "phase": 2,
            "name": "Infrastructure Discovery & Compute Deployment",
            "techniques": [
                {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
                {"id": "T1578.002", "name": "Modify Cloud Compute: Create Cloud Instance"},
                {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
                {"id": "T1496", "name": "Resource Hijacking"},
            ],
        },
        {
            "phase": 3,
            "name": "Persistence Hardening, Collection, Evasion & Phishing Infra",
            "techniques": [
                {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location"},
                {"id": "T1199", "name": "Trusted Relationship"},
                {"id": "T1098", "name": "Account Manipulation"},
                {"id": "T1530", "name": "Data from Cloud Storage"},
                {"id": "T1518.001", "name": "Software Discovery: Security Software Discovery"},
                {"id": "T1070", "name": "Indicator Removal"},
                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
                {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
            ],
        },
    ],

    # ── Full MITRE ATT&CK mappings (frontend mitreMappings) ───────────────────
    "mitre_mappings": [
        {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access", "platform": "AWS IAM",
         "description": "Bootstrap from a leaked lab-infra-admin long-term access key; GetUser (not GetCallerIdentity) to avoid the identity-check fingerprint."},
        {"id": "T1526", "name": "Cloud Service Discovery", "tactic": "Discovery", "platform": "AWS SES",
         "description": "Enumerate SES send quota and identities to assess phishing/spam capacity before committing."},
        {"id": "T1087.004", "name": "Account Discovery: Cloud Account", "tactic": "Discovery", "platform": "AWS IAM",
         "description": "ListUsers to map existing accounts and learn the ses-smtp-user.* naming pattern used for later masquerade."},
        {"id": "T1136.003", "name": "Create Account: Cloud Account", "tactic": "Persistence", "platform": "AWS IAM",
         "description": "Create the DangerDev@protonmail.me backdoor user with a login profile and access key."},
        {"id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles", "tactic": "Privilege Escalation", "platform": "AWS IAM",
         "description": "Attach AdministratorAccess to the backdoor user and pivot the active session to it."},
        {"id": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "Discovery", "platform": "AWS EC2",
         "description": "Enumerate regions, instances, security groups, VPCs, AZs and GPU-capable instance types (mining reconnaissance)."},
        {"id": "T1578.002", "name": "Modify Cloud Compute: Create Cloud Instance", "tactic": "Defense Evasion", "platform": "AWS EC2",
         "description": "Launch a t2.micro test instance, confirm running, then terminate — the lifecycle test before committing GPU spend (real p3.16xlarge documented-only)."},
        {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "platform": "EC2 / Windows",
         "description": "TCP SYN probe to port 3389 on the public Windows instance, generating a VPC Flow Log ACCEPT record (no interactive RDP)."},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "platform": "EC2 / Windows",
         "description": "Benign CPU-bound workload pre-deployed in EC2 UserData approximating the GPU-cryptomining lifecycle (CloudWatch CPU spike, no real mining)."},
        {"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion", "platform": "AWS IAM",
         "description": "Create a 'ses' user blending with SES auto-generated ses-smtp-user.* accounts; inspect typosquatted backdoor roles."},
        {"id": "T1199", "name": "Trusted Relationship", "tactic": "Initial Access", "platform": "AWS IAM / STS",
         "description": "Wire cross-account backdoor roles (AWSeservedSSO_AdminAccess, AWSLanding-Zones-ConfigRecorderRoles); AssumeRole returns the expected AccessDenied while still logging the event."},
        {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence", "platform": "AWS IAM",
         "description": "Create a second access key on alice.chen and reset her console password to retain access after the backdoor user is deleted."},
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection", "platform": "AWS S3 / IAM",
         "description": "Enumerate S3 buckets/objects plus instance profiles, group membership and SSH keys in a rapid discovery burst."},
        {"id": "T1518.001", "name": "Software Discovery: Security Software Discovery", "tactic": "Discovery", "platform": "AWS GuardDuty",
         "description": "Review GuardDuty findings using an anomalous RDS-console user-agent and probe SSM/SecretsManager access via SimulatePrincipalPolicy (no direct calls)."},
        {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "platform": "AWS IAM",
         "description": "Delete the ses masquerade user and the DangerDev@protonmail.me backdoor (the deletions are themselves CloudTrail indicators)."},
        {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development", "platform": "AWS Route53",
         "description": "DOCUMENTED ONLY — RegisterDomain for PayPal-mimicking domains is not executed; the simulated CloudTrail event is printed."},
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "platform": "AWS SES",
         "description": "VerifyEmailIdentity on a lab-controlled address is executed; SendEmail to real targets is documented-only (SES sandbox blocks delivery)."},
    ],

    # ── References (frontend references) ──────────────────────────────────────
    "references": [
        {"icon": ">", "title": "The Curious Case of DangerDev@protonmail.me", "source": "Invictus IR · invictus-ir.com", "type": "REPORT", "color": "cyan"},
        {"icon": "#", "title": "MITRE ATT&CK — T1136.003: Create Account: Cloud Account", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple"},
        {"icon": "#", "title": "MITRE ATT&CK — T1199: Trusted Relationship", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple"},
        {"icon": "~", "title": "AWS Security Best Practices: Rotate and Restrict Long-Term Access Keys", "source": "AWS Security Blog", "type": "DOCUMENTATION", "color": "orange"},
    ],

    # ── Infrastructure and cost metadata ──────────────────────────────────────
    "phase_count": 3,
    "estimated_duration_minutes": 8,
    "estimated_cost_per_hour_usd": 0.05,
    "default_ttl_hours": 4,
    "total_resources": 65,  # confirmed via `pulumi preview` (pulumi-aws v7)
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t2.micro"],
        "uses_lambda": False,
        "uses_secrets_manager": True,
        "uses_cloudtrail": True,
        "uses_guardduty": True,
    },
    "resource_costs": [
        {"name": "EC2 t2.micro (Windows)", "count": 1, "cost_per_hour_usd": 0.0162},
        {"name": "GuardDuty detector",     "count": 1, "cost_per_hour_usd": 0.01},
        {"name": "CloudTrail (data events)","count": 1, "cost_per_hour_usd": 0.01},
        {"name": "KMS key",                "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "Secrets Manager secret", "count": 1, "cost_per_hour_usd": 0.00055},
        {"name": "S3 buckets",             "count": 3, "cost_per_hour_usd": 0.0},
        {"name": "SNS topic",              "count": 1, "cost_per_hour_usd": 0.0},
    ],
}

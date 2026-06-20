"""MANIFEST for the LUCR-3 (Scattered Spider) adversary emulation."""

MANIFEST = {
    "schema_version": 1,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "lucr_3",
    "display_name": "LUCR-3 (Scattered Spider)",
    "description": (
        "21-technique multi-cloud identity attack emulation based on LUCR-3 "
        "(Scattered Spider / UNC3944): Okta MFA fatigue bypass, device registration, "
        "AWS SAML pivot, M365 SharePoint collection, AWS cloud discovery, "
        "IAM backdoor creation, Secrets Manager credential scraping, "
        "EC2 lateral movement via SSM, GuardDuty + CloudTrail disable, "
        "S3/DynamoDB/GitHub exfiltration, and M365 email cover-up. "
        "Requires Okta credentials via environment variables."
    ),
    "tier": "enterprise",

    # ── Readiness ─────────────────────────────────────────────────────────────
    "readiness": {"type": "none"},

    # ── UI catalogue metadata ──────────────────────────────────────────────────
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "Multi-Cloud",
        "Identity Attack",
        "MFA Fatigue",
        "SAML Pivot",
        "Scattered Spider",
        "Okta",
        "M365",
        "GitHub",
        "IAM Backdoor",
        "GuardDuty Disable",
    ],
    "technique_count": 21,
    "severity": "CRITICAL",
    "aliases": "Scattered Spider, Oktapus, UNC3944, STORM-0875",
    "attribution": "LUCR-3 — financial extortion via IP theft; demands in tens of millions USD",
    "active_since": "Documented by Permiso (2023)",
    "targets": "SaaS-heavy organizations with Okta + AWS + M365 + GitHub",
    "incidents": [
        "LUCR-3: Scattered Spider Getting SaaS-y in the Cloud (Permiso)",
        "MGM Resorts International breach (2023)",
        "Caesars Entertainment breach (2023)",
    ],

    # ── Kill-chain phases ──────────────────────────────────────────────────────
    "attack_path": [
        {
            "phase": 1,
            "name": "Initial IDP Compromise",
            "techniques": [
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
                {"id": "T1621",     "name": "Multi-Factor Authentication Request Generation"},
            ],
        },
        {
            "phase": 2,
            "name": "MFA Bypass & Device Registration",
            "techniques": [
                {"id": "T1111",     "name": "Multi-Factor Authentication Interception"},
                {"id": "T1098.005", "name": "Account Manipulation: Device Registration"},
            ],
        },
        {
            "phase": 3,
            "name": "AWS SAML Pivot",
            "techniques": [
                {"id": "T1550.001", "name": "Use Alternate Authentication Material: Application Access Token"},
            ],
        },
        {
            "phase": 4,
            "name": "M365 SharePoint Collection",
            "techniques": [
                {"id": "T1213.002", "name": "Data from Information Repositories: SharePoint"},
            ],
        },
        {
            "phase": 5,
            "name": "AWS Cloud Discovery",
            "techniques": [
                {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
                {"id": "T1619", "name": "Cloud Storage Object Discovery"},
                {"id": "T1082", "name": "System Information Discovery"},
            ],
        },
        {
            "phase": 6,
            "name": "AWS IAM Backdoor",
            "techniques": [
                {"id": "T1098",     "name": "Account Manipulation"},
                {"id": "T1136.003", "name": "Create Account: Cloud Account"},
                {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"},
            ],
        },
        {
            "phase": 7,
            "name": "Credential Harvest & EC2 Staging",
            "techniques": [
                {"id": "T1555.006", "name": "Credentials from Password Stores: Cloud Secrets Management Stores"},
                {"id": "T1578.002", "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance"},
            ],
        },
        {
            "phase": 8,
            "name": "Defense Evasion",
            "techniques": [
                {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
                {"id": "T1562.008", "name": "Impair Defenses: Disable or Modify Cloud Logs"},
            ],
        },
        {
            "phase": 9,
            "name": "Lateral Movement & Cover-Up",
            "techniques": [
                {"id": "T1021.004", "name": "Remote Services: SSH"},
                {"id": "T1072",     "name": "Software Deployment Tools"},
                {"id": "T1070.008", "name": "Indicator Removal: Clear Mailbox Data"},
            ],
        },
        {
            "phase": 10,
            "name": "Data Exfiltration",
            "techniques": [
                {"id": "T1530",     "name": "Data from Cloud Storage"},
                {"id": "T1213.003", "name": "Data from Information Repositories: Code Repositories"},
            ],
        },
    ],

    # ── Full MITRE mappings ────────────────────────────────────────────────────
    "mitre_mappings": [
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "tactic": "Initial Access",
            "platform": "Okta",
            "description": "POST to Okta /api/v1/authn with victim credentials purchased from deepweb marketplace or obtained via smishing.",
        },
        {
            "id": "T1621",
            "name": "Multi-Factor Authentication Request Generation",
            "tactic": "Credential Access",
            "platform": "Okta",
            "description": "Repeated MFA push/SMS requests to victim device to induce fatigue and accidental approval. SIMULATED.",
        },
        {
            "id": "T1111",
            "name": "Multi-Factor Authentication Interception",
            "tactic": "Credential Access",
            "platform": "Okta",
            "description": "OTP code interception via mock TOTP server. DOCUMENTED ONLY — SIM swapping is illegal.",
        },
        {
            "id": "T1098.005",
            "name": "Account Manipulation: Device Registration",
            "tactic": "Persistence",
            "platform": "Okta",
            "description": "Enroll attacker-controlled TOTP/SMS factor on victim account to establish persistent MFA access.",
        },
        {
            "id": "T1213.002",
            "name": "Data from Information Repositories: SharePoint",
            "tactic": "Collection",
            "platform": "Microsoft 365",
            "description": "Microsoft Graph API search for sensitive SharePoint/OneDrive documents (IT procedures, VPN configs, passwords).",
        },
        {
            "id": "T1580",
            "name": "Cloud Infrastructure Discovery",
            "tactic": "Discovery",
            "platform": "AWS",
            "description": "Enumerate IAM users/roles, EC2 instances, DynamoDB tables, S3 buckets, VPCs, SSM-managed instances via SAML federated session.",
        },
        {
            "id": "T1619",
            "name": "Cloud Storage Object Discovery",
            "tactic": "Discovery",
            "platform": "AWS S3",
            "description": "ListObjectsV2 on corporate and engineering S3 buckets to identify high-value data for exfiltration.",
        },
        {
            "id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "platform": "AWS EC2",
            "description": "DescribeInstances + DescribeInstanceInformation to enumerate EC2 instances and their SSM agent status.",
        },
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "tactic": "Persistence",
            "platform": "AWS IAM",
            "description": "CreateLoginProfile on backdoor IAM user; AttachUserPolicy AdministratorAccess.",
        },
        {
            "id": "T1136.003",
            "name": "Create Account: Cloud Account",
            "tactic": "Persistence",
            "platform": "AWS IAM",
            "description": "Create long-lived IAM backdoor user (svc-automation-lucr3) blending with legitimate service account naming.",
        },
        {
            "id": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials",
            "tactic": "Persistence",
            "platform": "AWS IAM",
            "description": "CreateAccessKey on backdoor IAM user; second long-lived key provides access independent of SAML session.",
        },
        {
            "id": "T1555.006",
            "name": "Credentials from Password Stores: Cloud Secrets Management Stores",
            "tactic": "Credential Access",
            "platform": "AWS Secrets Manager",
            "description": "ListSecrets + GetSecretValue on prod/database, prod/payments, prod/infrastructure (canary), prod/cicd/github-actions-token (canary). SIMULATED with synthetic secrets.",
        },
        {
            "id": "T1578.002",
            "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
            "tactic": "Defense Evasion",
            "platform": "AWS EC2",
            "description": "RunInstances to launch attacker-controlled EC2 instance with IAM instance profile for persistent cloud shell access.",
        },
        {
            "id": "T1550.001",
            "name": "Use Alternate Authentication Material: Application Access Token",
            "tactic": "Defense Evasion",
            "platform": "Okta / AWS STS",
            "description": "AssumeRoleWithSAML using Okta-issued SAML assertion to obtain temporary AWS credentials without long-term key.",
        },
        {
            "id": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "platform": "AWS GuardDuty",
            "description": "UpdateDetector Enable=False to disable GuardDuty threat detection before exfiltration.",
        },
        {
            "id": "T1562.008",
            "name": "Impair Defenses: Disable or Modify Cloud Logs",
            "tactic": "Defense Evasion",
            "platform": "AWS CloudTrail",
            "description": "StopLogging on CloudTrail trail to eliminate evidence of subsequent exfiltration activity.",
        },
        {
            "id": "T1021.004",
            "name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "platform": "AWS EC2 / SSM",
            "description": "StartSession via SSM Session Manager to EC2 target — lateral movement without SSH keys or open port 22.",
        },
        {
            "id": "T1072",
            "name": "Software Deployment Tools",
            "tactic": "Lateral Movement",
            "platform": "SCCM",
            "description": "SCCM enumeration for lateral movement to domain-joined endpoints. DOCUMENTED ONLY — requires domain-joined lab.",
        },
        {
            "id": "T1070.008",
            "name": "Indicator Removal: Clear Mailbox Data",
            "tactic": "Defense Evasion",
            "platform": "Microsoft 365",
            "description": "Microsoft Graph API hard/soft delete of security alert emails to prevent victim notification of the compromise.",
        },
        {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "tactic": "Collection",
            "platform": "AWS S3 / DynamoDB",
            "description": "GetObject on corporate and engineering S3 buckets + DynamoDB Scan on customer records table. Canary object access triggers alert.",
        },
        {
            "id": "T1213.003",
            "name": "Data from Information Repositories: Code Repositories",
            "tactic": "Collection",
            "platform": "GitHub",
            "description": "git clone of target repository using harvested GitHub PAT from Secrets Manager.",
        },
    ],

    # ── References ────────────────────────────────────────────────────────────
    "references": [
        {
            "icon": ">",
            "title": "LUCR-3: Scattered Spider Getting SaaS-y in the Cloud",
            "source": "Permiso Security · permiso.io",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": ">",
            "title": "Scattered Spider: The Modus Operandi",
            "source": "CrowdStrike · crowdstrike.com",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1621: Multi-Factor Authentication Request Generation",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1098.005: Account Manipulation: Device Registration",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "~",
            "title": "Okta Security: Phishing-Resistant MFA Guidance",
            "source": "Okta Security Blog",
            "type": "DOCUMENTATION",
            "color": "orange",
        },
    ],

    # ── Infrastructure & cost ─────────────────────────────────────────────────
    "phase_count": 10,
    "estimated_duration_minutes": 120,
    "estimated_cost_per_hour_usd": 0.059,
    "default_ttl_hours": 4,
    "total_resources": 26,
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t3.micro"],
        "uses_lambda": False,
        "uses_secrets_manager": True,
        "uses_cloudtrail": True,
        "uses_guardduty": True,
    },
    "resource_costs": [
        {"name": "EC2 t3.micro (target)",  "count": 1, "cost_per_hour_usd": 0.05},
        {"name": "GuardDuty detector",     "count": 1, "cost_per_hour_usd": 0.005},
        {"name": "CloudTrail trail",       "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "Secrets Manager secrets","count": 4, "cost_per_hour_usd": 0.0022},
        {"name": "S3 buckets",             "count": 3, "cost_per_hour_usd": 0.0},
        {"name": "IAM roles + users",      "count": 4, "cost_per_hour_usd": 0.0},
        {"name": "DynamoDB table",         "count": 1, "cost_per_hour_usd": 0.0},
        {"name": "GitHub repo",            "count": 1, "cost_per_hour_usd": 0.0},
    ],
    # LUCR-3 requires Okta credentials via environment variables:
    #   OKTA_VICTIM_USERNAME, OKTA_VICTIM_PASSWORD
    # Optional (for SAML pivot): OKTA_DOMAIN (or 'okta_org_url' Pulumi export)
    # Optional (for M365 phases): M365_TENANT_ID
    # Optional (for GitHub phases): GITHUB_OWNER
    "env_vars_required": [
        "OKTA_VICTIM_USERNAME",
        "OKTA_VICTIM_PASSWORD",
    ],
    "env_vars_optional": [
        "OKTA_DOMAIN",
        "FEDERATED_ROLE_ARN",
        "SAML_PROVIDER_ARN",
        "M365_TENANT_ID",
        "GITHUB_OWNER",
    ],
}

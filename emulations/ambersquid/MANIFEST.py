"""MANIFEST for the AMBERSQUID adversary emulation."""

MANIFEST = {
    "schema_version": 1,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "ambersquid",
    "display_name": "AMBERSQUID",
    "description": (
        "13-technique AWS cryptomining emulation based on the AMBERSQUID campaign: "
        "victim credentials injected via malicious container, IAM role persistence "
        "(AWSCodeCommit-Role / sugo-role / ecsTaskExecutionRole), multi-service miner "
        "deployment across Amplify, ECS Fargate, SageMaker, CodeBuild and CodeCommit "
        "(simulated), followed by CloudTrail StopLogging and indicator removal. "
        "Attributed to Indonesian-origin financially motivated threat actors."
    ),
    "tier": "enterprise",

    # ── Readiness ─────────────────────────────────────────────────────────────
    "readiness": {"type": "none"},

    # ── UI catalogue metadata ──────────────────────────────────────────────────
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "Cryptomining",
        "Container Abuse",
        "IAM Persistence",
        "Multi-Service Deployment",
        "CloudTrail Evasion",
        "ECS Fargate",
        "SageMaker",
        "CodeBuild",
    ],
    "technique_count": 13,
    "severity": "CRITICAL",
    "aliases": "",
    "attribution": "AMBERSQUID (Indonesia, financially motivated) — SRBMiner cryptomining across 16 AWS regions",
    "active_since": "Documented by Sysdig Threat Research Team (2023)",
    "targets": "AWS accounts with over-permissioned long-term IAM keys accessible via container env vars",
    "incidents": [
        "AMBERSQUID Cloud-Native Cryptomining Operation (Sysdig TRT)",
    ],

    # ── Kill-chain phases ──────────────────────────────────────────────────────
    "attack_path": [
        {
            "phase": 1,
            "name": "Resource Development (Documented)",
            "techniques": [
                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
                {"id": "T1608.001", "name": "Stage Capabilities: Upload Malware"},
            ],
        },
        {
            "phase": 2,
            "name": "Initial Execution: Malicious Container",
            "techniques": [
                {"id": "T1204.003", "name": "User Execution: Malicious Image"},
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
            ],
        },
        {
            "phase": 3,
            "name": "Persistence & Privilege Escalation",
            "techniques": [
                {"id": "T1136.003", "name": "Create Account: Cloud Account"},
                {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"},
            ],
        },
        {
            "phase": 4,
            "name": "Execution: Multi-Service Miner Deployment",
            "techniques": [
                {"id": "T1059.009", "name": "Command and Scripting Interpreter: Cloud API"},
                {"id": "T1580",     "name": "Cloud Infrastructure Discovery"},
                {"id": "T1525",     "name": "Implant Internal Image"},
                {"id": "T1610",     "name": "Deploy Container"},
                {"id": "T1578.002", "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance"},
            ],
        },
        {
            "phase": 5,
            "name": "Defense Evasion & Impact",
            "techniques": [
                {"id": "T1070", "name": "Indicator Removal"},
                {"id": "T1496", "name": "Resource Hijacking"},
            ],
        },
    ],

    # ── Full MITRE mappings ────────────────────────────────────────────────────
    "mitre_mappings": [
        {
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "platform": "Docker Hub / amplifyapp.com",
            "description": "Attacker registered Docker Hub accounts and amplifyapp subdomain for staging malicious SRBMiner images. DOCUMENTED ONLY.",
        },
        {
            "id": "T1608.001",
            "name": "Stage Capabilities: Upload Malware",
            "tactic": "Resource Development",
            "platform": "Docker Hub",
            "description": "UPX-packed SRBMiner-MULTI container pushed to Docker Hub bypassing static AV. SIMULATED — emulation uses a mock-sleep binary.",
        },
        {
            "id": "T1204.003",
            "name": "User Execution: Malicious Image",
            "tactic": "Execution",
            "platform": "ECS Fargate",
            "description": "Victim runs the malicious container with AWS credentials injected as env vars; entrypoint.sh launches attack scripts.",
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "tactic": "Defense Evasion",
            "platform": "AWS IAM / STS",
            "description": "Container uses victim long-lived IAM credentials from env vars; GetCallerIdentity + GetUser validate the session.",
        },
        {
            "id": "T1136.003",
            "name": "Create Account: Cloud Account",
            "tactic": "Persistence",
            "platform": "AWS IAM",
            "description": "Creates IAM roles AWSCodeCommit-Role, sugo-role, and ecsTaskExecutionRole with trust policies enabling cross-service access.",
        },
        {
            "id": "T1098.001",
            "name": "Account Manipulation: Additional Cloud Credentials",
            "tactic": "Persistence",
            "platform": "AWS IAM",
            "description": "Attaches AdministratorAccess and full-service managed policies to attacker-created IAM roles via AttachRolePolicy and PutRolePolicy.",
        },
        {
            "id": "T1059.009",
            "name": "Command and Scripting Interpreter: Cloud API",
            "tactic": "Execution",
            "platform": "AWS multi-service",
            "description": "Shell scripts invoke AWS API across services: Amplify CreateApp, CodeCommit CreateRepository, CodeBuild CreateProject, ECS CreateCluster/RegisterTaskDefinition, SageMaker CreateNotebookInstance.",
        },
        {
            "id": "T1580",
            "name": "Cloud Infrastructure Discovery",
            "tactic": "Discovery",
            "platform": "AWS EC2 / IAM / STS",
            "description": "Scripts enumerate available regions, account quotas, IAM roles/users, and S3 buckets to plan multi-region miner deployment.",
        },
        {
            "id": "T1525",
            "name": "Implant Internal Image",
            "tactic": "Persistence",
            "platform": "AWS CodeCommit",
            "description": "Push miner scripts to CodeCommit as build source for Amplify and CodeBuild pipelines. SIMULATED — empty repo, no malicious binaries.",
        },
        {
            "id": "T1610",
            "name": "Deploy Container",
            "tactic": "Defense Evasion",
            "platform": "Amazon ECS Fargate",
            "description": "ECS task definition registered for Fargate miner; SIMULATED — RegisterTaskDefinition only, service not created.",
        },
        {
            "id": "T1578.002",
            "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
            "tactic": "Defense Evasion",
            "platform": "AWS multi-service",
            "description": "EC2 Auto Scaling, CloudFormation, SageMaker notebooks, EC2 ImageBuilder pipelines. SIMULATED — dry-run describe calls only.",
        },
        {
            "id": "T1070",
            "name": "Indicator Removal",
            "tactic": "Defense Evasion",
            "platform": "AWS CloudTrail / S3",
            "description": "StopLogging on CloudTrail trail, DeleteObject on most recent CT log file, and DeleteRepository on CodeCommit repos.",
        },
        {
            "id": "T1496",
            "name": "Resource Hijacking",
            "tactic": "Impact",
            "platform": "EC2 / ECS / SageMaker",
            "description": "SRBMiner-MULTI mines ZEPHYR and Monero. SIMULATED — DescribeTasks on mock miner task; no real mining or network connections.",
        },
    ],

    # ── References ────────────────────────────────────────────────────────────
    "references": [
        {
            "icon": ">",
            "title": "AMBERSQUID Cloud-Native Cryptomining Operation",
            "source": "Sysdig TRT · sysdig.com",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1610: Deploy Container",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1578.002: Modify Cloud Compute Infrastructure",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "~",
            "title": "AWS Security Best Practices: Least Privilege IAM Roles",
            "source": "AWS Security Blog",
            "type": "DOCUMENTATION",
            "color": "orange",
        },
    ],

    # ── Infrastructure & cost ─────────────────────────────────────────────────
    "phase_count": 5,
    "estimated_duration_minutes": 60,
    "estimated_cost_per_hour_usd": 0.0027,
    "default_ttl_hours": 4,
    "total_resources": 17,
    "resources": {
        "ec2_count": 0,
        "instance_types": [],
        "uses_lambda": False,
        "uses_secrets_manager": True,
        "uses_cloudtrail": True,
        "uses_guardduty": False,
    },
    "resource_costs": [
        {"name": "CloudTrail trail",      "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "Secrets Manager secret","count": 1, "cost_per_hour_usd": 0.00056},
        {"name": "CloudWatch log group",  "count": 1, "cost_per_hour_usd": 0.0007},
        {"name": "ECS cluster",           "count": 1, "cost_per_hour_usd": 0.0},
        {"name": "S3 buckets",            "count": 2, "cost_per_hour_usd": 0.0},
        {"name": "IAM roles + users",     "count": 4, "cost_per_hour_usd": 0.0},
        {"name": "VPC / subnet / SG",     "count": 3, "cost_per_hour_usd": 0.0},
    ],
}

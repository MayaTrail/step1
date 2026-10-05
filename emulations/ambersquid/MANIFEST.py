"""MANIFEST for the AMBERSQUID adversary emulation."""

MANIFEST = {
    "schema_version": 3,

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

    # ── Dashboard contract (schema 3) ─────────────────────────────────────────
    "platform": "aws",
    "added": "2026-07",
    "services": [
        "IAM", "STS", "EC2", "ECS", "S3", "CloudTrail",
        "Secrets Manager", "CloudWatch", "Amplify",
        "CodeCommit", "CodeBuild", "SageMaker",
    ],

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
    "identities": {
        "victim_user": {"kind": "lab_user", "label": "The lab's victim user", "output": "victim_user_name"},
        "repo_role": {"kind": "attack_created", "label": "A CodeCommit role the attack creates"},
        "notebook_role": {"kind": "attack_created", "label": "A SageMaker role the attack creates"},
        "ecs_role": {"kind": "attack_created", "label": "An ECS role the attack creates"},
    },
    "attack_path": [
        {
            "phase": 1,
            "name": "Resource Development (Documented)",
            "aws_actions": [],
            "techniques": [
                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains"},
                {"id": "T1608.001", "name": "Stage Capabilities: Upload Malware"},
            ],
        },
        {
            "phase": 2,
            "name": "Initial Execution: Malicious Container",
            "aws_actions": [
                "ecs:RunTask",
                "ecs:DescribeTasks",
                "sts:GetCallerIdentity",
                "iam:GetUser",
                "iam:ListAttachedUserPolicies",
            ],
            "acting_as": {
                "connected_role": ["ecs:RunTask", "ecs:DescribeTasks"],
                "victim_user": ["sts:GetCallerIdentity", "iam:GetUser", "iam:ListAttachedUserPolicies"],
            },
            "aws_resources": {
                "ecs:RunTask": "arn:aws:ecs:{region}:{account_id}:task-definition/{task_family}",
                "ecs:DescribeTasks": "arn:aws:ecs:{region}:{account_id}:task/{cluster_name}/*",
                "sts:GetCallerIdentity": "*",
                "iam:GetUser": "arn:aws:iam::{account_id}:user/{victim_user_name}",
                "iam:ListAttachedUserPolicies": "arn:aws:iam::{account_id}:user/{victim_user_name}",
            },
            "techniques": [
                {"id": "T1204.003", "name": "User Execution: Malicious Image"},
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
            ],
        },
        {
            "phase": 3,
            "name": "Persistence & Privilege Escalation",
            "aws_actions": [
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "sts:AssumeRole",
            ],
            "acting_as": "victim_user",
            "aws_resources": {
                "iam:CreateRole": ["arn:aws:iam::{account_id}:role/AWSCodeCommit-Role", "arn:aws:iam::{account_id}:role/sugo-role", "arn:aws:iam::{account_id}:role/ecsTaskExecutionRole"],
                "iam:AttachRolePolicy": ["arn:aws:iam::{account_id}:role/AWSCodeCommit-Role", "arn:aws:iam::{account_id}:role/sugo-role", "arn:aws:iam::{account_id}:role/ecsTaskExecutionRole"],
                "sts:AssumeRole": ["arn:aws:iam::{account_id}:role/AWSCodeCommit-Role", "arn:aws:iam::{account_id}:role/sugo-role", "arn:aws:iam::{account_id}:role/ecsTaskExecutionRole"],
            },
            "techniques": [
                {"id": "T1136.003", "name": "Create Account: Cloud Account"},
                {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"},
            ],
        },
        {
            "phase": 4,
            "name": "Execution: Multi-Service Miner Deployment",
            "aws_actions": [
                "codecommit:CreateRepository",
                "codecommit:GetRepository",
                "amplify:CreateApp",
                "codebuild:CreateProject",
                "ecs:CreateCluster",
                "ecs:RegisterTaskDefinition",
                "iam:PassRole",
                "sagemaker:CreateNotebookInstance",
                "sagemaker:DescribeNotebookInstance",
                "sts:GetCallerIdentity",
                "ec2:DescribeRegions",
                "iam:GetAccountSummary",
                "iam:ListRoles",
                "iam:ListUsers",
                "s3:ListAllMyBuckets",
                "s3:GetObject",
                "secretsmanager:ListSecrets",
                "secretsmanager:GetSecretValue",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeInstanceTypeOfferings",
                "cloudformation:ValidateTemplate",
                "autoscaling:DescribeAutoScalingGroups",
            ],
            "acting_as": {
                "repo_role": ["codecommit:CreateRepository", "codecommit:GetRepository", "amplify:CreateApp", "codebuild:CreateProject", "iam:PassRole"],
                "notebook_role": ["sagemaker:CreateNotebookInstance", "sagemaker:DescribeNotebookInstance", "iam:PassRole"],
                "ecs_role": ["ecs:CreateCluster", "ecs:RegisterTaskDefinition", "iam:PassRole"],
                "victim_user": ["sts:GetCallerIdentity", "ec2:DescribeRegions", "iam:GetAccountSummary", "iam:ListRoles", "iam:ListUsers", "s3:ListAllMyBuckets", "s3:GetObject", "secretsmanager:ListSecrets", "secretsmanager:GetSecretValue", "ec2:DescribeLaunchTemplates", "ec2:DescribeInstanceTypeOfferings", "cloudformation:ValidateTemplate", "autoscaling:DescribeAutoScalingGroups"],
            },
            "aws_resources": {
                "sts:GetCallerIdentity": "*",
                "ec2:DescribeRegions": "*",
                "iam:GetAccountSummary": "*",
                "iam:ListRoles": "*",
                "iam:ListUsers": "*",
                "s3:ListAllMyBuckets": "*",
                "s3:GetObject": "arn:aws:s3:::{tfstate_bucket_name}/terraform.tfstate",
                "secretsmanager:ListSecrets": "*",
                "secretsmanager:GetSecretValue": "{canary_secret_arn}",
                "ec2:DescribeLaunchTemplates": "*",
                "ec2:DescribeInstanceTypeOfferings": "*",
                "cloudformation:ValidateTemplate": "*",
                "autoscaling:DescribeAutoScalingGroups": "*",
            },
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
            "aws_actions": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:StopLogging",
                "s3:ListBucket",
                "s3:DeleteObject",
                "codecommit:ListRepositories",
                "ecs:DescribeTasks",
            ],
            "acting_as": {
                "repo_role": ["codecommit:ListRepositories"],
                "victim_user": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:StopLogging", "s3:ListBucket", "s3:DeleteObject", "ecs:DescribeTasks"],
            },
            "aws_resources": {
                "cloudtrail:DescribeTrails": "*",
                "cloudtrail:GetTrailStatus": "arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}",
                "cloudtrail:StopLogging": "arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}",
                "s3:ListBucket": "arn:aws:s3:::{cloudtrail_bucket_name}",
                "s3:DeleteObject": "arn:aws:s3:::{cloudtrail_bucket_name}/*",
                "ecs:DescribeTasks": "arn:aws:ecs:{region}:{account_id}:task/{cluster_name}/*",
            },
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
            "title": "AWS's Hidden Threat: AMBERSQUID Cloud-Native Cryptojacking Operation",
            "source": "Sysdig TRT · sysdig.com · Sep 2023",
            "url": "https://www.sysdig.com/blog/ambersquid",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1610: Deploy Container",
            "source": "MITRE ATT&CK · mitre.org",
            "url": "https://attack.mitre.org/techniques/T1610/",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1578.002: Modify Cloud Compute Infrastructure: Create Cloud Instance",
            "source": "MITRE ATT&CK · mitre.org",
            "url": "https://attack.mitre.org/techniques/T1578/002/",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "~",
            "title": "Security best practices in IAM",
            "source": "AWS IAM User Guide · docs.aws.amazon.com",
            "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "type": "DOCUMENTATION",
            "color": "orange",
        },
    ],

    # ── Infrastructure & cost ─────────────────────────────────────────────────
    "phase_count": 5,
    "estimated_duration_minutes": 60,
    "estimated_cost_per_hour_usd": 0.0027,
    "default_ttl_hours": 4,
    "total_resources": 28,
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

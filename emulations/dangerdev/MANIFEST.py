"""
MANIFEST for the DANGERDEV enterprise emulation.

schema_version 3 — carries the full dashboard contract (apps/metrics/contracts.py):
a top-level `platform` identifier, an `added` month, and a `services` list (the
cloud services this emulation exercises) consumed by the Platform Overview
"Attack Surface Coverage" section.  schema_version 2 introduced `platform`/`added`;
schema_version 3 added `services`.  Increment this when adding fields that older
registry or view code cannot safely ignore.

Static cost estimates only — no AWS Pricing API calls.  Based on the real
DangerDev@protonmail.me campaign (Invictus IR).

UI metadata fields (origin, attack_path, mitre_mappings, references, etc.) are
consumed by EmulationListView which serialises them to camelCase for the
frontend.  The dashboard derives coverage metrics from `platform` and
`mitre_mappings`.
"""

MANIFEST = {
    "schema_version": 3,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "dangerdev",
    "display_name": "DangerDev",
    "description": (
        "17-step AWS adversary emulation based on the real DangerDev "
        "(DangerDev@protonmail.me) campaign: a leaked IAM admin key seeds backdoor "
        "user creation, cross-account trust backdoors, account hijacking, "
        "GPU-cryptomining reconnaissance, defense evasion, and phishing "
        "infrastructure: real Route 53 Domains and SES calls whose harmful outcomes "
        "(domain purchase, leaving the SES sandbox, mail to real people) are refused "
        "by IAM deny guards and the SES mailbox simulator."
    ),
    "tier": "enterprise",

    # Primary platform this emulation targets — drives the Platform Coverage
    # widget.  One of: aws, azure, gcp, k8s, ai (see SUPPORTED_PLATFORMS).
    "platform": "aws",

    # Month this emulation was added ("YYYY-MM").  Drives the Platform Overview
    # "Recently Added Emulations" ordering.
    "added": "2026-06",

    # Cloud services this emulation exercises.  Drives the Platform Overview
    # "Attack Surface Coverage" section, which buckets these into categories via
    # the frontend service taxonomy (src/data/attackSurface.ts).  Use canonical
    # short names, e.g. "IAM", "EC2", "S3".
    "services": [
        "IAM", "STS", "EC2", "S3", "SES", "GuardDuty",
        "CloudTrail", "Route53", "Secrets Manager", "KMS", "SNS",
    ],

    # ── Readiness (compatibility-critical) ───────────────────────────────────
    # No vulnerable web service — go straight to READY_FOR_ATTACK after deploy.
    # Consumed by the backend readiness resolver (apps/emulations/readiness.py),
    # which lands with the Phase 2 deploy-pipeline migration.
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
    "severity": "CRITICAL",
    "aliases": "DangerDev@protonmail.me",
    "attribution": "DangerDev (Indonesia, financially motivated) — Cryptomining + SES/PayPal phishing",
    "active_since": "Documented by Invictus IR",
    "targets": "AWS accounts with leaked long-term IAM admin access keys",
    "incidents": [
        "The Curious Case of DangerDev@protonmail.me (Invictus IR)",
    ],

    # ── Kill-chain phases (frontend attackPath) ───────────────────────────────
    "identities": {
        "leaked_admin": {"kind": "lab_user", "label": "The lab's leaked admin user", "output": "admin_user_name"},
        "backdoor_user": {"kind": "attack_created", "label": "A backdoor user the attack creates"},
        "alice": {"kind": "lab_user", "label": "The lab's hijacked user alice.chen", "output": "alice_user_name"},
    },
    "attack_path": [
        {
            "phase": 1,
            "name": "Initial Access & Persistence Establishment",
            "aws_actions": [
                "iam:GetUser",
                "iam:ListAttachedUserPolicies",
                "iam:ListUsers",
                "ses:GetSendQuota",
                "ses:ListIdentities",
                "iam:CreateUser",
                "iam:CreateLoginProfile",
                "iam:CreateAccessKey",
                "iam:AttachUserPolicy",
            ],
            "acting_as": "leaked_admin",
            "aws_resources": {
                "iam:GetUser": "arn:aws:iam::{account_id}:user/{admin_user_name}",
                "iam:ListAttachedUserPolicies": "arn:aws:iam::{account_id}:user/{admin_user_name}",
                "iam:ListUsers": "*",
                "ses:GetSendQuota": "*",
                "ses:ListIdentities": "*",
                "iam:CreateUser": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
                "iam:CreateLoginProfile": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
                "iam:CreateAccessKey": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
                "iam:AttachUserPolicy": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
            },
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
            # ec2:TerminateInstances is omitted although attack.py records it: the
            # instance is terminated as soon as it reaches running, to cap cost. A
            # policy denying it would stop that teardown, not the deployment.
            "aws_actions": [
                "ec2:DescribeRegions",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeAvailabilityZones",
                "ssm:GetParameter",
                "ec2:RunInstances",
                "ec2:DescribeInstanceStatus",
            ],
            "acting_as": "backdoor_user",
            "techniques": [
                {"id": "T1580", "name": "Cloud Infrastructure Discovery"},
                {"id": "T1578.002", "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance"},
                {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
                {"id": "T1496", "name": "Resource Hijacking"},
            ],
        },
        {
            "phase": 3,
            "name": "Persistence Hardening, Collection, Evasion & Phishing Infra",
            # DeleteAccessKey and DeleteUser are the attacker erasing the ses user in
            # step 15, not lab teardown. The teardown calls in the same function run
            # through lab_iam and are excluded, which is why iam:DetachUserPolicy and
            # iam:DeleteLoginProfile do not appear here.
            #
            # Steps 16-17 run as alice. route53domains:RegisterDomain,
            # ses:PutAccountDetails and ses:UpdateAccountSendingEnabled are real
            # calls that alice.chen's inline policy dangerdev-alice-emulation-guard
            # explicitly denies: AccessDenied is the expected, emulated outcome
            # (attempt-level), so the account check reporting them as refused for
            # this lab user is correct. ses:SendEmail is allowed only to
            # *@simulator.amazonses.com from the lab identity (conditions
            # ses:Recipients / ses:FromAddress). The SimulatePrincipalPolicy
            # pre-flight attack.py runs before each guarded call is a lab safety
            # interlock made by lab-infra-admin, not attacker tradecraft, and is
            # excluded like the teardown calls.
            "aws_actions": [
                "iam:CreateUser",
                "iam:CreateAccessKey",
                "iam:ListRoles",
                "iam:GetRole",
                "iam:AttachRolePolicy",
                "sts:AssumeRole",
                "iam:UpdateLoginProfile",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "iam:ListInstanceProfiles",
                "iam:ListGroupsForUser",
                "iam:ListSSHPublicKeys",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "iam:SimulatePrincipalPolicy",
                "iam:UpdateAccessKey",
                "iam:DeleteAccessKey",
                "iam:DeleteUser",
                "route53domains:CheckDomainAvailability",
                "route53domains:GetDomainSuggestions",
                "route53domains:RegisterDomain",
                "ses:GetSendQuota",
                "ses:GetAccount",
                "ses:ListIdentities",
                "ses:VerifyEmailIdentity",
                "ses:SendEmail",
                "ses:PutAccountDetails",
                "ses:UpdateAccountSendingEnabled",
            ],
            "acting_as": {
                "alice": [
                    "route53domains:CheckDomainAvailability",
                    "route53domains:GetDomainSuggestions",
                    "route53domains:RegisterDomain",
                    "ses:GetSendQuota",
                    "ses:GetAccount",
                    "ses:ListIdentities",
                    "ses:VerifyEmailIdentity",
                    "ses:SendEmail",
                    "ses:PutAccountDetails",
                    "ses:UpdateAccountSendingEnabled",
                ],
                "leaked_admin": ["iam:DeleteAccessKey", "iam:DeleteUser"],
                "backdoor_user": ["iam:CreateUser", "iam:CreateAccessKey", "iam:ListRoles", "iam:GetRole", "iam:AttachRolePolicy", "sts:AssumeRole", "iam:UpdateLoginProfile", "s3:ListAllMyBuckets", "s3:ListBucket", "iam:ListInstanceProfiles", "iam:ListGroupsForUser", "iam:ListSSHPublicKeys", "guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings", "iam:SimulatePrincipalPolicy", "iam:UpdateAccessKey", "iam:DeleteAccessKey", "iam:DeleteUser"],
            },
            "aws_resources": {
                # Route 53 Domains has no resource-level permissions.
                "route53domains:CheckDomainAvailability": "*",
                "route53domains:GetDomainSuggestions": "*",
                "route53domains:RegisterDomain": "*",
                "ses:GetSendQuota": "*",
                "ses:GetAccount": "*",
                "ses:ListIdentities": "*",
                "ses:VerifyEmailIdentity": "arn:aws:ses:{region}:{account_id}:identity/emulation-noreply@emulation-lab-noreply.example.com",
                "ses:SendEmail": "arn:aws:ses:{region}:{account_id}:identity/emulation-noreply@emulation-lab-noreply.example.com",
                "ses:PutAccountDetails": "*",
                "ses:UpdateAccountSendingEnabled": "*",
                "iam:DeleteAccessKey": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
                "iam:DeleteUser": "arn:aws:iam::{account_id}:user/DangerDev@protonmail.me",
            },
            "techniques": [
                {"id": "T1036.005", "name": "Masquerading: Match Legitimate Resource Name or Location"},
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
        {"id": "T1578.002", "name": "Modify Cloud Compute Infrastructure: Create Cloud Instance", "tactic": "Defense Evasion", "platform": "AWS EC2",
         "description": "Launch a t2.micro test instance, confirm running, then terminate — the lifecycle test before committing GPU spend (real p3.16xlarge documented-only)."},
        {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "platform": "EC2 / Windows",
         "description": "TCP SYN probe to port 3389 on the public Windows instance, generating a VPC Flow Log ACCEPT record (no interactive RDP)."},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "platform": "EC2 / Windows",
         "description": "Benign CPU-bound workload pre-deployed in EC2 UserData approximating the GPU-cryptomining lifecycle (CloudWatch CPU spike, no real mining)."},
        {"id": "T1036.005", "name": "Masquerading: Match Legitimate Resource Name or Location", "tactic": "Defense Evasion", "platform": "AWS IAM",
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
         "description": "EMULATED (attempt-level) — as hijacked alice.chen: real CheckDomainAvailability and GetDomainSuggestions on a lab-marked, non-brand name (us-east-1), then a real RegisterDomain refused by an explicit IAM Deny. CloudTrail records RegisterDomain with errorCode AccessDenied in us-east-1; no domain is ever purchased and no PayPal lookalike is ever requested."},
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "platform": "AWS SES",
         "description": "EMULATED (attempt-level) — as hijacked alice.chen: SES recon, VerifyEmailIdentity on an unverifiable example.com lab address, and a real SendEmail that IAM permits only to success@simulator.amazonses.com (expected MessageRejected: unverified sender). PutAccountDetails (leave sandbox) and UpdateAccountSendingEnabled are attempted and refused by IAM Deny. SendEmail is a CloudTrail data event, captured by the lab's SES data-event trail."},
    ],

    # ── References (frontend references) ──────────────────────────────────────
    "references": [
        {"icon": ">", "title": "The Curious Case of DangerDev@protonmail.me", "source": "Invictus IR · invictus-ir.com", "type": "REPORT", "color": "cyan", "url": "https://www.invictus-ir.com/nieuws/the-curious-case-of-dangerdev-protonmail-me"},
        {"icon": "#", "title": "MITRE ATT&CK — T1136.003: Create Account: Cloud Account", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple", "url": "https://attack.mitre.org/techniques/T1136/003/"},
        {"icon": "#", "title": "MITRE ATT&CK — T1199: Trusted Relationship", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple", "url": "https://attack.mitre.org/techniques/T1199/"},
        {"icon": "~", "title": "AWS Security Best Practices: Rotate and Restrict Long-Term Access Keys", "source": "AWS Security Blog · aws.amazon.com", "type": "DOCUMENTATION", "color": "orange", "url": "https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/"},
    ],

    # ── Infrastructure and cost metadata ──────────────────────────────────────
    "phase_count": 3,
    "estimated_duration_minutes": 8,
    "estimated_cost_per_hour_usd": 0.05,
    "default_ttl_hours": 4,
    # 65 confirmed via `pulumi preview` (pulumi-aws v7); +2 for the alice.chen
    # emulation-guard inline policy and the SES data-event trail (not yet
    # re-confirmed by preview).
    "total_resources": 68,
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
        {"name": "CloudTrail SES data-event trail (lab identity only, USD 0.10/100k events)", "count": 1, "cost_per_hour_usd": 0.0},
        {"name": "KMS key",                "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "Secrets Manager secret", "count": 1, "cost_per_hour_usd": 0.00055},
        {"name": "S3 buckets",             "count": 3, "cost_per_hour_usd": 0.0},
        {"name": "SNS topic",              "count": 1, "cost_per_hour_usd": 0.0},
    ],
}

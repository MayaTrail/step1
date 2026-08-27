"""MANIFEST for ECScape — cross-task IAM credential hijack in Amazon ECS (EC2 launch type).

Ported from the pipeline atomic/ output (aws.credential-access.ecscape), a Python
re-implementation of naorhaziz/ecscape. schema_version bumped 1 -> 3, top-level
`platform` added and `references` given outbound urls to satisfy the dashboard
contract. Not an atomic technique — stands up a full ECS-on-EC2 cluster with
co-resident victim tasks — so tier "enterprise" / origin "research-poc".
"""

MANIFEST = {
    "schema_version": 3,
    "name": "ecscape",
    "display_name": "ECScape",
    "description": (
        "Cross-task IAM credential hijack in Amazon ECS (EC2 launch type): a "
        "deny-all task impersonates the ECS agent and harvests every other "
        "task's role and execution-role credentials on the same container "
        "instance, breaking task isolation."
    ),
    "tier": "enterprise",
    "platform": "aws",
    "added": "2026-08",
    "services": ["Amazon ECS", "EC2", "AWS IAM", "AWS STS", "Secrets Manager"],
    "readiness": {"type": "none"},
    "origin": "research-poc",
    "origin_label": "RESEARCH POC",
    "tags": ["Credential Access", "Amazon ECS", "EC2", "IMDS"],
    "technique_count": 3,
    "severity": "HIGH",
    "aliases": "aws.credential-access.ecscape",
    "attribution": "Naor Haziz / Sweet Security — privilege-boundary research PoC",
    "active_since": "Research PoC (2025)",
    "targets": "Amazon ECS (EC2 launch type), EC2 instance role, ECS task/execution roles",
    "incidents": ["Sweet Security — ECScape: IAM Privilege Boundaries in Amazon ECS"],
    "attack_path": [
        {
            "phase": 1,
            "name": "Credential Access",
            "techniques": [
                {"id": "T1552.005", "name": "Unsecured Credentials: Cloud Instance Metadata API"},
                {"id": "T1552.007", "name": "Unsecured Credentials: Container API"},
            ],
        },
        {
            "phase": 2,
            "name": "Privilege Escalation",
            "techniques": [
                {"id": "T1134", "name": "Access Token Manipulation"},
            ],
        },
    ],
    "mitre_mappings": [
        {
            "id": "T1552.005",
            "name": "Unsecured Credentials: Cloud Instance Metadata API",
            "tactic": "Credential Access",
            "platform": "AWS ECS",
            "description": (
                "The attacker container reads the EC2 instance role's temporary "
                "credentials from IMDS (169.254.169.254), reachable because the "
                "task runs in host network mode."
            ),
        },
        {
            "id": "T1552.007",
            "name": "Unsecured Credentials: Container API",
            "tactic": "Credential Access",
            "platform": "AWS ECS",
            "description": (
                "Using the stolen instance role, the attacker queries the ECS "
                "agent introspection API (:51678) and ecs:DiscoverPollEndpoint, "
                "then opens a SigV4-signed ACS WebSocket with sendCredentials=true "
                "so the control plane streams the IAM credentials of every other "
                "task on the container instance."
            ),
        },
        {
            "id": "T1134",
            "name": "Access Token Manipulation",
            "tactic": "Privilege Escalation",
            "platform": "AWS ECS",
            "description": (
                "By impersonating the ECS agent (the identity the control plane "
                "trusts to receive pre-assumed task credentials), a deny-all task "
                "obtains the s3-control task role and the secret-execution role — "
                "credentials it could never assume directly via STS."
            ),
        },
    ],
    "references": [
        {
            "icon": ">",
            "title": "ECScape PoC (naorhaziz/ecscape)",
            "source": "GitHub · github.com",
            "type": "REPO",
            "color": "cyan",
            "url": "https://github.com/naorhaziz/ecscape",
        },
        {
            "icon": "#",
            "title": "ECScape — Understanding IAM Privilege Boundaries in Amazon ECS",
            "source": "Sweet Security · sweet.security",
            "type": "REPORT",
            "color": "cyan",
            "url": "https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs",
        },
    ],
    "phase_count": 2,
    "estimated_duration_minutes": 12,
    "estimated_cost_per_hour_usd": 0.03,
    "default_ttl_hours": 2,
    "total_resources": 27,
    "resources": {"ec2_count": 1, "instance_types": ["t3.small"]},
    "resource_costs": [],
}

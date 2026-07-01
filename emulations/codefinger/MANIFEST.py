"""MANIFEST for the Codefinger adversary emulation."""

MANIFEST = {
    "schema_version": 1,

    # ── Identity ─────────────────────────────────────────────────────────────
    "name": "codefinger",
    "display_name": "Codefinger",
    "description": (
        "5-technique AWS S3 ransomware emulation based on the Codefinger group: "
        "anonymous credential harvest from a public Terraform state bucket, "
        "S3 data enumeration, SSE-C re-encryption with attacker-held AES-256 key, "
        "lifecycle auto-delete scheduling (simulated), and version history purge "
        "to eliminate rollback recovery paths."
    ),
    "tier": "enterprise",

    # ── Readiness ─────────────────────────────────────────────────────────────
    "readiness": {"type": "none"},

    # ── UI catalogue metadata ──────────────────────────────────────────────────
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "S3 Ransomware",
        "SSE-C Encryption",
        "Credential Exposure",
        "Data Destruction",
        "Inhibit Recovery",
        "Lifecycle Abuse",
    ],
    "technique_count": 5,
    "severity": "CRITICAL",
    "aliases": "",
    "attribution": "Codefinger — financially motivated S3 ransomware group",
    "active_since": "Documented by Halcyon (2025)",
    "targets": "AWS accounts with exposed long-term IAM access keys and S3 write access",
    "incidents": [
        "Abusing AWS Native Services: Ransomware Encrypting S3 Buckets with SSE-C (Halcyon)",
    ],

    # ── Kill-chain phases ──────────────────────────────────────────────────────
    "attack_path": [
        {
            "phase": 1,
            "name": "Initial Access: Credential Harvesting",
            "techniques": [
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
            ],
        },
        {
            "phase": 2,
            "name": "Collection: S3 Object Enumeration",
            "techniques": [
                {"id": "T1530", "name": "Data from Cloud Storage"},
            ],
        },
        {
            "phase": 3,
            "name": "Impact: SSE-C Encryption (Simulated)",
            "techniques": [
                {"id": "T1486", "name": "Data Encrypted for Impact"},
            ],
        },
        {
            "phase": 4,
            "name": "Impact: Lifecycle Auto-Delete (Simulated)",
            "techniques": [
                {"id": "T1485", "name": "Data Destruction"},
            ],
        },
        {
            "phase": 5,
            "name": "Impact: Version History Purge",
            "techniques": [
                {"id": "T1490", "name": "Inhibit System Recovery"},
            ],
        },
    ],

    # ── Full MITRE mappings ────────────────────────────────────────────────────
    "mitre_mappings": [
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "tactic": "Initial Access",
            "platform": "AWS IAM",
            "description": (
                "Anonymous GetObject on a public Terraform state bucket retrieves "
                "an exposed long-term IAM access key pair; validated via "
                "GetCallerIdentity + ListBuckets."
            ),
        },
        {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "tactic": "Collection",
            "platform": "AWS S3",
            "description": (
                "Paginated ListObjectsV2 + HeadObject on the target bucket enumerates "
                "all objects and metadata; one GetObject per prefix confirms data-plane read access."
            ),
        },
        {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "platform": "AWS S3",
            "description": (
                "Runtime AES-256 SSE-C key generated; each synthetic object re-uploaded "
                "via PutObject with SSE-C headers (GetObject -> PutObject+SSE-C). "
                "CloudTrail logs only the HMAC of the key — data is irrecoverable without "
                "the attacker-held key. Ransom note dropped per prefix."
            ),
        },
        {
            "id": "T1485",
            "name": "Data Destruction",
            "tactic": "Impact",
            "platform": "AWS S3",
            "description": (
                "DeleteObject removes original keys, then a 1-day lifecycle expiry rule "
                "(PutBucketLifecycleConfiguration) is applied and immediately removed "
                "after CloudTrail capture to prevent real deletion of synthetic objects."
            ),
        },
        {
            "id": "T1490",
            "name": "Inhibit System Recovery",
            "tactic": "Impact",
            "platform": "AWS S3",
            "description": (
                "PutBucketVersioning suspends versioning, then all version entries and "
                "delete markers are bulk-purged via DeleteObjects to eliminate version "
                "rollback as an IR recovery path."
            ),
        },
    ],

    # ── References ────────────────────────────────────────────────────────────
    "references": [
        {
            "icon": ">",
            "title": "Abusing AWS Native Services: Ransomware Encrypting S3 Buckets with SSE-C",
            "source": "Halcyon · halcyon.ai",
            "type": "REPORT",
            "color": "cyan",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1486: Data Encrypted for Impact",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "#",
            "title": "MITRE ATT&CK — T1490: Inhibit System Recovery",
            "source": "MITRE ATT&CK · mitre.org",
            "type": "MITRE",
            "color": "purple",
        },
        {
            "icon": "~",
            "title": "AWS S3 SSE-C Encryption Documentation",
            "source": "AWS Documentation · docs.aws.amazon.com",
            "type": "DOCUMENTATION",
            "color": "orange",
        },
    ],

    # ── Infrastructure & cost ─────────────────────────────────────────────────
    "phase_count": 5,
    "estimated_duration_minutes": 30,
    "estimated_cost_per_hour_usd": 0.0014,
    "default_ttl_hours": 4,
    "total_resources": 13,
    "resources": {
        "ec2_count": 0,
        "instance_types": [],
        "uses_lambda": False,
        "uses_secrets_manager": False,
        "uses_cloudtrail": True,
        "uses_guardduty": False,
    },
    "resource_costs": [
        {"name": "CloudTrail trail",       "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "S3 buckets (bait/target/ct-log)", "count": 3, "cost_per_hour_usd": 0.0},
        {"name": "IAM user + access key",  "count": 1, "cost_per_hour_usd": 0.0},
    ],
}

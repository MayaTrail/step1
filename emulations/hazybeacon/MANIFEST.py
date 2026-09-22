"""
MANIFEST for the HazyBeacon enterprise emulation.

Ported from the apt_pipeline emulation_output/20260819_121014_HAZYBEACON run
(source: Qualys Threat Research, "HazyBeacon: AWS Lambda Function URL C2 abuse",
2026-06-02). Live-validated end-to-end against a real AWS account
(940482414561, us-east-1) on 2026-09-20: pulumi up (35 resources) -> attack.run()
-> pulumi destroy, zero orphans. See apt_pipeline/HAZYBEACON_LIVE_VALIDATION.md
for the full validation report.

schema_version 3 — carries the full dashboard contract (apps/metrics/contracts.py):
top-level `platform`, `added`, and `services` (Platform Overview "Attack Surface
Coverage"). The pipeline's auto-synthesized manifest shipped schema_version 1
with no `platform` key and truncated mitre_mappings descriptions — both fixed
here (same contract-violation class ECScape hit during the atomic port).
"""

MANIFEST = {
    "schema_version": 3,

    # -- Identity ----------------------------------------------------------
    "name": "hazybeacon",
    "display_name": "HazyBeacon",
    "description": (
        "10-step AWS adversary emulation based on the real HazyBeacon (CL-STA-1020) "
        "campaign: a leaked developer IAM key seeds cloud identity and resource "
        "discovery, then the attacker deploys a public, unauthenticated Lambda "
        "Function URL as a serverless C2 relay, applies masquerade tags, and "
        "simulates exfiltration of sensitive S3 objects over the relay channel."
    ),
    "tier": "enterprise",

    # Primary platform this emulation targets — drives the Platform Coverage widget.
    "platform": "aws",

    # Month this emulation was added ("YYYY-MM").
    "added": "2026-09",

    # Cloud services this emulation exercises — drives the Platform Overview
    # "Attack Surface Coverage" section (apps/metrics/aggregations.py::_SERVICE_CATEGORY).
    "services": ["IAM", "STS", "Lambda", "S3", "Secrets Manager", "CloudTrail", "EC2"],

    # -- Readiness (compatibility-critical) ---------------------------------
    # No vulnerable web service — the Lambda C2 relay is created and torn down
    # entirely inside attack.py, not by infra/__main__.py. Straight to
    # READY_FOR_ATTACK after deploy.
    "readiness": {"type": "none"},

    # -- UI catalogue metadata -----------------------------------------------
    "origin": "unknown",
    "origin_label": "APT EMULATION",
    "tags": [
        "Leaked Credentials",
        "Serverless C2",
        "Lambda Function URL",
        "Cloud Discovery",
        "Defense Evasion",
        "Data Exfiltration",
    ],
    "technique_count": 10,
    "severity": "HIGH",
    "aliases": "CL-STA-1020",
    "attribution": "HazyBeacon (unattributed, espionage-motivated)",
    "active_since": "Documented by Qualys Threat Research (2026)",
    "targets": "AWS accounts with leaked developer IAM access keys and permissive Lambda deployment rights",
    "incidents": [
        "HazyBeacon: AWS Lambda Function URL C2 Abuse (Qualys Threat Research)",
    ],

    # -- Kill-chain phases (frontend attackPath) -----------------------------
    "attack_path": [
        {
            "phase": 1,
            "name": "Reconnaissance & Credential Theft",
            "techniques": [
                {"id": "T1598.003", "name": "Phishing for Information: Spearphishing Link"},
                {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
            ],
        },
        {
            "phase": 2,
            "name": "Initial Access & Discovery",
            "techniques": [
                {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
                {"id": "T1087.004", "name": "Account Discovery: Cloud Account"},
                {"id": "T1069.003", "name": "Permission Groups Discovery: Cloud Groups"},
            ],
        },
        {
            "phase": 3,
            "name": "Execution & Defense Evasion",
            "techniques": [
                {"id": "T1648", "name": "Serverless Execution"},
                {"id": "T1564", "name": "Hide Artifacts"},
            ],
        },
        {
            "phase": 4,
            "name": "Command and Control & Exfiltration",
            "techniques": [
                {"id": "T1102", "name": "Web Service"},
                {"id": "T1090", "name": "Proxy"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            ],
        },
    ],

    # -- Full MITRE ATT&CK mappings (frontend mitreMappings) -----------------
    "mitre_mappings": [
        {"id": "T1598.003", "name": "Phishing for Information: Spearphishing Link", "tactic": "Reconnaissance", "platform": "Email",
         "description": "DOCUMENTED ONLY — HazyBeacon delivers a spearphishing link to a target developer, leading to backdoor installation on the developer workstation. The emulation begins after this step: credentials are pre-planted via EC2 UserData rather than a real phishing delivery."},
        {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "platform": "EC2 / Filesystem",
         "description": "The HazyBeacon backdoor reads AWS credentials from ~/.aws/credentials and a cached terraform.tfstate on the compromised developer workstation. Simulated via EC2 UserData — attack.py receives the harvested credentials as Pulumi stack outputs and never touches the EC2 filesystem directly."},
        {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access", "platform": "AWS IAM / STS",
         "description": "Use the harvested static IAM access key to authenticate to AWS and validate credential validity. GetCallerIdentity confirms the account ID and user ARN; GetUser retrieves IAM identity metadata — the first control-plane API calls made with the stolen credentials, establishing the attack session."},
        {"id": "T1087.004", "name": "Account Discovery: Cloud Account", "tactic": "Discovery", "platform": "AWS IAM / S3 / Secrets Manager",
         "description": "Enumerate IAM identities, account summary, S3 buckets, and SecretsManager secrets to map the victim AWS environment. Discovers the decoy admin honey-user, the exfil-target S3 bucket, and a fake high-value database-credentials secret; DescribeSecret confirms it as a worthwhile exfiltration target."},
        {"id": "T1069.003", "name": "Permission Groups Discovery: Cloud Groups", "tactic": "Discovery", "platform": "AWS IAM",
         "description": "Enumerate IAM groups and policy attachments to map permission boundaries and identify escalation paths. HazyBeacon reads group memberships and inline/managed policy documents to confirm the compromised identity has Lambda deployment rights before proceeding to T1648."},
        {"id": "T1648", "name": "Serverless Execution", "tactic": "Execution", "platform": "AWS Lambda",
         "description": "Deploy a Lambda function (BackupHandler) with a benign description to serve as the HazyBeacon C2 relay. Function code is a simulated echo handler packaged as an in-memory ZIP (no disk write). A Lambda Function URL is created with AuthType:NONE to expose a public HTTPS endpoint; iam:PassRole is exercised to attach the execution role."},
        {"id": "T1564", "name": "Hide Artifacts", "tactic": "Defense Evasion", "platform": "AWS Lambda",
         "description": "Apply innocuous organizational-style resource tags (e.g. ManagedBy:terraform) to the BackupHandler Lambda function to help it blend into legitimate IaC-managed infrastructure during visual review, reducing the likelihood of the function being flagged as anomalous in a cost or inventory audit."},
        {"id": "T1102", "name": "Web Service", "tactic": "Command and Control", "platform": "AWS Lambda Function URL",
         "description": "Simulate HazyBeacon beaconing to the deployed BackupHandler Lambda Function URL to establish a C2 channel over HTTPS. Per operational constraint, only synthetic beacon metadata is transmitted and the Lambda echo returns a static acknowledgement — no real C2 payload is relayed. Round-trip latency and response status are logged for detection engineering."},
        {"id": "T1090", "name": "Proxy", "tactic": "Command and Control", "platform": "AWS Lambda Function URL",
         "description": "DOCUMENTED ONLY — HazyBeacon uses the deployed BackupHandler Lambda function as a proxy, forwarding C2 traffic from the compromised host to attacker-controlled backend infrastructure and obscuring the true C2 origin behind a legitimate AWS domain. Not implemented in attack.py: the static echo handler deployed in T1648 represents the proxy's presence without forwarding live traffic."},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "platform": "AWS S3",
         "description": "Simulate exfiltration of sensitive data from the exfil-target S3 bucket via the BackupHandler Lambda C2 relay. attack.py performs read-only S3 enumeration (list_objects_v2, head_object on a bait terraform.tfstate) to identify exfiltration targets, logs what would be transmitted, then simulates (does not perform) the transfer over the relay."},
    ],

    # -- References (frontend references) ------------------------------------
    "references": [
        {"icon": ">", "title": "HazyBeacon: AWS Lambda Function URL C2 Abuse", "source": "Qualys Threat Research · blog.qualys.com", "type": "REPORT", "color": "cyan",
         "url": "https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse"},
        {"icon": "#", "title": "MITRE ATT&CK — T1648: Serverless Execution", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple",
         "url": "https://attack.mitre.org/techniques/T1648/"},
        {"icon": "#", "title": "MITRE ATT&CK — T1102: Web Service", "source": "MITRE ATT&CK · mitre.org", "type": "MITRE", "color": "purple",
         "url": "https://attack.mitre.org/techniques/T1102/"},
    ],

    # -- Infrastructure and cost metadata -------------------------------------
    "phase_count": 4,
    "estimated_duration_minutes": 10,
    "estimated_cost_per_hour_usd": 0.0131,
    "default_ttl_hours": 4,
    "total_resources": 35,  # confirmed via live `pulumi up`/`pulumi destroy` (2026-09-20)
    "resources": {
        "ec2_count": 1,
        "instance_types": ["t3.micro"],
        "uses_lambda": True,
        "uses_secrets_manager": True,
        "uses_cloudtrail": True,
    },
    "resource_costs": [
        {"name": "EC2 t3.micro (Linux)",     "count": 1, "cost_per_hour_usd": 0.0104},
        {"name": "CloudTrail trail",         "count": 1, "cost_per_hour_usd": 0.0014},
        {"name": "VPC Flow Log",             "count": 1, "cost_per_hour_usd": 0.0007},
        {"name": "Secrets Manager secret",   "count": 1, "cost_per_hour_usd": 0.00056},
        {"name": "S3 buckets",               "count": 2, "cost_per_hour_usd": 0.00006},
        {"name": "Lambda (attack-time only)", "count": 1, "cost_per_hour_usd": 0.0},
    ],

    # -- Related guardrails (guardrails/ SCP/RCP library) ---------------------
    # Hand-curated, not derived: each id is a catalogue slug from
    # guardrails.registry.discover() (backend/apps/guardrails). "blocks" means
    # the control denies the exact API call the attack chain depends on;
    # "mitigates" reduces the blast radius or a precondition without stopping
    # the chain outright; "hardens" is a defense-in-depth control PLAYBOOK.md
    # recommends but that this specific emulated chain doesn't trip over.
    "related_guardrails": [
        {
            "id": "deny-modification-to-lambda-url-config",
            "relevance": "blocks",
            "note": "Denies lambda:CreateFunctionUrlConfig/UpdateFunctionUrlConfig unless "
                    "FunctionUrlAuthType=AWS_IAM — would have rejected the T1648 step that "
                    "creates the AuthType:NONE public C2 endpoint outright.",
        },
        {
            "id": "require-mfa-for-sensitive-iam-operations",
            "relevance": "mitigates",
            "note": "Denies iam:CreateAccessKey (among other sensitive IAM ops) without MFA. "
                    "Doesn't stop this emulation, which starts from an already-leaked static "
                    "key, but blocks the attacker minting a fresh key as a fallback/backdoor.",
        },
        {
            "id": "enforce-imdsv2-on-ec2-instances",
            "relevance": "hardens",
            "note": "PLAYBOOK.md's real-world 'what would have prevented this' guidance. Not "
                    "exercised by this emulation (the leaked credential is planted via EC2 "
                    "UserData, not read from IMDS by attack.py), but closes the IMDS-theft path "
                    "real HazyBeacon intrusions have also used.",
        },
    ],
}

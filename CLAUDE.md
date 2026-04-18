# MayaTrail

Cloud APT emulation platform for security teams. Website: mayatrail.tech

## What This Project Does

1. APT Emulation in Cloud (AWS)
2. Individual attack path emulation
3. IR playbooks for each emulated attack
4. Detection engineering rules (Sigma) based on emulated attacks
5. Graphical representation of attack emulation
6. MITRE ATT&CK mappings for each attack technique
7. Guardrails to help organizations block threat actors at the org level

## Directory Structure

```
MayaTrail/
├── CLAUDE.md
├── Maya Playbook Framework  (1).pdf    # Master playbook template
├── PB-AWS-S3-DATA-01 (1).pdf           # Example playbook (S3 exfil)
├── MayaTrail Research.pdf
├── playbooks/                           # Playbook library
│   ├── index.json                       # Machine-readable registry
│   └── aws/                             # Organized by cloud/service
│       ├── iam/
│       ├── sts/
│       ├── s3/
│       └── kms/
├── .claude/skills/write-playbook/       # Playbook authoring skill
│   ├── SKILL.md
│   └── example-playbook.md
└── step1-dev0.2-aws-pulumi/             # Backend
    ├── Dockerfile
    ├── README.md
    ├── frontend/                        # React 18 (CDN, no build tools)
    └── src/
        ├── __main__.py                  # Pulumi infra provisioning (MayaTrailInfra)
        ├── runner.py                    # CLI orchestration (deploy, destroy, emulate)
        ├── cleanup.py
        ├── entrypoint.sh               # Docker entrypoint
        ├── Pulumi.yaml
        ├── requirements.txt
        └── simulations/                 # Attack emulation modules
            ├── attach_role_policy.py    # Privilege escalation via role assumption
            ├── enumeration.py           # Service/permission discovery
            ├── s3_initial_access.py     # S3 data exfiltration + ransom
            ├── s3_kms_encryption.py     # KMS ransomware simulation
            ├── eventual_consistency.py  # AWS consistency window exploitation
            └── logger.py               # Centralized logging
```

## Tech Stack

- **Backend:** Python 3, Pulumi 3.207, boto3 1.41.2
- **Frontend:** React 18 via CDN (no build system)
- **Cloud:** AWS (default region: ap-south-1)
- **Infra:** Docker, S3-backed Pulumi state
- **Detection Format:** Sigma

## Existing Attack Simulations

| Simulation File | Attack Type | MITRE Technique |
|---|---|---|
| `attach_role_policy.py` | Privilege Escalation via IAM Role Policy Attachment | T1098 (Account Manipulation) |
| `enumeration.py` | Service & Permission Discovery via IAM PolicySimulator | T1580 (Cloud Infrastructure Discovery) |
| `s3_initial_access.py` | S3 Data Exfiltration, Object Deletion, Ransom Upload | T1537 (Transfer Data to Cloud Account) |
| `s3_kms_encryption.py` | KMS Ransomware - External Key, Encrypt, Delete Key Material | T1486 (Data Encrypted for Impact) |
| `eventual_consistency.py` | Exploit AWS Eventual Consistency to Delete Policies/Roles | T1070 (Indicator Removal) |

## Playbook & Detection Engineering Rules

These rules apply every time a playbook or detection is written:

- Every playbook MUST follow the Maya Playbook Framework (5 sections: Governance, Triage, Containment, Investigation, Recovery)
- Playbook ID format: `PB-[Cloud]-[Service]-[APICall]-[NN]` (e.g., `PB-AWS-STS-AssumeRole-01`)
- Generate one playbook per distinct AWS API call in the simulation, not one per simulation
- Each per-API-call playbook is a standalone, reusable module — it must be self-contained and not depend on the context of any specific simulation
- Playbooks MUST be written to `playbooks/<cloud>/<service>/` (e.g., `playbooks/aws/iam/`)
- Deduplicate by checking `playbooks/index.json` for existing `api_call` entries before generating
- After generating playbooks, update `playbooks/index.json` with new entries
- Playbooks are derived from API calls found in simulations but are reusable across simulations
- Every containment action MUST have an exact rollback command
- Containment MUST be graduated: L1 (low impact) → L2 (service degradation) → L3 (nuclear option)
- Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`
- Detection rules MUST be in Sigma format
- All response and containment steps MUST include executable CLI commands (AWS CLI, etc.)
- MITRE ATT&CK technique mapping is mandatory for every playbook
- Severity matrix is mandatory with concrete, measurable conditions (not vague)
- Use `/write-playbook <simulation-name>` to author playbooks
- Playbook modules (`playbooks/*.py`) must NOT use `os.environ.update()` for credential swaps — use explicit `boto3.Session()` objects instead

## Backend Commands

```bash
# Deploy infrastructure
cd step1-dev0.2-aws-pulumi/src && pulumi up

# Destroy infrastructure
cd step1-dev0.2-aws-pulumi/src && pulumi destroy

# Run emulations
cd step1-dev0.2-aws-pulumi/src && python runner.py --emulate

# Docker build (backend)
cd step1-dev0.2-aws-pulumi/src && docker build -t mayatrail .

# Docker build (frontend)
cd step1-dev0.2-aws-pulumi && docker build -t mayatrail-frontend .
```

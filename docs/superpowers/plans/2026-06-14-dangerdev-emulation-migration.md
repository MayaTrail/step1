# DANGERDEV Emulation Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the raw pipeline DANGERDEV output into a backend-compatible `emulations/dangerdev/` package on MayaTrail/step1 `main`, plus the one backend generalization (manifest-driven readiness) and worker dependency (`pulumi-tls`) it needs, then prove it with a paired live deploy → attack → destroy.

**Architecture:** Three work areas — (1) the `emulations/dangerdev/` package (MANIFEST + attack + infra + playbook + detections), (2) a back-compatible readiness change in `apps/emulations/`, (3) `backend/requirements.txt` gaining `pulumi-tls`. The infra is ported to the worker's real runtime, **pulumi-aws 7.11.1**. Names stay static for fidelity (safe because the backend deploys per-user-account + enforces one active stack per user).

**Tech Stack:** Python 3, Pulumi (`pulumi==3.207.0`, `pulumi-aws==7.11.1`, `pulumi-tls` 5.x), boto3, Django 5 + Celery (backend), Django test runner.

**Source of truth:** `docs/superpowers/specs/2026-06-14-dangerdev-emulation-migration-design.md` (gitignored).

**Paths:**
- Pipeline source (read-only): `C:\Users\Ayush\Documents\apt\apt\apt_pipeline\apt_pipeline\emulation_output\20260422_111749_DANGERDEV\`
- Backend repo (all writes): `C:\Users\Ayush\Documents\mayatrail\step1\` (referred to below as `<REPO>`)

**Git note:** Everything lands in MayaTrail/step1 `main`. **Confirm branch + commit message with the user before any `git commit`/`push`** (standing rule). Commit steps below are checkpoints; pause for confirmation at each.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `emulations/dangerdev/__init__.py` | Empty package marker |
| `emulations/dangerdev/MANIFEST.py` | Catalogue metadata dict (+ `readiness: none`) |
| `emulations/dangerdev/attack.py` | `run(outputs, region)` attack chain (17 steps) |
| `emulations/dangerdev/PLAYBOOK.md` | Sanitized IR guide |
| `emulations/dangerdev/infra/__init__.py` | Empty marker |
| `emulations/dangerdev/infra/Pulumi.yaml` | Pulumi project (`mayatrail-dangerdev`, plain python) |
| `emulations/dangerdev/infra/requirements.txt` | Dev-reference deps (v7) |
| `emulations/dangerdev/infra/__main__.py` | Pulumi program (v7-ported, no auto-trigger) |
| `emulations/dangerdev/detections/*` | 15 KQL + Sigma + notes (verbatim copy) |
| `apps/emulations/readiness.py` | **New** pure helper: resolve readiness from manifest |
| `apps/emulations/tests/__init__.py`, `tests/test_readiness.py` | **New** unit tests for the helper |
| `apps/emulations/tasks.py` | Modified: deploy branch + generalized poll |
| `emulations/scarleteel/MANIFEST.py` | Modified: explicit default `readiness` (no behavior change) |
| `backend/requirements.txt` | Modified: add `pulumi-tls` |

---

## Phase A — `emulations/dangerdev/` package (static-validatable, no AWS)

### Task A1: Scaffold package + copy verbatim assets

**Files:**
- Create: `<REPO>/emulations/dangerdev/__init__.py` (empty)
- Create: `<REPO>/emulations/dangerdev/infra/__init__.py` (empty)
- Copy: pipeline `detections/` → `<REPO>/emulations/dangerdev/detections/`

- [ ] **Step 1: Create the package dirs + empty markers**

```powershell
$src = "C:\Users\Ayush\Documents\apt\apt\apt_pipeline\apt_pipeline\emulation_output\20260422_111749_DANGERDEV"
$dst = "C:\Users\Ayush\Documents\mayatrail\step1\emulations\dangerdev"
New-Item -ItemType Directory -Force "$dst\infra" | Out-Null
New-Item -ItemType File -Force "$dst\__init__.py" | Out-Null
New-Item -ItemType File -Force "$dst\infra\__init__.py" | Out-Null
```

- [ ] **Step 2: Copy detections verbatim**

```powershell
Copy-Item -Recurse -Force "$src\detections" "$dst\detections"
Get-ChildItem "$dst\detections" | Measure-Object   # expect 32 files (15 kql + 15 sigma + 2 notes)
```

- [ ] **Step 3: Verify layout**

Run:
```powershell
Get-ChildItem "C:\Users\Ayush\Documents\mayatrail\step1\emulations\dangerdev" -Recurse | Select-Object FullName
```
Expected: `__init__.py`, `infra/__init__.py`, `detections/` populated.

### Task A2: `infra/Pulumi.yaml` + `infra/requirements.txt`

**Files:**
- Create: `<REPO>/emulations/dangerdev/infra/Pulumi.yaml`
- Create: `<REPO>/emulations/dangerdev/infra/requirements.txt`

- [ ] **Step 1: Write `Pulumi.yaml`**

```yaml
name: mayatrail-dangerdev
runtime: python
description: DangerDev APT emulation — AWS IAM abuse, cryptomining recon, phishing infra.
```

- [ ] **Step 2: Write `requirements.txt`** (dev reference; worker uses `backend/requirements.txt`)

```
pulumi>=3.0.0,<4.0.0
pulumi-aws>=7.0.0,<8.0.0
pulumi-tls>=5.0.0,<6.0.0
```

### Task A3: Port `infra/__main__.py` (structural edits + v7 S3)

**Files:**
- Create: `<REPO>/emulations/dangerdev/infra/__main__.py` (start as a copy of the pipeline file, then edit)

- [ ] **Step 1: Copy the pipeline `__main__.py`**

```powershell
Copy-Item -Force "$src\infra\__main__.py" "$dst\infra\__main__.py"
```

- [ ] **Step 2: Header — drop the auto-trigger imports**

Replace:
```python
import json
import os
import subprocess

import pulumi
import pulumi_aws as aws
import pulumi_tls as tls
```
with:
```python
import json

import pulumi
import pulumi_aws as aws
import pulumi_tls as tls
```

- [ ] **Step 3: Standardize the MayaTrail tag**

In the `TAGS` dict, change `"MayaTrail": "true",` to `"MayaTrail": "dangerdev",`.

- [ ] **Step 4: Region-derive the subnet AZ (Gap D)**

In the `public_subnet` resource, replace `availability_zone="us-east-1a",` with `availability_zone=f"{region}a",`.

- [ ] **Step 5: v7 port — `log_bucket` (Gap C)**

Replace the `log_bucket = aws.s3.Bucket(...)` block (the one with inline
`server_side_encryption_configuration`/`versioning`/`lifecycle_rules`) with:
```python
log_bucket = aws.s3.BucketV2(
    "dangerdev-log-bucket",
    bucket=f"dangerdev-lab-logs-{account_id}",
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "dangerdev-log-bucket-sse",
    bucket=log_bucket.id,
    rules=[aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="aws:kms",
        ),
    )],
)

aws.s3.BucketVersioningV2(
    "dangerdev-log-bucket-versioning",
    bucket=log_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketLifecycleConfigurationV2(
    "dangerdev-log-bucket-lifecycle",
    bucket=log_bucket.id,
    rules=[aws.s3.BucketLifecycleConfigurationV2RuleArgs(
        id="expire-90d",
        status="Enabled",
        filter=aws.s3.BucketLifecycleConfigurationV2RuleFilterArgs(prefix=""),
        expiration=aws.s3.BucketLifecycleConfigurationV2RuleExpirationArgs(days=90),
    )],
)
```

- [ ] **Step 6: v7 port — `leaked_creds_bucket`**

Replace the `leaked_creds_bucket = aws.s3.Bucket(...)` block (inline `versioning` +
`logging`) with:
```python
leaked_creds_bucket = aws.s3.BucketV2(
    "dangerdev-leaked-creds-bucket",
    bucket=f"dangerdev-infra-state-{account_id}",
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketVersioningV2(
    "dangerdev-leaked-creds-bucket-versioning",
    bucket=leaked_creds_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketLoggingV2(
    "dangerdev-leaked-creds-bucket-logging",
    bucket=leaked_creds_bucket.id,
    target_bucket=log_bucket.id,
    target_prefix="s3-access/",
)
```

- [ ] **Step 7: v7 port — `sensitive_bucket`**

Replace the `sensitive_bucket = aws.s3.Bucket(...)` block (inline SSE AES256 +
`versioning` + `logging`) with:
```python
sensitive_bucket = aws.s3.BucketV2(
    "dangerdev-sensitive-s3-bucket",
    bucket=f"dangerdev-prod-data-archive-{account_id}",
    force_destroy=True,
    tags=TAGS,
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "dangerdev-sensitive-bucket-sse",
    bucket=sensitive_bucket.id,
    rules=[aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
        apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
            sse_algorithm="AES256",
        ),
    )],
)

aws.s3.BucketVersioningV2(
    "dangerdev-sensitive-bucket-versioning",
    bucket=sensitive_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
)

aws.s3.BucketLoggingV2(
    "dangerdev-sensitive-bucket-logging",
    bucket=sensitive_bucket.id,
    target_bucket=log_bucket.id,
    target_prefix="s3-access/",
)
```

- [ ] **Step 8: v7 port — bucket objects → `BucketObjectv2`**

Change `aws.s3.BucketObject(` to `aws.s3.BucketObjectv2(` in both places:
the `dangerdev-tfstate-object` resource and the `dangerdev-sensitive-obj-*`
resource inside the `_bait_objects` loop.

- [ ] **Step 9: Remove the auto-trigger machinery**

Delete the entire `def _trigger_attack(...)` function, the
`# AUTO-TRIGGER DISABLED ...` comment block, and the commented-out
`pulumi.Output.all(...).apply(lambda args: _trigger_attack(*args))` block.
Keep everything from `# Stack exports` onward (the `pulumi.export(...)` lines).

- [ ] **Step 10: Byte-compile to catch syntax errors**

Run (from `<REPO>`):
```powershell
python -m py_compile emulations\dangerdev\infra\__main__.py
```
Expected: no output (success). If `SyntaxError`, fix and re-run.

- [ ] **Step 11: Confirm only the three third-party imports remain**

Run:
```powershell
Select-String -Path "emulations\dangerdev\infra\__main__.py" -Pattern "^import |^from " 
```
Expected: only `import json`, `import pulumi`, `import pulumi_aws as aws`,
`import pulumi_tls as tls`. (No `os`, no `subprocess`.)

### Task A4: Synthesize `MANIFEST.py`

**Files:**
- Create: `<REPO>/emulations/dangerdev/MANIFEST.py`

- [ ] **Step 1: Write the MANIFEST** (descriptions sourced from `attack.py` step comments + `phase0b_metadata.json`)

```python
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
         "description": "Delete the ses masquerade user and the DangerDev@protonmail.me backdoor (deletions are themselves CloudTrail indicators)."},
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
    "total_resources": 52,  # refine from `pulumi preview` in Task D
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
```

- [ ] **Step 2: Verify it imports and has the required keys**

Run (from `<REPO>`):
```powershell
python -c "import sys; sys.path.insert(0,'.'); from emulations.dangerdev.MANIFEST import MANIFEST as m; req={'name','display_name','description','tier'}; assert req <= set(m), req - set(m); assert m['readiness']=={'type':'none'}; print('OK', m['name'], 'phases', m['phase_count'], 'techniques', m['technique_count'])"
```
Expected: `OK dangerdev phases 3 techniques 17`

### Task A5: Port `attack.py` to `run(outputs, region)`

**Files:**
- Create: `<REPO>/emulations/dangerdev/attack.py` (copy of pipeline `emulation_scripts/attack.py`, then edit)

Keep all 17 steps, the `CredentialStore`, `_events`, masquerade logic, and the
static name lookups **verbatim**. Edit only the boundary.

- [ ] **Step 1: Copy the pipeline attack script**

```powershell
Copy-Item -Force "$src\emulation_scripts\attack.py" "$dst\attack.py"
```

- [ ] **Step 2: Header — imports**

Replace:
```python
import sys
import time
import random
import json
import socket
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
```
with:
```python
import json
import logging
import random
import socket
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
```

- [ ] **Step 3: Region-aware session/client helpers**

Replace:
```python
def make_session(key_id: str, secret: str, region: str = "us-east-1") -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )


def boto_client(creds: CredentialStore, service: str,
                cred_id: str = None, region: str = "us-east-1", **kwargs):
    return creds.get(cred_id).client(service, region_name=region, **kwargs)
```
with:
```python
def make_session(key_id: str, secret: str, region: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
    )


def boto_client(creds: CredentialStore, service: str,
                cred_id: str = None, **kwargs):
    # Region is inherited from the session (created with the run() region).
    return creds.get(cred_id).client(service, **kwargs)
```

- [ ] **Step 4: Thread `region` through the phase signatures**

- `def phase1(creds: CredentialStore, account_id: str) -> str:` → `def phase1(creds: CredentialStore, account_id: str, region: str) -> str:`
- `def phase2(creds: CredentialStore, account_id: str):` → `def phase2(creds: CredentialStore, account_id: str, region: str):`
- `def phase3(creds: CredentialStore, account_id: str):` → `def phase3(creds: CredentialStore, account_id: str, region: str):`

- [ ] **Step 5: Remove every literal region argument (sessions now carry region)**

In all of `phase1/phase2/phase3`:
- Delete every `region="us-east-1"` argument from `boto_client(...)` calls (e.g. `boto_client(creds, "ses", "leaked_admin_session", region="us-east-1")` → `boto_client(creds, "ses", "leaked_admin_session")`).
- Change every direct `.client("<svc>", region_name="us-east-1")` to `.client("<svc>")` (inherits session region) — affects the GuardDuty client and the alice SES client.
- Append `, region` to every `make_session(...)` call so the session is built in the run region: the `dangerdev_session` (Step 4 phase1), `ses_masquerade_session` and `alice_hijacked_session` (phase3), and both cleanup sessions.

- [ ] **Step 6: Step 15 self-cleanup — use the leaked-admin session, not env keys**

Replace the operator-key lookup + session creation:
```python
    lab_op_key_id = os.environ.get("LAB_OPERATOR_KEY_ID")
    lab_op_secret = os.environ.get("LAB_OPERATOR_SECRET_KEY")

    if not lab_op_key_id or not lab_op_secret:
        print_err("LAB_OPERATOR_KEY_ID / LAB_OPERATOR_SECRET_KEY not set")
        print_err("Manual cleanup required: DetachUserPolicy, DeleteAccessKey, DeleteLoginProfile, DeleteUser for DangerDev@protonmail.me")
    else:
        lab_iam = make_session(lab_op_key_id, lab_op_secret).client("iam", region_name="us-east-1")
```
with:
```python
    # lab-infra-admin (Administrator, a different principal than the backdoor
    # user) performs the self-cleanup deletions the pivoted session cannot.
    if creds.has("leaked_admin_session"):
        lab_iam = creds.get("leaked_admin_session").client("iam")
    else:
        lab_iam = None

    if lab_iam is None:
        print_err("leaked_admin_session unavailable — manual cleanup of DangerDev@protonmail.me required")
    else:
```
(Keep the existing indented `try/except` cleanup body under the new `else:`.)

- [ ] **Step 7: Post-17 cleanup — same swap**

Replace:
```python
    lab_op_key_id = os.environ.get("LAB_OPERATOR_KEY_ID")
    lab_op_secret = os.environ.get("LAB_OPERATOR_SECRET_KEY")
    alice_hijacked_meta = creds.meta("alice_hijacked_session")
    alice_hijacked_key_id = alice_hijacked_meta.get("key_id")
    if alice_hijacked_key_id and lab_op_key_id and lab_op_secret:
        op_delay(1, 2)
        try:
            lab_cleanup_iam = make_session(lab_op_key_id, lab_op_secret).client("iam", region_name="us-east-1")
```
with:
```python
    alice_hijacked_meta = creds.meta("alice_hijacked_session")
    alice_hijacked_key_id = alice_hijacked_meta.get("key_id")
    if alice_hijacked_key_id and creds.has("leaked_admin_session"):
        op_delay(1, 2)
        try:
            lab_cleanup_iam = creds.get("leaked_admin_session").client("iam")
```

- [ ] **Step 8: Replace `sys.exit(1)` calls with `RuntimeError`**

In `phase1`, replace the credential-failure `sys.exit(1)` (after the
`CreateAccessKey DangerDev` failure) with:
```python
        raise RuntimeError("Could not create DangerDev@protonmail.me access key — aborting")
```

- [ ] **Step 9: Replace `main()` + `__main__` with `run(outputs, region)`**

Replace the whole entry-point block:
```python
def main(target_info: str = ""):
    print("DangerDev — Automated Post-Exploitation Attack Script")
    print("MayaTrail Adversary Emulation  |  AWS  |  3 phases  |  17 steps")
    print(f"Target context: {target_info or '(from environment variables)'}\n")

    leaked_key_id = os.environ.get("LEAKED_KEY_ID")
    leaked_secret = os.environ.get("LEAKED_SECRET_KEY")
    account_id = os.environ.get("ACCOUNT_ID", "")

    if not leaked_key_id or not leaked_secret:
        print("FATAL: LEAKED_KEY_ID and LEAKED_SECRET_KEY must be set (lab-infra-admin from bait tfstate)")
        sys.exit(1)

    creds = CredentialStore()
    creds.add("leaked_admin_session", make_session(leaked_key_id, leaked_secret), {
        "key_id": leaked_key_id,
        "username": "lab-infra-admin",
    })
    creds.activate("leaked_admin_session")

    try:
        account_id = phase1(creds, account_id)
        phase2(creds, account_id)
        phase3(creds, account_id)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by operator")
    except Exception as exc:
        print_err(f"Unhandled exception: {exc}")
        import traceback
        traceback.print_exc()
    finally:
        print_summary()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
```
with:
```python
def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Entry point called by the run_emulation_attack Celery task.

    Args:
        outputs: Pulumi stack outputs. Requires admin_access_key_id and
                 admin_access_key_secret (the leaked lab-infra-admin credential).
        region:  AWS region the stack was deployed in (Stack.region).
    """
    print("DangerDev — Automated Post-Exploitation Attack Script")
    print("MayaTrail Adversary Emulation  |  AWS  |  3 phases  |  17 steps")
    logger.info("DangerDev emulation starting (region=%s)", region)

    leaked_key_id = outputs.get("admin_access_key_id")
    leaked_secret = outputs.get("admin_access_key_secret")
    if not leaked_key_id or not leaked_secret:
        raise RuntimeError(
            "admin_access_key_id / admin_access_key_secret missing from stack "
            "outputs — cannot bootstrap the leaked-admin credential."
        )

    account_id = ""
    creds = CredentialStore()
    creds.add("leaked_admin_session", make_session(leaked_key_id, leaked_secret, region), {
        "key_id": leaked_key_id,
        "username": "lab-infra-admin",
    })
    creds.activate("leaked_admin_session")

    try:
        account_id = phase1(creds, account_id, region)
        phase2(creds, account_id, region)
        phase3(creds, account_id, region)
    except Exception as exc:
        print_err(f"Unhandled exception: {exc}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        print_summary()
```

- [ ] **Step 10: Byte-compile + import + signature check**

Run (from `<REPO>`, in the backend Python env that has boto3):
```powershell
python -m py_compile emulations\dangerdev\attack.py
python -c "import sys, inspect; sys.path.insert(0,'.'); from emulations.dangerdev import attack; sig=inspect.signature(attack.run); assert list(sig.parameters)[:2]==['outputs','region'], sig; print('run signature OK:', sig)"
```
Expected: `run signature OK: (outputs: dict, region: str = 'us-east-1') -> None`

- [ ] **Step 11: Confirm no `os`/`sys`/`environ` left**

Run:
```powershell
Select-String -Path "emulations\dangerdev\attack.py" -Pattern "os\.environ|sys\.exit|sys\.argv|^import os|^import sys"
```
Expected: no matches.

### Task A6: Port + sanitize `PLAYBOOK.md`

**Files:**
- Create: `<REPO>/emulations/dangerdev/PLAYBOOK.md` (from pipeline `ir_playbooks/playbook_DANGERDEV.md`)

- [ ] **Step 1: Copy to the package root**

```powershell
Copy-Item -Force "$src\ir_playbooks\playbook_DANGERDEV.md" "$dst\PLAYBOOK.md"
```

- [ ] **Step 2: Sanitize run-specific artifacts**

Read `PLAYBOOK.md` and generalize any captured run specifics so it reads as a
reusable IR guide: replace concrete public IPs, EC2 instance IDs (`i-...`),
access-key IDs (`AKIA...`/`ASIA...`), account numbers other than the documented
adversary accounts, and absolute timestamps with generic placeholders
(e.g. `<INSTANCE_IP>`, `<INSTANCE_ID>`, `<TIMESTAMP>`). Keep the technique
narrative and detection guidance intact.

- [ ] **Step 3: Verify no leftover live IPs/instance IDs**

Run:
```powershell
Select-String -Path "emulations\dangerdev\PLAYBOOK.md" -Pattern "\bi-[0-9a-f]{8,}\b|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
```
Expected: no matches.

### Task A7: Registry integration check (whole package)

- [ ] **Step 1: `registry.discover()` lists dangerdev with detections**

Run (from `<REPO>`):
```powershell
python -c "import sys; sys.path.insert(0,'.'); from emulations.registry import discover; d={e['name']:e for e in discover()}; e=d['dangerdev']; assert e['tier']=='enterprise'; assert e['detection_files'], 'no detections'; print('dangerdev registered | detections:', len(e['detection_files']), '| readiness:', e['manifest']['readiness'])"
```
Expected: `dangerdev registered | detections: 32 | readiness: {'type': 'none'}` (count per A1).

- [ ] **Step 2 (commit checkpoint — confirm with user first):**

```powershell
git -C "C:\Users\Ayush\Documents\mayatrail\step1" add emulations/dangerdev
git -C "C:\Users\Ayush\Documents\mayatrail\step1" commit -m "feat(emulations): add DANGERDEV backend-compatible package"
```

---

## Phase B — backend readiness change (TDD)

### Task B1: Failing test for the readiness helper

**Files:**
- Create: `<REPO>/backend/apps/emulations/tests/__init__.py` (empty)
- Create: `<REPO>/backend/apps/emulations/tests/test_readiness.py`

> Note: if `backend/apps/emulations/tests.py` already exists, convert it to the
> `tests/` package by moving it to `tests/test_legacy.py` first (Django discovers
> either a `tests.py` module or a `tests/` package, not both).

- [ ] **Step 1: Write the failing test**

```python
from apps.emulations.readiness import DEFAULT_READINESS, resolve_readiness, requires_http_probe


def test_absent_readiness_defaults_to_ec2_http():
    r = resolve_readiness({})
    assert r == DEFAULT_READINESS
    assert r["ip_output"] == "vuln_instance_ip"
    assert requires_http_probe(r) is True


def test_none_readiness_skips_probe():
    r = resolve_readiness({"readiness": {"type": "none"}})
    assert r["type"] == "none"
    assert requires_http_probe(r) is False


def test_custom_ec2_http_readiness_passthrough():
    custom = {"type": "ec2_http", "ip_output": "web_ip", "port": 9000, "path": "/ready"}
    r = resolve_readiness({"readiness": custom})
    assert r == custom
    assert requires_http_probe(r) is True
```

- [ ] **Step 2: Run it; verify it fails (module missing)**

Run (from `<REPO>/backend`, backend env active):
```powershell
python manage.py test apps.emulations.tests.test_readiness -v 2
```
Expected: FAIL — `ModuleNotFoundError: No module named 'apps.emulations.readiness'`.

### Task B2: Implement the readiness helper

**Files:**
- Create: `<REPO>/backend/apps/emulations/readiness.py`

- [ ] **Step 1: Write the pure helper**

```python
"""
Readiness contract for emulation stacks.

An emulation's MANIFEST may declare a `readiness` block describing how the
backend decides a freshly-deployed stack is ready for the attack phase:

    {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"}
        Poll http://<outputs[ip_output]>:<port><path> until 200 (scarleteel model).

    {"type": "none"}
        No probe — the stack is ready immediately after deploy (e.g. IAM/
        credential-abuse emulations with no vulnerable web service).

When the field is absent the legacy ec2_http behavior is used, so existing
emulations need no change.
"""

from __future__ import annotations

from typing import Any

DEFAULT_READINESS: dict[str, Any] = {
    "type": "ec2_http",
    "ip_output": "vuln_instance_ip",
    "port": 8080,
    "path": "/health",
}


def resolve_readiness(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the manifest's readiness block, or the legacy default if absent."""
    return manifest.get("readiness") or DEFAULT_READINESS


def requires_http_probe(readiness: dict[str, Any]) -> bool:
    """True when the stack must pass an HTTP readiness probe before attack."""
    return readiness.get("type") != "none"
```

- [ ] **Step 2: Run the test; verify it passes**

Run (from `<REPO>/backend`):
```powershell
python manage.py test apps.emulations.tests.test_readiness -v 2
```
Expected: PASS (3 tests OK).

### Task B3: Wire readiness into `tasks.py`

**Files:**
- Modify: `<REPO>/backend/apps/emulations/tasks.py`

- [ ] **Step 1: Import the helper**

Add to the `from apps.emulations.registry import get_emulation` import area:
```python
from apps.emulations.readiness import resolve_readiness, requires_http_probe
```

- [ ] **Step 2: Branch on readiness in `deploy_emulation_stack`**

Replace:
```python
            stack.outputs = {key: val.value for key, val in result.outputs.items()}
            stack.status = Stack.Status.EC2_BOOTING
            stack.save(update_fields=["status", "outputs", "updated_at"])
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # Begin non-blocking EC2 readiness polling.
        poll_ec2_readiness.apply_async(args=[stack_id], queue="enterprise")

        logger.info("Emulation stack deployed: name=%s → EC2_BOOTING", stack.name)
        return {"stack_id": stack_id, "status": stack.status}
```
with:
```python
            stack.outputs = {key: val.value for key, val in result.outputs.items()}
            readiness = resolve_readiness(manifest)
            if requires_http_probe(readiness):
                stack.status = Stack.Status.EC2_BOOTING
            else:
                # No vulnerable web service — ready for attack immediately.
                stack.status = Stack.Status.READY_FOR_ATTACK
            stack.save(update_fields=["status", "outputs", "updated_at"])
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        if requires_http_probe(readiness):
            poll_ec2_readiness.apply_async(args=[stack_id], queue="enterprise")
            logger.info("Emulation stack deployed: name=%s → EC2_BOOTING", stack.name)
        else:
            logger.info("Emulation stack deployed: name=%s → READY_FOR_ATTACK (no probe)", stack.name)
        return {"stack_id": stack_id, "status": stack.status}
```
(`manifest` is already in scope — it was fetched above for `total_resources`.)

- [ ] **Step 3: Generalize `poll_ec2_readiness`**

Replace:
```python
    Stack = apps.get_model("infrastructure", "Stack")

    stack = _get_stack(stack_id)
    ip = stack.outputs.get("vuln_instance_ip")

    if not ip:
        logger.error(
            "poll_ec2_readiness: no vuln_instance_ip in outputs for stack=%s", stack_id,
        )
        stack.status = Stack.Status.FAILED
        stack.save(update_fields=["status", "updated_at"])
        return

    try:
        resp = http_requests.get(f"http://{ip}:8080/health", timeout=5)
```
with:
```python
    Stack = apps.get_model("infrastructure", "Stack")

    stack = _get_stack(stack_id)
    entry = get_emulation(stack.emulation_type)
    manifest = entry.get("manifest", entry) if entry else {}
    readiness = resolve_readiness(manifest)
    ip = stack.outputs.get(readiness["ip_output"])

    if not ip:
        logger.error(
            "poll_ec2_readiness: no %s in outputs for stack=%s",
            readiness["ip_output"], stack_id,
        )
        stack.status = Stack.Status.FAILED
        stack.save(update_fields=["status", "updated_at"])
        return

    try:
        resp = http_requests.get(
            f"http://{ip}:{readiness['port']}{readiness['path']}", timeout=5,
        )
```

- [ ] **Step 4: Sanity-check imports compile**

Run (from `<REPO>/backend`):
```powershell
python -c "import ast; ast.parse(open(r'apps/emulations/tasks.py', encoding='utf-8').read()); print('tasks.py parses')"
```
Expected: `tasks.py parses`

### Task B4: Explicit default readiness on scarleteel (documentation, no behavior change)

**Files:**
- Modify: `<REPO>/emulations/scarleteel/MANIFEST.py`

- [ ] **Step 1: Add the readiness block**

In scarleteel's `MANIFEST` dict, after the `"tier": "enterprise",` line add:
```python
    "readiness": {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"},
```

- [ ] **Step 2: Confirm scarleteel still resolves to the same behavior**

Run (from `<REPO>/backend`):
```powershell
python -c "import sys; sys.path.insert(0,'..'); from emulations.scarleteel.MANIFEST import MANIFEST as m; from apps.emulations.readiness import resolve_readiness, requires_http_probe; r=resolve_readiness(m); assert r['ip_output']=='vuln_instance_ip' and requires_http_probe(r); print('scarleteel readiness OK', r)"
```
Expected: `scarleteel readiness OK {...}`

- [ ] **Step 3: Commit checkpoint (confirm with user first)**

```powershell
git -C "C:\Users\Ayush\Documents\mayatrail\step1" add backend/apps/emulations emulations/scarleteel/MANIFEST.py
git -C "C:\Users\Ayush\Documents\mayatrail\step1" commit -m "feat(emulations): manifest-driven readiness gating (back-compatible)"
```

---

## Phase C — worker dependency

### Task C1: Add `pulumi-tls` to the worker image

**Files:**
- Modify: `<REPO>/backend/requirements.txt`

- [ ] **Step 1: Add the dependency** (after the `pulumi-aws==7.11.1` line)

```
pulumi-tls>=5.0.0,<6.0.0
```

- [ ] **Step 2: Resolve + freeze the exact version to match repo style**

```powershell
# in the backend env
pip install "pulumi-tls>=5.0.0,<6.0.0"
pip show pulumi-tls | Select-String "Version"
```
Then edit `backend/requirements.txt` to pin the exact resolved version
(e.g. `pulumi-tls==5.2.0`).

- [ ] **Step 3: Verify the program imports under the installed deps**

```powershell
python -c "import pulumi_aws, pulumi_tls; print('pulumi-aws', pulumi_aws.__version__ if hasattr(pulumi_aws,'__version__') else 'ok'); print('pulumi-tls import ok')"
```
Expected: no ImportError.

- [ ] **Step 4: Rebuild the enterprise worker image** (so the running worker has the dep)

```powershell
docker compose -f "C:\Users\Ayush\Documents\mayatrail\step1\docker-compose.yml" build worker_enterprise
```
(Confirm the exact service name from `docker-compose.yml`; pair this with the user.)

- [ ] **Step 5: Commit checkpoint (confirm with user first)**

```powershell
git -C "C:\Users\Ayush\Documents\mayatrail\step1" add backend/requirements.txt
git -C "C:\Users\Ayush\Documents\mayatrail\step1" commit -m "build(worker): add pulumi-tls for DANGERDEV keypair"
```

---

## Phase D — static validation gate (all of the above, no live AWS)

### Task D1: Full static validation

- [ ] **Step 1: Registry + manifest + attack signature (re-run A4/A5/A7 checks together)**

Run (from `<REPO>`):
```powershell
python -c "import sys; sys.path.insert(0,'.'); from emulations.registry import discover; names=[e['name'] for e in discover()]; assert 'dangerdev' in names and 'scarleteel' in names, names; print('registry OK:', names)"
```
Expected: `registry OK: ['dangerdev', 'scarleteel']` (order may vary).

- [ ] **Step 2: `pulumi preview` type-checks the infra on v7 (needs AWS creds)**

This is the authoritative Gap C check. With STS creds + the Pulumi state backend
configured the same way the worker uses them (or a local `PULUMI_BACKEND_URL`),
from `emulations/dangerdev/infra`:
```powershell
$env:PULUMI_CONFIG_PASSPHRASE=""
pulumi stack init dev-preview
pulumi config set aws:region us-east-1
pulumi preview
pulumi stack rm dev-preview --yes
```
Expected: preview completes with a resource plan and **no error diagnostics**.
If v7 surfaces further deltas (e.g. `aws.guardduty.Detector(datasources=...)`),
fix them here — convert `datasources` to `aws.guardduty.DetectorFeature` if the
inline arg errors — and re-run until clean.

- [ ] **Step 3: Refine `total_resources`**

Count the resources in the preview plan and update
`emulations/dangerdev/MANIFEST.py` `total_resources` to the real number (drives
the deploy progress bar).

- [ ] **Step 4: Backend tests still green**

Run (from `<REPO>/backend`):
```powershell
python manage.py test apps.emulations -v 1
```
Expected: all pass.

---

## Phase E — paired live run (interactive; user approves each AWS step)

> Driven together: Claude issues commands, the user approves each AWS-touching
> action. Requires the MayaTrail stack running (enterprise worker with the
> rebuilt image, Redis, Postgres, Pulumi S3 state bucket) and an enterprise
> `User` with a valid `aws_role_arn`. Region: `us-east-1`.

### Task E1: Deploy → READY_FOR_ATTACK

- [ ] **Step 1: Trigger a deploy** (pick the path that fits the running stack)
  - API: `POST /api/emulations/deploy/` with `{"emulation_type":"dangerdev","stack_name":"dangerdev-<suffix>"}` as an enterprise user, **or**
  - Django shell: create a `Stack` and call `deploy_emulation_stack(stack_id)` on the enterprise queue.
- [ ] **Step 2:** Watch the worker log; confirm `pulumi up` provisions all resources (keypair created via `pulumi-tls`).
- [ ] **Step 3:** Confirm `stack.outputs` is populated (incl. `admin_access_key_id`/`admin_access_key_secret`) and status transitions **straight to `READY_FOR_ATTACK`** (no `poll_ec2_readiness`).

### Task E2: Run the attack

- [ ] **Step 1:** `POST /api/emulations/<stack_id>/attack/` (or enqueue `run_emulation_attack(run_id)`).
- [ ] **Step 2:** Stream the `EmulationRun.stdout`; confirm all 17 steps print, the credential pivots occur, and the `[EXPECTED_FAILURE]` AssumeRole + documented-only Steps 16/17 behave as designed.
- [ ] **Step 3:** Spot-check CloudTrail for the expected events and GuardDuty for findings.

### Task E3: Destroy + verify clean

- [ ] **Step 1:** `pulumi destroy` via `destroy_emulation_stack` (or wait for TTL auto-destroy).
- [ ] **Step 2:** Verify no orphaned IAM principals remain — `DangerDev@protonmail.me` and `ses` are attack-created and should have been removed by the Step 15 / post-17 self-cleanup. Manually delete any stragglers.
- [ ] **Step 3:** Confirm the `Stack` record is deleted and billing surface is gone.

---

## Self-review notes (author)
- **Spec coverage:** §5.1→A4, §5.2→A5, §5.3→A3, §5.4→A2, §5.5→A2, §5.6→A6, §5.7→A1, §5.8→A1, §6→B1-B4, §7→C1, §8.1→D1, §8.2→E1-E3. Gaps A/B/C/D/E all have tasks.
- **Region threading (A5 Steps 3-5)** is the subtlest edit — sessions carry region, clients inherit; verified the cleanup sessions (B6/B7) and phase sessions all get `region`.
- **`total_resources`** is a deliberate estimate refined in D1 Step 3 (not a placeholder — it has a concrete value + a refinement step).
- **GuardDuty `datasources`** on v7 is the one infra unknown; D1 Step 2 catches and fixes it if needed.

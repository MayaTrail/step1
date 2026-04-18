---
id: aws-secretsmanager-getsecretvalue
api_call: secretsmanager:GetSecretValue
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - SECRET_ID
  - REGION
provided_outputs:
  - STOLEN_SECRET_NAME
  - STOLEN_SECRET_ARN
  - SOURCE_IP
---

# Playbook: Unauthorized Secret Value Retrieval

**ID:** PB-AWS-SecretsManager-GetSecretValue-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Unauthorized Secret Value Retrieval |
| **Playbook ID** | PB-AWS-SecretsManager-GetSecretValue-01 |
| **Version** | 1.0 |
| **Scenario** | An attacker calls `secretsmanager:GetSecretValue` to retrieve plaintext secret values. In the SCARLETEEL 2.0 campaign, the attacker used stolen EC2 instance role credentials (principal `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589`) from IPv6 address `2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad` to retrieve `prod/database/master_credentials` containing database admin credentials (`db_admin` / `Pr0d-M4st3r-P@ss!2026`). This occurred after `ListSecrets` enumeration and after CloudTrail was disabled via `StopLogging` — the attacker timed the most sensitive exfiltration for the blind window. |
| **Trigger** | CloudTrail event `GetSecretValue` from a principal that should not access production secrets, from an unrecognized source IP, or targeting high-value secrets (database credentials, API keys, encryption keys). |

### Severity Matrix

| Severity | Condition | Action |
|---|---|---|
| **CRITICAL** | `GetSecretValue` called by an EC2 instance role from a non-instance IP, OR targeting a secret with `prod` or `master` in the name, OR occurring after a `StopLogging` event in the same session. | Wake CISO & Legal immediately — production secrets are stolen. Begin emergency rotation within 15 minutes. |
| **HIGH** | `GetSecretValue` called by an unexpected principal (not in the secret's resource policy allow list) OR from an unrecognized IP, targeting any secret. | Immediate IR triage. Verify caller's authorization. |
| **MEDIUM** | `GetSecretValue` called by a known application role but at an unusual frequency (>10 calls/minute) or targeting secrets outside its normal scope. | Next-business-day triage. May indicate application misconfiguration or early-stage compromise. |

- **Prerequisites:**
  - Roles: `IncidentResponseRole` with read access to CloudTrail, SecretsManager, IAM
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1528: Steal Application Access Token
  - T1552.001: Unsecured Credentials: Credentials in Files
- **Stakeholders:** Security Oncall, CISO, Engineering Lead (for emergency credential rotation), DBA team (if database credentials stolen)
- **SLA Target:** Triage: 5 mins (CRITICAL), 15 mins (HIGH)
- **Compliance:** If stolen secret provides access to PII/financial data, GDPR 72-hour clock starts immediately. PCI DSS breach notification if payment credentials. SOC 2 incident logging mandatory.

### Related Playbooks

- [PB-AWS-SecretsManager-ListSecrets-01](PB-AWS-SecretsManager-ListSecrets-01.md) — Precursor enumeration step
- [PB-AWS-CloudTrail-StopLogging-01](../cloudtrail/PB-AWS-CloudTrail-StopLogging-01.md) — Often precedes secret theft in SCARLETEEL
- [SCARLETEEL-V2-CHRONOLOGICAL](../../campaigns/SCARLETEEL-V2-CHRONOLOGICAL.md) — Full SCARLETEEL 2.0 kill chain

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identify the Caller and Target Secret:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,
       secretId: .requestParameters.secretId, errorCode, userAgent}'
  ```

- [ ] **What does this secret contain?**
  ```bash
  aws secretsmanager describe-secret \
    --secret-id <SECRET_ID> \
    --region <REGION> --profile <IR_PROFILE> | jq '{Name, Description, Tags, LastAccessedDate, RotationEnabled}'
  ```
  Determine the blast radius: database credentials, API keys, encryption keys, or other sensitive material.

- [ ] **Who is authorized to access this secret?**
  ```bash
  aws secretsmanager get-resource-policy \
    --secret-id <SECRET_ID> \
    --region <REGION> --profile <IR_PROFILE>
  ```
  Compare the caller ARN against the resource policy. If the caller is not in the allowed principals, this is unauthorized access.

- [ ] **Confirm Credential Exfiltration (if EC2 role):**
  ```bash
  aws ec2 describe-instances \
    --instance-ids <INSTANCE_ID> \
    --query "Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]" \
    --output text --profile <IR_PROFILE>
  ```

- [ ] **Check for preceding StopLogging:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
    --start-time <INCIDENT_START_TIME> \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      {eventTime, callerArn: .userIdentity.arn, trail: .requestParameters.name}'
  ```
  If `StopLogging` preceded `GetSecretValue` from the same principal, this is SCARLETEEL Phase 6 — the attacker deliberately blinded logging before exfiltrating secrets.

### Step 2.2: Decision Gate

- IF `GetSecretValue` succeeded + source IP != instance IP + secret contains production credentials → **CONFIRMED secret theft. Containment L2 + emergency rotation.**
- IF `GetSecretValue` succeeded + preceded by `StopLogging` → **SCARLETEEL pattern confirmed. Containment L3, full campaign investigation.**
- IF `GetSecretValue` failed (AccessDenied) → **Attempt blocked. L1 containment, investigate the compromised principal.**
- IF `GetSecretValue` from known application role at normal frequency → **Likely benign. Verify and close.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action | Rollback |
|---|---|---|---|
| **L1 (Soft)** | Suspected unauthorized access | Revoke old sessions on the compromised role (see ListSecrets playbook L1) | Delete the emergency deny policy |
| **L2 (Hard)** | Confirmed secret theft | Deny-all SecretsManager: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenyAll` |
| **L3 (Nuclear)** | Production secrets stolen, active attack | Emergency rotate ALL stolen secrets + deny-all on role + isolate EC2 instance | Coordinated restore after investigation |

**CRITICAL CHECK:** Before L2/L3, confirm the asset is NOT tagged `Critical-Production-App`.

---

## 4. Investigation & Forensics

### Step 4.1: Determine Exactly Which Secrets Were Stolen

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.eventName == "GetSecretValue" and .userIdentity.arn == "<CALLER_ARN>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, secretId: .requestParameters.secretId, sourceIP: .sourceIPAddress, errorCode}'
```

### Step 4.2: Assess Downstream Impact Per Secret

For each stolen secret, determine what the attacker can now access:

| Secret Name Pattern | Impact | Immediate Action |
|---|---|---|
| `prod/database/*` | Full database access — read, write, drop | Change DB password, audit DB access logs |
| `*/api-key/*` | Third-party API access | Regenerate API key with the provider |
| `*/encryption/*` | Decrypt protected data | Rotate encryption keys, re-encrypt data |
| `*/ssh/*` or `*/keypair/*` | SSH access to infrastructure | Remove old keys from authorized_keys |

### Step 4.3: Timeline Correlation

```bash
# Full activity from this principal
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.arn == "<CALLER_ARN>" or
            .sourceIPAddress == "<SOURCE_IP>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, eventSource, sourceIP: .sourceIPAddress, errorCode}'
```

### Step 4.4: Evidence Preservation

```bash
# Export all SecretsManager events
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.eventSource == "secretsmanager.amazonaws.com")]' \
  > /tmp/secretsmanager_forensics.json
```

---

## 5. Recovery & Hardening

### 5.1: Emergency Rotation (Immediate)

```bash
# Rotate the stolen secret
aws secretsmanager rotate-secret \
  --secret-id <SECRET_ID> \
  --region <REGION> --profile <IR_PROFILE>

# If no rotation Lambda configured, manually update:
aws secretsmanager update-secret \
  --secret-id <SECRET_ID> \
  --secret-string '<NEW_CREDENTIAL_JSON>' \
  --region <REGION> --profile <IR_PROFILE>
```

**Critical:** Also change the credential at the downstream system (database password, API key at the provider, etc.). Rotating only the SecretsManager value without changing the actual credential is insufficient.

### 5.2: Harden

| Fix | Implementation | Priority |
|---|---|---|
| **Secret resource policies** | Add explicit `Principal` allow-list to each secret's resource policy | P1 |
| **Remove SecretsManager from EC2 roles** | EC2 roles should not have `secretsmanager:GetSecretValue` unless specifically needed for that secret ARN only | P1 |
| **Enable automatic rotation** | Configure rotation Lambdas with 30-day max rotation interval | P1 |
| **Alert on GetSecretValue from compute** | EventBridge rule: `GetSecretValue` where `userIdentity.principalId` contains `:i-` → SNS alert | P2 |
| **Enable GuardDuty** | Detects credential exfiltration patterns | P2 |
| **VPC Endpoint for SecretsManager** | Force SecretsManager calls through VPC endpoint to control network path | P3 |

### 5.3: Verify

```bash
# Confirm rotation occurred
aws secretsmanager describe-secret \
  --secret-id <SECRET_ID> \
  --region <REGION> --profile <IR_PROFILE> | jq '{LastRotatedDate, VersionIdsToStages}'

# Confirm downstream service works with new credentials
# (application-specific verification)

# Confirm resource policy restricts access
aws secretsmanager get-resource-policy \
  --secret-id <SECRET_ID> \
  --region <REGION> --profile <IR_PROFILE>
```

---

## Detection Rule (Sigma Format)

```yaml
title: AWS Secrets Manager GetSecretValue from EC2 Instance Role
id: e5f6a7b8-9203-4567-ef01-23456789abcd
status: experimental
description: >
  Detects secretsmanager:GetSecretValue called by an EC2 instance role.
  In SCARLETEEL 2.0, this is the final exfiltration step (Phase 6) where
  the attacker retrieves production database credentials after disabling
  CloudTrail. The attacker used stolen IMDSv1 credentials from an
  off-instance IP (IPv6), confirmed by ec2RoleDelivery: "1.0" and
  userAgent containing "os/windows" on a Linux instance.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.credential_access
  - attack.t1528
  - attack.t1552.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: GetSecretValue
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: selection
falsepositives:
  - EC2-hosted applications that legitimately fetch secrets at startup or rotation
level: critical
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1528 | Steal Application Access Token | Credential Access |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access |

---

## Verified Against Emulation Logs

Validated against CloudTrail events from SCARLETEEL 2.0 emulation on 2026-04-11:

| Time (UTC) | Event | Principal | Source IP | Secret | Result |
|---|---|---|---|---|---|
| 12:13:05 | `GetSecretValue` | `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` | `2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad` | `prod/database/master_credentials` | OK |

**Key observations:**
- This event occurred **40 seconds after `StopLogging`** (12:12:25) — the attacker deliberately blinded audit logging before exfiltrating the most sensitive asset.
- Source IP is IPv6, not matching EC2 instance IP `13.220.122.208` — credential exfiltration confirmed.
- `ec2RoleDelivery: "1.0"` confirms IMDSv1 was the credential source.
- `userAgent: os/windows` on a Linux EC2 instance — dead giveaway of off-instance credential use.
- The `requestParameters.secretId` field shows `prod/database/master_credentials` — the attacker knew the name from the preceding `ListSecrets` call at the same timestamp.

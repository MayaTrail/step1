---
id: aws-secretsmanager-listsecrets
api_call: secretsmanager:ListSecrets
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - REGION
provided_outputs:
  - ENUMERATED_SECRET_NAMES
  - SECRET_COUNT
  - SOURCE_IP
---

# Playbook: Secrets Manager Secret Enumeration

**ID:** PB-AWS-SecretsManager-ListSecrets-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Secrets Manager Secret Enumeration |
| **Playbook ID** | PB-AWS-SecretsManager-ListSecrets-01 |
| **Version** | 1.0 |
| **Scenario** | An attacker calls `secretsmanager:ListSecrets` to enumerate all secrets in the account. In the SCARLETEEL 2.0 campaign, the attacker used stolen EC2 instance role credentials (principal `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589`) from IPv6 address `2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad` to discover `prod/database/master_credentials`. This is a precursor to `GetSecretValue` — the attacker enumerates available secrets before selectively exfiltrating high-value targets. |
| **Trigger** | CloudTrail event `ListSecrets` from a principal that is not a secrets management administrator, from an unrecognized source IP, or from an EC2 instance role that should not have SecretsManager access. |

### Severity Matrix

| Severity | Condition | Action |
|---|---|---|
| **CRITICAL** | `ListSecrets` called by an EC2 instance role or Lambda execution role (compute-based identity) AND source IP does not match the instance/function's expected network. | Immediate IR response — attacker is harvesting secrets with stolen compute credentials. Check for follow-on `GetSecretValue` within minutes. |
| **HIGH** | `ListSecrets` called by a human principal from an unrecognized IP or outside business hours, OR followed by `GetSecretValue` on 2+ secrets within 5 minutes. | Immediate triage. Verify the caller's business need for secret enumeration. |
| **MEDIUM** | `ListSecrets` called by a known admin principal or CI/CD role from an expected IP, but no corresponding change request exists. | Next-business-day triage. |

- **Prerequisites:**
  - Roles: `IncidentResponseRole` with read access to CloudTrail, SecretsManager, IAM
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
  - T1526: Cloud Service Discovery
- **Stakeholders:** Security Oncall, CISO (if production secrets enumerated), Engineering Lead (for secret rotation coordination)
- **SLA Target:** Triage: 15 mins
- **Compliance:** If enumerated secrets include database credentials for PII stores, GDPR/CCPA notification assessment required. SOC 2 incident logging mandatory.

### Related Playbooks

- [PB-AWS-SecretsManager-GetSecretValue-01](PB-AWS-SecretsManager-GetSecretValue-01.md) — Attacker retrieves actual secret values after enumeration
- [PB-AWS-IAM-ListUsers-01](../iam/PB-AWS-IAM-ListUsers-01.md) — Often occurs in same reconnaissance burst
- [SCARLETEEL-V2-CHRONOLOGICAL](../../campaigns/SCARLETEEL-V2-CHRONOLOGICAL.md) — Full SCARLETEEL 2.0 kill chain

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identify the Caller:** Who called `ListSecrets`?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,
       userAgent, errorCode}'
  ```
  Extract `userIdentity.arn` (caller), `sourceIPAddress`, `errorCode`.

- [ ] **Caller Identity Type:** Is this a compute role (EC2/Lambda)?
  Check `userIdentity.type` — if `AssumedRole` with principal containing `:i-` (EC2) or `:function:` (Lambda), escalate.
  Check for `ec2RoleDelivery` or `inScopeOf.issuerType` fields — these confirm EC2-issued credentials.

- [ ] **Check for Follow-On GetSecretValue:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      select(.userIdentity.arn == "<CALLER_ARN>") |
      {eventTime, secretId: .requestParameters.secretId, errorCode}'
  ```
  If `GetSecretValue` follows `ListSecrets` from the same principal, the attacker is actively exfiltrating — escalate immediately.

- [ ] **Confirm Credential Exfiltration (if EC2 role):**
  ```bash
  aws ec2 describe-instances \
    --instance-ids <INSTANCE_ID> \
    --query "Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]" \
    --output text --profile <IR_PROFILE>
  ```
  If `sourceIPAddress` from the event does not match the instance IP, credentials were stolen and used externally.

### Step 2.2: Decision Gate

- IF `ListSecrets` from EC2 role + non-instance source IP + followed by `GetSecretValue` → **CONFIRMED credential theft + secret exfiltration. Go to Containment L2.**
- IF `ListSecrets` from EC2 role + non-instance source IP, no `GetSecretValue` yet → **Probable credential theft. Go to Containment L1, continue investigation.**
- IF `ListSecrets` from known admin principal during business hours → **Verify business justification. Likely benign.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action | Rollback |
|---|---|---|---|
| **L1 (Soft)** | Suspected credential theft | Revoke old sessions: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions` |
| **L2 (Hard)** | Confirmed exfiltration or `GetSecretValue` observed | Deny SecretsManager access: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenySecrets --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"secretsmanager:*","Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyDenySecrets` |
| **L3 (Nuclear)** | Production secrets confirmed stolen | Rotate ALL enumerated secrets immediately + deny-all on compromised role | Restore original role policy after investigation |

**CRITICAL CHECK:** Before L2/L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<INSTANCE_ID>" "Name=key,Values=Critical-Production-App" \
  --output text --profile <IR_PROFILE>
```

---

## 4. Investigation & Forensics

### Step 4.1: Scope the Enumeration

```bash
# What secrets exist in the account?
aws secretsmanager list-secrets \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .SecretList[] | {Name, ARN, Description, LastAccessedDate}'
```

Every secret returned by this API is now considered "known to the attacker" — the response payload contains secret names, ARNs, descriptions, tags, and last-accessed dates.

### Step 4.2: Check What Secrets Were Actually Retrieved

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    .Events[] | .CloudTrailEvent | fromjson |
    select(.userIdentity.arn == "<CALLER_ARN>") |
    {eventTime, secretId: .requestParameters.secretId, sourceIP: .sourceIPAddress, errorCode}'
```

### Step 4.3: Blast Radius Assessment

| Asset | Check | Compromised If |
|---|---|---|
| Secret names/ARNs | `ListSecrets` succeeded | All secret metadata exposed to attacker |
| Secret values | `GetSecretValue` succeeded | Actual credential values stolen |
| Database access | Secret contains DB creds | Assume database was accessed |
| API keys | Secret contains third-party API keys | Assume third-party services accessed |

### Step 4.4: Correlate with Kill Chain

```bash
# All activity from the same principal in the attack window
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.arn == "<CALLER_ARN>")] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, eventSource, sourceIP: .sourceIPAddress, errorCode}'
```

In SCARLETEEL 2.0, `ListSecrets` + `GetSecretValue` occurs in Phase 6 (Secondary Pivot) — after CloudTrail has already been disabled. Check if `StopLogging` preceded this event.

### Step 4.5: Evidence Preservation

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.eventSource == "secretsmanager.amazonaws.com")]' > /tmp/secretsmanager_events.json
```

---

## 5. Recovery & Hardening

### 5.1: Immediate Rotation

```bash
# Rotate each compromised secret
aws secretsmanager rotate-secret \
  --secret-id <SECRET_NAME> \
  --region <REGION> --profile <IR_PROFILE>

# If no rotation Lambda is configured, manually update:
aws secretsmanager update-secret \
  --secret-id <SECRET_NAME> \
  --secret-string '{"username":"<USER>","password":"<NEW_PASSWORD>"}' \
  --region <REGION> --profile <IR_PROFILE>
```

Also rotate credentials at the downstream system (database password change, API key regeneration, etc.).

### 5.2: Harden

| Fix | Implementation | Priority |
|---|---|---|
| **Scope SecretsManager access** | Remove `secretsmanager:ListSecrets` and `secretsmanager:GetSecretValue` from EC2 roles unless specifically needed. Use resource-level ARN restrictions. | P1 |
| **Enable automatic rotation** | Configure rotation Lambdas for all production secrets | P1 |
| **Add resource policy** | Restrict `GetSecretValue` to specific IAM principals via secret resource policy | P2 |
| **Enable GuardDuty** | Detects `InstanceCredentialExfiltration.OutsideAWS` when EC2 creds are used off-instance | P2 |
| **Alert on ListSecrets from compute** | CloudWatch alarm on `ListSecrets` where `userIdentity.principalId` contains `:i-` | P2 |

### 5.3: Verify

```bash
# Confirm secret was rotated
aws secretsmanager describe-secret \
  --secret-id <SECRET_NAME> \
  --region <REGION> --profile <IR_PROFILE> | jq '{LastRotatedDate, VersionIdsToStages}'

# Confirm downstream service works with new credentials
# (application-specific verification)
```

---

## Detection Rule (Sigma Format)

```yaml
title: AWS Secrets Manager Enumeration from EC2 Instance Role
id: d4e5f6a7-8192-0345-def0-123456789abc
status: experimental
description: >
  Detects secretsmanager:ListSecrets called by an EC2 instance role.
  In SCARLETEEL 2.0, this is the first step of the secondary pivot
  (Phase 6) where the attacker harvests production secrets after
  disabling CloudTrail.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.discovery
  - attack.t1526
  - attack.credential_access
  - attack.t1087.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: ListSecrets
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: selection
falsepositives:
  - EC2-hosted secret rotation Lambdas or configuration management tools
  - Application bootstrap that legitimately lists secrets on startup
level: high
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1526 | Cloud Service Discovery | Discovery |
| T1087.004 | Account Discovery: Cloud Account | Discovery |

---

## Verified Against Emulation Logs

Validated against CloudTrail events from SCARLETEEL 2.0 emulation on 2026-04-11:

| Time (UTC) | Event | Principal | Source IP | Result |
|---|---|---|---|---|
| 12:13:05 | `ListSecrets` | `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` | `2401:4900:1c88:3f9e:551b:c1cb:db2c:a7ad` | OK |

**Key observation:** Source IP is IPv6 — does not match EC2 instance IP `13.220.122.208`. Confirms credential exfiltration. The `ec2RoleDelivery: "1.0"` field in the event confirms IMDSv1 was the credential source. UserAgent `os/windows` confirms creds used from a Windows machine, not the AL2023 Linux instance.

---
id: aws-iam-listuserpolicies
api_call: iam:ListUserPolicies
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
provided_outputs:
  - ENUMERATED_POLICY_NAMES
  - SOURCE_IP
---

# Playbook: IAM Inline Policy Enumeration via ListUserPolicies

**ID:** PB-AWS-IAM-ListUserPolicies-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:ListUserPolicies` to enumerate all inline policies attached to an IAM user, identifying policies to modify, delete, or exploit for privilege escalation.
- **Trigger:** CloudTrail event `ListUserPolicies` from an unrecognized source IP, by a principal other than the target user, or followed by `DeleteUserPolicy` or `PutUserPolicy` within 10 minutes.
- **Severity Matrix:**
  - **CRITICAL:** `ListUserPolicies` followed by `DeleteUserPolicy` within 10 minutes from an external IP. **Action:** Wake CISO & Legal immediately — attacker is stripping security policies.
  - **HIGH:** `ListUserPolicies` from an external IP targeting a service account or admin user. **Action:** Immediate IR team response.
  - **MEDIUM:** `ListUserPolicies` from an unrecognized principal on an internal IP with no follow-up destructive actions. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
  - T1580: Cloud Infrastructure Discovery
- **Stakeholders:** Security Engineering, Cloud Platform Team; escalate to CISO if correlated with policy deletion
- **SLA Target:** Triage: 30 mins (standalone), 15 mins (if correlated with subsequent policy modifications)
- **Compliance:** Standalone enumeration does not trigger reporting clocks. If part of a confirmed compromise chain, SOC 2 incident logging begins at detection.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who called `ListUserPolicies`? Is this a known admin or automated tool?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUserPolicies \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, and `requestParameters.userName`.

- [ ] **Target User Context:** What policies does the target user have? Are they sensitive?
  ```bash
  aws iam list-user-policies --user-name <USERNAME>
  aws iam list-attached-user-policies --user-name <USERNAME>
  ```

- [ ] **Subsequent Activity:** Did the same caller modify or delete any of the enumerated policies?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --max-results 50
  ```

- [ ] **Broader Reconnaissance:** Did the same caller enumerate policies for other users?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUserPolicies \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND matches IAM audit schedule: **Mark False Positive & Close.**
- IF `Source_IP == External` AND followed by `DeleteUserPolicy` or `PutUserPolicy` within 10 minutes: **Go to Containment Level 2 (IMMEDIATE) — active policy manipulation.**
- IF `Source_IP == External` AND no follow-up actions: **Go to Investigation — reconnaissance phase.**
- IF multiple `ListUserPolicies` calls targeting different users from the same principal: **Go to Containment Level 1 — automated reconnaissance tooling.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Anomalous enumeration, no follow-up actions | **Deny IAM read actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:List*","iam:Get*"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR` |
| **L2 (Hard)** | Enumeration followed by policy modification/deletion | **Deny all actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Confirmed credential compromise with active policy stripping | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **Which user's policies were enumerated?** Confirm the target and cross-reference with the user's actual policy set.

- **Were policies subsequently modified?** Check for policy changes within 30 minutes:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --max-results 100
  ```

- **Broader enumeration scope:** Did the same principal also call `ListAttachedUserPolicies`, `ListGroupPolicies`, or `ListRolePolicies`?

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('ListUserPolicies', 'DeleteUserPolicy', 'PutUserPolicy', 'GetUserPolicy')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-listpolicies-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-listpolicies-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-listpolicies-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-listpolicies-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the affected user:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** `ListUserPolicies` is read-only — no resource damage to reverse. If subsequent `DeleteUserPolicy` was detected, refer to PB-AWS-IAM-DeleteUserPolicy-01 for restoration steps.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:ListUserPolicies`** to admin principals only via SCP:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:ListUserPolicies", "iam:ListAttachedUserPolicies", "iam:GetUserPolicy"],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": ["SecurityAdmin", "IAMAdmin"] }
         }
       }]
     }
     ```
   - **Enable IAM Access Analyzer** to detect overly permissive policies.

4. **Verify:** Attempt `ListUserPolicies` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam list-user-policies --user-name <USERNAME>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `ListUserPolicies` alerted on? (Yes/No)
   - Did the caller enumerate policies for multiple users? (Yes/No)
   - Were the enumerated policies subsequently modified or deleted?
   - Time from enumeration to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM ListUserPolicies Enumeration
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
level: medium
description: Detects iam:ListUserPolicies calls which enumerate inline policies attached to an IAM user. Attackers use this to identify policies they can modify or delete to weaken security controls or strip permissions during eventual consistency exploitation.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1087.004
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: ListUserPolicies
  condition: selection
falsepositives:
  - IAM administrators performing routine policy audits
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) reading policy state during plan operations
  - AWS Config rules evaluating IAM policy compliance
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Discovery | `ListUserPolicies` reveals the inline policies attached to an IAM user, exposing the user's permission scope and identifying policies the attacker can target for modification or deletion |
| T1580 | Cloud Infrastructure Discovery | Discovery | Enumerating user policies exposes the IAM permission architecture, helping the attacker understand what actions are available and what controls need to be bypassed |

---
id: aws-iam-listattachedrolepolicies
api_call: iam:ListAttachedRolePolicies
required_inputs:
  - INCIDENT_START_TIME
  - ROLE_NAME
  - ACCOUNT_ID
provided_outputs:
  - ATTACHED_POLICY_ARNS
  - ATTACHED_POLICY_NAMES
  - SOURCE_IP
---

# Playbook: Managed Policy Enumeration via ListAttachedRolePolicies

**ID:** PB-AWS-IAM-ListAttachedRolePolicies-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:ListAttachedRolePolicies` to enumerate all managed policies attached to an IAM role, identifying which policies to detach or determining the role's permission scope before exploitation.
- **Trigger:** CloudTrail event `ListAttachedRolePolicies` from an unrecognized source IP, from a non-admin principal, or followed by `DetachRolePolicy` within 10 minutes.
- **Severity Matrix:**
  - **CRITICAL:** `ListAttachedRolePolicies` followed by `DetachRolePolicy` AND `DeleteRole` within 15 minutes from an external IP. **Action:** Wake CISO & Legal immediately — attacker executing role destruction chain.
  - **HIGH:** `ListAttachedRolePolicies` from an external IP targeting a role attached to production workloads. **Action:** Immediate IR team response.
  - **MEDIUM:** `ListAttachedRolePolicies` from an unrecognized principal on an internal IP with no follow-up actions. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, IAM Access Analyzer
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
  - T1580: Cloud Infrastructure Discovery
- **Stakeholders:** Security Engineering, Cloud Platform Team; escalate to CISO if correlated with policy detachment
- **SLA Target:** Triage: 30 mins (standalone), 15 mins (if correlated with subsequent `DetachRolePolicy`)
- **Compliance:** Standalone enumeration does not trigger reporting clocks. If part of a role destruction chain, SOC 2 incident logging begins at detection.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who enumerated the role's policies?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListAttachedRolePolicies \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, and `requestParameters.roleName`.

- [ ] **Role Context:** What is this role used for? Is it attached to production services?
  ```bash
  aws iam get-role --role-name <ROLE_NAME>
  aws iam list-role-tags --role-name <ROLE_NAME>
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  ```

- [ ] **Subsequent Activity:** Did the same caller detach policies or delete the role?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \
    --start-time <EVENT_TIME> --max-results 20
  ```

- [ ] **Broader Reconnaissance:** Did the same caller enumerate policies on multiple roles?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListAttachedRolePolicies \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND matches IAM audit schedule: **Mark False Positive & Close.**
- IF `Source_IP == External` AND followed by `DetachRolePolicy` within 10 minutes: **Go to Containment Level 2 (IMMEDIATE) — active policy stripping.**
- IF `Source_IP == External` AND no follow-up destructive actions: **Go to Investigation — reconnaissance phase.**
- IF multiple roles enumerated from the same principal within 5 minutes: **Go to Containment Level 1 — automated reconnaissance tooling.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Anomalous enumeration, no follow-up actions | **Deny IAM read actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:List*","iam:Get*"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR` |
| **L2 (Hard)** | Enumeration followed by `DetachRolePolicy` | **Deny all IAM actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR` |
| **L3 (Nuclear)** | Confirmed credential compromise with active role destruction | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **Which role's policies were enumerated?** Confirm the target role and its current policy state:
  ```bash
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  aws iam list-role-policies --role-name <ROLE_NAME>
  ```

- **Were policies subsequently detached or the role deleted?** Check for the full destruction chain:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \
    --start-time <EVENT_TIME> --max-results 50
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRole \
    --start-time <EVENT_TIME> --max-results 10
  ```

- **Were multiple roles targeted?** Check for mass enumeration:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListAttachedRolePolicies \
    --start-time <INCIDENT_START_TIME> --max-results 100
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('ListAttachedRolePolicies', 'DetachRolePolicy', 'DeleteRole')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-listrpolicies-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-listrpolicies-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-listrpolicies-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-listrpolicies-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the caller:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** `ListAttachedRolePolicies` is read-only — no resource damage to reverse. If subsequent `DetachRolePolicy` was detected, refer to PB-AWS-IAM-DetachRolePolicy-01 for restoration steps.

3. **Harden (The "Never Again" Fix):**
   - **Restrict IAM enumeration** to admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:ListAttachedRolePolicies", "iam:ListRolePolicies"],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": ["SecurityAdmin", "IAMAdmin"] }
         }
       }]
     }
     ```
   - **Enable IAM Access Analyzer** to monitor for permission changes.

4. **Verify:** Attempt `ListAttachedRolePolicies` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam list-attached-role-policies --role-name <ROLE_NAME>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `ListAttachedRolePolicies` alerted on? (Yes/No)
   - Did the caller subsequently detach or delete any policies? (Yes/No)
   - Were multiple roles targeted in the same session?
   - Time from enumeration to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM ListAttachedRolePolicies Enumeration
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9012
status: experimental
level: medium
description: Detects iam:ListAttachedRolePolicies calls which enumerate managed policies attached to an IAM role. Attackers use this to identify policies to detach before deleting the role, or to understand the role's permission scope for exploitation.
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
    eventName: ListAttachedRolePolicies
  condition: selection
falsepositives:
  - IAM administrators auditing role configurations
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) reading role state during plan operations
  - IAM Access Analyzer scanning role policies
  - AWS Config rules evaluating role compliance
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Discovery | `ListAttachedRolePolicies` reveals the managed policies attached to a role, exposing the role's permission scope and which policies need to be detached before the role can be deleted |
| T1580 | Cloud Infrastructure Discovery | Discovery | Enumerating role policies exposes the IAM architecture, helping the attacker understand permission boundaries and identify targets for policy detachment or role destruction |

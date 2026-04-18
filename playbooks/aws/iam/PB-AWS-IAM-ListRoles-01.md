---
id: aws-iam-listroles
api_call: iam:ListRoles
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - CALLER_ARN
provided_outputs:
  - ENUMERATED_ROLE_NAMES
  - ENUMERATED_ROLE_ARNS
---

# Playbook: IAM Role Enumeration via ListRoles

**ID:** PB-AWS-IAM-ListRoles-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:ListRoles` to enumerate all IAM roles in the account, identifying targets for privilege escalation (via `AssumeRole` or `AttachRolePolicy`) or lateral movement to cross-account roles.
- **Trigger:** CloudTrail event `ListRoles` from an unrecognized source IP, from a principal that does not normally enumerate IAM, or followed by `AssumeRole` / `AttachRolePolicy` within 10 minutes.
- **Severity Matrix:**
  - **CRITICAL:** `ListRoles` followed by `AssumeRole` on a high-privilege role AND `AttachRolePolicy` with `AdministratorAccess` within 10 minutes. **Action:** Wake CISO & Legal immediately — active privilege escalation chain.
  - **HIGH:** `ListRoles` from an external IP followed by `AssumeRole` or `AttachRolePolicy` within 10 minutes. **Action:** Immediate IR team response.
  - **MEDIUM:** `ListRoles` from an unrecognized principal or external IP with no follow-up escalation activity within 15 minutes. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, IAM Access Analyzer
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
  - T1580: Cloud Infrastructure Discovery
- **Stakeholders:** Security Engineering, Cloud Platform Team; escalate to CISO if correlated with privilege escalation
- **SLA Target:** Triage: 30 mins (standalone), 15 mins (if correlated with subsequent `AssumeRole`/`AttachRolePolicy`)
- **Compliance:** Standalone enumeration does not trigger reporting clocks. If part of a confirmed compromise chain, SOC 2 incident logging begins at detection.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who called `ListRoles`? Is this a known admin, CI/CD service account, or unknown principal?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListRoles \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, and `userAgent`.

- [ ] **Permission Check:** Does this principal normally have `iam:ListRoles` permissions? Is it part of their job function?
  ```bash
  aws iam simulate-principal-policy \
    --policy-source-arn <CALLER_ARN> \
    --action-names iam:ListRoles
  ```

- [ ] **Subsequent Activity:** Did the same principal call `AssumeRole` or `AttachRolePolicy` within 10 minutes?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --end-time <EVENT_TIME_PLUS_10MIN> \
    --max-results 50
  ```

- [ ] **Frequency Check:** Is this a single call or part of a reconnaissance burst? Multiple enumeration calls (`ListRoles`, `ListUsers`, `ListPolicies`) within a short window indicate automated tooling.

- [ ] **Threat Intel:** Check the source IP against threat intelligence and corporate IP ranges.

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND `ListRoles` matches a scheduled audit or IaC operation: **Mark False Positive & Close.**
- IF `Source_IP == External` AND followed by `AssumeRole` on a high-privilege role within 10 minutes: **Go to Containment Level 2 (IMMEDIATE) — active escalation chain.**
- IF `Source_IP == External` AND no follow-up escalation activity within 15 minutes: **Go to Investigation — early-stage reconnaissance.**
- IF multiple enumeration calls (`ListRoles`, `ListUsers`, `ListPolicies`, `ListGroups`) from the same principal within 5 minutes: **Go to Containment Level 1 — automated reconnaissance tooling.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Anomalous `ListRoles` from external IP, no follow-up actions yet | **Deny IAM read actions for the principal:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:List*","iam:Get*"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR` |
| **L2 (Hard)** | `ListRoles` followed by `AssumeRole` or `AttachRolePolicy` from external IP | **Deny all actions for the principal:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Confirmed credential compromise with active privilege escalation chain | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM principal is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What roles were returned?** If the attacker used `MaxItems` parameter, determine how many roles they enumerated:
  ```bash
  aws iam list-roles --max-items 10
  ```

- **What did they do with the results?** Check if the same principal attempted `AssumeRole`, `GetRole`, or `AttachRolePolicy` on any of the enumerated roles:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <LISTROLES_TIME> --end-time <LISTROLES_TIME_PLUS_30MIN> \
    --max-results 100
  ```

- **Broader reconnaissance scope:** Did the same principal also enumerate users, policies, or groups?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <WINDOW_START> --end-time <WINDOW_END> \
    --max-results 200
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.maxItems') AS max_items,
       errorcode
FROM cloudtrail_logs
WHERE eventname = 'ListRoles'
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

**Correlated query — full enumeration-to-escalation chain:**

```sql
SELECT eventtime, eventname, eventsource, sourceipaddress,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn
FROM cloudtrail_logs
WHERE useridentity.arn = '<CALLER_ARN>'
  AND eventname IN ('ListRoles', 'AssumeRole', 'AttachRolePolicy', 'GetRole')
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-rolesenum-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-rolesenum-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-rolesenum-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-rolesenum-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the affected principal:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** `ListRoles` is read-only — no resource damage to reverse. Focus on blocking the attacker from acting on the enumerated intelligence.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:ListRoles` to least privilege** — most workloads don't need to enumerate all roles. Use IAM policies to deny `iam:List*` for non-admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": [
           "iam:ListRoles",
           "iam:ListUsers",
           "iam:ListPolicies",
           "iam:ListGroups"
         ],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": ["SecurityAdmin", "IAMAdmin"] }
         }
       }]
     }
     ```
   - **Enable IAM Access Analyzer** to continuously monitor for overly permissive role configurations the attacker could target.
   - **Implement permission boundaries** on all non-admin roles to limit the blast radius even if they are assumed.

4. **Verify:** Attempt `ListRoles` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam list-roles --max-items 1
   # Expected: AccessDenied (if SCP/policy is in place)
   ```

5. **Post-Mortem:**
   - Was `ListRoles` alerted on, or was it only detected during investigation? (Alerted/Manual)
   - Did the principal have `iam:ListRoles` permission by design or by overly broad policy?
   - Were the enumerated roles appropriately scoped with permission boundaries?
   - How were the credentials initially compromised?
   - Time from `ListRoles` event to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM ListRoles Enumeration from External IP
id: f6a7b8c9-d0e1-2f3a-4b5c-6d7e8f901234
status: experimental
level: medium
description: Detects iam:ListRoles calls which enumerate all IAM roles in the account. Attackers use this to identify targets for privilege escalation via AssumeRole or AttachRolePolicy. Most legitimate workloads do not need to list all roles.
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
    eventName: ListRoles
  condition: selection
falsepositives:
  - IAM administrators performing routine audits of role configurations
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) listing roles during plan/import operations
  - AWS Config rules evaluating IAM role compliance
  - IAM Access Analyzer scanning role trust policies
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Discovery | `ListRoles` reveals all IAM roles in the account including their ARNs, trust policies, and descriptions — providing a target list for privilege escalation |
| T1580 | Cloud Infrastructure Discovery | Discovery | Enumerating IAM roles exposes the account's identity architecture, revealing cross-account trust relationships, service roles, and potential pivot points |

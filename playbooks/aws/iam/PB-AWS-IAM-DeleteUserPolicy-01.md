---
id: aws-iam-deleteuserpolicy
api_call: iam:DeleteUserPolicy
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - POLICY_NAME
  - ACCOUNT_ID
provided_outputs:
  - DELETED_POLICY_NAME
  - POLICY_DOCUMENT_BACKUP
  - SOURCE_IP
---

# Playbook: Unauthorized Inline Policy Deletion via DeleteUserPolicy

**ID:** PB-AWS-IAM-DeleteUserPolicy-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:DeleteUserPolicy` to remove an inline IAM policy from a user — weakening security controls, removing deny policies that restrict the attacker, or stripping audit/compliance policies to operate undetected.
- **Trigger:** CloudTrail event `DeleteUserPolicy` from an unrecognized source IP, targeting a policy with "Deny" statements, or preceded by `ListUserPolicies` enumeration within 10 minutes.
- **Severity Matrix:**
  - **CRITICAL:** Deleted policy contained `"Effect": "Deny"` statements restricting sensitive actions (`iam:*`, `s3:*`, `sts:*`). **Action:** Wake CISO & Legal immediately — attacker is dismantling security guardrails.
  - **HIGH:** `DeleteUserPolicy` from an external IP or by a principal other than the policy's target user. **Action:** Immediate IR team response.
  - **MEDIUM:** `DeleteUserPolicy` from an internal IP that doesn't correlate with a change management ticket. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1562.007: Impair Defenses: Disable or Modify Cloud Firewall
  - T1070: Indicator Removal
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team, Compliance (if deleted policy enforced regulatory controls)
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the deleted policy enforced GDPR/CCPA/SOC 2 controls, compliance team must be notified within 1 hour. Regulatory reporting clocks may start.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who deleted the policy?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUserPolicy \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn` (caller), `requestParameters.userName` (target user), and `requestParameters.policyName` (deleted policy).

- [ ] **Policy Content:** What did the deleted policy contain? Retrieve from CloudTrail `requestParameters` or AWS Config history:
  ```bash
  aws configservice get-resource-config-history \
    --resource-type AWS::IAM::User \
    --resource-id <USERNAME> \
    --limit 10
  ```

- [ ] **Preceding Enumeration:** Was this preceded by `ListUserPolicies`?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUserPolicies \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```

- [ ] **Subsequent Activity:** What did the caller do after removing the policy? Check for privilege escalation:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --max-results 100
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND matches change management ticket: **Mark False Positive & Close.**
- IF deleted policy contained `Deny` statements AND `Source_IP == External`: **Go to Containment Level 2 (IMMEDIATE) — attacker removing security controls.**
- IF preceded by `ListUserPolicies` from same IP within 10 minutes: **Go to Containment Level 2 — deliberate enumerate-and-delete chain.**
- IF `Caller == Policy_Owner` AND `Source_IP == Internal` AND no subsequent suspicious activity: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Policy deletion detected, unknown intent | **Re-apply the deleted policy immediately:** `aws iam put-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME> --policy-document '<POLICY_DOCUMENT_BACKUP>'` AND deny further policy modifications: `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyPolicyMod-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:DeleteUserPolicy","iam:PutUserPolicy"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyPolicyMod-IR` |
| **L2 (Hard)** | Confirmed attacker removing security policies | **Deny all actions for the caller AND restore the deleted policy:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Multiple policies deleted, active exploitation confirmed | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What policies remain on the user?** Verify current policy state:
  ```bash
  aws iam list-user-policies --user-name <USERNAME>
  aws iam list-attached-user-policies --user-name <USERNAME>
  ```

- **Were other users' policies deleted?** Check for cross-user policy stripping:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUserPolicy \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **What actions were taken after the policy was removed?** The attacker may have removed a deny policy to enable previously blocked actions:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --max-results 200
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(requestparameters, '$.policyName') AS policy_name,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('DeleteUserPolicy', 'ListUserPolicies', 'PutUserPolicy', 'GetUserPolicy')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-delpolicy-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-delpolicy-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-delpolicy-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-delpolicy-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the affected user:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** Re-apply the deleted inline policy using the backed-up policy document:
   ```bash
   aws iam put-user-policy --user-name <USERNAME> \
     --policy-name <POLICY_NAME> \
     --policy-document '<POLICY_DOCUMENT_BACKUP>'
   ```
   Verify the restored policy matches the original:
   ```bash
   aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME>
   ```

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:DeleteUserPolicy`** via SCP for non-admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:DeleteUserPolicy", "iam:DeleteRolePolicy"],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": "SecurityAdmin" }
         }
       }]
     }
     ```
   - **Use managed policies instead of inline policies** — managed policies are versioned and easier to audit/restore.
   - **Enable AWS Config** to track IAM policy changes and trigger alerts on deletion.

4. **Verify:** Attempt `DeleteUserPolicy` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam delete-user-policy --user-name <USERNAME> --policy-name <POLICY_NAME>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `DeleteUserPolicy` alerted on? (Yes/No)
   - Was the deleted policy content preserved in CloudTrail or AWS Config? (Yes/No)
   - Was this part of an eventual consistency exploitation chain? (Yes/No)
   - Time from policy deletion to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM Inline User Policy Deleted
id: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f90
status: experimental
level: high
description: Detects iam:DeleteUserPolicy calls which remove inline policies from IAM users. Attackers delete policies to weaken security controls, remove deny statements that restrict their actions, or strip compliance-enforcing policies during eventual consistency window exploitation.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.defense_evasion
  - attack.t1562.007
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: DeleteUserPolicy
  condition: selection
falsepositives:
  - IAM administrators removing deprecated or redundant inline policies during cleanup
  - Infrastructure-as-code tools removing inline policies as part of migration to managed policies
  - Automated policy lifecycle management
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion | `DeleteUserPolicy` removes IAM policies that may contain deny statements restricting the attacker's actions — effectively disabling IAM-based security controls |
| T1070 | Indicator Removal | Defense Evasion | Deleting policies can remove audit-enforcing or logging-related IAM controls, reducing the attacker's footprint |

---
id: aws-iam-deleteaccesskey
api_call: iam:DeleteAccessKey
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCESS_KEY_ID
  - ACCOUNT_ID
provided_outputs:
  - DELETED_KEY_ID
  - DELETION_TIME
  - SOURCE_IP
---

# Playbook: Unauthorized IAM Access Key Deletion

**ID:** PB-AWS-IAM-DeleteAccessKey-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:DeleteAccessKey` to destroy a user's legitimate access keys — either to lock out the legitimate user (denial of service), cover tracks by removing the compromised key, or as part of an eventual consistency exploitation where deleted credentials remain usable during the propagation window.
- **Trigger:** CloudTrail event `DeleteAccessKey` from an unrecognized source IP, by a principal other than the key owner, or followed by immediate `CreateAccessKey` (key rotation by attacker).
- **Severity Matrix:**
  - **CRITICAL:** `DeleteAccessKey` by a non-owner principal AND followed by `CreateAccessKey` within 5 minutes — attacker is rotating keys to lock out the legitimate user. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** `DeleteAccessKey` from an external IP targeting a service account or production user's keys. **Action:** Immediate IR team response.
  - **MEDIUM:** `DeleteAccessKey` from an internal IP that doesn't match a scheduled rotation. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1531: Account Access Removal
  - T1070.004: Indicator Removal: File Deletion
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the key deletion disrupts production services or locks out legitimate users, SOC 2 incident logging is mandatory.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who deleted the key? Was it the key owner or a different principal?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn` (caller) and `requestParameters.userName` + `requestParameters.accessKeyId` (target).

- [ ] **Key Status Context:** Was this the user's only active key? Are they now locked out?
  ```bash
  aws iam list-access-keys --user-name <USERNAME>
  ```

- [ ] **Subsequent Activity:** Did the same caller immediately create a new key (attacker key rotation)?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --start-time <DELETION_TIME> --max-results 10
  ```

- [ ] **Eventual Consistency Check:** Was the deleted key used for API calls after deletion (exploitation of propagation delay)?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <DELETION_TIME> --max-results 100 \
    --query 'Events[?contains(CloudTrailEvent, `<DELETED_KEY_ID>`)]'
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Key_Owner` AND `Source_IP == Corporate_VPN` AND matches scheduled rotation: **Mark False Positive & Close.**
- IF `Caller != Key_Owner` AND followed by `CreateAccessKey` within 5 minutes: **Go to Containment Level 3 (IMMEDIATE) — attacker key takeover.**
- IF `Deleted_Key used after deletion` (eventual consistency exploitation): **Go to Containment Level 2 — active exploitation of propagation window.**
- IF `Caller == Key_Owner` AND `Source_IP == External`: **Go to Investigation — possible compromised credentials performing cleanup.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious key deletion, no confirmed attacker key creation | **Deny further IAM key operations for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyKeyOps-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreateAccessKey","iam:DeleteAccessKey","iam:UpdateAccessKey"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyKeyOps-IR` |
| **L2 (Hard)** | Deleted key being exploited during consistency window | **Deny all actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Cross-user key deletion + attacker created replacement key | **Deactivate ALL keys for the affected user AND delete the attacker-created key:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **Was the deleted key used after deletion?** Check for eventual consistency exploitation:
  ```bash
  aws cloudtrail lookup-events \
    --start-time <DELETION_TIME> --max-results 200 \
    --query 'Events[?contains(CloudTrailEvent, `<DELETED_KEY_ID>`)]'
  ```

- **Were other users' keys deleted?** Check for mass key deletion across IAM users:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **Was a replacement key created?** Identify any attacker-created keys:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(requestparameters, '$.accessKeyId') AS deleted_key_id,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('DeleteAccessKey', 'CreateAccessKey', 'UpdateAccessKey')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-deletekey-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-deletekey-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-deletekey-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-deletekey-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Create a new access key for the legitimate user to restore their access:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   ```
   If an attacker-created replacement key exists, delete it:
   ```bash
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <CREATED_ACCESS_KEY_ID>
   ```

2. **Restore:** If the deleted key was the user's only active key, they are locked out of API access. Issue a new key and distribute it securely. Update any services/applications that relied on the deleted key.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:DeleteAccessKey`** to the key owner and IAM admins only:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "iam:DeleteAccessKey",
         "Resource": "arn:aws:iam::*:user/${aws:username}",
         "Condition": {
           "StringNotEquals": { "aws:PrincipalTag/Role": "IAMAdmin" },
           "StringNotEquals": { "aws:username": "${aws:username}" }
         }
       }]
     }
     ```
   - **Enable CloudTrail alerting** for `DeleteAccessKey` events targeting service accounts.
   - **Implement credential last-used monitoring** to detect orphaned or unused keys before they become targets.

4. **Verify:** Attempt `DeleteAccessKey` from a non-admin, non-owner principal and confirm it is denied:
   ```bash
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `DeleteAccessKey` alerted on? (Yes/No)
   - Was the deleted key used after deletion (eventual consistency window)? (Yes/No)
   - Was a replacement key created by the attacker? (Yes/No)
   - How long between key deletion and IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM Access Key Deleted by Non-Owner Principal
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
level: high
description: Detects iam:DeleteAccessKey calls which remove long-term AWS credentials. Attackers delete keys to lock out legitimate users, cover tracks, or exploit the eventual consistency window where deleted credentials remain temporarily usable.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1531
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: DeleteAccessKey
  condition: selection
falsepositives:
  - Scheduled credential rotation by IAM administrators
  - Automated key lifecycle management tools
  - Users rotating their own access keys as part of security hygiene
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1531 | Account Access Removal | Impact | `DeleteAccessKey` removes a user's API credentials, potentially locking them out of programmatic access to AWS |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion | Deleting the compromised access key removes the credential artifact that would link the attacker's activity to a specific key ID |

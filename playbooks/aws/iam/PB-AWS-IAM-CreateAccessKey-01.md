---
id: aws-iam-createaccesskey
api_call: iam:CreateAccessKey
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
provided_outputs:
  - CREATED_ACCESS_KEY_ID
  - KEY_CREATION_TIME
  - SOURCE_IP
---

# Playbook: Unauthorized IAM Access Key Creation

**ID:** PB-AWS-IAM-CreateAccessKey-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:CreateAccessKey` to generate new long-term credentials for a compromised IAM user, establishing persistent access that survives password resets and session revocations.
- **Trigger:** CloudTrail event `CreateAccessKey` from an unrecognized source IP, for a user who already has 2 active keys, or by a principal other than the key owner.
- **Severity Matrix:**
  - **CRITICAL:** `CreateAccessKey` called by a principal other than the key owner (cross-user key creation) AND source IP is external. **Action:** Wake CISO & Legal immediately — attacker is establishing persistent backdoor access.
  - **HIGH:** `CreateAccessKey` for a user who already has 2 active access keys (AWS maximum), or creation from an external IP during non-business hours. **Action:** Immediate IR team response.
  - **MEDIUM:** `CreateAccessKey` from an internal IP for a user's own account but outside normal credential rotation schedules. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, Threat Intel feeds
- **MITRE ATT&CK Mapping:**
  - T1098.001: Account Manipulation: Additional Cloud Credentials
  - T1136.003: Create Account: Cloud Account
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team; Legal if the user has access to regulated data
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the compromised user has access to PII/financial data stores, SOC 2 incident logging is mandatory. GDPR/CCPA clocks start if data access is confirmed.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who created the key? Was it the user themselves or a different principal?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn` (the caller) and `requestParameters.userName` (the target user). If they differ, this is cross-user key creation — high severity.

- [ ] **Existing Keys:** How many active keys does this user already have?
  ```bash
  aws iam list-access-keys --user-name <USERNAME>
  ```

- [ ] **IP Reputation:** Check the source IP against threat intelligence and corporate IP ranges.

- [ ] **Timing Context:** Does this align with a scheduled credential rotation? Check change management tickets.

- [ ] **Subsequent Activity:** Did the newly created key get used immediately?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <KEY_CREATION_TIME> --max-results 50 \
    --query 'Events[?contains(CloudTrailEvent, `<CREATED_ACCESS_KEY_ID>`)]'
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Key_Owner` AND `Source_IP == Corporate_VPN` AND matches scheduled rotation window: **Mark False Positive & Close.**
- IF `Caller != Key_Owner` AND `Source_IP == External`: **Go to Containment Level 3 (IMMEDIATE) — backdoor credential creation.**
- IF `Caller == Key_Owner` AND `Source_IP == External` AND key used within minutes of creation: **Go to Containment Level 2 — compromised user creating persistence.**
- IF `Caller == Key_Owner` AND `Source_IP == Internal` AND no subsequent suspicious activity: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious key creation, no confirmed abuse yet | **Deactivate the newly created key:** `aws iam update-access-key --user-name <USERNAME> --access-key-id <CREATED_ACCESS_KEY_ID> --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <CREATED_ACCESS_KEY_ID> --status Active` |
| **L2 (Hard)** | Confirmed unauthorized key creation, key already in use | **Delete the unauthorized key AND deny CreateAccessKey:** `aws iam delete-access-key --user-name <USERNAME> --access-key-id <CREATED_ACCESS_KEY_ID>` AND `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyCreateAccessKey-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyCreateAccessKey-IR` |
| **L3 (Nuclear)** | Cross-user key creation confirmed — attacker has IAM write access | **Deactivate ALL access keys for the target user AND the calling principal:** For each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **Was the new key used?** Track all API calls made with the created access key:
  ```bash
  aws cloudtrail lookup-events \
    --start-time <KEY_CREATION_TIME> --max-results 200 \
    --query 'Events[?contains(CloudTrailEvent, `<CREATED_ACCESS_KEY_ID>`)]'
  ```

- **Were keys created for other users?** Check if the attacker created keys across multiple IAM users:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **Current key inventory:** List all access keys for the affected user to identify any other unauthorized keys:
  ```bash
  aws iam list-access-keys --user-name <USERNAME>
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS created_key_id,
       errorcode
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey'
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-createkey-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-createkey-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-createkey-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-createkey-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Delete the unauthorized access key and rotate all remaining keys for the affected user:
   ```bash
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <CREATED_ACCESS_KEY_ID>
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** `CreateAccessKey` creates a credential — no data damage to reverse. Focus on ensuring the unauthorized key was never used to modify resources. If it was, follow the relevant service-specific playbooks.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:CreateAccessKey`** via SCP so only authorized principals can create keys:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "iam:CreateAccessKey",
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": ["SecurityAdmin", "IAMAdmin"] }
         }
       }]
     }
     ```
   - **Enforce maximum key age** via AWS Config rule `access-keys-rotated` (max 90 days).
   - **Limit to 1 active key per user** via monitoring — alert when a user has 2 active keys.

4. **Verify:** Attempt `CreateAccessKey` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `CreateAccessKey` monitored and alerted on? (Yes/No)
   - Was the key created by the user themselves or a different principal?
   - How long was the unauthorized key active before detection?
   - Were there any controls preventing cross-user key creation?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM Access Key Created for Another User
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
level: high
description: Detects iam:CreateAccessKey calls which generate new long-term AWS credentials. Attackers use this to establish persistent access that survives session revocation and password resets. Cross-user key creation (caller != target) is particularly suspicious.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.persistence
  - attack.t1098.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateAccessKey
  condition: selection
falsepositives:
  - Scheduled credential rotation by IAM administrators
  - CI/CD pipelines creating service account keys during initial setup
  - AWS Organizations creating keys for new member accounts
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | `CreateAccessKey` generates new long-term credentials (AccessKeyId + SecretAccessKey) that provide persistent API access independent of console passwords or session tokens |
| T1136.003 | Create Account: Cloud Account | Persistence | Creating access keys effectively creates a new authentication path for the IAM user, functioning as an alternate credential set |

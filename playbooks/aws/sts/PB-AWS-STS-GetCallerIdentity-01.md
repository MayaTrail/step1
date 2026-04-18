---
id: aws-sts-getcalleridentity
api_call: sts:GetCallerIdentity
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
provided_outputs:
  - CALLER_ARN
  - ACCOUNT_ID
  - USER_ID
  - SOURCE_IP
---

# Playbook: Identity Probe via STS GetCallerIdentity

**ID:** PB-AWS-STS-GetCallerIdentity-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An unauthorized actor calls `sts:GetCallerIdentity` to discover the compromised principal's ARN, account ID, and user ID — typically the first action after obtaining stolen credentials.
- **Trigger:** CloudTrail event `GetCallerIdentity` from an unrecognized source IP, outside business hours, or at anomalous frequency (>5 calls within 1 minute from the same principal).
- **Severity Matrix:**
  - **CRITICAL:** `GetCallerIdentity` from an external IP followed by `AssumeRole` or `AttachRolePolicy` within 5 minutes. **Action:** Wake CISO & Legal immediately — active compromise chain in progress.
  - **HIGH:** `GetCallerIdentity` from an external/unknown IP outside business hours with no matching CI/CD pipeline execution. **Action:** Immediate IR team response.
  - **MEDIUM:** `GetCallerIdentity` from an unrecognized user agent (not AWS SDK/CLI default) but from an internal IP range. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, Threat Intel feeds (GreyNoise, VirusTotal)
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
  - T1082: System Information Discovery
- **Stakeholders:** Security Engineering, Cloud Platform Team; escalate to CISO if followed by privilege escalation activity
- **SLA Target:** Triage: 30 mins (standalone), 15 mins (if correlated with subsequent suspicious API calls)
- **Compliance:** Standalone `GetCallerIdentity` does not trigger reporting clocks. If part of a confirmed compromise chain, SOC 2 incident logging begins at detection.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who made the call? Is this a known service account, CI/CD pipeline, or human user?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract the `userIdentity.arn` and `sourceIPAddress` from results.

- [ ] **IP Reputation:** Check the source IP against threat intelligence and corporate VPN/office IP ranges:
  ```bash
  # Extract source IPs from recent GetCallerIdentity events
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
    --start-time <24H_AGO> --max-results 50 \
    --query 'Events[].{IP:CloudTrailEvent}' --output json
  ```

- [ ] **User Agent Analysis:** Is the user agent a standard AWS SDK (e.g., `aws-cli/2.x`, `Boto3/1.x`) or a custom/unusual tool?

- [ ] **Frequency Analysis:** Is this a single call or part of a burst? More than 5 calls in 60 seconds from the same principal is anomalous.

- [ ] **Subsequent Activity:** Check if the same principal made additional API calls within 5 minutes:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --end-time <EVENT_TIME_PLUS_5MIN> \
    --max-results 50
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Source_IP == Corporate_VPN` AND `UserAgent == Known_SDK` AND call matches a scheduled pipeline execution: **Mark False Positive & Close.**
- IF `Source_IP == External` AND followed by `AssumeRole` or `AttachRolePolicy` within 5 minutes: **Go to Containment Level 2 (IMMEDIATE) — active compromise chain.**
- IF `Source_IP == External` AND no subsequent suspicious activity within 15 minutes: **Go to Investigation — possible credential testing or early-stage reconnaissance.**
- IF `Frequency > 5 calls/min` from same principal: **Go to Containment Level 1 — automated tooling probing the account.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Anomalous `GetCallerIdentity` from external IP, no follow-up actions yet | **Add deny policy for STS calls:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenySTS-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"sts:*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenySTS-IR` |
| **L2 (Hard)** | `GetCallerIdentity` followed by `AssumeRole` from external IP | **Deny all actions for the user:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Confirmed credential compromise with active follow-on exploitation | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **Which principal was probed?** Confirm the full ARN returned by the identity call:
  ```bash
  aws sts get-caller-identity
  ```

- **What did the principal do next?** Track all API calls from the same identity within a 30-minute window:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <EVENT_TIME> --end-time <EVENT_TIME_PLUS_30MIN> \
    --max-results 100
  ```

- **Were other credentials tested?** Check if the same source IP called `GetCallerIdentity` with different credentials (credential stuffing):
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
    --start-time <WINDOW_START> --end-time <WINDOW_END> \
    --max-results 100
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       useridentity.accountid AS account_id,
       errorcode, errormessage
FROM cloudtrail_logs
WHERE eventname = 'GetCallerIdentity'
  AND eventsource = 'sts.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-identityprobe-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-identityprobe-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-identityprobe-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-identityprobe-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the affected user:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** `GetCallerIdentity` is read-only — no resource damage to reverse. Focus on preventing the attacker from using the intelligence gathered (ARN, account ID) in subsequent attacks.

3. **Harden (The "Never Again" Fix):**
   - **Enforce MFA on all human user credentials** — compromised long-term keys without MFA are the primary vector:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*",
         "Condition": {
           "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
         }
       }]
     }
     ```
   - **Implement credential rotation policy** — enforce maximum key age of 90 days via AWS Config rule `access-keys-rotated`.
   - **Enable GuardDuty anomaly detection** for unusual API call patterns.

4. **Verify:** Confirm the old access keys are deactivated and the user can only authenticate with new credentials + MFA:
   ```bash
   aws iam list-access-keys --user-name <USERNAME>
   # Confirm only the new key exists and status is Active
   ```

5. **Post-Mortem:**
   - Was `GetCallerIdentity` logged and alerted on? (Yes/No)
   - Did the alert correlate with subsequent `AssumeRole` / `AttachRolePolicy` events? (Yes/No)
   - How were the credentials initially compromised? (leaked in code, phishing, metadata service)
   - Time from `GetCallerIdentity` event to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS GetCallerIdentity from External IP
id: d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90
status: experimental
level: medium
description: Detects sts:GetCallerIdentity calls which are commonly the first action an attacker takes after obtaining compromised AWS credentials. Alone this is low severity, but it is a strong indicator when correlated with subsequent privilege escalation activity.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1087.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: GetCallerIdentity
  condition: selection
falsepositives:
  - AWS SDKs (boto3, AWS CLI) automatically calling GetCallerIdentity for credential validation on session startup
  - CI/CD pipelines verifying identity before assuming deployment roles
  - Terraform/Pulumi/CloudFormation providers validating credentials during plan/preview operations
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Discovery | `GetCallerIdentity` reveals the principal's ARN, account ID, and user ID — core reconnaissance data for targeting subsequent privilege escalation or lateral movement |
| T1082 | System Information Discovery | Discovery | The account ID and ARN structure expose organizational information (account naming conventions, IAM architecture) useful for planning further attacks |

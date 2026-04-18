---
id: aws-s3-deleteobjects
api_call: s3:DeleteObjects
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
provided_outputs:
  - DELETED_OBJECT_KEYS
  - DELETION_COUNT
  - SOURCE_IP
---

# Playbook: Unauthorized Bulk S3 Object Deletion via DeleteObjects

**ID:** PB-AWS-S3-DeleteObjects-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized Bulk S3 Object Deletion via DeleteObjects
- **Playbook ID:** PB-AWS-S3-DeleteObjects-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity performs bulk object deletion from S3 buckets using the `DeleteObjects` API, potentially as part of a ransomware operation, sabotage, or evidence destruction.
- **Trigger:** CloudTrail S3 data event where `eventName == DeleteObjects` from an unexpected identity, or any DeleteObjects call against a bucket tagged `DataClassification:PII` or `Critical-Production-App`.
- **Severity Matrix:**
  - **CRITICAL:** DeleteObjects called against a bucket tagged `DataClassification:PII` or `Critical-Production-App` AND >50 objects deleted in a single call. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** DeleteObjects called by an identity with no prior delete permissions or from a non-corporate IP. **Action:** Immediate IR team response.
  - **MEDIUM:** DeleteObjects against a non-sensitive dev/test bucket by a known identity. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:Get*`, `s3:List*`, `s3:PutBucketPolicy`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail S3 data events MUST be enabled; S3 versioning must be enabled for recovery
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1485** — Data Destruction (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance, Legal, CISO
- **SLA Target:** Triage within 15 minutes; CRITICAL severity: immediate response
- **Compliance:** GDPR Article 33, SOC2 CC6.1, potential regulatory reporting for data loss

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who performed the deletion?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObjects \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Bucket Context:** Is versioning enabled (can we recover)?
  ```bash
  aws s3api get-bucket-versioning --bucket <BUCKET_NAME>
  ```

- [ ] **Deletion Scale:** How many objects were targeted?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `DeleteObjects`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters'
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObjects \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Preceding Activity:** Was this preceded by ListObjects/GetObject (exfil-then-destroy pattern)?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == CI/CD pipeline` AND `Bucket == build-artifacts` AND `within deployment window` → **Mark False Positive & Close.**
- **IF** `Bucket tagged Critical-Production-App or PII` → **Proceed to Containment Level 2 IMMEDIATELY.**
- **IF** `>50 objects deleted` AND `preceded by GetObject (exfil-then-destroy)` → **Proceed to Containment Level 3.**
- **IF** `Known identity, small deletion count, non-sensitive bucket` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Small deletion, known identity | **Deny delete operations for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyS3Delete --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteObjects"],"Resource":"arn:aws:s3:::*/*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyS3Delete` |
| **L2 (Hard)** | Sensitive bucket or unauthorized identity | **Lock bucket and disable keys:**`aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:DeleteObject","s3:DeleteObjects"],"Resource":"arn:aws:s3:::<BUCKET_NAME>/*","Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"}}}]}'` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws s3api delete-bucket-policy --bucket <BUCKET_NAME>` and `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransomware pattern (exfil + delete + ransom upload) | **Full deny, lock all buckets, revoke all sessions:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws s3api get-bucket-tagging --bucket <BUCKET_NAME> --query 'TagSet[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **List deleted objects** (requires versioning to be enabled):
  ```bash
  aws s3api list-object-versions --bucket <BUCKET_NAME> \
    --query 'DeleteMarkers[*].[Key,VersionId,LastModified,IsLatest]' --output table
  ```

- **Quantify the damage:**
  ```bash
  aws s3api list-object-versions --bucket <BUCKET_NAME> \
    --query 'length(DeleteMarkers[?IsLatest==`true`])'
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
    requestparameters,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'DeleteObjects'
  AND eventtime >= '<INCIDENT_START_TIME>'
ORDER BY eventtime DESC
LIMIT 100;
```

### 4.3 Evidence Preservation

1. **Create forensic bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-<INCIDENT_ID> --region <REGION>
   ```

2. **Enable encryption and block public access:**
   ```bash
   aws s3api put-bucket-encryption --bucket forensic-evidence-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   aws s3api put-public-access-block --bucket forensic-evidence-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```

3. **Copy relevant CloudTrail logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/<INCIDENT_DATE>/ \
     s3://forensic-evidence-<INCIDENT_ID>/cloudtrail-logs/
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:**
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_ACCESS_KEY_ID>
   ```

2. **Restore:** If versioning was enabled, recover deleted objects:
   ```bash
   # List delete markers and remove them to restore objects
   aws s3api list-object-versions --bucket <BUCKET_NAME> \
     --query 'DeleteMarkers[?IsLatest==`true`].[Key,VersionId]' --output text | \
     while read key vid; do
       aws s3api delete-object --bucket <BUCKET_NAME> --key "$key" --version-id "$vid"
     done
   ```
   If versioning was NOT enabled, restore from the most recent backup.

3. **Harden (The "Never Again" Fix):**
   - Enable S3 versioning on all sensitive buckets:
     ```bash
     aws s3api put-bucket-versioning --bucket <BUCKET_NAME> --versioning-configuration Status=Enabled
     ```
   - Enable MFA Delete to require MFA for deletion:
     ```bash
     aws s3api put-bucket-versioning --bucket <BUCKET_NAME> \
       --versioning-configuration Status=Enabled,MFADelete=Enabled \
       --mfa "arn:aws:iam::<ACCOUNT_ID>:mfa/<MFA_DEVICE> <MFA_CODE>"
     ```
   - Apply S3 Object Lock for compliance-critical data:
     ```bash
     aws s3api put-object-lock-configuration --bucket <BUCKET_NAME> \
       --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":365}}}'
     ```

4. **Verify:**
   ```bash
   aws s3api delete-object --bucket <BUCKET_NAME> --key test-object  # Should require MFA or fail
   ```

5. **Post-Mortem:**
   - Was versioning enabled before the attack? If not, data may be unrecoverable.
   - Was MFA Delete enforced? This is the single most effective control against object deletion.
   - Was the deletion part of a larger ransomware chain (exfil → delete → ransom upload)?

---

## Detection Rule (Sigma)

```yaml
title: Bulk S3 Object Deletion via DeleteObjects
id: b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
level: high
description: Detects DeleteObjects API calls against S3 buckets which may indicate data destruction as part of ransomware, sabotage, or evidence tampering.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: DeleteObjects
  condition: selection
falsepositives:
  - Lifecycle policy cleanup operations
  - CI/CD pipelines cleaning build artifacts
  - Legitimate data retention policy enforcement
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1485 | Data Destruction | Impact | DeleteObjects permanently removes multiple S3 objects in a single call, enabling rapid data destruction as part of ransomware or sabotage operations |

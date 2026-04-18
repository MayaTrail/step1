---
id: aws-s3-deletebucket
api_call: s3:DeleteBucket
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
provided_outputs:
  - DELETED_BUCKET_NAME
  - DELETION_TIME
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Bucket Deletion via DeleteBucket

**ID:** PB-AWS-S3-DeleteBucket-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Bucket Deletion via DeleteBucket
- **Playbook ID:** PB-AWS-S3-DeleteBucket-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity deletes an entire S3 bucket, destroying the storage container itself after its objects have been removed. This is typically the final stage of a ransomware or sabotage operation.
- **Trigger:** CloudTrail event where `eventName == DeleteBucket` from any identity outside of an approved decommissioning workflow.
- **Severity Matrix:**
  - **CRITICAL:** DeleteBucket called against any bucket tagged `Critical-Production-App`, `DataClassification:PII`, or `DataClassification:Financial`. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** DeleteBucket called by an identity not in the `InfraAdmins` group or from a non-corporate IP. **Action:** Immediate IR team response.
  - **MEDIUM:** DeleteBucket called against a dev/test bucket by a known administrator during business hours. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1485** — Data Destruction (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance, Legal, CISO
- **SLA Target:** Triage within 15 minutes; CRITICAL: immediate response
- **Compliance:** GDPR Article 33, SOC2 CC6.1, regulatory reporting for data loss

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who deleted the bucket?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Authorization Check:** Is this identity a member of the infrastructure admins group?
  ```bash
  aws iam list-groups-for-user --user-name <USERNAME> \
    --query 'Groups[*].GroupName' --output text
  ```

- [ ] **Change Window Check:** Was there an approved decommissioning ticket for this bucket?
  (Manual verification against change management system)

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Preceding Activity:** Check for the exfil-delete-ransom pattern.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == InfraAdmin` AND `Approved change ticket exists` AND `Source_IP == corporate` → **Mark False Positive & Close.**
- **IF** `Bucket was tagged Critical-Production-App or PII` → **Proceed to Containment Level 3 IMMEDIATELY.**
- **IF** `Identity not in InfraAdmins` OR `Source_IP == non-corporate` → **Proceed to Containment Level 2.**
- **IF** `Dev/test bucket, known admin, business hours` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Dev/test bucket, known identity | **Deny DeleteBucket for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyDeleteBucket --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyDeleteBucket` |
| **L2 (Hard)** | Unauthorized identity or non-approved deletion | **Deactivate all access keys:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Production/PII bucket deleted or ransomware pattern | **Full deny, SCP to block all S3 deletions account-wide:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and apply SCP: `aws organizations update-policy --policy-id <SCP_ID> --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteBucket","s3:DeleteObject"],"Resource":"*"}]}'` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and revert SCP to previous version |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **How many buckets were deleted?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `DeleteBucket`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort -u
  ```

- **Was data exfiltrated before deletion?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort -u
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
    errorcode,
    errormessage
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'DeleteBucket'
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

2. **Restore:** S3 bucket deletion is irreversible — the bucket name is released and data is gone. Recovery requires:
   - Recreate the bucket with the same name (if still available):
     ```bash
     aws s3 mb s3://<BUCKET_NAME> --region <REGION>
     ```
   - Restore objects from cross-region replication, backup vaults, or versioned snapshots.
   - Restore bucket policies, ACLs, and configurations from infrastructure-as-code state (Terraform/Pulumi).

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to deny DeleteBucket except for authorized roles:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyDeleteBucketExceptAuthorized",
         "Effect": "Deny",
         "Action": "s3:DeleteBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": "arn:aws:iam::*:role/InfraDecommissionRole"
           }
         }
       }]
     }
     ```
   - Enable cross-region replication for critical buckets.
   - Require approval workflows for bucket deletion via AWS Config custom rules.

4. **Verify:**
   ```bash
   aws s3 rb s3://<TEST_BUCKET_NAME>  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was DeleteBucket monitored as a high-severity event?
   - Were critical buckets protected by SCPs? If not, this is a gap.
   - Was cross-region replication enabled for disaster recovery?
   - Was IaC state available to recreate the bucket and its configuration?

---

## Detection Rule (Sigma)

```yaml
title: S3 Bucket Deletion via DeleteBucket
id: c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
level: critical
description: Detects DeleteBucket API calls which indicate complete S3 bucket destruction, a hallmark of ransomware and sabotage operations.
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
    eventName: DeleteBucket
  condition: selection
falsepositives:
  - Authorized infrastructure decommissioning
  - IaC destroy operations (Terraform destroy, Pulumi destroy) during approved maintenance
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1485 | Data Destruction | Impact | DeleteBucket permanently destroys the S3 storage container, representing the final irreversible step in data destruction after all objects have been removed |

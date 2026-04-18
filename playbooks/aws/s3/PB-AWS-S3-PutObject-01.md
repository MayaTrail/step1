---
id: aws-s3-putobject
api_call: s3:PutObject
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
  - OBJECT_KEY
provided_outputs:
  - UPLOADED_OBJECT_KEY
  - OBJECT_SIZE_BYTES
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Object Upload via PutObject

**ID:** PB-AWS-S3-PutObject-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Object Upload via PutObject
- **Playbook ID:** PB-AWS-S3-PutObject-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity uploads objects to S3 buckets, potentially delivering ransomware payloads, defacing web-hosted content, staging malware, or planting ransom notes after data destruction.
- **Trigger:** CloudTrail S3 data event where `eventName == PutObject` from an unexpected identity, targeting a bucket outside normal application write patterns, or uploading files with suspicious names/extensions.
- **Severity Matrix:**
  - **CRITICAL:** PutObject to a bucket tagged `Critical-Production-App` by an identity not in the application's service role, OR PutObject preceded by DeleteObjects in the same bucket (ransom note delivery pattern). **Action:** Wake CISO & Legal immediately.
  - **HIGH:** PutObject from a non-corporate IP or by an identity with no prior write permissions to this bucket. **Action:** Immediate IR team response.
  - **MEDIUM:** PutObject to a non-sensitive bucket by a known identity with write permissions. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:Get*`, `s3:List*`, `s3:DeleteObject`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail S3 data events MUST be enabled
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact) — when used for ransomware payload delivery
  - **T1491.002** — External Defacement (Impact) — when used to modify web-hosted content
- **Stakeholders:** Security Operations, Cloud Engineering, Application Teams, Legal
- **SLA Target:** Triage within 15 minutes for CRITICAL; 30 minutes for HIGH
- **Compliance:** SOC2 CC6.1; GDPR/CCPA if PII bucket is modified

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who uploaded the object?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Object Inspection:** What was uploaded?
  ```bash
  aws s3api head-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
    --query '{ContentType:ContentType,ContentLength:ContentLength,ServerSideEncryption:ServerSideEncryption,Metadata:Metadata}'
  ```

- [ ] **Content Analysis:** Download and inspect the uploaded object (in a sandbox):
  ```bash
  aws s3api get-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> /tmp/forensic-sample-<INCIDENT_ID>
  file /tmp/forensic-sample-<INCIDENT_ID>
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | select(.requestParameters.bucketName == "<BUCKET_NAME>") | .sourceIPAddress' | sort -u
  ```

- [ ] **Ransomware Pattern Check:** Was this PutObject preceded by DeleteObjects on the same bucket?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == application service role` AND `Bucket == application data bucket` AND `Source_IP == VPC endpoint` → **Mark False Positive & Close.**
- **IF** `PutObject preceded by DeleteObjects` (ransom note pattern) → **Proceed to Containment Level 3 IMMEDIATELY.**
- **IF** `Object name contains ransom/encrypted/locked keywords` OR `Content-Type is unexpected` → **Proceed to Containment Level 2.**
- **IF** `Known identity, expected bucket, normal object` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Suspicious upload, low confidence | **Deny PutObject for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyPutObject --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::*/*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyPutObject` |
| **L2 (Hard)** | Confirmed malicious upload | **Delete the malicious object and disable keys:**`aws s3api delete-object --bucket <BUCKET_NAME> --key <OBJECT_KEY>` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | Object deletion is intentional; `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransomware delivery or mass defacement | **Full deny, lock bucket, delete all attacker objects:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and `aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::<BUCKET_NAME>/*","Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"}}}]}'` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and `aws s3api delete-bucket-policy --bucket <BUCKET_NAME>` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws s3api get-bucket-tagging --bucket <BUCKET_NAME> --query 'TagSet[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **What objects were uploaded and to which buckets?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `PutObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | "\(.requestParameters.bucketName)/\(.requestParameters.key)"' | sort -u
  ```

- **Were existing objects overwritten?** (check versioning):
  ```bash
  aws s3api list-object-versions --bucket <BUCKET_NAME> --prefix <OBJECT_KEY> \
    --query 'Versions[*].[VersionId,LastModified,IsLatest]' --output table
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
    json_extract_scalar(requestparameters, '$.key') AS object_key,
    json_extract_scalar(additionalEventData, '$.bytesTransferredIn') AS bytes_uploaded,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'PutObject'
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

3. **Preserve the malicious object for analysis:**
   ```bash
   aws s3 cp s3://<BUCKET_NAME>/<OBJECT_KEY> s3://forensic-evidence-<INCIDENT_ID>/malicious-objects/<OBJECT_KEY>
   ```

4. **Copy relevant CloudTrail logs:**
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

2. **Restore:** Remove attacker-uploaded objects and restore originals from versioning:
   ```bash
   # Delete attacker's object
   aws s3api delete-object --bucket <BUCKET_NAME> --key <OBJECT_KEY>

   # If an original object was overwritten, restore the previous version
   aws s3api list-object-versions --bucket <BUCKET_NAME> --prefix <OBJECT_KEY> \
     --query 'Versions[?IsLatest==`false`] | [0].VersionId' --output text
   # Copy the previous version back as the current version
   aws s3api copy-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
     --copy-source "<BUCKET_NAME>/<OBJECT_KEY>?versionId=<PREVIOUS_VERSION_ID>"
   ```

3. **Harden (The "Never Again" Fix):**
   - Restrict PutObject to authorized roles via bucket policy:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyPutObjectExceptAuthorized",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::<BUCKET_NAME>/*",
         "Condition": {
           "StringNotEquals": {
             "aws:PrincipalArn": [
               "arn:aws:iam::<ACCOUNT_ID>:role/ApplicationWriteRole",
               "arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"
             ]
           }
         }
       }]
     }
     ```
   - Enable S3 versioning to preserve original objects when overwritten.
   - Enable S3 Object Lock for immutable storage requirements.

4. **Verify:**
   ```bash
   aws s3api put-object --bucket <BUCKET_NAME> --key test-upload --body /dev/null  # Should be denied
   ```

5. **Post-Mortem:**
   - Was the uploaded object a ransom note? Analyze content for threat intel.
   - Were PutObject calls to sensitive buckets being monitored?
   - Was the upload part of a larger attack chain (exfil → delete → ransom upload)?
   - Were bucket write permissions scoped to the minimum necessary principals?

---

## Detection Rule (Sigma)

```yaml
title: Suspicious S3 Object Upload via PutObject
id: e5f6a7b8-c9d0-1e2f-3a4b-5c6d7e8f9a0b
status: experimental
level: medium
description: Detects PutObject API calls against S3 buckets which may indicate ransomware payload delivery, defacement, or unauthorized data staging.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1486
  - attack.t1491.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: PutObject
  condition: selection
falsepositives:
  - Application workloads writing data to S3
  - CI/CD pipelines deploying static assets
  - Backup services writing data to S3
  - Log delivery services (CloudTrail, ALB, VPC Flow Logs)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | PutObject is used to deliver ransomware payloads and ransom notes to victim buckets after data has been exfiltrated and deleted |
| T1491.002 | External Defacement | Impact | PutObject can overwrite web-hosted content in S3 static website buckets, enabling public-facing defacement |

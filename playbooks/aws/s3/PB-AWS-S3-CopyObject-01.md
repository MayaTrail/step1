---
id: aws-s3-copyobject
api_call: s3:CopyObject
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
  - OBJECT_KEY
  - KMS_KEY_ID
provided_outputs:
  - COPIED_OBJECT_KEYS
  - ENCRYPTION_KEY_ARN
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Object Re-encryption via CopyObject

**ID:** PB-AWS-S3-CopyObject-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Object Re-encryption via CopyObject
- **Playbook ID:** PB-AWS-S3-CopyObject-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity uses CopyObject with `ServerSideEncryption: aws:kms` to re-encrypt S3 objects in-place with an attacker-controlled KMS key, rendering the data inaccessible once the attacker deletes their key material. This is the execution phase of a KMS-based ransomware attack.
- **Trigger:** CloudTrail S3 data event where `eventName == CopyObject` with `SSEKMSKeyId` pointing to a non-standard or recently created KMS key, or bulk CopyObject calls (>10 objects in <5 minutes) by an unexpected identity.
- **Severity Matrix:**
  - **CRITICAL:** CopyObject with `SSEKMSKeyId` pointing to a KMS key with `Origin == EXTERNAL` against a bucket tagged `DataClassification:PII` or `Critical-Production-App`. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** Bulk CopyObject (>10 objects) with KMS re-encryption by an identity not in the application's authorized roles. **Action:** Immediate IR team response.
  - **MEDIUM:** Single CopyObject with KMS encryption change by a known identity. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:Get*`, `s3:List*`, `s3:CopyObject`, `kms:Describe*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail S3 data events MUST be enabled
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance, CISO, Legal
- **SLA Target:** Triage within 10 minutes — this is active ransomware execution
- **Compliance:** GDPR Article 33 (72-hour notification), CCPA, SOC2 CC6.1

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who performed the CopyObject re-encryption?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CopyObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **KMS Key Analysis:** Is the encryption key attacker-controlled?
  ```bash
  aws kms describe-key --key-id <KMS_KEY_ID> \
    --query 'KeyMetadata.{KeyId:KeyId,Origin:Origin,KeyState:KeyState,Description:Description,CreationDate:CreationDate}'
  ```

- [ ] **Key Tags:** Check for attacker indicators.
  ```bash
  aws kms list-resource-tags --key-id <KMS_KEY_ID> --query 'Tags[*]' --output table
  ```

- [ ] **Bucket Sensitivity:** Check data classification of the targeted bucket.
  ```bash
  aws s3api get-bucket-tagging --bucket <BUCKET_NAME> 2>/dev/null || echo "No tags found"
  ```

- [ ] **Volume Assessment:** How many objects were re-encrypted?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `CopyObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | "\(.requestParameters.bucketName)/\(.requestParameters.key)"' | wc -l
  ```

- [ ] **Ransomware Chain Check:** Was this preceded by CreateKey (EXTERNAL) → GetParametersForImport → ImportKeyMaterial?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CopyObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

### Step 2.2: Decision Logic

- **IF** `KMS Key Origin == AWS_KMS` AND `Key is organization-managed` AND `Identity == authorized app role` → **Mark False Positive & Close.**
- **IF** `KMS Key Origin == EXTERNAL` AND `Key created within last 2 hours` → **Proceed to Containment Level 3 IMMEDIATELY** (active ransomware execution).
- **IF** `>10 objects re-encrypted` AND `KMS key is non-standard` → **Proceed to Containment Level 2.**
- **IF** `Known identity, org-managed key, single object` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Single object, known identity | **Deny CopyObject for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyCopyObject --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"arn:aws:s3:::*/*","Condition":{"StringEquals":{"s3:x-amz-copy-source":"*"}}}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyCopyObject` |
| **L2 (Hard)** | Bulk re-encryption or unauthorized key | **Disable the attacker's KMS key and lock the identity:**`aws kms disable-key --key-id <KMS_KEY_ID>` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws kms enable-key --key-id <KMS_KEY_ID>` and `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Active ransomware confirmed (EXTERNAL key + bulk encrypt) | **Full lockdown — deny all S3 writes, disable key, lock identity:**`aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:PutObject","s3:CopyObject"],"Resource":"arn:aws:s3:::<BUCKET_NAME>/*","Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"}}}]}'` and `aws kms disable-key --key-id <KMS_KEY_ID>` and `aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws s3api delete-bucket-policy --bucket <BUCKET_NAME>` and `aws kms enable-key --key-id <KMS_KEY_ID>` and `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws s3api get-bucket-tagging --bucket <BUCKET_NAME> --query 'TagSet[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **List all objects re-encrypted with the attacker's key:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `CopyObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | "\(.requestParameters.bucketName)/\(.requestParameters.key)"' | sort -u
  ```

- **Check if previous object versions exist** (recovery depends on this):
  ```bash
  aws s3api get-bucket-versioning --bucket <BUCKET_NAME>
  ```

- **List object versions to identify pre-attack versions:**
  ```bash
  aws s3api list-object-versions --bucket <BUCKET_NAME> \
    --query 'Versions[*].[Key,VersionId,LastModified,IsLatest]' --output table
  ```

- **Verify which KMS key was used for each object:**
  ```bash
  aws s3api head-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
    --query '{SSEKMSKeyId:SSEKMSKeyId,ServerSideEncryption:ServerSideEncryption}'
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
    json_extract_scalar(requestparameters, '$.x-amz-server-side-encryption') AS sse_type,
    json_extract_scalar(requestparameters, '$.x-amz-server-side-encryption-aws-kms-key-id') AS kms_key_id,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'CopyObject'
  AND eventtime >= '<INCIDENT_START_TIME>'
ORDER BY eventtime DESC
LIMIT 500;
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

2. **Restore:** Recovery depends on S3 versioning status:
   - **If versioning was enabled:** Restore pre-attack versions of all affected objects:
     ```bash
     # For each affected object, find the previous version and restore it
     aws s3api list-object-versions --bucket <BUCKET_NAME> --prefix <OBJECT_KEY> \
       --query 'Versions[?IsLatest==`false`] | [0].VersionId' --output text
     # Copy the previous version back as the current version
     aws s3api copy-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
       --copy-source "<BUCKET_NAME>/<OBJECT_KEY>?versionId=<PREVIOUS_VERSION_ID>" \
       --server-side-encryption aws:kms --ssekms-key-id <ORG_MANAGED_KEY_ID>
     ```
   - **If versioning was NOT enabled:** Data re-encrypted with the attacker's key is recoverable ONLY if the KMS key material has not been deleted. If the key is still active, re-encrypt with an org-controlled key:
     ```bash
     aws s3api copy-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
       --copy-source "<BUCKET_NAME>/<OBJECT_KEY>" \
       --server-side-encryption aws:kms --ssekms-key-id <ORG_MANAGED_KEY_ID>
     ```
   - **If key material was deleted:** Objects are **permanently unrecoverable** — escalate to CISO and Legal.

3. **Harden (The "Never Again" Fix):**
   - Set default bucket encryption to an organization-managed KMS key:
     ```bash
     aws s3api put-bucket-encryption --bucket <BUCKET_NAME> \
       --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<ORG_MANAGED_KEY_ID>"},"BucketKeyEnabled":true}]}'
     ```
   - Apply bucket policy to deny CopyObject with non-approved KMS keys:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyNonApprovedKMSKeys",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::<BUCKET_NAME>/*",
         "Condition": {
           "StringNotEquals": {
             "s3:x-amz-server-side-encryption-aws-kms-key-id": "<ORG_MANAGED_KEY_ARN>"
           },
           "StringEquals": {
             "s3:x-amz-server-side-encryption": "aws:kms"
           }
         }
       }]
     }
     ```
   - Enable S3 versioning on all sensitive buckets.
   - Block EXTERNAL-origin KMS keys at the SCP level (see CreateKey playbook).

4. **Verify:**
   ```bash
   aws s3api copy-object --bucket <BUCKET_NAME> --key test-object \
     --copy-source "<BUCKET_NAME>/test-object" \
     --server-side-encryption aws:kms --ssekms-key-id <ATTACKER_KEY_ID>  # Should be denied
   ```

5. **Post-Mortem:**
   - Was S3 versioning enabled before the attack? This is the single most critical recovery control.
   - Was default bucket encryption enforced with an org-managed key?
   - Were CopyObject calls with KMS re-encryption being monitored?
   - How quickly was the re-encryption detected? Was the attacker able to complete the full chain?

---

## Detection Rule (Sigma)

```yaml
title: S3 Object Re-encryption with KMS Key via CopyObject (Ransomware Execution)
id: c4d5e6f7-a8b9-0c1d-2e3f-4a5b6c7d8e9f
status: experimental
level: critical
description: Detects CopyObject API calls with KMS server-side encryption, which may indicate ransomware re-encryption of S3 objects with an attacker-controlled key.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: CopyObject
  condition: selection
falsepositives:
  - Legitimate bucket migration or reorganization operations
  - Key rotation workflows re-encrypting objects with a new CMK
  - Cross-region replication with different encryption keys
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | CopyObject with SSEKMSKeyId re-encrypts S3 objects in-place with an attacker-controlled KMS key, enabling ransomware where the attacker controls decryption after deleting the key material |

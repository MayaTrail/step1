---
id: aws-s3-listobjectsv2
api_call: s3:ListObjectsV2
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
provided_outputs:
  - ENUMERATED_OBJECT_KEYS
  - OBJECT_COUNT
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Object Enumeration via ListObjectsV2

**ID:** PB-AWS-S3-ListObjectsV2-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Object Enumeration via ListObjectsV2
- **Playbook ID:** PB-AWS-S3-ListObjectsV2-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity lists objects within an S3 bucket to identify high-value files for exfiltration, deletion, or ransomware operations.
- **Trigger:** CloudTrail event where `eventName == ListObjects` (logged as `ListObjects` in CloudTrail for both v1 and v2) from an unexpected identity, IP, or with unusual volume.
- **Severity Matrix:**
  - **CRITICAL:** ListObjectsV2 called against buckets tagged `DataClassification:PII` or `DataClassification:Financial` by an identity with no prior S3 access history AND followed by GetObject calls within 5 minutes. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** ListObjectsV2 called across >5 distinct buckets in <15 minutes from a non-corporate IP. **Action:** Immediate IR team response.
  - **MEDIUM:** ListObjectsV2 called by a known identity against a non-sensitive bucket outside of business hours. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:List*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (S3 data events must be enabled for object-level logging)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1083** — File and Directory Discovery (Discovery)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance
- **SLA Target:** Triage within 30 minutes of alert
- **Compliance:** SOC2 CC6.1, GDPR Article 33 if PII bucket is involved

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Identify the caller and verify authorization.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjects \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Bucket Sensitivity:** Check the targeted bucket's data classification.
  ```bash
  aws s3api get-bucket-tagging --bucket <BUCKET_NAME> 2>/dev/null || echo "No tags found"
  ```

- [ ] **IP Reputation:** Extract and assess the source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListObjects \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | select(.requestParameters.bucketName == "<BUCKET_NAME>") | .sourceIPAddress'
  ```

- [ ] **Follow-on Activity:** Check if listing was followed by GetObject calls (exfiltration indicator).
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`) || contains(CloudTrailEvent, `ListObjects`)].{Time:EventTime,Event:EventName}' \
    --output table
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == application service role` AND `Bucket == application data bucket` AND `Source_IP == VPC endpoint` → **Mark False Positive & Close.**
- **IF** `>5 buckets listed in <15 min` OR `Identity has no S3 policy` → **Proceed to Containment Level 2.**
- **IF** `Known identity, single bucket, no follow-on GetObject` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Known identity, single bucket | **Deny ListObjects for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyListObjects --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Resource":"arn:aws:s3:::*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyListObjects` |
| **L2 (Hard)** | Multi-bucket enumeration or unauthorized identity | **Deactivate access keys:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Compromised identity with confirmed data access | **Full deny and restrict bucket:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and `aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::<BUCKET_NAME>","arn:aws:s3:::<BUCKET_NAME>/*"],"Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"}}}]}'` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and `aws s3api delete-bucket-policy --bucket <BUCKET_NAME>` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
aws s3api get-bucket-tagging --bucket <BUCKET_NAME> --query 'TagSet[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **Which buckets and prefixes were enumerated?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `ListObjects`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | {bucket: .requestParameters.bucketName, prefix: .requestParameters.prefix}'
  ```

- **What objects were visible?** (assess exposure scope)
  ```bash
  aws s3api list-objects-v2 --bucket <BUCKET_NAME> --max-keys 100 \
    --query 'Contents[*].[Key,Size,LastModified]' --output table
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
    json_extract_scalar(requestparameters, '$.prefix') AS prefix,
    json_extract_scalar(requestparameters, '$.max-keys') AS max_keys,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'ListObjects'
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

2. **Restore:** ListObjectsV2 is a read-only call; no data damage to restore. Determine whether enumerated object names revealed sensitive information (e.g., filenames containing PII identifiers).

3. **Harden (The "Never Again" Fix):**
   - Enforce VPC endpoint conditions on bucket policies:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyListObjectsOutsideVPC",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:ListBucket",
         "Resource": "arn:aws:s3:::<BUCKET_NAME>",
         "Condition": {
           "StringNotEquals": {
             "aws:sourceVpce": "<VPC_ENDPOINT_ID>"
           }
         }
       }]
     }
     ```
   - Enable S3 data event logging in CloudTrail for object-level visibility.

4. **Verify:**
   ```bash
   aws s3api list-objects-v2 --bucket <BUCKET_NAME>  # Should return Access Denied from non-VPC source
   ```

5. **Post-Mortem:**
   - Were S3 data events enabled in CloudTrail? If not, this activity may have been invisible.
   - Were bucket naming conventions revealing sensitive information about contents?
   - Should object-level ACLs be replaced with bucket policies for centralized control?

---

## Detection Rule (Sigma)

```yaml
title: S3 Object Enumeration via ListObjectsV2
id: 9c5a3b4d-6e7f-8a9b-0c1d-2e3f4a5b6c7d
status: experimental
level: medium
description: Detects ListObjects API calls against S3 buckets which may indicate an attacker enumerating objects for exfiltration or destruction.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1083
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: ListObjects
  condition: selection
falsepositives:
  - Application workloads performing routine S3 operations
  - AWS Console browsing bucket contents
  - Backup and sync tools (AWS DataSync, S3 Sync)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1083 | File and Directory Discovery | Discovery | ListObjectsV2 reveals object keys, sizes, and metadata within a bucket, enabling attackers to identify high-value targets for exfiltration or ransomware |

---
id: aws-s3-getobject
api_call: s3:GetObject
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
  - OBJECT_KEY
provided_outputs:
  - EXFILTRATED_OBJECT_KEYS
  - DATA_VOLUME_BYTES
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Data Exfiltration via GetObject

**ID:** PB-AWS-S3-GetObject-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Data Exfiltration via GetObject
- **Playbook ID:** PB-AWS-S3-GetObject-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity downloads objects from S3 buckets, potentially exfiltrating sensitive data to an attacker-controlled destination.
- **Trigger:** CloudTrail S3 data event where `eventName == GetObject` from an unexpected identity, IP, or with anomalous volume (>100 GetObject calls in <10 minutes).
- **Severity Matrix:**
  - **CRITICAL:** GetObject volume >10GB from a bucket tagged `DataClassification:PII` or `DataClassification:Financial` to a non-corporate IP. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** >100 GetObject calls in <10 minutes from an identity that normally does not access this bucket. **Action:** Immediate IR team response.
  - **MEDIUM:** GetObject from a non-sensitive bucket by a known identity outside business hours. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:Get*`, `s3:List*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail S3 data events MUST be enabled (this is not a management event)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1530** — Data from Cloud Storage Object (Collection)
- **Stakeholders:** Security Operations, Data Governance, Legal (if PII), CISO
- **SLA Target:** Triage within 15 minutes of alert for CRITICAL; 30 minutes for HIGH
- **Compliance:** GDPR Article 33 (72-hour notification), CCPA, SOC2 CC6.1 if personal data is involved

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who downloaded the data?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Volume Assessment:** Quantify the data downloaded.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.key' | wc -l
  ```

- [ ] **Bucket Sensitivity:** Check data classification of the targeted bucket.
  ```bash
  aws s3api get-bucket-tagging --bucket <BUCKET_NAME> 2>/dev/null || echo "No tags found"
  ```

- [ ] **IP Reputation:** Assess the destination/source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Data Content Check:** Assess whether downloaded objects contain sensitive data.
  ```bash
  aws s3api head-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
    --query '{ContentType:ContentType,ContentLength:ContentLength,ServerSideEncryption:ServerSideEncryption}'
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == application service role` AND `Source_IP == VPC endpoint` AND `Volume < 1GB` → **Mark False Positive & Close.**
- **IF** `Volume > 10GB` OR `Bucket contains PII/Financial data` → **Proceed to Containment Level 2 IMMEDIATELY.**
- **IF** `Source_IP == non-corporate` AND `>50 objects downloaded` → **Proceed to Containment Level 2.**
- **IF** `Known identity, small volume, non-sensitive bucket` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Suspicious but low volume (<1GB) | **Deny GetObject for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyGetObject --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::*/*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyGetObject` |
| **L2 (Hard)** | Confirmed exfiltration (>10GB or PII bucket) | **Deactivate all access keys and restrict bucket:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` and `aws s3api put-bucket-policy --bucket <BUCKET_NAME> --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::<BUCKET_NAME>/*","Condition":{"StringNotEquals":{"aws:PrincipalArn":"arn:aws:iam::<ACCOUNT_ID>:role/IncidentResponseRole"}}}]}'` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` and `aws s3api delete-bucket-policy --bucket <BUCKET_NAME>` |
| **L3 (Nuclear)** | Massive exfiltration, compromised identity, lateral movement | **Full account lockdown:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and apply VPC endpoint policy to block all S3 egress | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
aws s3api get-bucket-tagging --bucket <BUCKET_NAME> --query 'TagSet[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **Quantify exfiltration volume by object:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | "\(.requestParameters.bucketName)/\(.requestParameters.key)"' | sort -u
  ```

- **Check for lateral movement to other buckets:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
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
    errorcode,
    bytestransferred
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'GetObject'
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
   Revoke all active sessions:
   ```bash
   aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOldSessions \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'
   ```

2. **Restore:** Verify object integrity — compare checksums of remaining objects against known-good backups:
   ```bash
   aws s3api head-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> --query 'ETag'
   ```

3. **Harden (The "Never Again" Fix):**
   - Enforce VPC endpoint conditions to prevent data egress outside the network:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyGetObjectOutsideVPC",
         "Effect": "Deny",
         "Principal": "*",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::<BUCKET_NAME>/*",
         "Condition": {
           "StringNotEquals": {
             "aws:sourceVpce": "<VPC_ENDPOINT_ID>"
           }
         }
       }]
     }
     ```
   - Enable S3 access logging and CloudTrail S3 data events.
   - Consider enabling Macie for automated PII detection.

4. **Verify:**
   ```bash
   # From outside VPC — should fail
   aws s3api get-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> /tmp/test-download
   # Expected: Access Denied
   ```

5. **Post-Mortem:**
   - Was the data exfiltration volume quantifiable? Calculate total bytes transferred.
   - Were S3 data events enabled? If not, object-level access was invisible.
   - Was there a data loss prevention (DLP) control that should have triggered?
   - Notify Legal/Compliance if PII or financial data was confirmed exfiltrated.

---

## Detection Rule (Sigma)

```yaml
title: Bulk S3 Data Exfiltration via GetObject
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
level: high
description: Detects high-volume GetObject API calls against S3 buckets which may indicate data exfiltration by a compromised or malicious identity.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetObject
  condition: selection
falsepositives:
  - Application workloads performing routine data reads
  - Backup services (AWS Backup, custom sync jobs)
  - Data pipeline tools (AWS Glue, EMR) reading source data
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1530 | Data from Cloud Storage Object | Collection | GetObject directly retrieves object contents from S3, enabling attackers to exfiltrate sensitive data including PII, financial records, and intellectual property |

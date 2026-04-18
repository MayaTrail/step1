---
id: aws-s3-getbucketpolicy
api_call: s3:GetBucketPolicy
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
provided_outputs:
  - BUCKET_POLICY_DOCUMENT
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Bucket Policy Reconnaissance via GetBucketPolicy

**ID:** PB-AWS-S3-GetBucketPolicy-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Bucket Policy Reconnaissance via GetBucketPolicy
- **Playbook ID:** PB-AWS-S3-GetBucketPolicy-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity retrieves S3 bucket policies to understand access controls and identify misconfigurations exploitable for data exfiltration or privilege escalation.
- **Trigger:** CloudTrail event where `eventName == GetBucketPolicy` from an unexpected identity or IP address.
- **Severity Matrix:**
  - **CRITICAL:** GetBucketPolicy called against a bucket tagged `DataClassification:PII` or `DataClassification:Financial` by an identity with no prior S3 access history. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** GetBucketPolicy called from a non-corporate IP or by a recently compromised identity against >3 distinct buckets within 10 minutes. **Action:** Immediate IR team response.
  - **MEDIUM:** GetBucketPolicy called by a known developer outside of change windows. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:GetBucketPolicy`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1580** — Cloud Infrastructure Discovery (Discovery)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance
- **SLA Target:** Triage within 30 minutes of alert
- **Compliance:** SOC2 CC6.1 if bucket contains regulated data

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Identify who called GetBucketPolicy and whether they have legitimate need.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetBucketPolicy \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Bucket Context:** Determine the sensitivity of the targeted bucket.
  ```bash
  aws s3api get-bucket-tagging --bucket <BUCKET_NAME> 2>/dev/null || echo "No tags found"
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetBucketPolicy \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress'
  ```

- [ ] **Pattern Check:** Is this identity accessing policies across multiple buckets (spray pattern)?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetBucketPolicy`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort -u
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == IaC pipeline (Terraform/Pulumi)` AND `Source_IP == CI/CD range` → **Mark False Positive & Close.**
- **IF** `Identity has no S3 permissions in policy` AND `call succeeded` → **Proceed to Containment Level 2** (permission boundary misconfiguration).
- **IF** `>3 buckets targeted in <10 min` → **Proceed to Containment Level 2.**
- **IF** `Known identity, single bucket, during change window` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Single bucket, known identity | **Deny GetBucketPolicy for this user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyGetBucketPolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetBucketPolicy","Resource":"arn:aws:s3:::*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyGetBucketPolicy` |
| **L2 (Hard)** | Multi-bucket spray or unauthorized identity | **Deactivate access keys:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Compromised identity with evidence of exfiltration | **Full deny and session revocation:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **Which buckets were targeted?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetBucketPolicy`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort | uniq -c | sort -rn
  ```

- **Did the identity proceed to data access after reading policies?**
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
    requestparameters,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'GetBucketPolicy'
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

2. **Restore:** GetBucketPolicy is a read-only call; no data damage to restore. Focus on determining whether policy information was used to exploit bucket access.

3. **Harden (The "Never Again" Fix):**
   - Restrict GetBucketPolicy to authorized roles via SCP:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyGetBucketPolicyExceptAuthorized",
         "Effect": "Deny",
         "Action": "s3:GetBucketPolicy",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": [
               "arn:aws:iam::*:role/SecurityAuditRole",
               "arn:aws:iam::*:role/IncidentResponseRole"
             ]
           }
         }
       }]
     }
     ```
   - Enable bucket policy change alerting via EventBridge.

4. **Verify:**
   ```bash
   aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/TestRole --role-session-name verify-test
   aws s3api get-bucket-policy --bucket <BUCKET_NAME>  # Should return Access Denied
   ```

5. **Post-Mortem:**
   - Was GetBucketPolicy being monitored as a recon indicator?
   - Were bucket policies overly permissive, giving the attacker useful information?
   - Should bucket policies be simplified to reduce information leakage?

---

## Detection Rule (Sigma)

```yaml
title: S3 Bucket Policy Reconnaissance via GetBucketPolicy
id: 8b4f2a3c-5d6e-7f8a-9b0c-1d2e3f4a5b6c
status: experimental
level: low
description: Detects GetBucketPolicy API calls which may indicate an attacker is profiling S3 bucket access controls to identify exploitable misconfigurations.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1580
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: GetBucketPolicy
  condition: selection
falsepositives:
  - Infrastructure-as-code tools reading bucket configurations
  - AWS Config rules evaluating bucket compliance
  - Authorized security audit scans
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1580 | Cloud Infrastructure Discovery | Discovery | GetBucketPolicy reveals bucket access controls, allowing attackers to identify which principals have access and whether cross-account or public access is configured |

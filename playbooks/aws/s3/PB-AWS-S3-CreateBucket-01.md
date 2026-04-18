---
id: aws-s3-createbucket
api_call: s3:CreateBucket
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - BUCKET_NAME
  - REGION
provided_outputs:
  - CREATED_BUCKET_NAME
  - BUCKET_REGION
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Bucket Creation via CreateBucket

**ID:** PB-AWS-S3-CreateBucket-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Bucket Creation via CreateBucket
- **Playbook ID:** PB-AWS-S3-CreateBucket-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity creates a new S3 bucket, potentially to stage exfiltrated data, host ransomware payloads, or establish persistence within the account.
- **Trigger:** CloudTrail event where `eventName == CreateBucket` from an identity not in the `InfraAdmins` group or from a non-IaC pipeline source.
- **Severity Matrix:**
  - **CRITICAL:** CreateBucket followed by PutObject containing ransom messages or exfiltrated data within 10 minutes, OR bucket created with public access enabled. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** CreateBucket called by an identity with no prior S3 admin permissions or from a non-corporate IP. **Action:** Immediate IR team response.
  - **MEDIUM:** CreateBucket by a known admin outside of IaC deployment pipelines. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1537** — Transfer Data to Cloud Account (Exfiltration)
- **Stakeholders:** Security Operations, Cloud Engineering, FinOps (unauthorized resource creation)
- **SLA Target:** Triage within 30 minutes of alert
- **Compliance:** SOC2 CC6.1, potential cost implications for unauthorized resource creation

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who created the bucket?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateBucket \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Bucket Configuration:** Is the new bucket publicly accessible?
  ```bash
  aws s3api get-public-access-block --bucket <BUCKET_NAME> 2>/dev/null || echo "No public access block configured"
  aws s3api get-bucket-policy --bucket <BUCKET_NAME> 2>/dev/null || echo "No bucket policy"
  aws s3api get-bucket-acl --bucket <BUCKET_NAME>
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateBucket \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Follow-on Activity:** Check if objects were uploaded to the new bucket.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `PutObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort -u
  ```

- [ ] **Bucket Contents:** Check what was uploaded.
  ```bash
  aws s3 ls s3://<BUCKET_NAME>/ --recursive
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == IaC pipeline (Terraform/Pulumi)` AND `Source_IP == CI/CD range` → **Mark False Positive & Close.**
- **IF** `Bucket is publicly accessible` OR `Contains ransom note` → **Proceed to Containment Level 3 IMMEDIATELY.**
- **IF** `Identity not in InfraAdmins` OR `Source_IP == non-corporate` → **Proceed to Containment Level 2.**
- **IF** `Known admin, no objects uploaded, no public access` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Known identity, no public access | **Deny CreateBucket for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyCreateBucket --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:CreateBucket","Resource":"arn:aws:s3:::*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyCreateBucket` |
| **L2 (Hard)** | Unauthorized identity or suspicious bucket | **Block public access and disable keys:**`aws s3api put-public-access-block --bucket <BUCKET_NAME> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws s3api delete-public-access-block --bucket <BUCKET_NAME>` and `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransom bucket or public data staging | **Delete the attacker's bucket and lock the identity:**`aws s3 rb s3://<BUCKET_NAME> --force` and `aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` (bucket deletion is intentional — no rollback) |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **How many buckets were created?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `CreateBucket`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.bucketName' | sort -u
  ```

- **What region was the bucket created in?** (attackers may choose regions far from your operations)
  ```bash
  aws s3api get-bucket-location --bucket <BUCKET_NAME>
  ```

- **Was data uploaded to the bucket?**
  ```bash
  aws s3api list-objects-v2 --bucket <BUCKET_NAME> --query 'Contents[*].[Key,Size,LastModified]' --output table
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
    json_extract_scalar(requestparameters, '$.CreateBucketConfiguration.LocationConstraint') AS bucket_region,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'CreateBucket'
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

3. **Preserve attacker bucket contents before deletion:**
   ```bash
   aws s3 sync s3://<BUCKET_NAME>/ s3://forensic-evidence-<INCIDENT_ID>/attacker-bucket-contents/
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

2. **Restore:** Delete the attacker-created bucket (after preserving evidence):
   ```bash
   aws s3 rb s3://<BUCKET_NAME> --force
   ```

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to restrict CreateBucket to IaC roles only:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyCreateBucketExceptIaC",
         "Effect": "Deny",
         "Action": "s3:CreateBucket",
         "Resource": "arn:aws:s3:::*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": [
               "arn:aws:iam::*:role/PulumiDeployRole",
               "arn:aws:iam::*:role/TerraformDeployRole"
             ]
           }
         }
       }]
     }
     ```
   - Enable S3 account-level public access block:
     ```bash
     aws s3control put-public-access-block --account-id <ACCOUNT_ID> \
       --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
     ```

4. **Verify:**
   ```bash
   aws s3 mb s3://test-unauthorized-bucket  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was CreateBucket being monitored? It is a key indicator of staging operations.
   - Was account-level public access block enabled? If not, any new bucket could be made public.
   - Was the bucket naming convention suspicious (random names, typosquatting)?

---

## Detection Rule (Sigma)

```yaml
title: Unauthorized S3 Bucket Creation
id: d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a
status: experimental
level: high
description: Detects CreateBucket API calls which may indicate an attacker creating staging buckets for data exfiltration or ransomware payload delivery.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.exfiltration
  - attack.t1537
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName: CreateBucket
  condition: selection
falsepositives:
  - Infrastructure-as-code deployments (Terraform, Pulumi, CloudFormation)
  - Authorized administrators creating new buckets via console or CLI
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1537 | Transfer Data to Cloud Account | Exfiltration | CreateBucket establishes a new storage container that attackers can use to stage exfiltrated data, host ransom notes, or create infrastructure for persistent access |

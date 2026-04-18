---
id: aws-s3-listbuckets
api_call: s3:ListBuckets
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
provided_outputs:
  - ENUMERATED_BUCKET_NAMES
  - ENUMERATED_BUCKET_ARNS
  - SOURCE_IP
---

# Playbook: Unauthorized S3 Bucket Enumeration via ListBuckets

**ID:** PB-AWS-S3-ListBuckets-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized S3 Bucket Enumeration via ListBuckets
- **Playbook ID:** PB-AWS-S3-ListBuckets-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity enumerates all S3 buckets in the account using the `ListBuckets` API call to map the data landscape for further exploitation.
- **Trigger:** CloudTrail event where `eventName == ListBuckets` from an unexpected identity, IP, or outside of normal operating hours.
- **Severity Matrix:**
  - **CRITICAL:** ListBuckets called by an identity that has never accessed S3 before AND account contains buckets tagged `DataClassification:PII` or `DataClassification:Financial`. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** ListBuckets called from a non-corporate IP range or from a geographic location inconsistent with the identity's normal pattern. **Action:** Immediate IR team response.
  - **MEDIUM:** ListBuckets called outside business hours by a known service account with S3 permissions. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `s3:List*`, `iam:Get*`, `cloudtrail:LookupEvents` permissions
  - Logs: CloudTrail enabled (management events), S3 Server Access Logs (optional)
  - Tools: AWS CLI v2, Athena (for log queries), jq
- **MITRE ATT&CK Mapping:**
  - **T1580** — Cloud Infrastructure Discovery (Discovery)
- **Stakeholders:** Security Operations, Cloud Engineering, Data Governance
- **SLA Target:** Triage within 30 minutes of alert
- **Compliance:** May trigger SOC2 CC6.1 review if sensitive data buckets are present

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Determine who called ListBuckets and whether they are authorized for S3 access.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username,Source:Resources}' \
    --output table
  ```

- [ ] **User Authorization Check:** Verify the identity's IAM policies include S3 permissions.
  ```bash
  aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:user/<USERNAME> \
    --action-names s3:ListBuckets \
    --output table
  ```

- [ ] **IP Reputation:** Check the source IP against known corporate ranges and threat intel.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress'
  ```

- [ ] **Asset Context:** Enumerate buckets and their data classifications.
  ```bash
  aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
    xargs -I {} aws s3api get-bucket-tagging --bucket {} 2>/dev/null
  ```

- [ ] **Historical Baseline:** Has this identity called ListBuckets before?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time $(date -d '-30 days' --iso-8601) \
    --query 'Events[?contains(CloudTrailEvent, `ListBuckets`)].EventTime' \
    --output text
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == known service account` AND `Source_IP == corporate range` AND `Time == business hours` → **Mark False Positive & Close.**
- **IF** `Identity has never accessed S3` AND `Source_IP == non-corporate or flagged` → **Proceed to Containment Level 2.**
- **IF** `Identity is authorized for S3` AND `Source_IP == unusual` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Unusual IP but known identity | **Add explicit deny for ListBuckets:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyListBuckets --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBuckets","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyListBuckets` |
| **L2 (Hard)** | Confirmed unauthorized enumeration | **Disable all access keys:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Compromised identity confirmed, lateral movement suspected | **Attach full deny policy and revoke sessions:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` followed by `aws iam create-login-profile --user-name <USERNAME> --password-reset-required` | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **List all buckets visible to this identity** (to understand what the attacker saw):
  ```bash
  aws s3api list-buckets --query 'Buckets[*].[Name,CreationDate]' --output table
  ```

- **Check for follow-on activity** by the same identity (did they proceed to access bucket contents?):
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' \
    --output table
  ```

- **Volume analysis** — how many times was ListBuckets called?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets \
    --start-time <INCIDENT_START_TIME> \
    --query 'length(Events)'
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    useridentity.principalid,
    sourceipaddress,
    useragent,
    errorcode,
    errormessage
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname = 'ListBuckets'
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
   - Rotate access keys for the affected identity:
     ```bash
     aws iam create-access-key --user-name <USERNAME>
     aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_ACCESS_KEY_ID>
     ```
   - Revoke active sessions:
     ```bash
     aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOldSessions \
       --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'
     ```

2. **Restore:** ListBuckets is a read-only enumeration call; no data damage to restore. Focus on ensuring the attacker did not proceed to data access or exfiltration.

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to restrict ListBuckets to authorized roles only:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyListBucketsExceptAuthorized",
         "Effect": "Deny",
         "Action": "s3:ListAllMyBuckets",
         "Resource": "*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": [
               "arn:aws:iam::*:role/AuthorizedS3Role",
               "arn:aws:iam::*:role/IncidentResponseRole"
             ]
           }
         }
       }]
     }
     ```
   - Enforce least-privilege: remove blanket `s3:*` permissions and scope to specific buckets.

4. **Verify:**
   ```bash
   aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/TestRole --role-session-name verify-test
   aws s3api list-buckets  # Should return Access Denied
   ```

5. **Post-Mortem:**
   - Was ListBuckets being monitored? If not, add a CloudWatch metric filter.
   - Was there a delay between enumeration and detection? Quantify the gap.
   - Were bucket names revealing (e.g., `prod-customer-pii-data`)? Consider obfuscating bucket naming conventions.

---

## Detection Rule (Sigma)

```yaml
title: Unauthorized S3 Bucket Enumeration via ListBuckets
id: 7a3e1f2b-4c5d-6e7f-8a9b-0c1d2e3f4a5b
status: experimental
level: medium
description: Detects S3 ListBuckets API calls which may indicate reconnaissance of the account's data storage landscape.
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
    eventName: ListBuckets
  condition: selection
falsepositives:
  - Legitimate administrative tools and dashboards that list buckets
  - AWS Console sessions by authorized administrators
  - Infrastructure-as-code tools (Terraform, Pulumi) during plan/apply
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1580 | Cloud Infrastructure Discovery | Discovery | ListBuckets reveals all S3 bucket names in the account, enabling attackers to identify high-value data targets for subsequent exfiltration or ransomware operations |

---
id: aws-kms-deleteimportedkeymaterial
api_call: kms:DeleteImportedKeyMaterial
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - KEY_ID
provided_outputs:
  - DELETED_KEY_MATERIAL_KEY_ID
  - KEY_STATE_AFTER_DELETION
  - SOURCE_IP
---

# Playbook: Unauthorized KMS Key Material Deletion via DeleteImportedKeyMaterial

**ID:** PB-AWS-KMS-DeleteImportedKeyMaterial-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized KMS Key Material Deletion via DeleteImportedKeyMaterial
- **Playbook ID:** PB-AWS-KMS-DeleteImportedKeyMaterial-01
- **Version:** 1.0
- **Scenario:** An attacker deletes the imported key material from a KMS key that was used to encrypt S3 objects (or other resources), rendering all data encrypted with that key permanently unrecoverable. This is the final destructive step in a KMS-based ransomware attack — the point of no return.
- **Trigger:** CloudTrail event where `eventName == DeleteImportedKeyMaterial` from any identity, at any time. This call is inherently high-severity and should always generate an alert.
- **Severity Matrix:**
  - **CRITICAL:** DeleteImportedKeyMaterial called against a key that was used to encrypt >0 objects or resources. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** DeleteImportedKeyMaterial called by an identity not in the `KeyAdministrators` group, regardless of whether the key was used for encryption. **Action:** Immediate IR team response.
  - **MEDIUM:** DeleteImportedKeyMaterial called by an approved key administrator against a key in a scheduled decommissioning workflow. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `kms:Describe*`, `kms:List*`, `s3:Get*`, `s3:List*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events), S3 data events (for encryption correlation)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact)
  - **T1485** — Data Destruction (Impact)
- **Stakeholders:** CISO, Legal, Security Operations, Cloud Engineering, Data Governance, Executive Team (if data loss confirmed)
- **SLA Target:** Triage within 10 minutes — this may indicate irreversible data loss
- **Compliance:** GDPR Article 33 (72-hour notification if personal data involved), CCPA, SOC2 CC6.1, potential SEC reporting for material data loss

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who deleted the key material?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteImportedKeyMaterial \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Key State:** Verify the key is now in `PendingImport` state (key material deleted).
  ```bash
  aws kms describe-key --key-id <KEY_ID> \
    --query 'KeyMetadata.{KeyId:KeyId,KeyState:KeyState,Origin:Origin,Description:Description}'
  ```

- [ ] **Encryption Impact:** Were any resources encrypted with this key?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CopyObject \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | select(.requestParameters | tostring | contains("<KEY_ID>")) | "\(.requestParameters.bucketName)/\(.requestParameters.key)"' 2>/dev/null
  ```

- [ ] **Full Attack Chain:** Map the complete ransomware timeline.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteImportedKeyMaterial \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == approved key admin` AND `Key in approved decommissioning workflow` AND `No resources encrypted with this key` → **Mark False Positive & Close.**
- **IF** `Any resources were encrypted with this key` → **Proceed to Containment Level 3 IMMEDIATELY** (data loss in progress).
- **IF** `Identity not a key admin` OR `Preceded by CreateKey → Import → Encrypt chain` → **Proceed to Containment Level 3.**
- **IF** `Approved admin, no encrypted resources, scheduled workflow` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | No resources encrypted, known admin | **Deny further KMS delete operations for user:**`aws iam put-user-policy --user-name <USERNAME> --policy-name DenyKMSDelete --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["kms:DeleteImportedKeyMaterial","kms:ScheduleKeyDeletion"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyKMSDelete` |
| **L2 (Hard)** | Unauthorized identity or unclear impact | **Deactivate access keys and deny all KMS operations:**`aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Data encrypted with this key (ransomware confirmed) | **Full identity lockdown, SCP to block all KMS deletions, begin emergency data recovery:**`aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and apply SCP to deny `kms:DeleteImportedKeyMaterial` account-wide | `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

**NOTE:** DeleteImportedKeyMaterial is **irreversible** — the key material cannot be recovered from AWS. Containment focuses on locking the attacker and preventing further damage, not reversing the deletion.

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **Identify all resources encrypted with the now-unusable key:**
  ```bash
  # Check S3 objects encrypted with this key
  aws s3api list-objects-v2 --bucket <BUCKET_NAME> --query 'Contents[*].Key' --output text | \
    xargs -I {} aws s3api head-object --bucket <BUCKET_NAME> --key {} \
    --query '{Key: "'{}'" , SSEKMSKeyId: SSEKMSKeyId}' 2>/dev/null | \
    grep "<KEY_ID>"
  ```

- **Check for EBS volumes encrypted with this key:**
  ```bash
  aws ec2 describe-volumes --filters Name=encrypted,Values=true \
    --query 'Volumes[?KmsKeyId==`<KEY_ARN>`].[VolumeId,State,Size]' --output table
  ```

- **Assess data recoverability:**
  ```bash
  # Check if S3 versioning is enabled (pre-attack versions may be recoverable)
  aws s3api get-bucket-versioning --bucket <BUCKET_NAME>
  ```

- **Check if the attacker left a ransom note:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `PutObject`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | "\(.requestParameters.bucketName)/\(.requestParameters.key)"'
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.keyId') AS key_id,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'DeleteImportedKeyMaterial'
  AND eventtime >= '<INCIDENT_START_TIME>'
ORDER BY eventtime DESC
LIMIT 100;
```

**Full ransomware chain query:**

```sql
SELECT
    eventtime,
    eventname,
    eventsource,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    requestparameters
FROM cloudtrail_logs
WHERE useridentity.arn = '<CALLER_ARN>'
  AND eventtime >= '<INCIDENT_START_TIME>'
  AND eventname IN ('CreateKey', 'GetParametersForImport', 'ImportKeyMaterial', 'CopyObject', 'DeleteImportedKeyMaterial')
ORDER BY eventtime ASC;
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

3. **Preserve key metadata (key still exists, just without material):**
   ```bash
   aws kms describe-key --key-id <KEY_ID> > /tmp/kms-key-<KEY_ID>-metadata.json
   aws kms get-key-policy --key-id <KEY_ID> --policy-name default > /tmp/kms-key-<KEY_ID>-policy.json
   aws kms list-resource-tags --key-id <KEY_ID> > /tmp/kms-key-<KEY_ID>-tags.json
   aws s3 cp /tmp/kms-key-<KEY_ID>-metadata.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
   aws s3 cp /tmp/kms-key-<KEY_ID>-policy.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
   aws s3 cp /tmp/kms-key-<KEY_ID>-tags.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
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
   Revoke active sessions:
   ```bash
   aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOldSessions \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'
   ```

2. **Restore:** Once key material is deleted, data encrypted with that key is **permanently unrecoverable** via that key. Recovery paths:
   - **S3 versioning:** If enabled, restore pre-attack object versions encrypted with org-managed keys:
     ```bash
     aws s3api list-object-versions --bucket <BUCKET_NAME> --prefix <OBJECT_KEY> \
       --query 'Versions[?IsLatest==`false`] | sort_by(@, &LastModified) | [-1].VersionId' --output text
     aws s3api copy-object --bucket <BUCKET_NAME> --key <OBJECT_KEY> \
       --copy-source "<BUCKET_NAME>/<OBJECT_KEY>?versionId=<PREVIOUS_VERSION_ID>" \
       --server-side-encryption aws:kms --ssekms-key-id <ORG_MANAGED_KEY_ID>
     ```
   - **Cross-region replication:** If replicas exist in another region with different encryption.
   - **AWS Backup:** Restore from backup vaults if configured.
   - **No versioning, no backups:** Data is **permanently lost** — document for legal and compliance.

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to deny `kms:DeleteImportedKeyMaterial` except for a break-glass role:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyDeleteImportedKeyMaterial",
         "Effect": "Deny",
         "Action": "kms:DeleteImportedKeyMaterial",
         "Resource": "*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassKeyManagementRole"
           }
         }
       }]
     }
     ```
   - Block EXTERNAL-origin KMS keys entirely (see CreateKey playbook) — this eliminates the entire attack surface.
   - Enable S3 versioning on ALL buckets as a recovery safety net.
   - Enable MFA Delete on critical buckets.
   - Set up CloudWatch alarm with SNS notification for `DeleteImportedKeyMaterial`.

4. **Verify:**
   ```bash
   aws kms delete-imported-key-material --key-id <TEST_KEY_ID>  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was DeleteImportedKeyMaterial being monitored? This is the highest-severity KMS event possible.
   - Was S3 versioning enabled? This is the primary recovery control for this attack.
   - How much time elapsed between CreateKey and DeleteImportedKeyMaterial? Could earlier detection have prevented data loss?
   - Was the full ransomware chain (CreateKey → GetParametersForImport → ImportKeyMaterial → CopyObject → DeleteImportedKeyMaterial) detectable as a correlated sequence?
   - Should all EXTERNAL-origin KMS operations be blocked at the organization level?

---

## Detection Rule (Sigma)

```yaml
title: KMS Imported Key Material Deletion (Ransomware Completion)
id: d5e6f7a8-b9c0-1d2e-3f4a-5b6c7d8e9f0a
status: experimental
level: critical
description: Detects DeleteImportedKeyMaterial API calls which indicate the final destructive step of a KMS-based ransomware attack — deleting key material to make encrypted data permanently unrecoverable.
author: MayaTrail
date: 2026/03/12
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1486
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: kms.amazonaws.com
    eventName: DeleteImportedKeyMaterial
  condition: selection
falsepositives:
  - Authorized key decommissioning after data migration to a new key
  - Compliance-driven key material destruction (rare)
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | DeleteImportedKeyMaterial destroys the only copy of key material for an EXTERNAL-origin KMS key, making all data encrypted with that key permanently unrecoverable — the point of no return in a cloud ransomware attack |
| T1485 | Data Destruction | Impact | While the data still physically exists, deleting the key material renders it cryptographically destroyed — equivalent to data destruction without physical deletion |

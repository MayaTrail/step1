---
id: aws-kms-createkey
api_call: kms:CreateKey
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
provided_outputs:
  - KEY_ID
  - KEY_ARN
  - KEY_ORIGIN
  - SOURCE_IP
---

# Playbook: Unauthorized KMS Key Creation via CreateKey

**ID:** PB-AWS-KMS-CreateKey-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized KMS Key Creation via CreateKey
- **Playbook ID:** PB-AWS-KMS-CreateKey-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity creates a new KMS key, potentially with `EXTERNAL` origin to enable attacker-controlled key material import for ransomware encryption operations.
- **Trigger:** CloudTrail event where `eventName == CreateKey` from an unexpected identity, or any CreateKey with `Origin == EXTERNAL` outside of approved key management workflows.
- **Severity Matrix:**
  - **CRITICAL:** CreateKey with `Origin == EXTERNAL` by any identity not in the `KeyAdministrators` group, OR CreateKey followed by GetParametersForImport within 10 minutes. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** CreateKey by an identity that has never managed KMS keys before, or from a non-corporate IP. **Action:** Immediate IR team response.
  - **MEDIUM:** CreateKey with `Origin == AWS_KMS` (standard) by a known administrator outside of change windows. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `kms:Describe*`, `kms:List*`, `kms:ScheduleKeyDeletion`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, CISO, Legal (if ransomware suspected)
- **SLA Target:** Triage within 15 minutes for EXTERNAL origin; 30 minutes for standard keys
- **Compliance:** SOC2 CC6.1, potential regulatory reporting if ransomware is confirmed

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who created the key?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateKey \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Key Configuration:** What type of key was created? Is it EXTERNAL origin?
  ```bash
  aws kms describe-key --key-id <KEY_ID> \
    --query 'KeyMetadata.{KeyId:KeyId,Origin:Origin,KeyState:KeyState,KeyUsage:KeyUsage,Description:Description,CreationDate:CreationDate}'
  ```

- [ ] **Key Tags:** Check for attacker indicators in key tags.
  ```bash
  aws kms list-resource-tags --key-id <KEY_ID> --query 'Tags[*]' --output table
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateKey \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Follow-on Activity:** Check if GetParametersForImport or ImportKeyMaterial followed (ransomware chain indicator).
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

- [ ] **Key Policy:** Check if the key policy grants cross-account access.
  ```bash
  aws kms get-key-policy --key-id <KEY_ID> --policy-name default --output text
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == approved key admin` AND `Origin == AWS_KMS` AND `within change window` → **Mark False Positive & Close.**
- **IF** `Origin == EXTERNAL` AND `Identity not in KeyAdministrators` → **Proceed to Containment Level 2 IMMEDIATELY.**
- **IF** `Origin == EXTERNAL` AND `followed by GetParametersForImport` → **Proceed to Containment Level 3** (ransomware chain in progress).
- **IF** `Origin == AWS_KMS`, `known identity, outside change window` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Standard key, known identity | **Disable the key:**`aws kms disable-key --key-id <KEY_ID>` | `aws kms enable-key --key-id <KEY_ID>` |
| **L2 (Hard)** | EXTERNAL origin or unauthorized identity | **Schedule key deletion and disable access keys:**`aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws kms cancel-key-deletion --key-id <KEY_ID>` and `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransomware chain confirmed (CreateKey → Import → Encrypt) | **Immediate key deletion schedule (minimum wait), full identity lockdown:**`aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7` and `aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` and apply SCP to deny `kms:CreateKey` account-wide | `aws kms cancel-key-deletion --key-id <KEY_ID>` and `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **List all KMS keys created by this identity:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `CreateKey`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .responseElements.keyMetadata.keyId'
  ```

- **Check if any of the keys were used to encrypt resources:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `Encrypt`) || contains(CloudTrailEvent, `GenerateDataKey`) || contains(CloudTrailEvent, `CopyObject`)].{Time:EventTime,Event:EventName}' --output table
  ```

- **List all KMS keys with EXTERNAL origin in the account:**
  ```bash
  aws kms list-keys --query 'Keys[*].KeyId' --output text | \
    xargs -I {} aws kms describe-key --key-id {} --query 'KeyMetadata | select(.Origin == `EXTERNAL`) | {KeyId:KeyId,State:KeyState,Description:Description}' 2>/dev/null
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(responseelements, '$.keyMetadata.keyId') AS key_id,
    json_extract_scalar(responseelements, '$.keyMetadata.origin') AS key_origin,
    json_extract_scalar(responseelements, '$.keyMetadata.keyUsage') AS key_usage,
    json_extract_scalar(requestparameters, '$.description') AS key_description,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'CreateKey'
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

3. **Preserve key metadata before deletion:**
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

2. **Restore:** If the attacker's key was used to encrypt data:
   - Identify all objects encrypted with the attacker's key (see CopyObject playbook).
   - If the key material is still available (key state != `PendingDeletion`), re-encrypt objects with an organization-controlled key before scheduling deletion.
   - If key material has been deleted, restore objects from versioning or backups.

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to deny `kms:CreateKey` with `Origin == EXTERNAL` except for authorized roles:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyExternalKMSKeys",
         "Effect": "Deny",
         "Action": "kms:CreateKey",
         "Resource": "*",
         "Condition": {
           "StringEquals": {
             "kms:KeyOrigin": "EXTERNAL"
           },
           "StringNotLike": {
             "aws:PrincipalArn": "arn:aws:iam::*:role/ApprovedKeyManagementRole"
           }
         }
       }]
     }
     ```
   - Restrict `kms:CreateKey` to dedicated key administrator roles via IAM conditions.
   - Enable AWS Config rule `kms-cmk-not-scheduled-for-deletion` for monitoring.

4. **Verify:**
   ```bash
   aws kms create-key --origin EXTERNAL --key-usage ENCRYPT_DECRYPT  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was KMS key creation being monitored as a high-severity event?
   - Were EXTERNAL-origin keys ever needed in this account? If not, the SCP should blanket-deny them.
   - Was the CreateKey the start of a ransomware chain? Map the full timeline.

---

## Detection Rule (Sigma)

```yaml
title: KMS Key Creation with External Origin (Ransomware Indicator)
id: f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c
status: experimental
level: high
description: Detects KMS CreateKey API calls, particularly those with EXTERNAL origin which enable attacker-controlled key material import for ransomware operations.
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
    eventSource: kms.amazonaws.com
    eventName: CreateKey
  condition: selection
falsepositives:
  - Authorized key management workflows creating new CMKs
  - Infrastructure-as-code deployments provisioning KMS keys
  - Key rotation processes creating replacement keys
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | CreateKey with EXTERNAL origin allows attackers to create KMS keys backed by their own key material, enabling ransomware encryption where the attacker controls the decryption capability |

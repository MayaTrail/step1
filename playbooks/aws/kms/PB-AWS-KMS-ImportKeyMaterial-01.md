---
id: aws-kms-importkeymaterial
api_call: kms:ImportKeyMaterial
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - KEY_ID
provided_outputs:
  - IMPORTED_KEY_ID
  - EXPIRATION_MODEL
  - SOURCE_IP
---

# Playbook: Unauthorized KMS Key Material Import via ImportKeyMaterial

**ID:** PB-AWS-KMS-ImportKeyMaterial-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized KMS Key Material Import via ImportKeyMaterial
- **Playbook ID:** PB-AWS-KMS-ImportKeyMaterial-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity imports custom key material into a KMS key with EXTERNAL origin, giving the attacker exclusive control over the encryption/decryption capability. This is the critical weaponization step in a KMS-based ransomware attack.
- **Trigger:** CloudTrail event where `eventName == ImportKeyMaterial` from any identity not in an approved key management workflow.
- **Severity Matrix:**
  - **CRITICAL:** ImportKeyMaterial called with `ExpirationModel == KEY_MATERIAL_DOES_NOT_EXPIRE` by an identity not in `KeyAdministrators`, especially if preceded by CreateKey (EXTERNAL) and GetParametersForImport within the same session. **Action:** Wake CISO & Legal immediately.
  - **HIGH:** ImportKeyMaterial called by any identity outside of an approved BYOK workflow. **Action:** Immediate IR team response.
  - **MEDIUM:** ImportKeyMaterial called by an approved key administrator during a scheduled key rotation. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `kms:Describe*`, `kms:List*`, `kms:DisableKey`, `kms:ScheduleKeyDeletion`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, CISO, Legal
- **SLA Target:** Triage within 15 minutes — this is a ransomware weaponization event
- **Compliance:** SOC2 CC6.1, GDPR Article 33, potential regulatory reporting for ransomware

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who imported the key material?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ImportKeyMaterial \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Key State:** Verify the target key now has imported material active.
  ```bash
  aws kms describe-key --key-id <KEY_ID> \
    --query 'KeyMetadata.{KeyId:KeyId,KeyState:KeyState,Origin:Origin,ExpirationModel:ExpirationModel,ValidTo:ValidTo}'
  ```

- [ ] **Expiration Model:** Does the key material expire?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ImportKeyMaterial \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.expirationModel'
  ```

- [ ] **Full Chain Check:** Map the complete attack chain for this identity.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,Event:EventName}' --output table
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ImportKeyMaterial \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == approved key admin` AND `Key in approved BYOK workflow` AND `ExpirationModel has expiry date` → **Mark False Positive & Close.**
- **IF** `ExpirationModel == KEY_MATERIAL_DOES_NOT_EXPIRE` AND `Identity not in KeyAdministrators` → **Proceed to Containment Level 3 IMMEDIATELY.**
- **IF** `Part of CreateKey → GetParametersForImport → ImportKeyMaterial chain by same identity within 1 hour` → **Proceed to Containment Level 3** (active ransomware operation).
- **IF** `Known admin, approved key, during change window` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Known admin, approved workflow | **Disable the key to prevent use:**`aws kms disable-key --key-id <KEY_ID>` | `aws kms enable-key --key-id <KEY_ID>` |
| **L2 (Hard)** | Unauthorized import | **Delete the imported key material and disable access keys:**`aws kms delete-imported-key-material --key-id <KEY_ID>` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | Key material deletion is intentional (no rollback — reimport if needed); `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransomware chain confirmed | **Delete key material, schedule key deletion, full lockdown:**`aws kms delete-imported-key-material --key-id <KEY_ID>` and `aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7` and `aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws kms cancel-key-deletion --key-id <KEY_ID>` and `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

**WARNING:** Deleting imported key material at L2/L3 will make any data encrypted with this key permanently unrecoverable. This is intentional for an attacker-controlled key — but verify the key is NOT being used for legitimate encryption before proceeding.

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **Was the key used to encrypt any resources after import?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `Encrypt`) || contains(CloudTrailEvent, `GenerateDataKey`) || contains(CloudTrailEvent, `CopyObject`)].{Time:EventTime,Event:EventName}' --output table
  ```

- **List all grants on this key** (attacker may have created grants for persistence):
  ```bash
  aws kms list-grants --key-id <KEY_ID> --query 'Grants[*].{GrantId:GrantId,Grantee:GranteePrincipal,Operations:Operations}' --output table
  ```

- **Check key policy for cross-account access:**
  ```bash
  aws kms get-key-policy --key-id <KEY_ID> --policy-name default --output text
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.keyId') AS key_id,
    json_extract_scalar(requestparameters, '$.expirationModel') AS expiration_model,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'ImportKeyMaterial'
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

3. **Preserve key metadata:**
   ```bash
   aws kms describe-key --key-id <KEY_ID> > /tmp/kms-key-<KEY_ID>-metadata.json
   aws kms get-key-policy --key-id <KEY_ID> --policy-name default > /tmp/kms-key-<KEY_ID>-policy.json
   aws kms list-grants --key-id <KEY_ID> > /tmp/kms-key-<KEY_ID>-grants.json
   aws s3 cp /tmp/kms-key-<KEY_ID>-metadata.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
   aws s3 cp /tmp/kms-key-<KEY_ID>-policy.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
   aws s3 cp /tmp/kms-key-<KEY_ID>-grants.json s3://forensic-evidence-<INCIDENT_ID>/kms-evidence/
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
   - **Before deleting key material:** Re-encrypt all affected objects with an organization-controlled key.
   - **If key material was already deleted by attacker:** Restore objects from S3 versioning or backups (see DeleteImportedKeyMaterial playbook).
   - **If no versioning/backups:** Data is permanently unrecoverable — escalate to CISO and Legal.

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to deny `kms:ImportKeyMaterial` except for authorized roles:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyImportKeyMaterialExceptAuthorized",
         "Effect": "Deny",
         "Action": "kms:ImportKeyMaterial",
         "Resource": "*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": "arn:aws:iam::*:role/ApprovedKeyManagementRole"
           }
         }
       }]
     }
     ```
   - Block EXTERNAL-origin KMS key creation entirely if not needed (see CreateKey playbook).
   - Enable CloudWatch alarm on `ImportKeyMaterial` events.

4. **Verify:**
   ```bash
   aws kms import-key-material --key-id <KEY_ID> \
     --import-token <TOKEN> --encrypted-key-material <DATA> \
     --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was ImportKeyMaterial being monitored? This is the most critical event in a KMS ransomware chain.
   - Was the import token obtained via GetParametersForImport? Map the full chain timeline.
   - Were any resources encrypted before containment? Quantify the blast radius.
   - Should all key material import operations be blocked at the organization level?

---

## Detection Rule (Sigma)

```yaml
title: KMS Key Material Import (Ransomware Weaponization)
id: b3c4d5e6-f7a8-9b0c-1d2e-3f4a5b6c7d8e
status: experimental
level: critical
description: Detects ImportKeyMaterial API calls which indicate attacker-controlled key material being injected into a KMS key — the weaponization step of a cloud ransomware attack.
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
    eventName: ImportKeyMaterial
  condition: selection
falsepositives:
  - Authorized BYOK (Bring Your Own Key) workflows for compliance
  - Scheduled key material rotation for imported keys
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | ImportKeyMaterial injects attacker-controlled cryptographic key material into a KMS key, giving the attacker exclusive control over decryption — the weaponization step that enables ransomware encryption of any AWS resource using KMS |

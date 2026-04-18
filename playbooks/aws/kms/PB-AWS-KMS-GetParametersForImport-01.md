---
id: aws-kms-getparametersforimport
api_call: kms:GetParametersForImport
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - KEY_ID
provided_outputs:
  - IMPORT_TOKEN
  - WRAPPING_ALGORITHM
  - SOURCE_IP
---

# Playbook: Unauthorized KMS Import Parameter Retrieval via GetParametersForImport

**ID:** PB-AWS-KMS-GetParametersForImport-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

- **Playbook Name:** Unauthorized KMS Import Parameter Retrieval via GetParametersForImport
- **Playbook ID:** PB-AWS-KMS-GetParametersForImport-01
- **Version:** 1.0
- **Scenario:** An unauthorized or compromised identity retrieves the public key and import token required to import custom key material into a KMS key, a critical step in a KMS-based ransomware attack chain.
- **Trigger:** CloudTrail event where `eventName == GetParametersForImport` from any identity not in an approved key management workflow.
- **Severity Matrix:**
  - **CRITICAL:** GetParametersForImport called against a key with `Origin == EXTERNAL` that was created within the last 60 minutes by the same identity (active ransomware chain). **Action:** Wake CISO & Legal immediately.
  - **HIGH:** GetParametersForImport called by an identity that is not a designated key administrator. **Action:** Immediate IR team response.
  - **MEDIUM:** GetParametersForImport called by a known key administrator against a key in an approved import workflow. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole` with `kms:Describe*`, `kms:List*`, `cloudtrail:LookupEvents`, `iam:Get*`
  - Logs: CloudTrail enabled (management events)
  - Tools: AWS CLI v2, Athena, jq
- **MITRE ATT&CK Mapping:**
  - **T1486** — Data Encrypted for Impact (Impact)
- **Stakeholders:** Security Operations, Cloud Engineering, CISO
- **SLA Target:** Triage within 15 minutes (this is a ransomware chain indicator)
- **Compliance:** SOC2 CC6.1; potential regulatory reporting if ransomware chain is confirmed

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who requested the import parameters?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetParametersForImport \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].{Time:EventTime,User:Username}' \
    --output table
  ```

- [ ] **Key Context:** Which key are they importing material into? When was it created?
  ```bash
  aws kms describe-key --key-id <KEY_ID> \
    --query 'KeyMetadata.{KeyId:KeyId,Origin:Origin,KeyState:KeyState,CreationDate:CreationDate,Description:Description}'
  ```

- [ ] **Chain Analysis:** Was a CreateKey call made by the same identity shortly before?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `CreateKey`) || contains(CloudTrailEvent, `GetParametersForImport`) || contains(CloudTrailEvent, `ImportKeyMaterial`)].{Time:EventTime,Event:EventName}' --output table
  ```

- [ ] **IP Reputation:** Check source IP.
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetParametersForImport \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .sourceIPAddress' | sort -u
  ```

- [ ] **Wrapping Algorithm:** What wrapping algorithm was requested? (Indicates sophistication)
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetParametersForImport \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[*].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.wrappingAlgorithm'
  ```

### Step 2.2: Decision Logic

- **IF** `Identity == approved key admin` AND `Key in approved import workflow` → **Mark False Positive & Close.**
- **IF** `CreateKey (EXTERNAL) by same identity within last 60 min` → **Proceed to Containment Level 3 IMMEDIATELY** (ransomware chain in progress).
- **IF** `Identity not a key admin` OR `Source_IP == non-corporate` → **Proceed to Containment Level 2.**
- **IF** `Known key admin, key in expected state, during change window` → **Proceed to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command | Rollback Command |
|---|---|---|---|
| **L1 (Soft)** | Known admin, single key | **Disable the target KMS key to block import:**`aws kms disable-key --key-id <KEY_ID>` | `aws kms enable-key --key-id <KEY_ID>` |
| **L2 (Hard)** | Unauthorized identity or suspicious key | **Disable key and deactivate access keys:**`aws kms disable-key --key-id <KEY_ID>` and `aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[*].AccessKeyId' --output text \| xargs -I {} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive` | `aws kms enable-key --key-id <KEY_ID>` and `aws iam update-access-key --user-name <USERNAME> --access-key-id <ACCESS_KEY_ID> --status Active` |
| **L3 (Nuclear)** | Ransomware chain confirmed | **Schedule key deletion, full identity lockdown, SCP to block all KMS imports:**`aws kms schedule-key-deletion --key-id <KEY_ID> --pending-window-in-days 7` and `aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` | `aws kms cancel-key-deletion --key-id <KEY_ID>` and `aws iam detach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EmergencyDenyAll` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> --query 'Tags[?Key==`Application`].Value' --output text
```

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

- **How many keys have import parameters been requested for?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `GetParametersForImport`)].CloudTrailEvent' --output text | \
    jq -r '. | fromjson | .requestParameters.keyId' | sort -u
  ```

- **Was ImportKeyMaterial called after this?** (chain completion check)
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `ImportKeyMaterial`)].{Time:EventTime}' --output table
  ```

- **Was the key used to encrypt any resources?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> \
    --query 'Events[?contains(CloudTrailEvent, `Encrypt`) || contains(CloudTrailEvent, `GenerateDataKey`) || contains(CloudTrailEvent, `CopyObject`)].{Time:EventTime,Event:EventName}' --output table
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT
    eventtime,
    useridentity.arn AS caller_arn,
    sourceipaddress,
    useragent,
    json_extract_scalar(requestparameters, '$.keyId') AS key_id,
    json_extract_scalar(requestparameters, '$.wrappingAlgorithm') AS wrapping_algorithm,
    json_extract_scalar(requestparameters, '$.wrappingKeySpec') AS wrapping_key_spec,
    errorcode
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'GetParametersForImport'
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

2. **Restore:** GetParametersForImport is a preparatory call — no direct data damage. However, if this was part of a chain and key material was imported and used for encryption, see the ImportKeyMaterial and CopyObject playbooks for recovery steps.

3. **Harden (The "Never Again" Fix):**
   - Apply an SCP to deny `kms:GetParametersForImport` except for authorized roles:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "DenyGetParametersForImportExceptAuthorized",
         "Effect": "Deny",
         "Action": "kms:GetParametersForImport",
         "Resource": "*",
         "Condition": {
           "StringNotLike": {
             "aws:PrincipalArn": "arn:aws:iam::*:role/ApprovedKeyManagementRole"
           }
         }
       }]
     }
     ```
   - If EXTERNAL-origin keys are never needed, deny `kms:CreateKey` with `Origin == EXTERNAL` at the SCP level (see CreateKey playbook).

4. **Verify:**
   ```bash
   aws kms get-parameters-for-import --key-id <KEY_ID> \
     --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_2048  # Should be denied by SCP
   ```

5. **Post-Mortem:**
   - Was GetParametersForImport being monitored? It is a strong ransomware chain indicator.
   - Was this part of a CreateKey → GetParametersForImport → ImportKeyMaterial → Encrypt chain?
   - Should all EXTERNAL-origin KMS operations be blocked at the organization level?

---

## Detection Rule (Sigma)

```yaml
title: KMS Import Parameters Retrieved (Ransomware Chain Indicator)
id: a2b3c4d5-e6f7-8a9b-0c1d-2e3f4a5b6c7d
status: experimental
level: high
description: Detects GetParametersForImport API calls against KMS keys, which indicates preparation for importing attacker-controlled key material — a critical step in cloud ransomware operations.
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
    eventName: GetParametersForImport
  condition: selection
falsepositives:
  - Authorized key import workflows for BYOK (Bring Your Own Key) compliance requirements
  - Key rotation processes using imported key material
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | GetParametersForImport retrieves the wrapping public key and import token needed to inject attacker-controlled key material into a KMS key, enabling ransomware encryption of cloud resources |

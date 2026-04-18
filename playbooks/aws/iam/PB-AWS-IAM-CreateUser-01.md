---
id: aws-iam-createuser
api_call: iam:CreateUser
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - CALLER_ARN
provided_outputs:
  - CREATED_USERNAME
  - CREATION_TIME
  - SOURCE_IP
---

# Playbook: Unauthorized IAM User Creation

**ID:** PB-AWS-IAM-CreateUser-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Unauthorized IAM User Creation |
| **Playbook ID** | PB-AWS-IAM-CreateUser-01 |
| **Version** | 1.0 |
| **Scenario** | An attacker calls `iam:CreateUser` to create a backdoor IAM user in the target AWS account. In the SCARLETEEL campaign, the attacker used stolen EC2 instance role credentials (principal `i-0aea82a9977cd62a4`) from IP `122.162.144.65` to attempt creation of a user named `ScarleteelBackdoor`. This technique establishes persistent access that survives credential rotation of the original compromised identity, giving the attacker an independent foothold in the account. |
| **Trigger** | CloudTrail event `CreateUser` from a principal that is not an IAM administrator, from an unrecognized source IP, or creating a user with a name that does not match organizational naming conventions. |

### Severity Matrix

| Severity | Condition | Action |
|---|---|---|
| **CRITICAL** | `CreateUser` called by an EC2 instance role or Lambda execution role (compute-based identity) AND source IP is external or does not match the expected VPC NAT gateway. | Wake CISO & Legal immediately — attacker has compromised compute credentials and is building persistent backdoor access. |
| **HIGH** | `CreateUser` called by a human IAM user or SSO role AND the created username does not match organizational naming patterns (e.g., contains "backdoor", "test", random strings) OR creation occurs outside business hours. | Immediate IR team response. |
| **MEDIUM** | `CreateUser` called by a known admin principal AND the created username follows naming conventions but no corresponding HR onboarding ticket exists. | Next-business-day triage. |

- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, Threat Intel feeds
- **MITRE ATT&CK Mapping:**
  - T1136.003: Create Account: Cloud Account
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team, Identity & Access Management Team; Legal if the account contains regulated data
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the account hosts PII/financial data, SOC 2 incident logging is mandatory. Unauthorized user creation in accounts subject to FedRAMP or PCI-DSS must be reported within 24 hours. GDPR/CCPA clocks start if the created user accessed personal data.

### Related Playbooks

- [PB-AWS-IAM-CreateAccessKey-01](PB-AWS-IAM-CreateAccessKey-01.md) — Attacker creates access keys for the backdoor user
- [PB-AWS-IAM-ListUsers-01](PB-AWS-IAM-ListUsers-01.md) — Reconnaissance step preceding user creation
- [SCARLETEEL-V1-CHRONOLOGICAL](../../campaigns/SCARLETEEL-V1-CHRONOLOGICAL.md) — Full SCARLETEEL kill chain

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identify the Creator:** Who called `CreateUser` and what user was created?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn` (the caller), `requestParameters.userName` (the created user), `sourceIPAddress`, and `errorCode`.

- [ ] **Caller Identity Type:** Determine if the caller is an EC2 instance role, Lambda role, or human user:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
    --start-time <INCIDENT_START_TIME> --max-results 10 \
    --query 'Events[].{Time:EventTime,Event:CloudTrailEvent}' --output json
  ```
  Check `userIdentity.type` — if `AssumedRole` with principal containing `:i-` (EC2) or `:function:` (Lambda), escalate severity.

- [ ] **Does the Created User Exist?** Confirm if the `CreateUser` call succeeded:
  ```bash
  aws iam get-user --user-name <CREATED_USERNAME>
  ```
  If AccessDenied or NoSuchEntity, the user was not created (call may have been denied by policy).

- [ ] **IP Reputation:** Check the source IP against threat intelligence and corporate IP ranges.

- [ ] **Subsequent Activity:** Did the attacker attach policies, create keys, or perform other actions after user creation?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <CREATION_TIME> --max-results 100 \
    --lookup-attributes AttributeKey=Username,AttributeValue=<CREATED_USERNAME>
  ```

- [ ] **Naming Convention Check:** Does the username match organizational patterns (e.g., `firstname.lastname`, `svc-appname`)?

### Step 2.2: The "Is It Real?" Decision Gate

- IF `errorCode == AccessDenied` AND no user was created: **Confirmed blocked attempt. Investigate the compromised caller identity — go to Investigation.**
- IF `Caller == EC2_Instance_Role` AND `Source_IP == External`: **Go to Containment Level 3 (IMMEDIATE) — compute credential theft with backdoor user creation.**
- IF `Caller == Human_IAM_User` AND `Username_Does_Not_Match_Naming_Convention` AND `Source_IP == External`: **Go to Containment Level 2 — compromised admin creating persistence.**
- IF `Caller == Known_Admin` AND `Username_Matches_Convention` AND no suspicious follow-up activity: **Verify with HR/IT for legitimate onboarding. If unconfirmed, go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious user created, no confirmed abuse yet | **Deny all actions for the created user via inline policy:** `aws iam put-user-policy --user-name <CREATED_USERNAME> --policy-name DenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <CREATED_USERNAME> --policy-name DenyAll-IR` |
| **L2a (Hard)** | Confirmed unauthorized user creation — revoke access keys | **Delete all access keys for the created user:** `aws iam list-access-keys --user-name <CREATED_USERNAME> --query 'AccessKeyMetadata[].AccessKeyId' --output text \| xargs -I{} aws iam delete-access-key --user-name <CREATED_USERNAME> --access-key-id {}` AND `aws iam delete-login-profile --user-name <CREATED_USERNAME> 2>/dev/null` | Re-create access keys and login profile as needed (document before deletion) |
| **L2b (Hard)** | Confirmed unauthorized user creation — strip policies | **Remove all attached and inline policies from the created user:** `aws iam list-attached-user-policies --user-name <CREATED_USERNAME> --query 'AttachedPolicies[].PolicyArn' --output text \| xargs -I{} aws iam detach-user-policy --user-name <CREATED_USERNAME> --policy-arn {}` AND `aws iam list-user-policies --user-name <CREATED_USERNAME> --query 'PolicyNames[]' --output text \| xargs -I{} aws iam delete-user-policy --user-name <CREATED_USERNAME> --policy-name {}` | Re-attach policies as needed (document before deletion) |
| **L3a (Nuclear)** | Confirmed attacker-created backdoor user | **Delete the backdoor user entirely:** `aws iam delete-user --user-name <CREATED_USERNAME>` | Recreate user if legitimate: `aws iam create-user --user-name <CREATED_USERNAME>` |
| **L3b (Nuclear)** | The calling principal is compromised — revoke sessions | **Revoke caller sessions:** For IAM user: `aws iam put-user-policy --user-name <CALLER_USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` For role: `aws iam put-role-policy --role-name <CALLER_ROLE_NAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Remove session revocation: `aws iam delete-user-policy --user-name <CALLER_USERNAME> --policy-name RevokeOlderSessions-IR` or `aws iam delete-role-policy --role-name <CALLER_ROLE_NAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the calling principal is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <CALLER_USERNAME> | grep Critical-Production-App
aws iam list-role-tags --role-name <CALLER_ROLE_NAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What did the attacker do after creating the user?** Look for policy attachments, access key creation, and login profile creation:
  ```bash
  aws cloudtrail lookup-events \
    --start-time <CREATION_TIME> --max-results 200 \
    --query 'Events[?contains(CloudTrailEvent, `<CREATED_USERNAME>`)]'
  ```

- **Were other users created?** Check for bulk user creation indicating a wider campaign:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **What other API calls did the compromised caller make?** Map the full attack chain:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<CALLER_ARN> \
    --start-time <INCIDENT_START_TIME> --max-results 200
  ```

- **Current IAM user inventory:** List all users to identify any other unauthorized accounts:
  ```bash
  aws iam list-users --query 'Users[].{UserName:UserName,Created:CreateDate}' --output table
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       useridentity.type AS caller_type,
       useridentity.principalid AS caller_principal,
       json_extract_scalar(requestparameters, '$.userName') AS created_username,
       json_extract_scalar(requestparameters, '$.tags') AS user_tags,
       errorcode, errormessage
FROM cloudtrail_logs
WHERE eventname = 'CreateUser'
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-createuser-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-createuser-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-createuser-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-createuser-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Delete the unauthorized user and all associated resources:
   ```bash
   # Remove access keys
   aws iam list-access-keys --user-name <CREATED_USERNAME> --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -I{} aws iam delete-access-key --user-name <CREATED_USERNAME> --access-key-id {}
   # Remove inline policies
   aws iam list-user-policies --user-name <CREATED_USERNAME> --query 'PolicyNames[]' --output text | xargs -I{} aws iam delete-user-policy --user-name <CREATED_USERNAME> --policy-name {}
   # Detach managed policies
   aws iam list-attached-user-policies --user-name <CREATED_USERNAME> --query 'AttachedPolicies[].PolicyArn' --output text | xargs -I{} aws iam detach-user-policy --user-name <CREATED_USERNAME> --policy-arn {}
   # Remove login profile
   aws iam delete-login-profile --user-name <CREATED_USERNAME> 2>/dev/null
   # Delete user
   aws iam delete-user --user-name <CREATED_USERNAME>
   ```

2. **Restore:** `CreateUser` creates an identity — no data damage to reverse. Focus on ensuring the created user was not used to modify resources. If it was, follow the relevant service-specific playbooks for each action taken by the backdoor user.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:CreateUser`** via SCP so only authorized principals can create IAM users:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "iam:CreateUser",
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": ["SecurityAdmin", "IAMAdmin"] }
         }
       }]
     }
     ```
   - **Deny IAM write actions from EC2/Lambda roles** via SCP — compute identities should never create IAM users:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy"],
         "Resource": "*",
         "Condition": {
           "StringLike": { "aws:PrincipalArn": ["arn:aws:sts::*:assumed-role/*"] }
         }
       }]
     }
     ```
   - **Enforce user naming convention** via AWS Config custom rule to detect users that do not match `^(svc-|admin-|[a-z]+\.[a-z]+$)` patterns.
   - **Enable GuardDuty** IAM anomaly detection for unusual `CreateUser` activity.

4. **Verify:** Attempt `CreateUser` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam create-user --user-name test-verify-deny
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `CreateUser` monitored and alerted on? (Yes/No)
   - Was the calling principal authorized to create IAM users?
   - How was the calling principal compromised (e.g., stolen EC2 instance role credentials)?
   - How long did the backdoor user exist before detection?
   - Did the backdoor user perform any actions before containment?
   - Are SCPs in place to prevent compute roles from performing IAM write operations?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM User Created by Non-Admin or Compute Role
id: 7c3d8e2f-1a4b-5c6d-8e9f-0a1b2c3d4e5f
status: experimental
level: high
description: Detects iam:CreateUser calls which create new IAM identities. In the SCARLETEEL campaign, attackers used stolen EC2 instance role credentials to create backdoor users like "ScarleteelBackdoor" for persistent access. User creation by compute roles (EC2, Lambda) is particularly suspicious as these principals should never perform IAM identity management.
author: MayaTrail
date: 2026/04/05
references:
  - https://mayatrail.tech
  - https://sysdig.com/blog/scarleteel-2-0/
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: CreateUser
  filter_denied:
    errorCode: AccessDenied
  condition: selection and not filter_denied
falsepositives:
  - HR-initiated onboarding workflows using authorized automation
  - CI/CD pipelines creating service accounts during environment provisioning
  - AWS Organizations account setup automation
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1136.003 | Create Account: Cloud Account | Persistence | `CreateUser` creates a new IAM identity that provides independent, persistent access to the AWS account. In SCARLETEEL, the attacker attempted to create user "ScarleteelBackdoor" to maintain access beyond the compromised EC2 instance role session |
| T1098 | Account Manipulation | Persistence | The created user becomes a platform for further account manipulation — attaching policies, creating access keys, and establishing console access |
| T1078.004 | Valid Accounts: Cloud Accounts | Defense Evasion, Persistence | A newly created IAM user with a legitimate-looking name can blend in with authorized users, evading detection by appearing as a valid account |

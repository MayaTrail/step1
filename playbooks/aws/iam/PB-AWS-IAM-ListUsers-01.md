---
id: aws-iam-listusers
api_call: iam:ListUsers
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - CALLER_ARN
provided_outputs:
  - ENUMERATED_USERNAMES
  - SOURCE_IP
---

# Playbook: IAM User Enumeration via ListUsers

**ID:** PB-AWS-IAM-ListUsers-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | IAM User Enumeration via ListUsers |
| **Playbook ID** | PB-AWS-IAM-ListUsers-01 |
| **Version** | 1.0 |
| **Scenario** | An attacker calls `iam:ListUsers` to enumerate all IAM users in the account as part of reconnaissance. In the SCARLETEEL campaign, this API call was used in two phases: first by the attacker using stolen EC2 instance role credentials to discover which IAM users exist in the account, and later by a lateral movement user (`scarleteel-secondary-user`) which received AccessDenied due to zero-permission configuration. `ListUsers` is a common first step before privilege escalation — the attacker identifies high-value targets (admin users, service accounts) to attack next. |
| **Trigger** | CloudTrail event `ListUsers` from an EC2 instance role, Lambda execution role, or any principal that has no legitimate need for IAM enumeration; OR a burst of IAM read calls (`ListUsers`, `ListRoles`, `ListPolicies`, `GetUser`) within a short time window from the same source. |

### Severity Matrix

| Severity | Condition | Action |
|---|---|---|
| **CRITICAL** | `ListUsers` called by a compute role (EC2/Lambda) AND followed within 10 minutes by IAM write calls (`CreateUser`, `CreateAccessKey`, `AttachUserPolicy`) from the same source IP or principal. | Wake CISO & Legal immediately — active privilege escalation in progress after reconnaissance. |
| **HIGH** | `ListUsers` called by a compute role or unknown principal AND source IP is external or does not match expected NAT gateway AND 3+ other IAM enumeration calls (`ListRoles`, `ListPolicies`, `GetAccountAuthorizationDetails`) within a 5-minute window. | Immediate IR team response. |
| **MEDIUM** | `ListUsers` called by a human IAM user from an internal IP but with no corresponding change management ticket or operational justification. | Next-business-day triage. |

- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena, Threat Intel feeds
- **MITRE ATT&CK Mapping:**
  - T1087.004: Account Discovery: Cloud Account
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team; Incident Response if enumeration is followed by IAM modifications
- **SLA Target:** Triage: 15 mins
- **Compliance:** IAM enumeration may indicate early-stage compromise. If the account contains PII/financial data, begin SOC 2 incident logging immediately. Document the reconnaissance scope for potential regulatory reporting.

### Related Playbooks

- [PB-AWS-IAM-CreateUser-01](PB-AWS-IAM-CreateUser-01.md) — Attacker creates a backdoor user after enumeration
- [PB-AWS-IAM-CreateAccessKey-01](PB-AWS-IAM-CreateAccessKey-01.md) — Attacker creates access keys for persistence
- [PB-AWS-STS-GetCallerIdentity-01](../sts/PB-AWS-STS-GetCallerIdentity-01.md) — Attacker identifies their own identity before enumeration
- [SCARLETEEL-V1-CHRONOLOGICAL](../../campaigns/SCARLETEEL-V1-CHRONOLOGICAL.md) — Full SCARLETEEL kill chain

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identify the Caller:** Who called `ListUsers` and from where?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `userIdentity.type`, `sourceIPAddress`, `userAgent`, and `errorCode`.

- [ ] **Caller Identity Type:** Determine if the caller is a compute role, human user, or service:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
    --start-time <INCIDENT_START_TIME> --max-results 10 \
    --query 'Events[].{Time:EventTime,Event:CloudTrailEvent}' --output json
  ```
  If `userIdentity.type` is `AssumedRole` with principal containing `:i-` (EC2) or `:function:` (Lambda), escalate severity.

- [ ] **Was it Denied?** Check if the call returned AccessDenied (zero-permission user attempting recon):
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --query 'Events[?contains(CloudTrailEvent, `AccessDenied`)]'
  ```
  Even denied calls are suspicious — the attacker is probing for permissions.

- [ ] **Enumeration Burst Detection:** Did the same principal call other discovery APIs within a 5-minute window?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> --max-results 100 \
    --lookup-attributes AttributeKey=Username,AttributeValue=<CALLER_ARN> \
    --query 'Events[?contains(CloudTrailEvent, `List`) || contains(CloudTrailEvent, `Get`) || contains(CloudTrailEvent, `Describe`)]'
  ```

- [ ] **IP Reputation:** Check the source IP against threat intelligence and corporate IP ranges.

- [ ] **Subsequent Write Actions:** Did enumeration lead to privilege escalation attempts?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> --max-results 100 \
    --lookup-attributes AttributeKey=Username,AttributeValue=<CALLER_ARN> \
    --query 'Events[?contains(CloudTrailEvent, `Create`) || contains(CloudTrailEvent, `Attach`) || contains(CloudTrailEvent, `Put`)]'
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Authorized_Admin` AND `Source_IP == Corporate_VPN` AND matches audit/compliance workflow: **Mark False Positive & Close.**
- IF `errorCode == AccessDenied` AND caller is a zero-permission or minimal-permission user: **Confirmed probing — investigate the caller identity. Go to Investigation.**
- IF `Caller == EC2_Instance_Role` AND followed by IAM write calls: **Go to Containment Level 3 (IMMEDIATE) — active attack chain: recon leading to privilege escalation.**
- IF `Caller == EC2_Instance_Role` AND `Source_IP == External` AND no follow-up write calls yet: **Go to Containment Level 2 — compromised compute performing reconnaissance.**
- IF `Caller == Human_User` AND enumeration burst detected (3+ List/Get/Describe calls in 5 mins): **Go to Containment Level 1 — investigate for possible credential compromise.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious enumeration, no confirmed follow-up abuse | **Deny IAM read actions for the calling principal:** For IAM user: `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:List*","iam:Get*"],"Resource":"*"}]}'` For role: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyIAMRead-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:List*","iam:Get*"],"Resource":"*"}]}'` | For user: `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyIAMRead-IR` For role: `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyIAMRead-IR` |
| **L2 (Hard)** | Confirmed compromised compute role performing recon | **Deny ALL actions for the role AND isolate the EC2 instance:** `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` AND `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ISOLATED_SG_ID>` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyAll-IR` AND `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID>` |
| **L3 (Nuclear)** | Confirmed recon leading to privilege escalation — active attack chain | **Revoke all sessions for the compromised principal AND stop the EC2 instance AND deny all actions:** `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` AND `aws ec2 stop-instances --instance-ids <INSTANCE_ID>` If caller is IAM user: `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions-IR` AND `aws ec2 start-instances --instance-ids <INSTANCE_ID>` Or for user: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the calling principal is NOT tagged `Critical-Production-App`:
```bash
aws iam list-role-tags --role-name <ROLE_NAME> | grep Critical-Production-App
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What did the attacker learn?** If `ListUsers` succeeded, identify all users the attacker now knows about:
  ```bash
  aws iam list-users --query 'Users[].{UserName:UserName,Created:CreateDate,PasswordLastUsed:PasswordLastUsed}' --output table
  ```

- **Full reconnaissance scope:** What other discovery calls did this principal make?
  ```bash
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> --max-results 200 \
    --lookup-attributes AttributeKey=Username,AttributeValue=<CALLER_ARN>
  ```

- **Did enumeration lead to targeting?** Check if any of the enumerated users were subsequently targeted with `CreateAccessKey`, `AttachUserPolicy`, or `CreateLoginProfile`:
  ```bash
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> --max-results 100 \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> --max-results 100 \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy
  ```

- **Multiple callers?** Check if the same reconnaissance pattern appears from different principals (lateral movement indicator, as seen in SCARLETEEL with `scarleteel-secondary-user`):
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       useridentity.type AS caller_type,
       useridentity.principalid AS caller_principal,
       errorcode, errormessage,
       readonly
FROM cloudtrail_logs
WHERE eventname = 'ListUsers'
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

**Correlated enumeration burst query:**
```sql
SELECT eventtime, eventname, sourceipaddress,
       useridentity.arn AS caller_arn,
       errorcode
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN ('ListUsers', 'ListRoles', 'ListPolicies', 'ListGroupsForUser',
                     'GetUser', 'GetAccountAuthorizationDetails', 'ListAttachedUserPolicies',
                     'ListUserPolicies', 'ListAccessKeys')
  AND useridentity.arn = '<CALLER_ARN>'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-listusers-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-listusers-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-listusers-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-listusers-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Revoke compromised credentials and rotate keys for the calling principal:
   ```bash
   # If caller is IAM user — deactivate and rotate access keys
   aws iam list-access-keys --user-name <USERNAME> --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -I{} aws iam update-access-key --user-name <USERNAME> --access-key-id {} --status Inactive
   # If caller is EC2 instance role — the instance metadata credentials expire automatically,
   # but revoke sessions to force re-authentication:
   aws iam put-role-policy --role-name <ROLE_NAME> --policy-name RevokeOlderSessions-IR \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'
   ```

2. **Restore:** `ListUsers` is a read-only call — no data or configuration was modified. Focus on identifying and remediating any follow-up actions the attacker took based on the reconnaissance data gathered.

3. **Harden (The "Never Again" Fix):**
   - **Restrict IAM enumeration from compute roles** via SCP — EC2 and Lambda roles should not enumerate IAM:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": [
           "iam:ListUsers",
           "iam:ListRoles",
           "iam:ListPolicies",
           "iam:GetAccountAuthorizationDetails"
         ],
         "Resource": "*",
         "Condition": {
           "StringLike": { "aws:PrincipalArn": ["arn:aws:sts::*:assumed-role/*"] }
         }
       }]
     }
     ```
   - **Apply least-privilege to the compromised role** — remove unnecessary IAM read permissions from EC2 instance profiles.
   - **Enable IMDSv2** on all EC2 instances to reduce credential theft via SSRF:
     ```bash
     aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens required --http-endpoint enabled
     ```
   - **Deploy GuardDuty** anomaly detection for unusual IAM API call patterns.

4. **Verify:** Attempt `ListUsers` from the hardened compute role and confirm it is denied:
   ```bash
   aws iam list-users
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `ListUsers` from compute roles monitored and alerted on? (Yes/No)
   - How did the attacker obtain the calling principal's credentials (e.g., SSRF to IMDS, exposed environment variables)?
   - Did the enumeration lead to successful privilege escalation?
   - Are SCPs in place to prevent compute roles from performing IAM enumeration?
   - Were there multiple principals performing enumeration (lateral movement indicator)?
   - Was the zero-permission user (`scarleteel-secondary-user` pattern) created as part of this attack chain?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM User Enumeration by Compute Role or Unauthorized Principal
id: 9f4a1b2c-3d5e-6f7a-8b9c-0d1e2f3a4b5c
status: experimental
level: medium
description: Detects iam:ListUsers calls used for IAM reconnaissance. In the SCARLETEEL campaign, attackers called ListUsers using stolen EC2 instance role credentials to identify IAM users for subsequent privilege escalation. Also observed from lateral movement users (scarleteel-secondary-user) receiving AccessDenied. Elevated to HIGH when correlated with subsequent IAM write calls from the same principal.
author: MayaTrail
date: 2026/04/05
references:
  - https://mayatrail.tech
  - https://sysdig.com/blog/scarleteel-2-0/
tags:
  - attack.discovery
  - attack.t1087.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: ListUsers
  filter_console:
    userIdentity.invokedBy: signin.amazonaws.com
  filter_service:
    userIdentity.invokedBy: '*.amazonaws.com'
  condition: selection and not filter_console and not filter_service
falsepositives:
  - Cloud management platforms (ServiceNow, Terraform) performing periodic IAM inventory
  - Security scanning tools (Prowler, ScoutSuite) running authorized audits
  - AWS Config rules evaluating IAM compliance
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Discovery | `ListUsers` returns the complete list of IAM users in the account, giving the attacker a map of all identities available for targeting. In SCARLETEEL, this was used to identify potential privilege escalation targets |
| T1580 | Cloud Infrastructure Discovery | Discovery | `ListUsers` is part of a broader IAM enumeration pattern — attackers chain it with `ListRoles`, `ListPolicies`, and `GetAccountAuthorizationDetails` to build a complete picture of the account's access control surface |
| T1078.004 | Valid Accounts: Cloud Accounts | Defense Evasion, Persistence | Knowledge of existing users enables the attacker to target specific accounts for credential theft or policy attachment, rather than creating new (more detectable) accounts |

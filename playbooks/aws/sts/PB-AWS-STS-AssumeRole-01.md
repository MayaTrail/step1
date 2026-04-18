---
id: aws-sts-assumerole
api_call: sts:AssumeRole
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ASSUMED_ROLE_NAME
  - ACCOUNT_ID
provided_outputs:
  - ROLE_SESSION_NAME
  - ASSUMED_ROLE_ARN
  - SESSION_CREDENTIALS
  - SOURCE_IP
---

# Playbook: Unauthorized Role Assumption via STS AssumeRole

**ID:** PB-AWS-STS-AssumeRole-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker uses `sts:AssumeRole` to assume an IAM role and obtain temporary credentials with that role's permissions — enabling privilege escalation, lateral movement across accounts, or defense evasion by operating under a different identity.
- **Trigger:** CloudTrail event `AssumeRole` from an unrecognized source IP, with a non-standard `RoleSessionName`, targeting a role outside the caller's normal access pattern, or cross-account assumption from an untrusted account.
- **Severity Matrix:**
  - **CRITICAL:** Assumed role has admin-level policies (`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`) attached, confirmed via `list-attached-role-policies`. **Action:** Wake CISO & Legal immediately — attacker has unrestricted access.
  - **HIGH:** Cross-account `AssumeRole` from an external IP or untrusted account ID, regardless of the role's permissions. **Action:** Immediate IR team response.
  - **MEDIUM:** Same-account `AssumeRole` from known IP range but with a non-standard `RoleSessionName` that doesn't match CI/CD or automation naming conventions. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled), GuardDuty enabled
  - Tools: AWS CLI, Athena, IAM Access Analyzer
- **MITRE ATT&CK Mapping:**
  - T1078.004: Valid Accounts: Cloud Accounts
  - T1550.001: Use Alternate Authentication Material: Application Access Token
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team; Legal if the assumed role has access to regulated data
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the assumed role has access to PII/financial data stores, GDPR/CCPA 72-hour notification clock may start upon confirmation. SOC 2 incident logging is mandatory.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who assumed the role? Retrieve the calling principal's identity:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, and `requestParameters.roleSessionName`.

- [ ] **Role Context:** What permissions does the assumed role grant?
  ```bash
  aws iam get-role --role-name <ASSUMED_ROLE_NAME>
  aws iam list-attached-role-policies --role-name <ASSUMED_ROLE_NAME>
  aws iam list-role-policies --role-name <ASSUMED_ROLE_NAME>
  ```

- [ ] **Trust Policy Check:** Who is allowed to assume this role? Is the calling principal in the trust policy?
  ```bash
  aws iam get-role --role-name <ASSUMED_ROLE_NAME> \
    --query 'Role.AssumeRolePolicyDocument'
  ```

- [ ] **Session Name Analysis:** Does the `RoleSessionName` match known automation patterns (e.g., `terraform-*`, `github-actions-*`, `pulumi-*`) or is it suspicious (e.g., `mayatrail-test`, `test123`, random strings)?

- [ ] **Cross-Account Check:** Is the calling account the same as the target account? Cross-account assumptions from untrusted accounts are high-severity:
  ```bash
  # Compare source account in userIdentity.accountId with the role's account
  aws iam get-role --role-name <ASSUMED_ROLE_NAME> --query 'Role.Arn'
  ```

- [ ] **Threat Intel:** Check the source IP against threat intelligence:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --max-results 10 --query 'Events[].CloudTrailEvent'
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Source_IP == Corporate_VPN` AND `RoleSessionName` matches CI/CD pattern AND `AssumeRole` is expected for this pipeline: **Mark False Positive & Close.**
- IF `AssumeRole` succeeded AND assumed role has `AdministratorAccess` or equivalent AND `Source_IP == External`: **Go to Containment Level 3 (IMMEDIATE) — admin-level compromise.**
- IF cross-account `AssumeRole` from untrusted account: **Go to Containment Level 2 — potential lateral movement.**
- IF same-account `AssumeRole` with unusual session name but no subsequent privilege escalation: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious `AssumeRole` from unusual IP, role has limited permissions | **Restrict who can assume the role — update trust policy to deny the suspicious principal:** `aws iam update-assume-role-policy --role-name <ASSUMED_ROLE_NAME> --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<ACCOUNT_ID>:root"},"Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":["<CORPORATE_CIDR>"]}}}]}'` | Restore original trust policy: `aws iam update-assume-role-policy --role-name <ASSUMED_ROLE_NAME> --policy-document '<ORIGINAL_TRUST_POLICY_JSON>'` |
| **L2 (Hard)** | Confirmed unauthorized cross-account assumption or suspicious session active | **Revoke all active sessions for the role:** `aws iam put-role-policy --role-name <ASSUMED_ROLE_NAME> --policy-name RevokeActiveSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | `aws iam delete-role-policy --role-name <ASSUMED_ROLE_NAME> --policy-name RevokeActiveSessions-IR` |
| **L3 (Nuclear)** | Assumed role has admin access and active exploitation confirmed | **Deny all actions on the calling user AND revoke role sessions:** User: `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` AND deactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND revoke role sessions (L2 command above) | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove deny policies: `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` AND `aws iam delete-role-policy --role-name <ASSUMED_ROLE_NAME> --policy-name RevokeActiveSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the role is NOT tagged `Critical-Production-App` or used by active production workloads:
```bash
aws iam list-role-tags --role-name <ASSUMED_ROLE_NAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What did the assumed session do?** Track all API calls made under the assumed role session:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<ROLE_SESSION_NAME> \
    --start-time <ASSUME_TIME> --max-results 100
  ```

- **Were other roles assumed?** Check if the attacker pivoted to additional roles (lateral movement chain):
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time <INCIDENT_START_TIME> --end-time <END_TIME> \
    --max-results 50
  ```

- **Data access audit:** Did the assumed session access S3, DynamoDB, Secrets Manager, or other data stores?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<ROLE_SESSION_NAME> \
    --start-time <ASSUME_TIME> --max-results 200 \
    --query 'Events[?contains(CloudTrailEvent, `GetObject`) || contains(CloudTrailEvent, `GetSecretValue`)]'
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, eventsource, sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.roleArn') AS assumed_role_arn,
       json_extract_scalar(requestparameters, '$.roleSessionName') AS session_name,
       json_extract_scalar(requestparameters, '$.durationSeconds') AS session_duration,
       useridentity.arn AS caller_arn,
       errorcode
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
  AND eventsource = 'sts.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-assumerole-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-assumerole-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-assumerole-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-assumerole-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Revoke the compromised session and rotate the calling user's credentials:
   ```bash
   # Revoke all sessions older than now (inline policy on the role)
   aws iam put-role-policy --role-name <ASSUMED_ROLE_NAME> \
     --policy-name RevokeOlderSessions-IR \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'
   # Rotate the calling user's keys
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** Audit and reverse any changes made by the assumed session. Check CloudTrail for destructive actions (deletions, policy changes, data exfiltration) and use service-specific recovery procedures.

3. **Harden (The "Never Again" Fix):**
   - **Lock down trust policies** — restrict `AssumeRole` to specific principals and require conditions:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Allow",
         "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:root" },
         "Action": "sts:AssumeRole",
         "Condition": {
           "IpAddress": { "aws:SourceIp": ["<CORPORATE_CIDR>"] },
           "Bool": { "aws:MultiFactorAuthPresent": "true" }
         }
       }]
     }
     ```
   - **Enforce external ID for cross-account roles** to prevent confused deputy attacks.
   - **Set maximum session duration** to the minimum required (default 1 hour, reduce if possible):
     ```bash
     aws iam update-role --role-name <ROLE_NAME> --max-session-duration 3600
     ```
   - **SCP to deny AssumeRole on sensitive roles** from non-approved principals.

4. **Verify:** Attempt to assume the role from an unauthorized IP and confirm it is denied:
   ```bash
   aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> \
     --role-session-name test-verification
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was the role's trust policy overly permissive (e.g., `Principal: "*"` or `Principal: {"AWS": "arn:aws:iam::<ACCOUNT_ID>:root"}`)?
   - Did GuardDuty detect the anomalous `AssumeRole`? (Yes/No)
   - Was the `RoleSessionName` monitored for non-standard values? (Yes/No)
   - How were the calling credentials initially compromised?
   - Time from `AssumeRole` event to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS AssumeRole from External IP or with Non-Standard Session Name
id: e5f6a7b8-c9d0-1e2f-3a4b-5c6d7e8f9012
status: experimental
level: high
description: Detects sts:AssumeRole calls which allow an identity to obtain temporary credentials for an IAM role. Unauthorized role assumption enables privilege escalation, lateral movement, and defense evasion by operating under a different identity.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.privilege_escalation
  - attack.lateral_movement
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  condition: selection
falsepositives:
  - CI/CD pipelines assuming deployment roles as part of normal operations
  - AWS services assuming service-linked roles (e.g., Lambda execution roles, ECS task roles)
  - Cross-account access configured for trusted partner accounts or AWS Organizations
  - Terraform/Pulumi/CloudFormation assuming provisioning roles during infrastructure deployments
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Defense Evasion | `AssumeRole` lets an attacker use valid role credentials to operate under a different identity, bypassing identity-based detections and gaining the role's permissions |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Lateral Movement | The temporary credentials returned by `AssumeRole` (AccessKeyId, SecretAccessKey, SessionToken) are bearer tokens usable from any location without the original credentials |

---
id: aws-iam-attachrolepolicy
api_call: iam:AttachRolePolicy
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ROLE_NAME
  - ROLE_SESSION_NAME
  - ACCOUNT_ID
  - POLICY_ARN
provided_outputs:
  - ATTACHED_POLICY_ARN
  - ESCALATED_ROLE_NAME
  - SESSION_ACTIONS_LOG
---

# Playbook: Privilege Escalation via IAM Role Policy Attachment

**ID:** PB-AWS-IAM-PRIVESC-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker with compromised IAM credentials identifies themselves via `sts:GetCallerIdentity`, assumes a target IAM role via `sts:AssumeRole` (session name `<ROLE_SESSION_NAME>`), and attaches the `AdministratorAccess` managed policy to that role using `iam:AttachRolePolicy` — gaining unrestricted AWS access.
- **Trigger:** CloudTrail event `AttachRolePolicy` with `policyArn` containing `AdministratorAccess`, GuardDuty finding `PrivilegeEscalation:IAMUser/AdministrativePermissions`, or anomalous `AssumeRole` event from an unrecognized source IP.
- **Severity Matrix:**
  - **CRITICAL:** `AdministratorAccess` confirmed attached to a role used by production workloads (verify via `aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`). **Action:** Wake CISO & Legal immediately — full account compromise is active.
  - **HIGH:** `AttachRolePolicy` for `AdministratorAccess` confirmed on any role AND source IP is external/unknown. **Action:** Immediate IR team response.
  - **MEDIUM:** `AssumeRole` from an external IP with session name matching known attack patterns (e.g., `mayatrail-test`) but no subsequent `AttachRolePolicy` event. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled), GuardDuty enabled
  - Tools: AWS CLI, Athena, IAM Access Analyzer
- **MITRE ATT&CK Mapping:**
  - T1098: Account Manipulation
  - T1078.004: Valid Accounts: Cloud Accounts
  - T1548: Abuse Elevation Control Mechanism
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team, Legal (if production data at risk)
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the escalated role had access to PII/financial data, GDPR/CCPA 72-hour notification clock starts. SOC 2 incident logging is mandatory.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who assumed the role? Retrieve the caller identity and check if this is a known service account or human user:
  ```bash
  aws sts get-caller-identity
  ```
  Check the user's permissions and policies — do they legitimately have `sts:AssumeRole` on this target?
  ```bash
  aws iam get-user --user-name <USERNAME>
  aws iam list-user-policies --user-name <USERNAME>
  aws iam list-attached-user-policies --user-name <USERNAME>
  ```

- [ ] **Asset Context:** Which role was targeted? Is it attached to production workloads?
  ```bash
  aws iam get-role --role-name <ROLE_NAME>
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  aws iam list-role-tags --role-name <ROLE_NAME>
  ```

- [ ] **Threat Intel:** Check the source IP of the `AssumeRole` and `AttachRolePolicy` calls against GreyNoise/VirusTotal and the corporate VPN list:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --max-results 20
  ```

- [ ] **Session Name Check:** Does the `RoleSessionName` match known attack tooling patterns? Check for non-standard session names that don't match your CI/CD or automation naming conventions (e.g., random strings, tool-generated names).

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Source_IP == Corporate_VPN` AND `User == Known_DevOps_Admin` AND `AssumeRole` matches a scheduled deployment: **Mark False Positive & Close.**
- IF `AttachRolePolicy` for `AdministratorAccess` confirmed in CloudTrail AND `Source_IP == External`: **Go to Containment Level 2 (IMMEDIATE).**
- IF `AssumeRole` succeeded AND `AttachRolePolicy` for `AdministratorAccess` confirmed AND role is used by production services: **Go to Containment Level 3 — credentials are compromised and blast radius is maximum.**
- IF `AssumeRole` from external IP but no subsequent `AttachRolePolicy` event: **Go to Investigation — possible failed or in-progress escalation attempt.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | `AttachRolePolicy` detected, source IP unrecognized, no confirmed admin attachment | **Block policy attachment on the role:** `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyAttachRolePolicy-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:AttachRolePolicy","iam:DetachRolePolicy","iam:PutRolePolicy"],"Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyAttachRolePolicy-IR` |
| **L2 (Hard)** | `AdministratorAccess` confirmed attached, attacker identity confirmed | **Deny all IAM actions for the user:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR` |
| **L3 (Nuclear)** | Credentials confirmed compromised (external IP, active session, admin attached to production role) | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke active sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App` or a service account tied to production workloads:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What was attached?** Confirm which policies are currently on the targeted role:
  ```bash
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  aws iam list-role-policies --role-name <ROLE_NAME>
  ```

- **Who else assumed this role?** Check for lateral movement — did the attacker use the escalated role to access other services:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time <INCIDENT_START_TIME> --end-time <END_TIME> \
    --max-results 50
  ```

- **What did the escalated session do?** Track all API calls made under the assumed role session:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<ROLE_SESSION_NAME> \
    --start-time <INCIDENT_START_TIME> --max-results 100
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.roleArn') AS assumed_role,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS attached_policy,
       json_extract_scalar(requestparameters, '$.roleSessionName') AS session_name
FROM cloudtrail_logs
WHERE eventname IN ('GetCallerIdentity', 'AssumeRole', 'AttachRolePolicy')
  AND useridentity.arn LIKE '%<USERNAME>%'
ORDER BY eventtime ASC;
```

This maps the full privilege escalation timeline: identity probe (`GetCallerIdentity`) → role assumption (`AssumeRole` with session `<ROLE_SESSION_NAME>`) → admin attachment (`AttachRolePolicy` for `AdministratorAccess`).

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-privesc-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-privesc-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-privesc-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-privesc-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize — Remove the escalation:** Detach `AdministratorAccess` from the compromised role immediately:
   ```bash
   aws iam detach-role-policy --role-name <ROLE_NAME> \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   ```
   Rotate all access keys for the compromised user:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** If the attacker used the escalated permissions to modify resources, audit CloudTrail for all actions taken under the `<ROLE_SESSION_NAME>` session and reverse them. Cross-reference with service-specific playbooks (e.g., PB-AWS-S3-DATA-01 for S3 damage).

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:AttachRolePolicy`** via SCP for all non-admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": [
           "iam:AttachRolePolicy",
           "iam:PutRolePolicy",
           "iam:AttachUserPolicy"
         ],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": "SecurityAdmin" }
         }
       }]
     }
     ```
   - **Add IAM permission boundary** to the role preventing self-escalation.
   - **Restrict AssumeRole** with an explicit condition requiring MFA or source IP allowlist on the role's trust policy.

4. **Verify:** Run the simulation again with the hardened policy and confirm `AttachRolePolicy` returns `AccessDenied`:
   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:user/<USERNAME> \
     --action-names iam:AttachRolePolicy sts:AssumeRole \
     --resource-arns arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
   ```

5. **Post-Mortem:**
   - Did GuardDuty detect the `AttachRolePolicy` for `AdministratorAccess`? (Yes/No)
   - Was there an existing SCP blocking `iam:AttachRolePolicy` for non-admins? (Yes/No)
   - Was the role trust policy open to any principal, or was it scoped? (check `AssumeRolePolicyDocument`)
   - Time from first `AssumeRole` event to IR team notification?

---

## Detection Rules

### Rule 1: AdministratorAccess Policy Attached to Role

```yaml
title: AWS AdministratorAccess Policy Attached to IAM Role
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
level: critical
description: Detects AttachRolePolicy calls that attach the AdministratorAccess managed policy to any IAM role. This is the final step of a privilege escalation attack where an attacker grants themselves unrestricted AWS access.
author: MayaTrail
date: 2026/02/25
references:
  - https://mayatrail.tech
tags:
  - attack.privilege_escalation
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: AttachRolePolicy
  filter_admin:
    requestParameters|contains: "AdministratorAccess"
  condition: selection and filter_admin
falsepositives:
  - Infrastructure-as-code pipelines (Terraform, Pulumi, CloudFormation) attaching admin policies during initial provisioning
  - Authorized security team granting temporary admin for break-glass scenarios
```

### Rule 2: AssumeRole Followed by AttachRolePolicy

```yaml
title: AWS Role Assumption Followed by Policy Attachment
id: b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
level: high
description: Detects the privilege escalation chain where an identity assumes a role and then attaches a managed policy to it. Maps to the MayaTrail attach_role_policy simulation (GetCallerIdentity -> AssumeRole -> AttachRolePolicy).
author: MayaTrail
date: 2026/02/25
references:
  - https://mayatrail.tech
tags:
  - attack.privilege_escalation
  - attack.t1098
  - attack.credential_access
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_assume:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  selection_attach:
    eventSource: iam.amazonaws.com
    eventName: AttachRolePolicy
  condition: selection_assume or selection_attach
  timeframe: 10m
falsepositives:
  - CI/CD pipelines that assume deployment roles and configure IAM as part of infrastructure provisioning
  - AWS Organizations management account performing cross-account role setup
```

### Rule 3: Identity Probe Before Role Assumption

```yaml
title: AWS GetCallerIdentity Followed by AssumeRole from External IP
id: c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f
status: experimental
level: medium
description: Detects the reconnaissance pattern where an attacker first identifies themselves via GetCallerIdentity then assumes a role. This is the initial phase of the privilege escalation chain emulated by MayaTrail attach_role_policy.
author: MayaTrail
date: 2026/02/25
references:
  - https://mayatrail.tech
tags:
  - attack.discovery
  - attack.t1078.004
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_identity:
    eventSource: sts.amazonaws.com
    eventName: GetCallerIdentity
  selection_assume:
    eventSource: sts.amazonaws.com
    eventName: AssumeRole
  condition: selection_identity or selection_assume
  timeframe: 5m
falsepositives:
  - AWS SDKs (boto3, AWS CLI) automatically calling GetCallerIdentity for credential validation
  - CI/CD pipelines that verify identity before assuming deployment roles
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Simulation Step |
|---|---|---|---|
| T1098 | Account Manipulation | Persistence | `iam_client.attach_role_policy(PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess", RoleName=role_name)` — attaching admin policy to escalate the role's permissions |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access / Defense Evasion | `sts_client.assume_role(RoleArn=role_arn, RoleSessionName="<ROLE_SESSION_NAME>")` — using valid credentials to assume a legitimate role |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation | The full chain: assume a role that has `iam:AttachRolePolicy` permission, then use that permission to attach `AdministratorAccess` to itself |

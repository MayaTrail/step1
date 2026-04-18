---
id: aws-iam-detachrolepolicy
api_call: iam:DetachRolePolicy
required_inputs:
  - INCIDENT_START_TIME
  - ROLE_NAME
  - POLICY_ARN
  - ACCOUNT_ID
provided_outputs:
  - DETACHED_POLICY_ARN
  - DETACHED_ROLE_NAME
  - SOURCE_IP
---

# Playbook: Unauthorized Managed Policy Detachment via DetachRolePolicy

**ID:** PB-AWS-IAM-DetachRolePolicy-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:DetachRolePolicy` to remove a managed policy from an IAM role — stripping the role's permissions to disrupt production workloads, removing security guardrails, or preparing the role for deletion as part of an eventual consistency exploitation chain.
- **Trigger:** CloudTrail event `DetachRolePolicy` from an unrecognized source IP, targeting a production role, or preceded by `ListAttachedRolePolicies` enumeration within 10 minutes.
- **Severity Matrix:**
  - **CRITICAL:** Detached policy is a security-critical managed policy (`SecurityAudit`, `ReadOnlyAccess`, or any policy with `Deny` statements) AND source IP is external. **Action:** Wake CISO & Legal immediately — attacker dismantling security controls.
  - **HIGH:** `DetachRolePolicy` targeting a role used by production workloads (Lambda, ECS, EC2 instance profiles) from any unrecognized source. **Action:** Immediate IR team response — production services may lose required permissions.
  - **MEDIUM:** `DetachRolePolicy` from an internal IP that doesn't correlate with a change management ticket. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1562.007: Impair Defenses: Disable or Modify Cloud Firewall
  - T1070: Indicator Removal
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team; Engineering if production role affected
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the detached policy enforced regulatory controls, compliance team must be notified within 1 hour. SOC 2 incident logging is mandatory for confirmed unauthorized changes.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who detached the policy?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, `requestParameters.roleName`, and `requestParameters.policyArn`.

- [ ] **Role Context:** Is this role attached to production services?
  ```bash
  aws iam get-role --role-name <ROLE_NAME>
  aws iam list-role-tags --role-name <ROLE_NAME>
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  ```

- [ ] **Policy Context:** What permissions did the detached policy grant?
  ```bash
  aws iam get-policy --policy-arn <POLICY_ARN>
  aws iam get-policy-version --policy-arn <POLICY_ARN> \
    --version-id $(aws iam get-policy --policy-arn <POLICY_ARN> --query 'Policy.DefaultVersionId' --output text)
  ```

- [ ] **Subsequent Activity:** Was the role deleted after policy detachment?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRole \
    --start-time <EVENT_TIME> --max-results 10
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND matches change management ticket: **Mark False Positive & Close.**
- IF `Source_IP == External` AND role tagged as production: **Go to Containment Level 2 (IMMEDIATE) — production role being stripped.**
- IF preceded by `ListAttachedRolePolicies` AND followed by `DeleteRole` from same IP: **Go to Containment Level 3 — full role destruction chain.**
- IF `Source_IP == Internal` AND no subsequent `DeleteRole`: **Go to Investigation — possible misconfiguration or unauthorized change.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious policy detachment, intent unclear | **Re-attach the detached policy:** `aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn <POLICY_ARN>` AND deny further policy modifications on the role: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyPolicyDetach-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:DetachRolePolicy","iam:DeleteRole","iam:DeleteRolePolicy"],"Resource":"*"}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyPolicyDetach-IR` |
| **L2 (Hard)** | Confirmed unauthorized detachment targeting production role | **Deny all IAM actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}'` AND re-attach the policy (L1 command) | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyIAM-IR` |
| **L3 (Nuclear)** | Full role destruction chain confirmed (enumerate → detach → delete) | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What policies remain on the role?** Verify current role state:
  ```bash
  aws iam list-attached-role-policies --role-name <ROLE_NAME>
  aws iam list-role-policies --role-name <ROLE_NAME>
  ```

- **Were policies detached from other roles?** Check for mass policy stripping:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **Does the role still exist?** Check if the attacker deleted it after stripping policies:
  ```bash
  aws iam get-role --role-name <ROLE_NAME>
  ```

- **Impact on services:** Are any Lambda functions, ECS tasks, or EC2 instances using this role now failing?

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('ListAttachedRolePolicies', 'DetachRolePolicy', 'DeleteRole', 'AttachRolePolicy')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-detachpol-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-detachpol-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-detachpol-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-detachpol-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the caller:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** Re-attach the detached managed policy:
   ```bash
   aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn <POLICY_ARN>
   ```
   Verify the policy is correctly re-attached:
   ```bash
   aws iam list-attached-role-policies --role-name <ROLE_NAME>
   ```

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:DetachRolePolicy`** via SCP for non-admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:DetachRolePolicy", "iam:DeleteRolePolicy"],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": "SecurityAdmin" }
         }
       }]
     }
     ```
   - **Protect critical roles** with permission boundaries that prevent policy detachment.
   - **Enable AWS Config rule** `iam-role-managed-policy-check` to alert on missing required policies.

4. **Verify:** Attempt `DetachRolePolicy` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn <POLICY_ARN>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `DetachRolePolicy` alerted on? (Yes/No)
   - Did any production services lose functionality due to the detachment? (Yes/No)
   - Was this part of an eventual consistency exploitation chain? (Yes/No)
   - Time from policy detachment to IR team notification?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM Managed Policy Detached from Role
id: 6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f901234
status: experimental
level: high
description: Detects iam:DetachRolePolicy calls which remove managed policies from IAM roles. Attackers detach policies to strip roles of permissions (disrupting production), remove security controls, or prepare roles for deletion during eventual consistency exploitation.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.defense_evasion
  - attack.t1562.007
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: DetachRolePolicy
  condition: selection
falsepositives:
  - IAM administrators removing deprecated policies during role cleanup
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) updating role configurations
  - Automated policy lifecycle management during role migrations
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion | `DetachRolePolicy` removes managed policies from a role, potentially stripping security controls like deny policies or audit policies |
| T1070 | Indicator Removal | Defense Evasion | Detaching security or logging policies from a role removes the controls that would detect or block the attacker's subsequent actions |

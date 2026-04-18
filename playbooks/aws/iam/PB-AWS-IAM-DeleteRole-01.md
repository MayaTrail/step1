---
id: aws-iam-deleterole
api_call: iam:DeleteRole
required_inputs:
  - INCIDENT_START_TIME
  - ROLE_NAME
  - ACCOUNT_ID
provided_outputs:
  - DELETED_ROLE_NAME
  - DELETED_ROLE_ARN
  - SOURCE_IP
---

# Playbook: Unauthorized IAM Role Deletion via DeleteRole

**ID:** PB-AWS-IAM-DeleteRole-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Context Wrapper

- **Scenario:** An attacker calls `iam:DeleteRole` to permanently remove an IAM role — disrupting all services that depend on the role (Lambda functions, ECS tasks, EC2 instance profiles), destroying trust relationships, and eliminating audit trails tied to the role's identity.
- **Trigger:** CloudTrail event `DeleteRole` from an unrecognized source IP, preceded by `DetachRolePolicy` or `ListAttachedRolePolicies` from the same principal, or targeting a role with active service associations.
- **Severity Matrix:**
  - **CRITICAL:** Deleted role was attached to production services (Lambda execution role, ECS task role, EC2 instance profile). **Action:** Wake CISO & Legal immediately — production outage is imminent or in progress.
  - **HIGH:** `DeleteRole` from an external IP or preceded by `DetachRolePolicy` chain within 15 minutes. **Action:** Immediate IR team response.
  - **MEDIUM:** `DeleteRole` targeting a role with no active service associations, from an internal IP. **Action:** Next-business-day triage.
- **Prerequisites:**
  - Roles: `IncidentResponseRole`, `EmergencyResponseUser`
  - Logs: CloudTrail (Management Events enabled), AWS Config
  - Tools: AWS CLI, Athena, CloudFormation/Terraform state (for recreation)
- **MITRE ATT&CK Mapping:**
  - T1485: Data Destruction
  - T1531: Account Access Removal
- **Stakeholders:** CISO, Security Engineering, Cloud Platform Team, Engineering leads (for production service recovery)
- **SLA Target:** Triage: 15 mins
- **Compliance:** If the deleted role was used by services processing PII/financial data, GDPR/CCPA 72-hour notification clocks may start. SOC 2 incident logging is mandatory.

---

## 2. Triage & Validation Logic

### Step 2.1: Automated Enrichment

- [ ] **Identity Context:** Who deleted the role?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRole \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```
  Extract `userIdentity.arn`, `sourceIPAddress`, and `requestParameters.roleName`.

- [ ] **Role Context:** What was this role used for? Check AWS Config for historical configuration:
  ```bash
  aws configservice get-resource-config-history \
    --resource-type AWS::IAM::Role \
    --resource-id <ROLE_NAME> \
    --limit 5
  ```

- [ ] **Service Impact:** Are any services now failing due to missing role?
  ```bash
  # Check Lambda functions using this role
  aws lambda list-functions --query "Functions[?Role && contains(Role, '<ROLE_NAME>')]"
  ```

- [ ] **Preceding Activity:** Was this preceded by policy detachment (required before role deletion)?
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \
    --start-time <INCIDENT_START_TIME> --max-results 20
  ```

- [ ] **Were other roles deleted?** Check for mass role deletion:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRole \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

### Step 2.2: The "Is It Real?" Decision Gate

- IF `Caller == Known_Admin` AND `Source_IP == Corporate_VPN` AND matches change management ticket AND role has no active service associations: **Mark False Positive & Close.**
- IF role was attached to production services AND `Source_IP == External`: **Go to Containment Level 3 (IMMEDIATE) — production outage.**
- IF preceded by `ListAttachedRolePolicies` → `DetachRolePolicy` → `DeleteRole` chain from same IP: **Go to Containment Level 3 — deliberate role destruction attack.**
- IF `Source_IP == Internal` AND role has no active associations: **Go to Investigation.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | Suspicious deletion of an unused role | **Deny further IAM destructive actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name DenyIAMDestroy-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:DeleteRole","iam:DeleteRolePolicy","iam:DetachRolePolicy","iam:DeleteUser"],"Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name DenyIAMDestroy-IR` |
| **L2 (Hard)** | Role deletion from external IP, no production impact yet | **Deny all actions for the caller:** `aws iam put-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'` | `aws iam delete-user-policy --user-name <USERNAME> --policy-name EmergencyDenyAll-IR` |
| **L3 (Nuclear)** | Production role destroyed, services failing | **Deactivate all access keys:** `aws iam list-access-keys --user-name <USERNAME>` then for each key: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Inactive` AND **Revoke sessions:** `aws iam put-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<CURRENT_ISO_TIMESTAMP>"}}}]}'` AND **Immediately begin role recreation (see Recovery)** | Reactivate keys: `aws iam update-access-key --user-name <USERNAME> --access-key-id <KEY_ID> --status Active` AND remove session revocation: `aws iam delete-user-policy --user-name <USERNAME> --policy-name RevokeOlderSessions-IR` |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the IAM user is NOT tagged `Critical-Production-App`:
```bash
aws iam list-user-tags --user-name <USERNAME> | grep Critical-Production-App
```

---

## 4. Investigation & Forensics (The Deep Dive)

### 4.1 Scope Assessment

- **What trust policy did the deleted role have?** Retrieve from AWS Config history:
  ```bash
  aws configservice get-resource-config-history \
    --resource-type AWS::IAM::Role \
    --resource-id <ROLE_NAME> \
    --limit 1
  ```

- **What services depended on this role?** Check for broken Lambda, ECS, EC2 instance profiles:
  ```bash
  aws lambda list-functions --query "Functions[?contains(Role, '<ROLE_NAME>')]"
  aws ecs list-services --cluster <CLUSTER_NAME>
  ```

- **Were other roles deleted?** Check for mass role destruction:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRole \
    --start-time <INCIDENT_START_TIME> --max-results 50
  ```

- **Full attack chain reconstruction:** Map the enumerate → detach → delete sequence:
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
    --start-time <INCIDENT_START_TIME> --max-results 200
  ```

### 4.2 Root Cause Analysis (Athena)

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       useridentity.arn AS caller_arn,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
       errorcode
FROM cloudtrail_logs
WHERE eventname IN ('ListAttachedRolePolicies', 'DetachRolePolicy', 'DeleteRolePolicy', 'DeleteRole', 'ListRoles')
  AND eventsource = 'iam.amazonaws.com'
  AND eventtime BETWEEN '<START_TIME>' AND '<END_TIME>'
ORDER BY eventtime ASC;
```

### 4.3 Evidence Preservation

1. **Create Forensic Bucket:**
   ```bash
   aws s3 mb s3://forensic-evidence-delrole-<INCIDENT_ID> --region <REGION>
   ```
2. **Secure It:**
   ```bash
   aws s3api put-public-access-block --bucket forensic-evidence-delrole-<INCIDENT_ID> \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-encryption --bucket forensic-evidence-delrole-<INCIDENT_ID> \
     --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
   ```
3. **Copy CloudTrail Logs:**
   ```bash
   aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/<ACCOUNT_ID>/CloudTrail/ \
     s3://forensic-evidence-delrole-<INCIDENT_ID>/cloudtrail-logs/ \
     --exclude "*" --include "*<INCIDENT_DATE>*"
   ```

---

## 5. Recovery & Hardening

1. **Sanitize:** Rotate all access keys for the caller:
   ```bash
   aws iam create-access-key --user-name <USERNAME>
   aws iam delete-access-key --user-name <USERNAME> --access-key-id <OLD_KEY_ID>
   ```

2. **Restore:** Recreate the deleted role using the configuration preserved in AWS Config or IaC state:
   ```bash
   # Recreate the role with its trust policy
   aws iam create-role --role-name <ROLE_NAME> \
     --assume-role-policy-document '<TRUST_POLICY_JSON>'

   # Re-attach all managed policies that were previously attached
   aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn <POLICY_ARN>

   # Re-apply any inline policies
   aws iam put-role-policy --role-name <ROLE_NAME> \
     --policy-name <INLINE_POLICY_NAME> \
     --policy-document '<INLINE_POLICY_JSON>'
   ```
   If using IaC (Terraform/Pulumi/CloudFormation), redeploy the stack to recreate the role with exact configuration.

3. **Harden (The "Never Again" Fix):**
   - **Restrict `iam:DeleteRole`** via SCP for all non-admin principals:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": ["iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DetachRolePolicy"],
         "Resource": "*",
         "Condition": {
           "StringNotLike": { "aws:PrincipalTag/Role": "SecurityAdmin" }
         }
       }]
     }
     ```
   - **Tag critical roles** with `Critical-Production-App` and implement SCP to deny deletion of tagged resources.
   - **Enable AWS Config** to track role changes and trigger alerts on deletion.

4. **Verify:** Attempt `DeleteRole` from a non-admin principal and confirm it is denied:
   ```bash
   aws iam delete-role --role-name <ROLE_NAME>
   # Expected: AccessDenied
   ```

5. **Post-Mortem:**
   - Was `DeleteRole` alerted on? (Yes/No)
   - Did any production services experience outages? (Yes/No)
   - Was the role configuration preserved in IaC state or AWS Config? (Yes/No)
   - Was this part of an eventual consistency exploitation chain? (Yes/No)
   - Time from role deletion to IR team notification?
   - Time from role deletion to role recreation?

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM Role Deleted
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f90123456
status: experimental
level: critical
description: Detects iam:DeleteRole calls which permanently remove IAM roles. This is a destructive action that can cause production outages for services depending on the role (Lambda, ECS, EC2 instance profiles). In the context of eventual consistency exploitation, attackers delete roles during the propagation window using credentials that have already been revoked.
author: MayaTrail
date: 2026/03/10
references:
  - https://mayatrail.tech
tags:
  - attack.impact
  - attack.t1485
  - attack.t1531
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: iam.amazonaws.com
    eventName: DeleteRole
  condition: selection
falsepositives:
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation) removing roles during stack teardown
  - IAM administrators decommissioning unused roles as part of least-privilege cleanup
  - Automated cleanup scripts removing temporary roles after deployment
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1485 | Data Destruction | Impact | `DeleteRole` permanently removes an IAM role, destroying its trust policy, inline policies, and all service associations — causing immediate impact to dependent workloads |
| T1531 | Account Access Removal | Impact | Deleting a role removes the identity that services use to authenticate, effectively revoking access for all workloads that depend on the role |

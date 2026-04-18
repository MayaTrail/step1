---
id: aws-iam-deleteuser
api_call: iam:DeleteUser
required_inputs:
  - INCIDENT_START_TIME
  - USERNAME
  - ACCOUNT_ID
  - CALLER_ARN
  - DELETED_USERNAME
provided_outputs:
  - DELETED_USERNAME
  - DELETION_TIME
  - SOURCE_IP
---

# Playbook: IAM User Deletion

**ID:** PB-AWS-IAM-DeleteUser-01 | **Version:** 1.0 | **Framework:** Maya Playbook Framework

---

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | IAM User Deletion |
| **Playbook ID** | PB-AWS-IAM-DeleteUser-01 |
| **Version** | 1.0 |
| **Scenario** | An attacker calls `iam:DeleteUser` to remove evidence of a backdoor user they created. In the SCARLETEEL 2.0 campaign, the attacker used stolen EC2 instance role credentials (principal `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589`) from IP `122.162.145.217` to create user `ScarleteelBackdoor`, verify the privilege escalation path worked, then immediately delete the user to cover their tracks — all within the same second (12:10:42 UTC). This create-then-delete pattern is a strong indicator of automated attack tooling testing IAM privilege boundaries. |
| **Trigger** | CloudTrail event `DeleteUser` from a principal that is not an IAM administrator, from an unrecognized source IP, or deleting a user that was recently created (within minutes). |

### Severity Matrix

| Severity | Condition | Action |
|---|---|---|
| **CRITICAL** | `DeleteUser` called by an EC2 instance role or Lambda role AND a `CreateUser` event for the same username exists within 5 minutes from the same principal. | Immediate IR response — attacker created and deleted a backdoor user to test permissions. The fact they cleaned up means they're sophisticated and may have established other persistence. |
| **HIGH** | `DeleteUser` called by an unexpected principal for a user that was created recently (same day) OR the deleted username matches known attacker patterns (`*backdoor*`, `*test*`, random strings). | Immediate triage. The user may have been created and used for lateral movement before deletion. |
| **MEDIUM** | `DeleteUser` called by a known admin but without a corresponding offboarding ticket or change request. | Next-business-day triage. Verify with IAM team. |

- **Prerequisites:**
  - Roles: `IncidentResponseRole` with read access to CloudTrail, IAM
  - Logs: CloudTrail (Management Events enabled)
  - Tools: AWS CLI, Athena
- **MITRE ATT&CK Mapping:**
  - T1070.004: Indicator Removal: File Deletion (adapted: identity deletion)
  - T1531: Account Access Removal
- **Stakeholders:** Security Oncall, IAM team, CISO (if part of a confirmed attack chain)
- **SLA Target:** Triage: 15 mins
- **Compliance:** SOC 2 requires audit trail of all identity lifecycle changes. If the deleted user accessed regulated data, preserve evidence before closing.

### Related Playbooks

- [PB-AWS-IAM-CreateUser-01](PB-AWS-IAM-CreateUser-01.md) — Preceding creation event (correlate timestamps)
- [PB-AWS-IAM-CreateAccessKey-01](PB-AWS-IAM-CreateAccessKey-01.md) — Check if keys were created for the user before deletion
- [SCARLETEEL-V2-CHRONOLOGICAL](../../campaigns/SCARLETEEL-V2-CHRONOLOGICAL.md) — Full SCARLETEEL 2.0 kill chain

---

## 2. Triage & Validation

### Step 2.1: Automated Enrichment

- [ ] **Identify the Caller and Deleted User:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUser \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress,
       deletedUser: .requestParameters.userName, errorCode}'
  ```

- [ ] **Correlate with CreateUser — was this user just created?**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      select(.requestParameters.userName == "<DELETED_USERNAME>") |
      {eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress, errorCode}'
  ```
  **Key signal:** If `CreateUser` and `DeleteUser` for the same username occur within minutes from the same principal, this is automated attack tooling — not legitimate administration.

- [ ] **Check if access keys were created for the deleted user:**
  ```bash
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
    --start-time <INCIDENT_START_TIME> --max-results 20 \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      .Events[] | .CloudTrailEvent | fromjson |
      select(.requestParameters.userName == "<DELETED_USERNAME>") |
      {eventTime, keyId: .responseElements.accessKey.accessKeyId, errorCode}'
  ```
  If keys were created before deletion, the attacker may have captured them for persistent access even though the user is now deleted.

- [ ] **What else did this principal do?**
  ```bash
  aws cloudtrail lookup-events \
    --start-time <INCIDENT_START_TIME> \
    --region <REGION> --output json --profile <IR_PROFILE> | jq '
      [.Events[] | .CloudTrailEvent | fromjson |
       select(.userIdentity.arn == "<CALLER_ARN>")] |
      sort_by(.eventTime) |
      .[] | {eventTime, eventName, errorCode}'
  ```

### Step 2.2: Decision Gate

- IF `CreateUser` + `DeleteUser` within seconds from EC2 role → **Automated attack tooling testing priv esc boundaries. Full campaign investigation. Go to Containment.**
- IF `DeleteUser` but user had active access keys → **Keys may still be valid even after user deletion (race condition). Containment L2.**
- IF `DeleteUser` by known admin with offboarding ticket → **Legitimate. Close.**
- IF `DeleteUser` by known admin without ticket → **Process violation. Flag to IAM team.**

---

## 3. Containment Strategy (Graduated Response)

| Level | Condition | Action | Rollback |
|---|---|---|---|
| **L1 (Soft)** | Suspected attack — user already deleted | Revoke sessions on the calling role: `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name EmergencyRevokeOldSessions` |
| **L2 (Hard)** | Access keys were created before deletion | Deactivate any captured keys (if key ID known): `aws iam update-access-key --user-name <DELETED_USERNAME> --access-key-id <KEY_ID> --status Inactive` Note: This may fail if user is already deleted. | N/A |
| **L3 (Nuclear)** | Part of confirmed multi-phase attack | Deny-all on compromised role + isolate EC2 instance | Restore after investigation |

**CRITICAL CHECK:** Before L2/L3, confirm the asset is NOT tagged `Critical-Production-App`.

---

## 4. Investigation & Forensics

### Step 4.1: Reconstruct the Create-Delete Sequence

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.eventName == "CreateUser" or .eventName == "DeleteUser" or
            .eventName == "CreateAccessKey" or .eventName == "AttachUserPolicy") |
     select(.requestParameters.userName == "<DELETED_USERNAME>" or
            (.requestParameters.userName // "") == "<DELETED_USERNAME>")] |
    sort_by(.eventTime)'
```

### Step 4.2: Assess What the Deleted User Did (If Anything)

Even though the user is deleted, any API calls made during its brief existence are still in CloudTrail:

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.userIdentity.arn | contains("<DELETED_USERNAME>"))] |
    sort_by(.eventTime) |
    .[] | {eventTime, eventName, sourceIP: .sourceIPAddress, errorCode}'
```

### Step 4.3: Evidence Preservation

The deleted user no longer exists in IAM, but CloudTrail retains all events for 90 days. Export immediately:

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_TIME> \
  --region <REGION> --output json --profile <IR_PROFILE> | jq '
    [.Events[] | .CloudTrailEvent | fromjson |
     select(.requestParameters.userName == "<DELETED_USERNAME>" or
            (.userIdentity.arn // "") | contains("<DELETED_USERNAME>"))]' \
  > /tmp/deleted_user_forensics.json
```

---

## 5. Recovery & Hardening

### 5.1: Immediate Actions

| Action | Command |
|---|---|
| Confirm user is actually deleted | `aws iam get-user --user-name <DELETED_USERNAME>` (should return NoSuchEntity) |
| Check for orphaned access keys | `aws iam list-access-keys --user-name <DELETED_USERNAME>` (should fail) |
| Revoke calling role's sessions | See Containment L1 |

### 5.2: Harden

| Fix | Implementation | Priority |
|---|---|---|
| **Block IAM writes from compute** | SCP denying `iam:CreateUser`, `iam:DeleteUser`, `iam:CreateAccessKey` when `aws:PrincipalArn` matches EC2/Lambda roles | P1 |
| **Alert on rapid create-delete** | EventBridge rule: `CreateUser` followed by `DeleteUser` for same username within 5 minutes → SNS alert | P1 |
| **Enable CloudTrail Insights** | Detects unusual IAM API call volume | P2 |

### 5.3: Verify

```bash
# Test SCP: attempt CreateUser from EC2 role (should be denied)
# (run from the EC2 instance or with assumed role)
aws iam create-user --user-name scp-test-user
# Expected: AccessDeniedException
```

---

## Detection Rule (Sigma Format)

```yaml
title: AWS IAM User Rapid Create-Delete from EC2 Instance Role
id: f6a7b8c9-0314-5678-f012-3456789abcde
status: experimental
description: >
  Detects the SCARLETEEL pattern where an EC2 instance role creates
  and then immediately deletes an IAM user. This indicates automated
  attack tooling testing IAM privilege boundaries. In the emulation,
  CreateUser("ScarleteelBackdoor") and DeleteUser occurred in the same
  second from stolen EC2 credentials.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/11
tags:
  - attack.defense_evasion
  - attack.t1070.004
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  create:
    eventSource: iam.amazonaws.com
    eventName: CreateUser
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  delete:
    eventSource: iam.amazonaws.com
    eventName: DeleteUser
    userIdentity.type: AssumedRole
    userIdentity.principalId|contains: ':i-'
  condition: create and delete | near create delete
  timeframe: 5m
falsepositives:
  - Infrastructure-as-code rollback deleting a just-created user (should not come from EC2 role)
level: critical
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion |
| T1531 | Account Access Removal | Impact |

---

## Verified Against Emulation Logs

Validated against CloudTrail events from SCARLETEEL 2.0 emulation on 2026-04-11:

| Time (UTC) | Event | Principal | Source IP | Target User | Result |
|---|---|---|---|---|---|
| 12:10:42 | `CreateUser` | `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` | `122.162.145.217` | `ScarleteelBackdoor` | OK |
| 12:10:42 | `DeleteUser` | `scarleteel-vuln-ec2-role-dea0778/i-0f94960b20ea0f589` | `122.162.145.217` | `ScarleteelBackdoor` | OK |

**Key observations:**
- Both events at the **exact same second** — automated tooling, not human activity.
- The attacker created the user to verify `iam:CreateUser` permission works, then immediately cleaned up. This is a privilege boundary probe.
- Source IP `122.162.145.217` does not match instance IP `13.220.122.208` — credential exfiltration confirmed.
- The `requestParameters.userName: "ScarleteelBackdoor"` naming is distinctive, but real attackers use legitimate-sounding names.

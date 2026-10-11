# IR Playbook: ATOMIC-iam-account-access-removal — AWS IAM Account Access Removal (T1531)

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Destructive / Impact — Bulk IAM Account Access Removal |
| Threat Actor | ATOMIC-iam-account-access-removal (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Impact (TA0040) |
| MITRE Techniques | T1531 — Account Access Removal |
| Sub-Actions | DeleteLoginProfile, UpdateAccessKey (Inactive), DeactivateMFADevice, RemoveUserFromGroup, DetachUserPolicy, PutUserPermissionsBoundary |

---

## 1. Preparation

### Prerequisites
- CloudTrail management events enabled (all regions); trail must include IAM service events
- CloudWatch Logs integration for CloudTrail (enables log insights queries)
- AWS Config with IAM recorder enabled
- GuardDuty enabled (detects anomalous IAM activity)
- IAM Access Analyzer enabled
- Incident response IAM break-glass role pre-staged with `iam:*`, `sts:*`, `cloudtrail:LookupEvents`
- Saved IAM user inventory snapshot (baseline for diffing after incident)
- SCPs or permission boundaries on critical users to limit blast radius of rogue IAM principals
- Pre-built CloudWatch Insights query saved for T1531 detection (see §2)
- On-call runbook for: who owns IAM user re-provisioning, which users are production-critical

### Assumed Inputs at Page 1
- AWS account ID: `$ACCOUNT_ID`
- AWS CLI profile with break-glass IAM/CloudTrail read permissions: `--profile ir-responder`
- Approximate incident start time (UTC): `$START_TIME` (e.g. `2026-10-11T08:00:00Z`)
- Approximate incident end time: `$END_TIME`

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Any of these alone confirms active or completed T1531 attack

| CloudTrail `eventName` | `eventSource` | What it means |
|---|---|---|
| `DeleteLoginProfile` | `iam.amazonaws.com` | Console password destroyed for a user |
| `UpdateAccessKey` with `status=Inactive` | `iam.amazonaws.com` | API/CLI key revoked |
| `DeactivateMFADevice` | `iam.amazonaws.com` | MFA factor removed from user |
| `RemoveUserFromGroup` | `iam.amazonaws.com` | Group-inherited permissions severed |
| `DetachUserPolicy` | `iam.amazonaws.com` | Managed policy stripped from user |
| `PutUserPermissionsBoundary` | `iam.amazonaws.com` | Permissions boundary applied (zeroing effective perms) |

#### MEDIUM-CONFIDENCE — Corroborating / precursor events

| CloudTrail `eventName` | Significance |
|---|---|
| `AssumeRole` by an unfamiliar or attacker-owned role | Attacker establishing session before IAM write actions |
| `ListUsers`, `ListAccessKeys`, `ListGroupsForUser` | Reconnaissance preceding bulk removal |
| `GetLoginProfile` | Confirming a target has a console profile before deleting it |
| `ListAttachedUserPolicies` | Mapping policies to strip |

---

### Key Investigation Queries

#### 2.1 — Enumerate all T1531 events in the incident window

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --query "Events[?EventName=='DeleteLoginProfile' || EventName=='UpdateAccessKey' || EventName=='DeactivateMFADevice' || EventName=='RemoveUserFromGroup' || EventName=='DetachUserPolicy' || EventName=='PutUserPermissionsBoundary'].[EventTime,EventName,Username,CloudTrailEvent]" \
  --output table
```

#### 2.2 — Identify the actor principal (AssumeRole that seeded attacker session)

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[2])
    print(e[0], ct['userIdentity'].get('arn',''), ct.get('requestParameters',{}).get('roleArn',''))
"
```

#### 2.3 — List all users whose login profiles were deleted

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteLoginProfile \
  --query "Events[].[EventTime,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[1])
    print(e[0], ct.get('requestParameters',{}).get('userName',''))
"
```

#### 2.4 — List all users whose access keys were deactivated

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAccessKey \
  --query "Events[].[EventTime,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[1])
    rp = ct.get('requestParameters',{})
    print(e[0], rp.get('userName',''), rp.get('accessKeyId',''), rp.get('status',''))
"
```

#### 2.5 — List group membership removals

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RemoveUserFromGroup \
  --query "Events[].[EventTime,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[1])
    rp = ct.get('requestParameters',{})
    print(e[0], rp.get('userName',''), rp.get('groupName',''))
"
```

#### 2.6 — List policy detachments

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DetachUserPolicy \
  --query "Events[].[EventTime,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[1])
    rp = ct.get('requestParameters',{})
    print(e[0], rp.get('userName',''), rp.get('policyArn',''))
"
```

#### 2.7 — Identify permissions boundary applications

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutUserPermissionsBoundary \
  --query "Events[].[EventTime,CloudTrailEvent]" \
  --output json | \
  python3 -c "
import json,sys
for e in json.load(sys.stdin):
    ct = json.loads(e[1])
    rp = ct.get('requestParameters',{})
    print(e[0], rp.get('userName',''), rp.get('permissionsBoundary',''))
"
```

#### 2.8 — Current state: enumerate all affected users (live snapshot)

```bash
# Replace USER1 USER2 with usernames identified above
for USER in lab-user-1 lab-user-2; do
  echo "=== $USER ==="
  aws iam get-user --profile ir-responder --user-name "$USER" \
    --query "User.[UserName,PermissionsBoundary.PermissionsBoundaryArn,CreateDate]" \
    --output table
  aws iam list-access-keys --profile ir-responder --user-name "$USER" \
    --query "AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]" --output table
  aws iam list-groups-for-user --profile ir-responder --user-name "$USER" \
    --query "Groups[].[GroupName]" --output table
  aws iam list-attached-user-policies --profile ir-responder --user-name "$USER" \
    --query "AttachedPolicies[].[PolicyName,PolicyArn]" --output table
  aws iam list-mfa-devices --profile ir-responder --user-name "$USER" \
    --query "MFADevices[].[SerialNumber,EnableDate]" --output table
done
```

#### 2.9 — CloudWatch Logs Insights query (if trail ships to CWL)

```
# Run in CloudWatch Logs Insights against your CloudTrail log group
fields @timestamp, eventName, userIdentity.arn, requestParameters.userName, requestParameters.status
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["DeleteLoginProfile","UpdateAccessKey","DeactivateMFADevice","RemoveUserFromGroup","DetachUserPolicy","PutUserPermissionsBoundary"]
| sort @timestamp asc
| limit 200
```

#### 2.10 — Identify the attacker role and any persistent access keys it owns

```bash
# Replace ATTACKER_ROLE with role name identified in AssumeRole events
ATTACKER_ROLE="atomic-iam-account-access-removal-attacker-role"
aws iam get-role --profile ir-responder --role-name "$ATTACKER_ROLE" \
  --query "Role.[RoleName,Arn,CreateDate,AssumeRolePolicyDocument]"
aws iam list-role-policies --profile ir-responder --role-name "$ATTACKER_ROLE"
aws iam list-attached-role-policies --profile ir-responder --role-name "$ATTACKER_ROLE"
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Deny all future AssumeRole calls for the attacker role

```bash
# Attach an explicit deny on sts:AssumeRole inline policy to the attacker role
ATTACKER_ROLE="atomic-iam-account-access-removal-attacker-role"
aws iam put-role-policy \
  --profile ir-responder \
  --role-name "$ATTACKER_ROLE" \
  --policy-name "IR-DENY-ASSUMEROLE" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"IRDenyAllAssumeRole",
      "Effect":"Deny",
      "Action":"sts:AssumeRole",
      "Resource":"*"
    }]
  }'
```

#### 3.2 — Revoke all active sessions from the attacker role (invalidate existing STS tokens)

```bash
# Attach an AWSRevokeOlderSessions-style policy to the role
aws iam put-role-policy \
  --profile ir-responder \
  --role-name "$ATTACKER_ROLE" \
  --policy-name "IR-REVOKE-SESSIONS" \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
      \"Sid\":\"IRRevokeOlderSessions\",
      \"Effect\":\"Deny\",
      \"Action\":\"*\",
      \"Resource\":\"*\",
      \"Condition\":{
        \"DateLessThan\":{
          \"aws:TokenIssueTime\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }
      }
    }]
  }"
```

#### 3.3 — Disable any long-lived access keys belonging to the attacker IAM principal

```bash
ATTACKER_USER="<attacker-iam-user-if-any>"
aws iam list-access-keys --profile ir-responder --user-name "$ATTACKER_USER" \
  --query "AccessKeyMetadata[].[AccessKeyId]" --output text | \
while read KEY_ID; do
  aws iam update-access-key \
    --profile ir-responder \
    --user-name "$ATTACKER_USER" \
    --access-key-id "$KEY_ID" \
    --status Inactive
  echo "Disabled $KEY_ID for $ATTACKER_USER"
done
```

#### 3.4 — Lock the attacker role's trust policy to prevent new AssumeRole from any principal

```bash
aws iam update-assume-role-policy \
  --profile ir-responder \
  --role-name "$ATTACKER_ROLE" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[]
  }'
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Delete all inline policies on the attacker role

```bash
aws iam list-role-policies --profile ir-responder --role-name "$ATTACKER_ROLE" \
  --query "PolicyNames[]" --output text | \
tr '\t' '\n' | while read POLICY; do
  aws iam delete-role-policy \
    --profile ir-responder \
    --role-name "$ATTACKER_ROLE" \
    --policy-name "$POLICY"
  echo "Deleted inline policy: $POLICY"
done
```

#### 4.2 — Detach all managed policies from the attacker role

```bash
aws iam list-attached-role-policies --profile ir-responder --role-name "$ATTACKER_ROLE" \
  --query "AttachedPolicies[].[PolicyArn]" --output text | \
tr '\t' '\n' | while read POLICY_ARN; do
  aws iam detach-role-policy \
    --profile ir-responder \
    --role-name "$ATTACKER_ROLE" \
    --policy-arn "$POLICY_ARN"
  echo "Detached policy: $POLICY_ARN"
done
```

#### 4.3 — Delete the attacker role

```bash
aws iam delete-role \
  --profile ir-responder \
  --role-name "$ATTACKER_ROLE"
```

#### 4.4 — Re-enable access keys for affected users

```bash
for USER in lab-user-1 lab-user-2; do
  aws iam list-access-keys --profile ir-responder --user-name "$USER" \
    --query "AccessKeyMetadata[?Status=='Inactive'].[AccessKeyId]" --output text | \
  tr '\t' '\n' | while read KEY_ID; do
    aws iam update-access-key \
      --profile ir-responder \
      --user-name "$USER" \
      --access-key-id "$KEY_ID" \
      --status Active
    echo "Re-enabled $KEY_ID for $USER"
  done
done
```

#### 4.5 — Restore group memberships for affected users

```bash
GROUP="prod-engineers"
for USER in lab-user-1 lab-user-2; do
  aws iam add-user-to-group \
    --profile ir-responder \
    --group-name "$GROUP" \
    --user-name "$USER"
  echo "Restored $USER to $GROUP"
done
```

#### 4.6 — Re-attach stripped managed policies

```bash
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/EngineeringReadOnly"
for USER in lab-user-1 lab-user-2; do
  aws iam attach-user-policy \
    --profile ir-responder \
    --user-name "$USER" \
    --policy-arn "$POLICY_ARN"
  echo "Reattached $POLICY_ARN to $USER"
done
```

#### 4.7 — Remove permissions boundaries applied by attacker

```bash
for USER in lab-user-1 lab-user-2; do
  aws iam delete-user-permissions-boundary \
    --profile ir-responder \
    --user-name "$USER"
  echo "Removed permissions boundary from $USER"
done
```

#### 4.8 — Recreate console login profiles for affected users

```bash
# Generate temporary passwords and force reset on next login
for USER in lab-user-1 lab-user-2; do
  TEMP_PW="TempPw$(openssl rand -hex 8)!"
  aws iam create-login-profile \
    --profile ir-responder \
    --user-name "$USER" \
    --password "$TEMP_PW" \
    --password-reset-required
  echo "Restored login profile for $USER — temp password: $TEMP_PW (deliver out-of-band)"
done
```

#### 4.9 — Re-enroll MFA devices for affected users (trigger out-of-band)

```bash
# MFA re-enrollment must be user-initiated; remove any stale deactivated virtual MFA serials
for USER in lab-user-1 lab-user-2; do
  # List any virtual MFA devices not currently assigned (orphaned)
  aws iam list-virtual-mfa-devices \
    --profile ir-responder \
    --assignment-status Unassigned \
    --query "VirtualMFADevices[?contains(SerialNumber,'$USER')].[SerialNumber]" \
    --output text | while read SERIAL; do
      aws iam delete-virtual-mfa-device \
        --profile ir-responder \
        --serial-number "$SERIAL"
      echo "Deleted orphaned virtual MFA: $SERIAL"
  done
done
# Notify affected users to re-register MFA via console/CLI
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Verify restored user state

```bash
for USER in lab-user-1 lab-user-2; do
  echo "=== Verification: $USER ==="
  aws iam get-login-profile --profile ir-responder --user-name "$USER" \
    --query "LoginProfile.UserName" --output text && echo "  [OK] Login profile present"
  aws iam list-access-keys --profile ir-responder --user-name "$USER" \
    --query "AccessKeyMetadata[].[AccessKeyId,Status]" --output table
  aws iam list-groups-for-user --profile ir-responder --user-name "$USER" \
    --query "Groups[].[GroupName]" --output table
  aws iam list-attached-user-policies --profile ir-responder --user-name "$USER" \
    --query "AttachedPolicies[].[PolicyName]" --output table
  aws iam get-user --profile ir-responder --user-name "$USER" \
    --query "User.PermissionsBoundary" --output text && echo "  (no boundary = clean)"
done
```

#### 5.2 — Verify attacker role no longer exists

```bash
aws iam get-role \
  --profile ir-responder \
  --role-name "atomic-iam-account-access-removal-attacker-role" 2>&1 | \
grep -q "NoSuchEntity" && echo "[OK] Attacker role deleted" || echo "[FAIL] Role still present"
```

#### 5.3 — Confirm no anomalous recent AssumeRole events post-containment

```bash
aws cloudtrail lookup-events \
  --profile ir-responder \
  --start-time "$CONTAINMENT_TIME" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output text
```

#### 5.4 — Re-validate IAM Access Analyzer findings

```bash
aws accessanalyzer list-findings \
  --profile ir-responder \
  --analyzer-arn "arn:aws:access-analyzer:us-east-1:${ACCOUNT_ID}:analyzer/default" \
  --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query "findings[].[id,resourceType,condition,createdAt]" \
  --output table
```

#### 5.5 — Review Config compliance for IAM rules post-recovery

```bash
aws configservice describe-compliance-by-config-rule \
  --profile ir-responder \
  --config-rule-names \
    "iam-user-group-membership-check" \
    "iam-user-mfa-enabled" \
    "iam-user-no-policies-check" \
  --query "ComplianceByConfigRules[].[ConfigRuleName,Compliance.ComplianceType]" \
  --output table
```

#### 5.6 — Notify affected users to rotate their own credentials post-restoration

```bash
# Deliver temporary passwords out-of-band (Slack DM, email) — do not print to shared terminals
# Instruct users to:
#   1. Log in with temp password and immediately set a new password
#   2. Re-register virtual MFA device under IAM > Security credentials
#   3. Rotate their own access keys (create new, delete old) via aws iam create-access-key
```

---

## 6. Lessons Learned

### Root Cause Questions
- How did the attacker principal (`atomic-iam-account-access-removal-attacker-role`) obtain IAM write permissions (`iam:DeleteLoginProfile`, `iam:UpdateAccessKey`, `iam:DeactivateMFADevice`, `iam:RemoveUserFromGroup`, `iam:DetachUserPolicy`, `iam:PutUserPermissionsBoundary`)?
- Was least-privilege enforced on roles with `iam:*`? Would a deny SCP on `iam:DeleteLoginProfile` for non-admin principals have blocked this?
- Were GuardDuty findings generated? Did any alert fire in under 5 minutes from first `DeleteLoginProfile`?
- Was a CloudWatch alarm wired to the CloudTrail log group for these specific event names?

### Preventive Controls

| Control | Implementation |
|---|---|
| SCP: block `iam:DeleteLoginProfile` outside break-glass role | Attach to OU; exempt only `arn:aws:iam::*:role/BreakGlass*` |
| SCP: block `iam:PutUserPermissionsBoundary` unless boundary ARN is approved | Condition on `iam:PermissionsBoundary` StringEquals approved ARN list |
| CloudWatch metric filter + alarm for `DeleteLoginProfile` | Filter `{ $.eventName = "DeleteLoginProfile" }` → alarm threshold 1 → SNS |
| CloudWatch metric filter + alarm for `UpdateAccessKey` status Inactive | Filter `{ $.eventName = "UpdateAccessKey" && $.requestParameters.status = "Inactive" }` |
| IAM role session policies: scope attacker-style roles to read-only by default | Attach `iam:ReadOnly` session policy at `AssumeRole` call |
| GuardDuty finding: `Policy:IAMUser/RootCredentialUsage` and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` | Ensure GuardDuty is enabled in all regions |
| AWS Config rule: `iam-user-mfa-enabled` with auto-remediation | Lambda auto-remediation re-enables MFA requirement |

### Detection Gap Identified
This attack generates **12 discrete CloudTrail events** across 6 IAM action types within seconds. A behavioral baseline alert for "more than 2 IAM write events on the same `requestParameters.userName` within 60 seconds from the same session" would provide high-fidelity, low-noise detection without tuning per-event alarms individually.

### References
- MITRE ATT&CK T1531: https://attack.mitre.org/techniques/T1531/
- AWS Security Blog: Protecting IAM users from account lockout attacks
- AWS Config managed rules for IAM: `iam-user-mfa-enabled`, `iam-user-group-membership-check`
- CloudTrail IAM event reference: `iam.amazonaws.com` management events
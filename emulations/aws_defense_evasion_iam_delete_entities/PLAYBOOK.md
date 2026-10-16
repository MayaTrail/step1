# IR Playbook: ATOMIC-iam-delete-entities — AWS

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Defense Evasion — Persistence Cleanup / Identity Destruction |
| Threat Actor | ATOMIC-iam-delete-entities |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Defense Evasion (TA0005) |
| MITRE Techniques | T1070.009 — Indicator Removal: Clear Persistence |

---

## 1. Preparation

### Prerequisites
- CloudTrail must be enabled with management events (Read + Write) in all regions and logging to a protected S3 bucket or CloudWatch Logs group.
- AWS Config must track IAM resource changes (`AWS::IAM::User`, `AWS::IAM::Role`, `AWS::IAM::Policy`).
- GuardDuty must be enabled; ensure the `UnauthorizedAccess:IAMUser/TorIPCaller` and `Persistence:IAMUser/UserPermissions` finding families are active.
- SCPs should deny `iam:DeleteUser`, `iam:DeleteRole`, `iam:DeleteAccessKey` from non-admin, non-automation principals at the org level (if not already in place, this incident motivates adding them).
- Maintain a baseline inventory of authorized IAM users and roles (exported nightly from `iam:ListUsers` / `iam:ListRoles`).
- Store CloudTrail log retention >= 365 days; enable log file validation.

### Tooling required
- `aws` CLI v2 with credentials scoped to a read-only investigation role.
- `jq` for JSON filtering.
- Access to the CloudTrail S3 bucket or CloudWatch Logs group.
- Optionally: Athena table over the CloudTrail bucket for large-window queries.

---

## 2. Identification

### Detection Triggers

#### HIGH-CONFIDENCE (always indicates suspicious or malicious activity)

| Audit Event | EventSource | Why High-Confidence |
|---|---|---|
| `DeleteUser` | `iam.amazonaws.com` | IAM users are rarely deleted in bulk; a service-named user (e.g., `svc-prod-recovery-admin`) being deleted outside a change window is strongly anomalous. |
| `DeleteRole` | `iam.amazonaws.com` | Roles with org-internal trust policies (e.g., `OrganizationAccountAccessRole-shadow`) deleted via an assumed-role session — not by automation or SCM pipelines — indicate adversarial cleanup. |
| `DeleteAccessKey` then `DeleteUser` in < 60s | `iam.amazonaws.com` | The exact deletion sequence (`DeleteAccessKey` → `DeleteLoginProfile` → `DeleteUserPolicy` → `DeleteUser`) is an APT cleanup pattern rarely seen in legitimate automation. |
| `AssumeRole` into an IAM-deletion-scoped role from an unexpected principal | `sts.amazonaws.com` | Lab runner / CI principal assuming a role whose permissions are limited to IAM delete APIs is a clear lateral-movement indicator. |

#### MEDIUM-CONFIDENCE (warrant investigation, may be legitimate)

| Audit Event | EventSource | Notes |
|---|---|---|
| `DeleteLoginProfile` | `iam.amazonaws.com` | Could be a user deprovisioning workflow; suspicious when issuer is an assumed-role session rather than HR automation. |
| `DeleteUserPolicy` / `DetachUserPolicy` | `iam.amazonaws.com` | May appear in IaC teardown; suspicious when followed immediately by `DeleteUser`. |
| `DeleteRolePolicy` / `DetachRolePolicy` | `iam.amazonaws.com` | Normal in IaC destroy; suspicious when done from a non-standard assumed-role session. |
| `GetCallerIdentity` before a burst of IAM deletes | `sts.amazonaws.com` | Attackers confirm identity before destructive operations; a `GetCallerIdentity` immediately before IAM bulk-delete is a scripted-attack signal. |

---

### Key Investigation Queries

#### 1. Find all IAM delete events in the last 24 hours
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUser \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,User:Username,Event:EventName,Resource:Resources[0].ResourceName}' \
  --output table
```

#### 2. Full deletion sequence — correlate by session / source IP
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[?contains(`["DeleteUser","DeleteRole","DeleteAccessKey","DeleteLoginProfile","DeleteUserPolicy","DeleteRolePolicy","DetachUserPolicy","DetachRolePolicy"]`, EventName)]
           .{Time:EventTime,EventName:EventName,Principal:Username,Source:CloudTrailEvent}' \
  --output json | jq 'sort_by(.Time)'
```

#### 3. Identify the STS AssumeRole that spawned the attacker session
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '. | fromjson | select(.requestParameters.roleArn != null) | {time: .eventTime, caller: .userIdentity.arn, role: .requestParameters.roleArn, session: .requestParameters.roleSessionName, ip: .sourceIPAddress}'
```

#### 4. Find all calls made by the suspicious assumed-role session
```bash
# Replace SESSION_NAME with the roleSessionName value found above (e.g., AtomicT1070009IAMDeleteEntities)
SESSION_NAME="AtomicT1070009IAMDeleteEntities"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="${SESSION_NAME}" \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,EventName:EventName,Resource:Resources[0].ResourceName}' \
  --output table
```

#### 5. Check AWS Config for the last known state of deleted IAM user
```bash
# Replace DELETED_USER_ARN with the ARN of the deleted user
DELETED_USER_ARN="arn:aws:iam::123456789012:user/svc-prod-recovery-admin"
aws configservice get-resource-config-history \
  --resource-type AWS::IAM::User \
  --resource-id "${DELETED_USER_ARN##*/}" \
  --limit 10 \
  --query 'configurationItems[*].{CaptureTime:configurationItemCaptureTime,Status:configurationItemStatus,Config:configuration}' \
  --output json | jq '.'
```

#### 6. Check AWS Config for last known state of deleted IAM role
```bash
DELETED_ROLE_NAME="OrganizationAccountAccessRole-shadow"
aws configservice get-resource-config-history \
  --resource-type AWS::IAM::Role \
  --resource-id "${DELETED_ROLE_NAME}" \
  --limit 10 \
  --query 'configurationItems[*].{CaptureTime:configurationItemCaptureTime,Status:configurationItemStatus,Config:configuration}' \
  --output json | jq '.'
```

#### 7. List GuardDuty findings for the time window
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id "${DETECTOR_ID}" \
  --finding-criteria '{"Criterion":{"updatedAt":{"GreaterThanOrEqual":1},"type":{"Equals":["Persistence:IAMUser/UserPermissions","UnauthorizedAccess:IAMUser/ConsoleLoginSuccess"]}}}' \
  --query 'FindingIds' \
  --output json
```

#### 8. Confirm deletion sequence timing (Athena — for broad window searches)
```sql
-- Run in Athena against your CloudTrail table
SELECT
  eventtime,
  eventname,
  useridentity.sessioncontext.sessionissuer.arn AS assumed_role,
  useridentity.arn AS caller_arn,
  requestparameters,
  sourceipaddress,
  useragent
FROM cloudtrail_logs
WHERE eventtime >= '2026-10-10T00:00:00Z'
  AND eventsource = 'iam.amazonaws.com'
  AND eventname IN (
    'DeleteUser','DeleteRole','DeleteAccessKey',
    'DeleteLoginProfile','DeleteUserPolicy','DeleteRolePolicy',
    'DetachUserPolicy','DetachRolePolicy'
  )
ORDER BY eventtime ASC;
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Revoke all active sessions from the attacker execution role
```bash
# Find the role name from the AssumeRole event, then attach a deny-all inline policy
# to immediately invalidate all issued sessions (AWS revokes sessions issued before this timestamp)
ATTACKER_ROLE_NAME="atomic-iam-delete-attacker-exec-role"
REVOKE_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

aws iam put-role-policy \
  --role-name "${ATTACKER_ROLE_NAME}" \
  --policy-name "RevokeAllSessions" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"${REVOKE_TIME}\"
        }
      }
    }]
  }"
```

#### Step 2 — Disable the attacker execution role (prevent new AssumeRole)
```bash
# Attach a deny-assume-role resource policy equivalent by modifying the trust policy
# to remove all trusted principals (effectively disabling new assumptions)
ATTACKER_ROLE_NAME="atomic-iam-delete-attacker-exec-role"

aws iam update-assume-role-policy \
  --role-name "${ATTACKER_ROLE_NAME}" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": []
  }'
```

#### Step 3 — Identify and disable any surviving access keys from the attacker session's user identity
```bash
# Find the IAM user or role the lab runner used to call AssumeRole
# If it is an IAM user, list and disable its keys
LAB_RUNNER_USER="<lab-runner-iam-user>"  # replace from AssumeRole event's userIdentity.userName
aws iam list-access-keys --user-name "${LAB_RUNNER_USER}" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}' \
  --output table

# Disable suspicious key
aws iam update-access-key \
  --user-name "${LAB_RUNNER_USER}" \
  --access-key-id "<KEY_ID>" \
  --status Inactive
```

#### Step 4 — Place an SCP to freeze IAM deletes in the affected account while investigation continues
```bash
# Create an emergency SCP (requires Organizations admin permissions)
aws organizations create-policy \
  --name "EmergencyFreezeIAMDeletes" \
  --type SERVICE_CONTROL_POLICY \
  --description "Emergency freeze during incident response - block IAM entity deletion" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": [
        "iam:DeleteUser",
        "iam:DeleteRole",
        "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "iam:DeleteUserPolicy",
        "iam:DeleteRolePolicy",
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalARN": [
            "arn:aws:iam::*:role/BreakGlassAdmin",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }]
  }'

# Attach to the affected account
POLICY_ID="<policy-id-from-above>"
ACCOUNT_ID="<affected-account-id>"
aws organizations attach-policy \
  --policy-id "${POLICY_ID}" \
  --target-id "${ACCOUNT_ID}"
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1 — Delete the attacker execution role (if no longer needed for investigation)
```bash
ATTACKER_ROLE_NAME="atomic-iam-delete-attacker-exec-role"

# First remove all inline policies
for POLICY in $(aws iam list-role-policies --role-name "${ATTACKER_ROLE_NAME}" --query 'PolicyNames[]' --output text); do
  aws iam delete-role-policy --role-name "${ATTACKER_ROLE_NAME}" --policy-name "${POLICY}"
  echo "Deleted inline policy: ${POLICY}"
done

# Detach managed policies
for POLICY_ARN in $(aws iam list-attached-role-policies --role-name "${ATTACKER_ROLE_NAME}" --query 'AttachedPolicies[*].PolicyArn' --output text); do
  aws iam detach-role-policy --role-name "${ATTACKER_ROLE_NAME}" --policy-arn "${POLICY_ARN}"
  echo "Detached: ${POLICY_ARN}"
done

# Delete the role
aws iam delete-role --role-name "${ATTACKER_ROLE_NAME}"
echo "Attacker execution role deleted."
```

#### Step 2 — Verify no residual backdoor users remain
```bash
# Search for service-named accounts matching the IOC pattern
aws iam list-users \
  --query 'Users[?contains(UserName, `svc-`) || contains(UserName, `recovery`) || contains(UserName, `backup-admin`)]
           .{UserName:UserName,Created:CreateDate,UserId:UserId}' \
  --output table

# For each suspicious user, check its access keys and last activity
SUSPECT_USER="svc-prod-recovery-admin"
aws iam list-access-keys --user-name "${SUSPECT_USER}"
aws iam get-user --user-name "${SUSPECT_USER}" \
  --query 'User.{Created:CreateDate,PasswordLastUsed:PasswordLastUsed}'
```

#### Step 3 — Verify no residual backdoor roles remain
```bash
# Search for shadow / org-impersonating role names matching IOC pattern
aws iam list-roles \
  --query 'Roles[?contains(RoleName, `OrganizationAccountAccessRole`) || contains(RoleName, `shadow`) || contains(RoleName, `CrossAccount`)]
           .{RoleName:RoleName,Created:CreateDate,Arn:Arn}' \
  --output table

# Inspect trust policy of any suspicious role
SUSPECT_ROLE="OrganizationAccountAccessRole-shadow"
aws iam get-role --role-name "${SUSPECT_ROLE}" \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json | jq '.'
```

#### Step 4 — Rotate credentials on the lab runner principal used to initiate the chain
```bash
# Disable old key
aws iam update-access-key \
  --user-name "${LAB_RUNNER_USER}" \
  --access-key-id "<OLD_KEY_ID>" \
  --status Inactive

# Create replacement key (only after verifying the user is legitimate)
aws iam create-access-key --user-name "${LAB_RUNNER_USER}"
```

#### Step 5 — Scan for any additional persisted access keys created during the attack window
```bash
# List all IAM users and their access keys created in the last 4 hours
CUTOFF=$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)
for USER in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name "${USER}" \
    --query "AccessKeyMetadata[?CreateDate>=\`${CUTOFF}\`].{User:'${USER}',KeyId:AccessKeyId,Created:CreateDate,Status:Status}" \
    --output json
done | jq '.[] | select(length > 0)'
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Remove the emergency SCP freeze (after IR closes)
```bash
POLICY_ID="<emergency-freeze-policy-id>"
ACCOUNT_ID="<affected-account-id>"

aws organizations detach-policy \
  --policy-id "${POLICY_ID}" \
  --target-id "${ACCOUNT_ID}"

aws organizations delete-policy --policy-id "${POLICY_ID}"
echo "Emergency SCP removed."
```

#### Step 2 — Verify IAM state matches the baseline snapshot
```bash
# Export current users and compare against pre-incident baseline
aws iam list-users --query 'Users[*].{UserName:UserName,Created:CreateDate}' \
  --output json > /tmp/current_users.json

# Diff against your baseline (stored in S3 or version control)
# aws s3 cp s3://your-config-bucket/iam-baseline/users.json /tmp/baseline_users.json
# diff /tmp/baseline_users.json /tmp/current_users.json

# Equivalent for roles
aws iam list-roles --query 'Roles[*].{RoleName:RoleName,Created:CreateDate,Arn:Arn}' \
  --output json > /tmp/current_roles.json
```

#### Step 3 — Verify CloudTrail is intact (check log file validation)
```bash
TRAIL_NAME="<your-trail-name>"
S3_BUCKET="<your-cloudtrail-bucket>"

aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:us-east-1:$(aws sts get-caller-identity --query Account --output text):trail/${TRAIL_NAME}" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

#### Step 4 — Confirm GuardDuty is enabled and not suppressed
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "${DETECTOR_ID}" \
  --query '{Status:Status,UpdatedAt:UpdatedAt,ServiceRole:ServiceRole}' \
  --output table

# Confirm no suppression rules masked this finding type
aws guardduty list-filters --detector-id "${DETECTOR_ID}" --output table
```

#### Step 5 — Re-enable any security services if they were impaired during the incident
```bash
# Verify AWS Config recorder is running
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[*].{Name:name,Recording:recording,LastStatus:lastStatus}' \
  --output table

# Re-start if stopped
aws configservice start-configuration-recorder \
  --configuration-recorder-name default
```

#### Step 6 — Create a post-incident detective control: alert on IAM entity bulk-deletion
```bash
# Create a CloudWatch metric filter and alarm for DeleteUser / DeleteRole bursts
LOG_GROUP="/aws/cloudtrail/management-events"  # adjust to your CW Logs group name

aws logs put-metric-filter \
  --log-group-name "${LOG_GROUP}" \
  --filter-name "IAMEntityDeletion" \
  --filter-pattern '{ ($.eventName = "DeleteUser") || ($.eventName = "DeleteRole") || ($.eventName = "DeleteAccessKey") }' \
  --metric-transformations \
    metricName=IAMEntityDeletionCount,metricNamespace=SecurityEvents,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name "IAMEntityBulkDeletion" \
  --alarm-description "Alert on IAM entity deletion burst - possible attacker cleanup" \
  --metric-name IAMEntityDeletionCount \
  --namespace SecurityEvents \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 3 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions "arn:aws:sns:us-east-1:$(aws sts get-caller-identity --query Account --output text):SecurityAlerts"
```

---

## 6. Lessons Learned

### What Would Have Prevented or Shortened This Incident

| Gap | Guardrail |
|---|---|
| Backdoor IAM user/role were created and persisted undetected | AWS Config rule `iam-user-no-policies-check` + nightly IAM drift detection against baseline; alert on new service-named users created outside IaC/SCM. |
| Attacker execution role had permissions to `DeleteUser` / `DeleteRole` | Enforce least-privilege SCP: deny `iam:Delete*` for all principals except an approved automation role ARN; require MFA condition on IAM destructive actions. |
| Deletion sequence ran to completion before any alert fired | Add a CloudWatch Logs metric filter (see Recovery Step 6) that fires within 5 minutes of 3+ IAM delete events from a single session. |
| `AssumeRole` into an IAM-deletion-scoped role was not anomaly-detected | Enable GuardDuty finding `Persistence:IAMUser/AnomalousBehavior`; baseline expected `AssumeRole` callers per role and alert on first-seen principals. |
| Deleted resources left no recovery path | Enable IAM Access Analyzer to capture resource policies and trust policies; snapshot IAM state daily to S3 with versioning enabled. |
| CloudTrail log validation not actively monitored | Subscribe to the `ValidateLogsComplete` CloudTrail SNS topic; fail-open alert if validation finds any gaps. |

### Sigma-style Correlation Rule (reference)
```yaml
title: APT IAM Persistence Cleanup Sequence
id: iam-delete-sequence-t1070009
status: stable
description: Detects the exact deletion sequence used by threat actors removing IAM-based persistence
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_events:
    eventSource: iam.amazonaws.com
    eventName|in:
      - DeleteAccessKey
      - DeleteLoginProfile
      - DeleteUserPolicy
      - DeleteUser
      - DeleteRolePolicy
      - DeleteRole
  selection_session:
    userIdentity.type: AssumedRole
  timeframe: 5m
  condition: selection_events AND selection_session | count() by userIdentity.sessionContext.sessionIssuer.arn >= 3
falsepositives:
  - IaC pipeline teardown (validate against change-management window)
  - Automated user deprovisioning (validate against HR workflow source IP/role)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.009
```
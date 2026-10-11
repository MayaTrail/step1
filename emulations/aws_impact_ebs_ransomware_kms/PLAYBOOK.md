# IR Playbook: ATOMIC-ebs-ransomware-kms — AWS EBS Ransomware via KMS Key Swap

## Classification

| Field | Value |
|-------|-------|
| Incident Type | EBS Ransomware — KMS Key Hijack |
| Threat Actor | ATOMIC-ebs-ransomware-kms |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Impact (T1486 — Data Encrypted for Impact) |
| Attack Surface | EC2 EBS volumes/snapshots, KMS CMKs |
| Execution Plane | Control plane (all actions via AWS APIs) |

---

## 1. Preparation

### Prerequisites — must be in place before this incident type occurs

**Logging**
- CloudTrail management events enabled in all regions (multi-region trail recommended)
- CloudTrail log integrity validation enabled
- CloudTrail logs delivered to S3 with S3 Object Lock (WORM) to prevent attacker log tampering
- GuardDuty enabled with EC2 and S3 protection plans active
- AWS Security Hub with AWS Foundational Security Best Practices standard enabled

**Alerting rules to pre-configure**
| Rule | Service | Threshold |
|------|---------|-----------|
| `ec2:CreateSnapshot` by non-automation principal | CloudTrail + EventBridge | Any |
| `ec2:CopySnapshot` where `kmsKeyId` != account-owned CMK | CloudTrail + EventBridge | Any |
| `ec2:DeleteVolume` outside change window | CloudTrail + EventBridge | Any |
| `ec2:DeleteSnapshot` in bulk (>3 in 5 min) | CloudTrail + EventBridge | >3 |
| `kms:ScheduleKeyDeletion` | CloudTrail + EventBridge | Any |
| `kms:PutKeyPolicy` — including `errorCode: AccessDenied` | CloudTrail + EventBridge | Any |

> **Note:** Do NOT filter on `errorCode IS NULL` for `kms:PutKeyPolicy` — the deny-guard fires an `AccessDenied` that is itself an IOC (account lockout attempt).

**IAM controls**
- Enforce MFA on all human IAM users; require SCP-level deny of EC2/KMS destructive actions from non-MFA sessions
- Tag all critical EBS volumes/snapshots with `data-classification: critical` or similar
- Enable EBS snapshot lock (immutability) on production backups
- Apply AWS Backup vault lock with a cooling-off period for critical volumes

**Runbook access**
- Keep this playbook in a location not hosted on AWS (attacker may destroy EC2 resources)
- Maintain an out-of-band communication channel (not reliant on the compromised account)

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — these events, in combination or sequence, always indicate compromise

| # | CloudTrail eventName | eventSource | Why it matters |
|---|---------------------|------------|----------------|
| 1 | `CreateSnapshot` | `ec2.amazonaws.com` | Unexpected snapshot of a volume not in a backup schedule |
| 2 | `CopySnapshot` with foreign `kmsKeyId` | `ec2.amazonaws.com` | Key swap — re-encryption under attacker CMK; victim loses data access |
| 3 | `DeleteVolume` | `ec2.amazonaws.com` | Original volume destroyed after re-encrypted copy created |
| 4 | `DeleteSnapshot` | `ec2.amazonaws.com` | Original backup destroyed — no victim-controlled recovery path |
| 5 | `ScheduleKeyDeletion` within 60s of `DeleteVolume`/`DeleteSnapshot` | `kms.amazonaws.com` | Ransom demand signature — data held hostage under expiring key |

#### MEDIUM-CONFIDENCE — supporting signals (may appear without full ransomware chain)

| # | CloudTrail eventName | eventSource | Why it matters |
|---|---------------------|------------|----------------|
| 6 | `GetCallerIdentity` from unusual principal | `sts.amazonaws.com` | Attacker credential validation prior to attack |
| 7 | `DescribeVolumes` + `DescribeSnapshots` in rapid succession | `ec2.amazonaws.com` | Enumeration phase — target discovery |
| 8 | `PutKeyPolicy` with `errorCode: AccessDenied` | `kms.amazonaws.com` | Attempted account lockout — deny-guard fired |
| 9 | `CancelKeyDeletion` | `kms.amazonaws.com` | Post-attack cleanup or dwell-period marker |

### Sequence Pattern — Ransomware Signature

```
GetCallerIdentity
  -> DescribeVolumes / DescribeSnapshots
  -> CreateSnapshot (of live volume)
  -> CopySnapshot (victim backup, kmsKeyId = ATTACKER_CMK)     [backup destroyed]
  -> CopySnapshot (staging snapshot, kmsKeyId = ATTACKER_CMK)  [live data copied under attacker key]
  -> DeleteVolume
  -> DeleteSnapshot
  -> ScheduleKeyDeletion                                         [ransom demand]
  -> PutKeyPolicy (errorCode: AccessDenied)                     [lockout attempt]
  -> CancelKeyDeletion                                           [dwell marker]
```

This sequence on a single principal within a short time window is unambiguous ransomware.

---

### Key Investigation Queries

#### 1. Identify the attacking principal — all KMS/EC2 destructive calls in the last 24 hours

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteVolume \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,User:Username,Event:EventName,Source:CloudTrailEvent}' \
  --output table
```

#### 2. Find all CopySnapshot calls — check kmsKeyId for foreign CMK

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CopySnapshot \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | 
    {time: .eventTime, 
     user: .userIdentity.arn, 
     sourceRegion: .requestParameters.sourceRegion, 
     kmsKeyId: .requestParameters.kmsKeyId,
     sourceSnapshot: .requestParameters.sourceSnapshotId}'
```

#### 3. Find ScheduleKeyDeletion — correlated with volume/snapshot destruction time

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | 
    {time: .eventTime, 
     user: .userIdentity.arn, 
     keyId: .requestParameters.keyId, 
     pendingWindowInDays: .requestParameters.pendingWindowInDays}'
```

#### 4. Find PutKeyPolicy AccessDenied — lockout attempt confirmation

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutKeyPolicy \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | 
    select(.errorCode == "AccessDenied") | 
    {time: .eventTime, 
     user: .userIdentity.arn, 
     keyId: .requestParameters.keyId, 
     error: .errorCode, 
     message: .errorMessage}'
```

#### 5. Full timeline for the attacking principal — replace ARN with identified attacker

```bash
ATTACKER_ARN="arn:aws:iam::ACCOUNT_ID:role/attacker-role"
START_TIME="$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)"

for event in GetCallerIdentity DescribeVolumes DescribeSnapshots CreateSnapshot CopySnapshot \
             DeleteVolume DeleteSnapshot ScheduleKeyDeletion PutKeyPolicy CancelKeyDeletion; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$event \
    --start-time "$START_TIME" \
    --output json | jq --arg event "$event" --arg arn "$ATTACKER_ARN" \
    '.Events[].CloudTrailEvent | fromjson | 
     select(.userIdentity.arn == $arn) | 
     {eventName: $event, time: .eventTime, sourceIP: .sourceIPAddress}'
done
```

#### 6. Identify attacker-controlled CMK ARN from CopySnapshot kmsKeyId

```bash
# Once you have the attacker CMK ARN, check its current state
aws kms describe-key --key-id "ATTACKER_CMK_ARN" \
  --query 'KeyMetadata.{KeyId:KeyId,State:KeyState,DeletionDate:DeletionDate,Description:Description}' \
  --output table
```

#### 7. List snapshots currently encrypted under the attacker CMK

```bash
ATTACKER_CMK_ARN="arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=encrypted,Values=true" \
  --query "Snapshots[?KmsKeyId=='$ATTACKER_CMK_ARN'].{SnapshotId:SnapshotId,VolumeId:VolumeId,State:State,StartTime:StartTime}" \
  --output table
```

#### 8. Check GuardDuty findings for the incident window

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "GreaterThanOrEqual": '"$(date -u -d '24 hours ago' +%s000)"'
      },
      "severity": {"GreaterThanOrEqual": 4}
    }
  }' \
  --output json | jq '.FindingIds[]' | \
  xargs -I{} aws guardduty get-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-ids {} \
    --query 'Findings[*].{Type:Type,Severity:Severity,Title:Title,UpdatedAt:UpdatedAt}' \
    --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Deny all actions for the attacking IAM principal (attacker-role)

```bash
# Attach a deny-all inline policy to the attacker role immediately
aws iam put-role-policy \
  --role-name attacker-role \
  --policy-name INCIDENT-RESPONSE-QUARANTINE \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

#### Step 2 — Revoke all active sessions for the attacking role (revoke existing STS tokens)

```bash
# Set MaxSessionDuration policy to invalidate outstanding sessions
aws iam update-role \
  --role-name attacker-role \
  --max-session-duration 3600

# Revoke all role sessions issued before now
aws iam put-role-policy \
  --role-name attacker-role \
  --policy-name INCIDENT-RESPONSE-REVOKE-SESSIONS \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
        }
      }
    }]
  }'
```

#### Step 3 — If attacker-role uses static access keys, deactivate them immediately

```bash
# List keys for the role's associated user (if static keys are in use)
aws iam list-access-keys --user-name ATTACKER_IAM_USER \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}' \
  --output table

# Deactivate each key
aws iam update-access-key \
  --user-name ATTACKER_IAM_USER \
  --access-key-id AKIAXXXXXXXXXXXXXXXX \
  --status Inactive
```

#### Step 4 — Cancel the scheduled CMK deletion (CRITICAL — preserves victim data recoverability)

```bash
# If ScheduleKeyDeletion was called on the attacker CMK and victim snapshots
# are encrypted under it, cancelling deletion is the ONLY path to data recovery
aws kms cancel-key-deletion --key-id "ATTACKER_CMK_ARN"

# Verify key is back to Enabled state
aws kms describe-key --key-id "ATTACKER_CMK_ARN" \
  --query 'KeyMetadata.{State:KeyState,DeletionDate:DeletionDate}' \
  --output table
```

> **Critical:** If `DeletionDate` has already passed, the key is permanently destroyed and victim data is unrecoverable without the attacker's cooperation. Time-to-containment is measured in days (the pending window).

#### Step 5 — Block further snapshot sharing or copying from attacker-controlled snapshots

```bash
# For each attacker-created snapshot, remove any share permissions
for SNAP_ID in snap-XXXXXXXXXXXXXXXXX snap-YYYYYYYYYYYYYYYYY; do
  aws ec2 reset-snapshot-attribute \
    --snapshot-id "$SNAP_ID" \
    --attribute createVolumePermission
done
```

#### Step 6 — Isolate affected region — restrict SCP to prevent further EBS/KMS destructive actions

```bash
# Apply SCP at OU level to deny destructive EC2/KMS actions (requires AWS Organizations admin)
# This is a draft policy — apply via AWS Organizations console or CLI
cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEBSDestructive",
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteVolume",
        "ec2:DeleteSnapshot",
        "ec2:CopySnapshot",
        "kms:ScheduleKeyDeletion",
        "kms:PutKeyPolicy",
        "kms:DeleteImportedKeyMaterial"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::ACCOUNT_ID:role/INCIDENT-RESPONSE-ROLE"
          ]
        }
      }
    }
  ]
}
EOF
```

---

## 4. Eradication

### Remove Attacker Access and Infrastructure

#### Step 1 — Delete attacker IAM role and all associated policies

```bash
# Detach managed policies first
aws iam list-attached-role-policies --role-name attacker-role \
  --query 'AttachedPolicies[*].PolicyArn' --output text | \
  tr '\t' '\n' | xargs -I{} aws iam detach-role-policy \
    --role-name attacker-role --policy-arn {}

# Delete inline policies
aws iam list-role-policies --role-name attacker-role \
  --query 'PolicyNames[*]' --output text | \
  tr '\t' '\n' | xargs -I{} aws iam delete-role-policy \
    --role-name attacker-role --policy-name {}

# Delete the role
aws iam delete-role --role-name attacker-role
```

#### Step 2 — Delete attacker static access keys

```bash
aws iam delete-access-key \
  --user-name ATTACKER_IAM_USER \
  --access-key-id AKIAXXXXXXXXXXXXXXXX
```

#### Step 3 — Schedule attacker CMK for deletion (after data is recovered)

```bash
# Only after victim data has been recovered and re-encrypted under a victim-controlled key
aws kms schedule-key-deletion \
  --key-id "ATTACKER_CMK_ARN" \
  --pending-window-in-days 7
```

#### Step 4 — Audit all snapshots created or copied during the attack window

```bash
START_TIME="ATTACK_START_ISO8601"
END_TIME="ATTACK_END_ISO8601"

aws ec2 describe-snapshots \
  --owner-ids self \
  --filters \
    "Name=tag:CreatedBy,Values=attacker-role" \
  --query "Snapshots[*].{SnapshotId:SnapshotId,KmsKeyId:KmsKeyId,StartTime:StartTime,VolumeId:VolumeId}" \
  --output table

# Also check by time window (no tag filter — attacker may not have tagged)
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=status,Values=completed" \
  --query "Snapshots[?StartTime>='$START_TIME' && StartTime<='$END_TIME'].{SnapshotId:SnapshotId,KmsKeyId:KmsKeyId,StartTime:StartTime}" \
  --output table
```

#### Step 5 — Verify no attacker-created IAM users, roles, or access keys remain

```bash
# Check for new IAM entities created during attack window
aws iam list-roles \
  --query 'Roles[*].{RoleName:RoleName,CreateDate:CreateDate}' \
  --output table | grep -E "$(date +%Y-%m-%d)"

aws iam list-users \
  --query 'Users[*].{UserName:UserName,CreateDate:CreateDate}' \
  --output table | grep -E "$(date +%Y-%m-%d)"
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Recover data from attacker-controlled snapshots (requires attacker CMK still valid)

```bash
# Create a new EBS volume from the attacker-encrypted snapshot
# (Only possible if CancelKeyDeletion was performed in time)
aws ec2 create-volume \
  --snapshot-id "snap-ATTACKER_COPY_SNAPSHOT_ID" \
  --availability-zone "REGION_AZ" \
  --kms-key-id "VICTIM_OWNED_CMK_ARN" \
  --encrypted \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=recovered-volume},{Key=recovery-incident,Value=ebs-ransomware-IR}]'
```

#### Step 2 — Re-encrypt recovered volume under victim-controlled CMK

```bash
# After mounting and verifying the recovered volume, create a clean snapshot
# re-encrypted under the victim CMK
aws ec2 create-snapshot \
  --volume-id "vol-RECOVERED_VOLUME_ID" \
  --description "IR-recovery: re-encrypted under victim CMK post-ransomware" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=recovery-incident,Value=ebs-ransomware-IR}]'

# Then copy to re-encrypt under victim key
aws ec2 copy-snapshot \
  --source-region "REGION" \
  --source-snapshot-id "snap-RECOVERED_SNAPSHOT_ID" \
  --kms-key-id "VICTIM_OWNED_CMK_ARN" \
  --encrypted \
  --description "IR-recovery: victim-CMK re-encryption"
```

#### Step 3 — Enable EBS snapshot lock on all critical snapshots going forward

```bash
aws ec2 lock-snapshot \
  --snapshot-id "snap-RECOVERED_CLEAN_SNAPSHOT_ID" \
  --lock-mode compliance \
  --lock-duration-days 30
```

#### Step 4 — Verify GuardDuty and Security Hub re-enabled and generating findings

```bash
# Verify GuardDuty detector is still enabled (attacker may have tried to disable)
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id "$DETECTOR_ID" \
  --query '{Status:Status,UpdatedAt:UpdatedAt}' --output table

# Verify Security Hub is enabled
aws securityhub describe-hub \
  --query '{HubArn:HubArn,SubscribedAt:SubscribedAt}' --output table
```

#### Step 5 — Rotate credentials for all principals that shared the same trust boundary as attacker-role

```bash
# List all roles with the same trust policy account
aws iam list-roles \
  --query 'Roles[*].{RoleName:RoleName,AssumedRolePolicy:AssumeRolePolicyDocument}' \
  --output json | jq '.[] | select(.AssumedRolePolicy | contains("attacker"))'

# Rotate any access keys for users in the same IAM group or with similar permissions
aws iam list-users --query 'Users[*].UserName' --output text | \
  tr '\t' '\n' | xargs -I{} aws iam list-access-keys --user-name {} \
  --query 'AccessKeyMetadata[*].{User:UserName,KeyId:AccessKeyId,Status:Status}'
```

#### Step 6 — Verify CloudTrail is intact and no gaps in log delivery

```bash
aws cloudtrail get-trail-status --name YOUR_TRAIL_NAME \
  --query '{IsLogging:IsLogging,LastDelivery:LatestDeliveryTime,LastDigestDelivery:LatestDigestDeliveryTime}' \
  --output table

# Validate log file integrity for the incident window
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:REGION:ACCOUNT_ID:trail/TRAIL_NAME" \
  --start-time "ATTACK_START_ISO8601" \
  --end-time "ATTACK_END_ISO8601" \
  --verbose
```

---

## 6. Lessons Learned

### What Would Have Prevented This

| Control | Gap Addressed | Implementation |
|---------|---------------|----------------|
| **EBS Snapshot Lock (compliance mode)** | Prevents `DeleteSnapshot` on protected snapshots entirely | `aws ec2 lock-snapshot --lock-mode compliance --lock-duration-days 30` on all production backups |
| **AWS Backup Vault Lock** | Immutable backup copies that cannot be deleted by any account principal (including root) | Enable via AWS Backup console; cooling-off period of 3+ days |
| **SCP deny on `kms:ScheduleKeyDeletion` without MFA** | Prevents ransom-demand step without compromising MFA | Apply SCP condition `"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}` |
| **SCP deny on `ec2:CopySnapshot` with non-account KMS keys** | Blocks the key-swap step entirely | Condition: `kms:ViaService` + account ID check |
| **KMS key policy deny for non-admin principals** | Prevents attacker from using their own CMK cross-account in this account | Require `kms:CallerAccount` condition on all `kms:Encrypt`/`kms:ReEncryptFrom` grants |
| **EventBridge rule: CopySnapshot + foreign kmsKeyId** | Alerts on the key-swap technique in real time | CloudTrail -> EventBridge -> SNS alert within 60 seconds |
| **GuardDuty EC2 protection** | Anomalous snapshot behavior generates finding | Keep enabled; test with `guardduty:CreateSampleFindings` |
| **AWS Security Hub EC2.4 / EC2.22 / KMS.3** | Unexpected snapshot creation, volume deletion, CMK scheduled for deletion | Findings auto-generated when Security Hub + FSBP standard enabled |

### Correlation Rule Recommendations

```
# Sigma-style correlation for full ransomware chain detection
detection logic:
  - within 10 minutes, SAME userIdentity.arn performs ALL of:
    - eventName: CopySnapshot AND requestParameters.kmsKeyId NOT LIKE "arn:aws:kms:REGION:THIS_ACCOUNT_ID:*"
    - eventName: DeleteVolume
    - eventName: DeleteSnapshot
    - eventName: ScheduleKeyDeletion
  -> severity: CRITICAL, label: EBS-Ransomware-KMS-Swap
```

### Key Timing Insight

The `ScheduleKeyDeletion` call occurring within seconds of `DeleteVolume`/`DeleteSnapshot` is the definitive ransomware signature in CloudTrail. Security teams should tune detection on this temporal correlation rather than any single event in isolation. The `PutKeyPolicy` `AccessDenied` event is a secondary signal confirming the attacker attempted full account lockout — detection rules must not exclude denied calls for KMS events.

### Dwell Time Constraint

The `pendingWindowInDays` value in `ScheduleKeyDeletion` defines the maximum response window. If that window expires before IR teams perform `CancelKeyDeletion`, the key is permanently destroyed and victim data is unrecoverable. **SLA target: containment within `pendingWindowInDays - 1` days of the ransomware event.**
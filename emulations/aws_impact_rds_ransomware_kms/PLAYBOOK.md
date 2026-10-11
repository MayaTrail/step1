# IR Playbook: ATOMIC-rds-ransomware-kms — AWS RDS KMS Ransomware

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Ransomware — RDS Snapshot Re-encryption |
| Threat Actor | ATOMIC-rds-ransomware-kms (technique emulation; pattern matches real-world RDS extortion campaigns) |
| Platform | aws |
| Severity | Critical (SEV1) |
| MITRE Tactics | Impact |
| MITRE Techniques | T1486 — Data Encrypted for Impact (control-plane variant) |
| Response Time | Immediate, all-hands |

---

## 1. Preparation

What must be in place **before** this incident type occurs.

### Detection Prerequisites
- **CloudTrail** multi-region trail enabled with management events (Read + Write) for `rds.amazonaws.com`, `sts.amazonaws.com`, `kms.amazonaws.com`
- **CloudTrail S3 bucket** integrity validation enabled; log delivery alerts on gaps
- **GuardDuty RDS Protection** enabled — detects anomalous snapshot creation by non-backup principals
- **AWS Security Hub** with AWS Foundational Security Best Practices standard enabled
- **AWS Config rule** `rds-instance-deletion-protection-enabled` in all regions
- **AWS Config rule** `rds-snapshot-encrypted` to baseline expected KMS key ARNs per instance
- Alerting on `CopyDBSnapshot` where `kmsKeyId` is not in an approved CMK list (EventBridge → SNS → PagerDuty)

### Operational Prerequisites
- Break-glass IAM role with `rds:*`, `kms:DescribeKey`, `iam:*` permissions for IR team — stored in AWS Secrets Manager
- Inventory of all production RDS instances, their designated KMS CMK ARNs, and expected snapshot naming conventions
- Runbook for `rds:RestoreDBInstanceFromDBSnapshot` documented and tested
- On-call rotation includes someone with RDS restore privileges
- Backup policy requiring cross-account or cross-region copies of critical snapshots (reduces leverage)

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — any one of these indicates active or completed ransomware

| Audit Event | Source | Signal |
|---|---|---|
| `CopyDBSnapshot` with `requestParameters.kmsKeyId` not in approved CMK list | CloudTrail | **Primary ransomware signal** — victim data re-encrypted under foreign key |
| `CopyDBSnapshot` immediately followed by `DeleteDBSnapshot` (same principal, <5 min) | CloudTrail | Backup elimination pattern |
| `ModifyDBInstance` with `requestParameters.deletionProtection = false` by non-automation principal | CloudTrail | Prerequisite to destroy; leading-edge signal |
| `DeleteDBInstance` with `errorCode: AccessDenied` from same session that did `CopyDBSnapshot` | CloudTrail | Denied destroy attempt — complete chain confirmed |
| `DeleteDBSnapshot` with `errorCode: AccessDenied` on production snapshot by attacker-role session | CloudTrail | Backup elimination attempt confirmed |
| GuardDuty finding type `RDS/AnomalousBehavior:RDS!IAMUser/AnomalousSnapshotActivity` | GuardDuty | Anomalous snapshot creation by non-backup-service principal |

#### MEDIUM-CONFIDENCE — correlate with above for confirmation

| Audit Event | Source | Signal |
|---|---|---|
| `AssumeRole` into a role with `rds:*` and `kms:ReEncrypt*` from a pipeline/admin principal | CloudTrail STS | Attacker credential bootstrap |
| `DescribeDBInstances` + `DescribeDBSnapshots` within 60 seconds from same assumed-role session | CloudTrail | Reconnaissance before ransomware chain |
| `CreateDBSnapshot` by a principal that is not an AWS Backup service role | CloudTrail | Staging snapshot creation |
| `kms:DescribeKey` on a KMS CMK not associated with the calling principal's normal workload | CloudTrail KMS | Attacker confirming key ownership before re-encryption |

---

### Key Investigation Queries

#### Step 1 — Identify the suspicious AssumeRole event

```bash
# Find AssumeRole events in the last 24h targeting roles with rds or kms in the name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[?contains(CloudTrailEvent, 'rds') || contains(CloudTrailEvent, 'ransomware') || contains(CloudTrailEvent, 'attacker')].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], user: .[1], detail: (.[2] | fromjson | {roleArn: .requestParameters.roleArn, sessionName: .requestParameters.roleSessionName, sourceIP: .sourceIPAddress})}'
```

#### Step 2 — Find the full attack chain from the assumed-role session

```bash
# Replace ATTACKER_ROLE_ARN with the ARN found in step 1
ATTACKER_ROLE_ARN="arn:aws:iam::123456789012:role/attacker-role"
SESSION_NAME="atomic-rds-ransomware-kms-session"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION_NAME" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[*].[EventTime,EventName,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], event: .[1], source: (.[2] | fromjson | .eventSource), error: (.[2] | fromjson | .errorCode // "success")}'
```

#### Step 3 — Find all CopyDBSnapshot events with non-standard KMS keys

```bash
# Requires CloudTrail S3 bucket access and Athena, or use lookup-events for recent events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CopyDBSnapshot \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | \
  jq '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.kmsKeyId != null) | {
    time: .eventTime,
    sourceSnapshot: .requestParameters.sourceDBSnapshotIdentifier,
    targetSnapshot: .requestParameters.targetDBSnapshotIdentifier,
    kmsKey: .requestParameters.kmsKeyId,
    principal: .userIdentity.arn,
    sourceIP: .sourceIPAddress
  }'
```

#### Step 4 — Identify the attacker KMS key and confirm ownership

```bash
# Inspect the KMS key used in CopyDBSnapshot — confirm it is NOT your org's key
ATTACKER_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"

aws kms describe-key \
  --key-id "$ATTACKER_KEY_ARN" \
  --query "KeyMetadata.{KeyId: KeyId, Arn: Arn, Description: Description, CreationDate: CreationDate, KeyManager: KeyManager, KeyState: KeyState}"

# Check key policy — does it include principals you don't recognize?
aws kms get-key-policy \
  --key-id "$ATTACKER_KEY_ARN" \
  --policy-name default \
  --output text | python3 -m json.tool
```

#### Step 5 — Enumerate all snapshots re-encrypted under the attacker key

```bash
# Find all DB snapshots whose KMS key ARN matches the attacker key
ATTACKER_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"

aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query "DBSnapshots[?KmsKeyId=='$ATTACKER_KEY_ARN'].[DBSnapshotIdentifier,DBInstanceIdentifier,SnapshotCreateTime,Status,KmsKeyId]" \
  --output table
```

#### Step 6 — Confirm deletion protection current state on target instances

```bash
aws rds describe-db-instances \
  --query "DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus,DeletionProtection,KmsKeyId,MultiAZ,StorageEncrypted]" \
  --output table
```

#### Step 7 — Check for ModifyDBInstance deletion-protection events in CloudTrail

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | \
  jq '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.deletionProtection == false) | {
    time: .eventTime,
    instance: .requestParameters.dBInstanceIdentifier,
    principal: .userIdentity.arn,
    sourceIP: .sourceIPAddress,
    error: (.errorCode // "success")
  }'
```

#### Step 8 — Confirm denied destroy attempts (do NOT filter on errorCode IS NULL)

```bash
# DeleteDBInstance — look for both success AND AccessDenied
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBInstance \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | \
  jq '.Events[].CloudTrailEvent | fromjson | {
    time: .eventTime,
    instance: .requestParameters.dBInstanceIdentifier,
    principal: .userIdentity.arn,
    errorCode: (.errorCode // "SUCCESS - CRITICAL"),
    errorMessage: (.errorMessage // "none")
  }'

# DeleteDBSnapshot — same logic
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBSnapshot \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json | \
  jq '.Events[].CloudTrailEvent | fromjson | {
    time: .eventTime,
    snapshot: .requestParameters.dBSnapshotIdentifier,
    principal: .userIdentity.arn,
    errorCode: (.errorCode // "SUCCESS - CRITICAL")
  }'
```

#### Step 9 — Check GuardDuty findings for this incident window

```bash
# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)

# Pull RDS-related findings from last 24h
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"Gte": '"$(date -u -d '24 hours ago' +%s000)"'},
      "resource.resourceType": {"Equals": ["RDSDBInstance"]}
    }
  }' \
  --output json | \
  jq '.FindingIds[]' | \
  xargs -I{} aws guardduty get-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-ids {} \
    --query "Findings[*].{Type: Type, Severity: Severity, Description: Description, Resource: Resource.RdsDbInstanceDetails}"
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Action 1 — Revoke the attacker IAM role session (invalidate all active sessions)

```bash
# Attach an inline deny-all policy to the attacker role to kill active sessions immediately
# Sessions issued before this policy will be denied on next API call (STS cached credentials
# are revoked by AWSRevokeOlderSessions managed policy or an explicit deny with DateLessThan)

ATTACKER_ROLE_NAME="attacker-role"
REVOKE_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

aws iam put-role-policy \
  --role-name "$ATTACKER_ROLE_NAME" \
  --policy-name "RevokeOlderSessions" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {
          \"aws:TokenIssueTime\": \"$REVOKE_TIME\"
        }
      }
    }]
  }"

# Verify policy attached
aws iam get-role-policy \
  --role-name "$ATTACKER_ROLE_NAME" \
  --policy-name "RevokeOlderSessions"
```

#### Action 2 — Re-enable deletion protection on production RDS instances

```bash
# If ModifyDBInstance to disable deletion protection SUCCEEDED (no errorCode in CloudTrail):
DB_INSTANCE_ID="prod-customer-db"

aws rds modify-db-instance \
  --db-instance-identifier "$DB_INSTANCE_ID" \
  --deletion-protection \
  --apply-immediately

# Confirm
aws rds describe-db-instances \
  --db-instance-identifier "$DB_INSTANCE_ID" \
  --query "DBInstances[0].{Status: DBInstanceStatus, DeletionProtection: DeletionProtection}"
```

#### Action 3 — Deny the attacker KMS key from being used for any further operations

```bash
# If the attacker KMS key is in YOUR account, disable it immediately
ATTACKER_KEY_ID="KEY-ID-HERE"

aws kms disable-key --key-id "$ATTACKER_KEY_ID"
aws kms cancel-key-deletion --key-id "$ATTACKER_KEY_ID" 2>/dev/null || true  # cancel any pending deletion that would wipe evidence

# Confirm disabled
aws kms describe-key \
  --key-id "$ATTACKER_KEY_ID" \
  --query "KeyMetadata.{KeyState: KeyState, KeyManager: KeyManager}"
```

#### Action 4 — Verify the live RDS instance is intact

```bash
DB_INSTANCE_ID="prod-customer-db"

aws rds describe-db-instances \
  --db-instance-identifier "$DB_INSTANCE_ID" \
  --query "DBInstances[0].{
    Status: DBInstanceStatus,
    DeletionProtection: DeletionProtection,
    MultiAZ: MultiAZ,
    KmsKeyId: KmsKeyId,
    StorageEncrypted: StorageEncrypted,
    LatestRestorableTime: LatestRestorableTime,
    AutoMinorVersionUpgrade: AutoMinorVersionUpgrade
  }"
```

#### Action 5 — Identify all re-encrypted snapshots and quarantine by tagging

```bash
ATTACKER_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"

# Tag all tainted snapshots for IR tracking (do NOT delete yet — evidence)
TAINTED_SNAPSHOTS=$(aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query "DBSnapshots[?KmsKeyId=='$ATTACKER_KEY_ARN'].DBSnapshotIdentifier" \
  --output text)

for SNAP in $TAINTED_SNAPSHOTS; do
  echo "Tagging $SNAP as tainted..."
  aws rds add-tags-to-resource \
    --resource-name "arn:aws:rds:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):snapshot:$SNAP" \
    --tags Key=ir-status,Value=tainted Key=ir-incident,Value=rds-ransomware-kms Key=ir-date,Value="$(date +%Y-%m-%d)"
done
```

#### Action 6 — Block further cross-account snapshot sharing (preventive)

```bash
# Ensure the tainted snapshots are not shared publicly or with unknown accounts
for SNAP in $TAINTED_SNAPSHOTS; do
  ATTRS=$(aws rds describe-db-snapshot-attributes \
    --db-snapshot-identifier "$SNAP" \
    --query "DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName=='restore']")
  echo "$SNAP share attributes: $ATTRS"
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1 — Delete the attacker IAM role (after evidence collection)

```bash
ATTACKER_ROLE_NAME="attacker-role"

# First, detach all managed policies
aws iam list-attached-role-policies \
  --role-name "$ATTACKER_ROLE_NAME" \
  --query "AttachedPolicies[*].PolicyArn" \
  --output text | \
  tr '\t' '\n' | \
  xargs -I{} aws iam detach-role-policy \
    --role-name "$ATTACKER_ROLE_NAME" \
    --policy-arn {}

# Delete all inline policies
aws iam list-role-policies \
  --role-name "$ATTACKER_ROLE_NAME" \
  --query "PolicyNames" \
  --output text | \
  tr '\t' '\n' | \
  xargs -I{} aws iam delete-role-policy \
    --role-name "$ATTACKER_ROLE_NAME" \
    --policy-name {}

# Delete the role
aws iam delete-role --role-name "$ATTACKER_ROLE_NAME"
```

#### Step 2 — Schedule deletion of the attacker KMS key

```bash
ATTACKER_KEY_ID="KEY-ID-HERE"

# Key must be disabled before scheduling deletion
aws kms disable-key --key-id "$ATTACKER_KEY_ID"

# Schedule for deletion with minimum waiting period (7 days) — gives time to attempt
# snapshot recovery operations before the key is gone
aws kms schedule-key-deletion \
  --key-id "$ATTACKER_KEY_ID" \
  --pending-window-in-days 7

# Confirm
aws kms describe-key \
  --key-id "$ATTACKER_KEY_ID" \
  --query "KeyMetadata.{KeyState: KeyState, DeletionDate: DeletionDate}"
```

#### Step 3 — Delete tainted re-encrypted snapshots (AFTER recovery validation)

```bash
# ONLY run after confirming the original live instance is healthy
# and any recovery from clean snapshots has been validated

ATTACKER_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID"

TAINTED_SNAPSHOTS=$(aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query "DBSnapshots[?KmsKeyId=='$ATTACKER_KEY_ARN'].DBSnapshotIdentifier" \
  --output text)

for SNAP in $TAINTED_SNAPSHOTS; do
  echo "Deleting tainted snapshot: $SNAP"
  aws rds delete-db-snapshot --db-snapshot-identifier "$SNAP"
done
```

#### Step 4 — Audit and remove any other roles with rds:* + kms:ReEncrypt* grants

```bash
# Find all IAM roles with potentially dangerous RDS + KMS combinations
aws iam list-roles \
  --query "Roles[*].[RoleName,Arn]" \
  --output text | \
while read ROLE_NAME ROLE_ARN; do
  POLICIES=$(aws iam list-attached-role-policies \
    --role-name "$ROLE_NAME" \
    --query "AttachedPolicies[*].PolicyArn" \
    --output text 2>/dev/null)
  for POLICY_ARN in $POLICIES; do
    VERSION=$(aws iam get-policy \
      --policy-arn "$POLICY_ARN" \
      --query "Policy.DefaultVersionId" \
      --output text 2>/dev/null)
    DOCUMENT=$(aws iam get-policy-version \
      --policy-arn "$POLICY_ARN" \
      --version-id "$VERSION" \
      --query "PolicyVersion.Document" \
      --output json 2>/dev/null)
    if echo "$DOCUMENT" | grep -q "kms:ReEncrypt"; then
      echo "REVIEW NEEDED: Role=$ROLE_NAME Policy=$POLICY_ARN has kms:ReEncrypt"
    fi
  done
done
```

#### Step 5 — Rotate credentials of any principal that assumed the attacker role

```bash
# Find the originating principal from the AssumeRole CloudTrail event
# If it was an IAM user access key, rotate it:
VICTIM_USER="pipeline-operator"

# Disable existing access keys
aws iam list-access-keys \
  --user-name "$VICTIM_USER" \
  --query "AccessKeyMetadata[*].[AccessKeyId,Status]" \
  --output text | \
while read KEY_ID STATUS; do
  echo "Deactivating $KEY_ID ($STATUS)"
  aws iam update-access-key \
    --user-name "$VICTIM_USER" \
    --access-key-id "$KEY_ID" \
    --status Inactive
done

# Create new key (out-of-band secure delivery required)
aws iam create-access-key --user-name "$VICTIM_USER"
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Verify original RDS instance is available and healthy

```bash
DB_INSTANCE_ID="prod-customer-db"

aws rds describe-db-instances \
  --db-instance-identifier "$DB_INSTANCE_ID" \
  --query "DBInstances[0].{
    Status: DBInstanceStatus,
    DeletionProtection: DeletionProtection,
    KmsKeyId: KmsKeyId,
    MultiAZ: MultiAZ,
    LatestRestorableTime: LatestRestorableTime,
    Endpoint: Endpoint
  }"
```

#### Step 2 — If instance was deleted (DeleteDBInstance succeeded), restore from clean snapshot

```bash
# Find the most recent clean snapshot (encrypted under your org's approved KMS key)
ORG_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/YOUR-ORG-KEY-ID"
DB_INSTANCE_ID="prod-customer-db"

CLEAN_SNAPSHOT=$(aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query "DBSnapshots[?KmsKeyId=='$ORG_KEY_ARN' && DBInstanceIdentifier=='$DB_INSTANCE_ID'] | sort_by(@, &SnapshotCreateTime) | [-1].DBSnapshotIdentifier" \
  --output text)

echo "Restoring from: $CLEAN_SNAPSHOT"

aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$DB_INSTANCE_ID-restored" \
  --db-snapshot-identifier "$CLEAN_SNAPSHOT" \
  --db-instance-class db.t3.medium \
  --multi-az \
  --deletion-protection \
  --no-publicly-accessible \
  --kms-key-id "$ORG_KEY_ARN"

# Monitor restore
aws rds wait db-instance-available \
  --db-instance-identifier "$DB_INSTANCE_ID-restored"
```

#### Step 3 — Confirm deletion protection is enforced on all production instances

```bash
# Audit all RDS instances — deletion protection should be true for all prod
aws rds describe-db-instances \
  --query "DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus,DeletionProtection,Tags[?Key=='Environment'].Value|[0]]" \
  --output table
```

#### Step 4 — Re-enable GuardDuty RDS Protection if it was disabled

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)

aws guardduty update-detector \
  --detector-id "$DETECTOR_ID" \
  --features '[{"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"}]'

# Confirm
aws guardduty get-detector \
  --detector-id "$DETECTOR_ID" \
  --query "Features[?Name=='RDS_LOGIN_EVENTS']"
```

#### Step 5 — Validate AWS Config rules are passing

```bash
# Check rds-instance-deletion-protection-enabled compliance
aws configservice describe-compliance-by-config-rule \
  --config-rule-names rds-instance-deletion-protection-enabled \
  --query "ComplianceByConfigRules[*].{Rule: ConfigRuleName, Compliance: Compliance.ComplianceType}"

# Check rds-snapshot-encrypted
aws configservice describe-compliance-by-config-rule \
  --config-rule-names rds-snapshot-encrypted \
  --query "ComplianceByConfigRules[*].{Rule: ConfigRuleName, Compliance: Compliance.ComplianceType}"
```

#### Step 6 — Verify no unauthorized KMS key aliases exist

```bash
# List all CMKs in account and flag any that don't match naming convention
aws kms list-aliases \
  --query "Aliases[?TargetKeyId != null && !starts_with(AliasName, 'alias/aws/')].[AliasName, TargetKeyId]" \
  --output table
```

#### Step 7 — Rotate the org's RDS KMS key (precautionary, if key metadata was exposed)

```bash
ORG_KEY_ARN="arn:aws:kms:us-east-1:ACCOUNT:key/YOUR-ORG-KEY-ID"

# Enable automatic rotation (annual) if not already on
aws kms enable-key-rotation --key-id "$ORG_KEY_ARN"

# Confirm
aws kms get-key-rotation-status \
  --key-id "$ORG_KEY_ARN" \
  --query "KeyRotationEnabled"
```

---

## 6. Lessons Learned

### What This Attack Exploited

| Gap | Root Cause | Guardrail |
|-----|-----------|-----------|
| A single compromised principal had `rds:*` + `kms:ReEncrypt*` | Overly broad IAM role permissions | Scope RDS roles to specific instance ARNs; require `kms:ViaService` condition on `kms:ReEncrypt*` |
| `CopyDBSnapshot` to an attacker KMS key was not pre-blocked | No SCP or permission boundary restricting `kmsKeyId` on copy operations | AWS Organizations SCP: Deny `rds:CopyDBSnapshot` unless `rds:KmsKeyId` matches `arn:aws:kms:*:ORG_ACCOUNT_ID:*` |
| No real-time alert on `CopyDBSnapshot` with foreign KMS key | EventBridge rule not configured | EventBridge rule: `eventSource = rds.amazonaws.com AND eventName = CopyDBSnapshot` → evaluate `requestParameters.kmsKeyId` against approved key ARN list → SNS alert |
| Deletion protection disabled silently | No alert on `ModifyDBInstance` with `deletionProtection=false` | EventBridge rule: `eventName = ModifyDBInstance AND requestParameters.deletionProtection = false` → immediate page |
| Detection rules filtered on `errorCode IS NULL` | Incomplete detection logic | **All RDS ransomware detection rules MUST include both success and AccessDenied events** — the blocked DeleteDBInstance is a high-fidelity signal, not noise |

### Prevention Guardrails — Deploy Immediately

```bash
# 1. SCP: Block CopyDBSnapshot with foreign KMS keys (attach to OU)
# Policy denies CopyDBSnapshot unless kmsKeyId is blank or belongs to this org
cat << 'EOF'
{
  "Sid": "DenyForeignKMSOnRDSCopy",
  "Effect": "Deny",
  "Action": ["rds:CopyDBSnapshot", "rds:CreateDBInstanceReadReplica"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "rds:KmsKeyId": "arn:aws:kms:*:ORG_ACCOUNT_ID:*"
    },
    "Null": {
      "rds:KmsKeyId": "false"
    }
  }
}
EOF

# 2. EventBridge rule for CopyDBSnapshot with non-org key
aws events put-rule \
  --name "DetectRDSRansomwareReencrypt" \
  --event-pattern '{
    "source": ["aws.rds"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CopyDBSnapshot"]
    }
  }' \
  --state ENABLED \
  --description "Detect CopyDBSnapshot for foreign KMS key ransomware pattern"

# 3. EventBridge rule for ModifyDBInstance disabling deletion protection
aws events put-rule \
  --name "DetectRDSDeletionProtectionDisabled" \
  --event-pattern '{
    "source": ["aws.rds"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["ModifyDBInstance"],
      "requestParameters": {
        "deletionProtection": [false]
      }
    }
  }' \
  --state ENABLED \
  --description "Detect deletion protection disabled on RDS instance"
```

### Key Detection Rule Reminders

> **CRITICAL:** Detection rules for T1486 on RDS MUST capture both `errorCode: null` (success) and `errorCode: AccessDenied`. The `DeleteDBInstance` and `DeleteDBSnapshot` events in this chain are expected to be denied by guardrails — filtering them out destroys the highest-fidelity signal in the full kill chain:
>
> `CreateDBSnapshot` -> `CopyDBSnapshot(attacker KMS)` -> `ModifyDBInstance(DeletionProtection=false)` -> `DeleteDBInstance(AccessDenied)` -> `DeleteDBSnapshot(AccessDenied)`

### Full T1486 Audit Trail Reference

| Step | Event | Source | Expected Outcome |
|------|-------|--------|-----------------|
| 1 | `AssumeRole` | sts.amazonaws.com | success |
| 2 | `DescribeDBInstances` | rds.amazonaws.com | success |
| 3 | `DescribeDBSnapshots` | rds.amazonaws.com | success |
| 4 | `CreateDBSnapshot` | rds.amazonaws.com | success |
| 5 | `CopyDBSnapshot` (attacker KMS key) | rds.amazonaws.com | **success — primary ransomware event** |
| 6 | `ModifyDBInstance` (DeletionProtection=false) | rds.amazonaws.com | success or AccessDenied |
| 7 | `DeleteDBInstance` | rds.amazonaws.com | AccessDenied (guardrail) |
| 8 | `DeleteDBSnapshot` | rds.amazonaws.com | AccessDenied (guardrail) |
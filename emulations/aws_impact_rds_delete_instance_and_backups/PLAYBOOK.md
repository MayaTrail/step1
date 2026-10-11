# IR Playbook: ATOMIC-rds-delete-instance-and-backups — AWS RDS Data Destruction

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Data Destruction / Database Wipeout |
| Threat Actor | ATOMIC-rds-delete-instance-and-backups (technique emulation) |
| Platform | AWS |
| Severity | Critical |
| MITRE Tactics | Impact (T1485 - Data Destruction) |
| MITRE Techniques | T1485 - Data Destruction |
| Affected Services | Amazon RDS, AWS STS, AWS CloudTrail, Amazon GuardDuty |

---

## 1. Preparation

### Prerequisites Before This Incident

**Detection Controls**
- CloudTrail management events enabled in all regions (multi-region trail recommended)
- Amazon GuardDuty enabled with RDS Protection feature active
- AWS Security Hub enabled with AWS Foundational Security Best Practice standard
- AWS Config rule `rds-instance-deletion-protection-enabled` active and alerting
- EventBridge rules routing RDS delete/modify events to SOC alerting pipeline

**Baseline Hygiene**
- All production RDS instances have `DeletionProtection=True` enforced via SCP or Config remediation
- Automated backups retention >= 7 days; manual snapshots tagged `env=prod` and copied cross-region
- IAM least privilege: `rds:DeleteDBInstance`, `rds:DeleteDBSnapshot`, `rds:ModifyDBInstance` restricted to dedicated backup service principals only, never to human IAM users
- Break-glass roles audited quarterly; no standing `rds:Delete*` grants on attacker-style roles
- RDS event subscription configured: `DeleteDBInstance`, `ModifyDBInstance`, `DeleteDBSnapshot` events forwarded to SNS -> PagerDuty/Slack

**Runbook Pre-Reads**
- Know your RDS instance identifiers and their backup schedules before an incident
- Know which principals legitimately call `rds:ModifyDBInstance` — this list should be short

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — These events together or individually constitute a confirmed incident

| Audit Event | EventSource | What It Means | Urgency |
|---|---|---|---|
| `DeleteDBInstance` with `skipFinalSnapshot=true` AND `deleteAutomatedBackups=true` | `rds.amazonaws.com` | Database AND all automated backups permanently destroyed | **P1 — page immediately** |
| `ModifyDBInstance` with `requestParameters.deletionProtection=false` followed within 5 min by `DeleteDBInstance` | `rds.amazonaws.com` | Deliberate bypass of deletion guard before wipe — no legitimate workflow does this back-to-back | **P1 — page immediately** |
| `DeleteDBSnapshot` where snapshot name matches production naming convention | `rds.amazonaws.com` | Manual backup eliminated before or concurrent with instance deletion | **P1 — page immediately** |

#### MEDIUM-CONFIDENCE — Warrants investigation, not automatic escalation

| Audit Event | EventSource | What It Means | Urgency |
|---|---|---|---|
| `ModifyDBInstance` with `deletionProtection=false` by a non-DBA principal | `rds.amazonaws.com` | May be misconfiguration, automation error, or early-stage attack | P2 — investigate within 1 hr |
| `DescribeDBSnapshots` with `SnapshotType=manual` from unusual principal | `rds.amazonaws.com` | Recon enumeration of backup landscape | P3 — correlate with other signals |
| `AssumeRole` into a high-privilege DB-management role from a pipeline/automation account | `sts.amazonaws.com` | Credential pivot into privileged identity | P3 — correlate with subsequent RDS calls |
| GuardDuty finding: `RDS:DBInstance/AnomalousBehavior` or `UnauthorizedAccess:RDSDBInstance/MaliciousIPCaller` | GuardDuty | Behavioral anomaly on RDS control plane | P2 — investigate within 1 hr |

---

### Key Investigation Queries

#### Step 1 — Identify the `AssumeRole` pivot into the DB principal

```bash
# Find AssumeRole calls where the assumed role has RDS delete permissions
# Adjust --start-time to your incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "2024-01-01T00:00:00Z" \
  --end-time "2024-01-01T23:59:59Z" \
  --query "Events[?contains(CloudTrailEvent, 'rds') || contains(CloudTrailEvent, 'attacker')].{Time:EventTime,User:Username,CT:CloudTrailEvent}" \
  --output json
```

```bash
# For targeted search by suspected attacker role ARN (replace with actual ARN)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=arn:aws:iam::ACCOUNT_ID:role/atomic-rds-delete-attacker-role \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, event: (.CloudTrailEvent | fromjson)}'
```

#### Step 2 — Find ModifyDBInstance calls that disabled DeletionProtection

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBInstance \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '
    .Events[] |
    select(
      (.CloudTrailEvent | fromjson).requestParameters.deletionProtection == false
    ) |
    {
      time: .EventTime,
      user: .Username,
      instance: ((.CloudTrailEvent | fromjson).requestParameters.dBInstanceIdentifier),
      deletionProtection: ((.CloudTrailEvent | fromjson).requestParameters.deletionProtection),
      applyImmediately: ((.CloudTrailEvent | fromjson).requestParameters.applyImmediately),
      sourceIP: ((.CloudTrailEvent | fromjson).sourceIPAddress),
      userAgent: ((.CloudTrailEvent | fromjson).userAgent)
    }'
```

#### Step 3 — Find DeleteDBSnapshot calls on production snapshots

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBSnapshot \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '
    .Events[] |
    {
      time: .EventTime,
      user: .Username,
      snapshot: ((.CloudTrailEvent | fromjson).requestParameters.dBSnapshotIdentifier),
      sourceIP: ((.CloudTrailEvent | fromjson).sourceIPAddress),
      sessionContext: ((.CloudTrailEvent | fromjson).userIdentity.sessionContext)
    }'
```

#### Step 4 — Find DeleteDBInstance with destructive parameters

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBInstance \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '
    .Events[] |
    select(
      ((.CloudTrailEvent | fromjson).requestParameters.skipFinalSnapshot == true) or
      ((.CloudTrailEvent | fromjson).requestParameters.deleteAutomatedBackups == true)
    ) |
    {
      time: .EventTime,
      user: .Username,
      instance: ((.CloudTrailEvent | fromjson).requestParameters.dBInstanceIdentifier),
      skipFinalSnapshot: ((.CloudTrailEvent | fromjson).requestParameters.skipFinalSnapshot),
      deleteAutomatedBackups: ((.CloudTrailEvent | fromjson).requestParameters.deleteAutomatedBackups),
      sourceIP: ((.CloudTrailEvent | fromjson).sourceIPAddress),
      roleArn: ((.CloudTrailEvent | fromjson).userIdentity.arn)
    }'
```

#### Step 5 — Reconstruct full attack timeline for a specific principal

```bash
# Replace ROLE_SESSION_ARN with the assumed-role session ARN from step 1
ATTACKER_ARN="arn:aws:sts::ACCOUNT_ID:assumed-role/atomic-rds-delete-attacker-role/atomic-rds-delete-session"

for event in AssumeRole DescribeDBInstances DescribeDBSnapshots ModifyDBInstance DeleteDBSnapshot DeleteDBInstance; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$event \
    --start-time "2024-01-01T00:00:00Z" \
    --output json | jq --arg arn "$ATTACKER_ARN" '
      .Events[] |
      select((.CloudTrailEvent | fromjson).userIdentity.arn == $arn) |
      {time: .EventTime, event: .EventName, source: .Username}'
done
```

#### Step 6 — Check current RDS instance and snapshot state

```bash
# List all RDS instances — confirm which are missing
aws rds describe-db-instances \
  --query "DBInstances[*].{ID:DBInstanceIdentifier,Status:DBInstanceStatus,DeletionProtection:DeletionProtection,Engine:Engine,AZ:AvailabilityZone}" \
  --output table

# List remaining manual snapshots for the affected instance
aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query "DBSnapshots[*].{ID:DBSnapshotIdentifier,Status:Status,Created:SnapshotCreateTime,DB:DBInstanceIdentifier}" \
  --output table

# List automated backups
aws rds describe-db-instance-automated-backups \
  --query "DBInstanceAutomatedBackups[*].{ID:DBInstanceIdentifier,Status:Status,BackupRetentionPeriod:BackupRetentionPeriod,Encrypted:Encrypted}" \
  --output table
```

#### Step 7 — Check GuardDuty findings

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "service.action.rdsLoginAttemptAction.remoteIpDetails.ipAddressV4": {},
      "type": {"Equals": ["RDS:DBInstance/AnomalousBehavior"]}
    }
  }' \
  --output json

# Broader: all findings in incident window
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $(aws guardduty list-findings \
    --detector-id $DETECTOR_ID \
    --sort-criteria '{"AttributeName":"createdAt","OrderBy":"DESC"}' \
    --max-results 10 \
    --query "FindingIds" \
    --output text) \
  --query "Findings[*].{Type:Type,Severity:Severity,Title:Title,UpdatedAt:UpdatedAt}" \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Revoke the attacker role session (deny all future API calls from this session)

```bash
# Attach an inline deny policy to the assumed role — invalidates all active sessions
ROLE_NAME="atomic-rds-delete-attacker-role"  # replace with actual role name

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EmergencyDenyAll" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "DateLessThan": {
            "aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
          }
        }
      }
    ]
  }'
```

```bash
# Alternatively, detach all permission policies from the role
aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query "AttachedPolicies[*].PolicyArn" --output text | \
  xargs -I{} aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn {}

# Remove any inline policies
aws iam list-role-policies --role-name "$ROLE_NAME" \
  --query "PolicyNames" --output text | \
  xargs -I{} aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name {}
```

#### 3.2 — Lock down the source IAM principal that assumed the attacker role

```bash
# Identify the source principal from the AssumeRole CloudTrail event
# If it's an IAM user:
SOURCE_USER="pipeline-admin-user"  # replace with actual username from CloudTrail
aws iam put-user-policy \
  --user-name "$SOURCE_USER" \
  --policy-name "EmergencyLockout" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# Deactivate access keys for the source user
aws iam list-access-keys --user-name "$SOURCE_USER" \
  --query "AccessKeyMetadata[*].AccessKeyId" --output text | \
  xargs -I{} aws iam update-access-key \
    --user-name "$SOURCE_USER" --access-key-id {} --status Inactive
```

#### 3.3 — Stop any in-progress RDS deletions (if deletion is still running)

```bash
# RDS deletion is async — check if instance is in 'deleting' state
aws rds describe-db-instances \
  --query "DBInstances[?DBInstanceStatus=='deleting'].DBInstanceIdentifier" \
  --output text

# Note: once DeleteDBInstance is called, it CANNOT be cancelled via API.
# If the instance is still in 'deleting' state, contact AWS Support immediately:
# aws support create-case \
#   --subject "URGENT: Unauthorized RDS deletion in progress - need immediate assistance" \
#   --service-code "amazon-rds" \
#   --severity-code "critical" \
#   --communication-body "Instance <id> being deleted by unauthorized principal..."
```

#### 3.4 — Re-enable deletion protection on any surviving RDS instances

```bash
# List all instances and re-enable DeletionProtection on any that lack it
aws rds describe-db-instances \
  --query "DBInstances[?DeletionProtection==\`false\`].DBInstanceIdentifier" \
  --output text | \
  xargs -I{} aws rds modify-db-instance \
    --db-instance-identifier {} \
    --deletion-protection \
    --apply-immediately
```

#### 3.5 — Scope blast radius — inventory all affected resources

```bash
# Check if any other RDS instances were modified or deleted in the incident window
aws rds describe-events \
  --source-type db-instance \
  --duration 360 \
  --query "Events[?contains(Message,'deletion') || contains(Message,'modified') || contains(Message,'DeletionProtection')].{Source:SourceIdentifier,Message:Message,Date:Date}" \
  --output table

# Check DB snapshot events
aws rds describe-events \
  --source-type db-snapshot \
  --duration 360 \
  --query "Events[?contains(Message,'deleted') || contains(Message,'Deleted')].{Source:SourceIdentifier,Message:Message,Date:Date}" \
  --output table
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Delete or permanently restrict the attacker IAM role

```bash
ROLE_NAME="atomic-rds-delete-attacker-role"

# Remove trust policy (prevents future assumption)
aws iam update-assume-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-document '{"Version":"2012-10-17","Statement":[]}'

# Delete the role entirely after confirming no legitimate use
aws iam delete-role --role-name "$ROLE_NAME"
```

#### 4.2 — Rotate credentials for any compromised principals

```bash
# Rotate access keys for the pipeline principal that was abused
SOURCE_USER="pipeline-admin-user"

# Delete old keys
aws iam list-access-keys --user-name "$SOURCE_USER" \
  --query "AccessKeyMetadata[*].AccessKeyId" --output text | \
  xargs -I{} aws iam delete-access-key \
    --user-name "$SOURCE_USER" --access-key-id {}

# Create new key (store securely in Secrets Manager, not environment variables)
aws iam create-access-key --user-name "$SOURCE_USER" \
  --query "AccessKey.{KeyId:AccessKeyId,Secret:SecretAccessKey}" --output json
```

#### 4.3 — Audit and remove any additional backdoors planted during the incident

```bash
# Check for any new IAM roles created during the incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '.Events[] | {time: .EventTime, role: .Resources[0].ResourceName, user: .Username}'

# Check for any new IAM users created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '.Events[] | {time: .EventTime, user: .Resources[0].ResourceName, creator: .Username}'

# Check for any policy attachments to unexpected principals
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \
  --start-time "2024-01-01T00:00:00Z" \
  --output json | jq '.Events[] | {time: .EventTime, role: .Username, policy: ((.CloudTrailEvent | fromjson).requestParameters.policyArn)}'
```

#### 4.4 — Remove emergency lockout policies (after eradication is confirmed)

```bash
# Only after the attacker principal is fully removed and rotated
aws iam delete-user-policy \
  --user-name "$SOURCE_USER" \
  --policy-name "EmergencyLockout"
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Assess data recovery options

```bash
# Check for any surviving automated backups (may still exist briefly after deletion)
aws rds describe-db-instance-automated-backups \
  --query "DBInstanceAutomatedBackups[*].{ID:DBInstanceIdentifier,Status:Status,Engine:Engine,AllocatedStorage:AllocatedStorage,RestoreWindow:RestoreWindow}" \
  --output table

# Check cross-region snapshot copies (if copy pipeline was in place)
aws rds describe-db-snapshots \
  --snapshot-type manual \
  --include-shared \
  --query "DBSnapshots[*].{ID:DBSnapshotIdentifier,Status:Status,Region:AvailabilityZone,Created:SnapshotCreateTime}" \
  --output table

# Check if a point-in-time restore window exists
aws rds describe-db-instances \
  --query "DBInstances[*].{ID:DBInstanceIdentifier,EarliestRestoreTime:DBInstanceAutomatedBackupsReplications}" \
  --output table
```

#### 5.2 — Restore from the most recent available backup

```bash
# Restore from automated backup (if still available in the deletion window)
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier "original-instance-id" \
  --target-db-instance-identifier "restored-instance-id" \
  --restore-time "2024-01-01T00:00:00Z" \
  --db-instance-class db.t3.micro \
  --multi-az \
  --publicly-accessible false \
  --deletion-protection

# Or restore from manual snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "restored-instance-id" \
  --db-snapshot-identifier "snapshot-id-from-cross-region-copy" \
  --db-instance-class db.t3.micro \
  --deletion-protection
```

#### 5.3 — Verify security controls are re-enabled

```bash
# Confirm GuardDuty RDS Protection is active
DETECTOR_ID=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)
aws guardduty get-detector --detector-id $DETECTOR_ID \
  --query "Features[?Name=='RDS_LOGIN_EVENTS'].{Name:Name,Status:Status}" \
  --output table

# Confirm Config rule compliance for deletion protection
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "rds-instance-deletion-protection-enabled" \
  --compliance-types NON_COMPLIANT \
  --query "EvaluationResults[*].{Resource:EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,Status:ComplianceType}" \
  --output table

# Verify all restored instances have DeletionProtection enabled
aws rds describe-db-instances \
  --query "DBInstances[*].{ID:DBInstanceIdentifier,DeletionProtection:DeletionProtection,Status:DBInstanceStatus}" \
  --output table

# Verify automated backups are re-enabled with correct retention
aws rds describe-db-instances \
  --query "DBInstances[*].{ID:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,PreferredBackupWindow:PreferredBackupWindow}" \
  --output table
```

#### 5.4 — Restore backup pipeline and cross-region copies

```bash
# Re-enable cross-region automated backup replication
aws rds start-db-instance-automated-backups-replication \
  --source-db-instance-arn "arn:aws:rds:us-east-1:ACCOUNT_ID:db:restored-instance-id" \
  --backup-retention-period 7 \
  --source-region us-east-1

# Create an immediate manual snapshot of the restored instance to re-establish a known-good backup
aws rds create-db-snapshot \
  --db-instance-identifier "restored-instance-id" \
  --db-snapshot-identifier "post-incident-baseline-$(date +%Y%m%d)" \
  --tags Key=env,Value=prod Key=incident,Value=rds-destruction-$(date +%Y%m%d)
```

---

## 6. Lessons Learned

### What Signals Were Available (and When)

| Signal | Latency | Would Have Caught It? |
|---|---|---|
| CloudTrail `ModifyDBInstance` (deletionProtection=false) | Near-real-time via EventBridge | Yes — leading-edge signal before destruction |
| CloudTrail `DeleteDBSnapshot` | Near-real-time | Yes — second opportunity before instance gone |
| CloudTrail `DeleteDBInstance` | Near-real-time | Yes — but too late to prevent data loss |
| GuardDuty RDS Protection anomaly | Minutes | Possibly — depends on baseline |
| AWS Config `rds-instance-deletion-protection-enabled` | Minutes (Config delivery lag) | Yes — on ModifyDBInstance |
| RDS Event Subscription via SNS | Real-time | Yes — `RDS-EVENT-0028` (deletion initiated) |

### Preventive Guardrails That Would Have Blocked This

**1. SCP to deny `rds:ModifyDBInstance` on `deletionProtection=false`**
```json
{
  "Effect": "Deny",
  "Action": "rds:ModifyDBInstance",
  "Resource": "*",
  "Condition": {
    "Bool": {"rds:DeletionProtection": "false"}
  }
}
```

**2. SCP to deny `DeleteDBInstance` with `skipFinalSnapshot=true`**
```json
{
  "Effect": "Deny",
  "Action": "rds:DeleteDBInstance",
  "Resource": "*",
  "Condition": {
    "Bool": {"rds:SkipFinalSnapshot": "true"}
  }
}
```

**3. IAM Permission Boundary on DB-management roles**
- Scope `rds:Delete*` and `rds:Modify*` to non-production resource ARNs by tag (`env=prod` denied)
- Require MFA for any `rds:Delete*` call: `"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}`

**4. Cross-region snapshot replication by default**
- Automated backup replication to a second region eliminates single-region destruction as a complete recovery failure
- Secondary region account should use separate IAM identity — compromising one region's credentials should not reach the replica

**5. EventBridge rule for immediate paging**
```bash
aws events put-rule \
  --name "RDS-DeletionProtection-Disabled" \
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
  --state ENABLED
```

### Key Takeaways

- **ModifyDBInstance (deletionProtection=false) is the last safe intervention point** — alert on this with a 1-minute SLA, not a 15-minute one. By the time `DeleteDBInstance` fires, data is gone.
- **The attack is a 3-step pattern**: disable protection → delete backups → delete instance. Any alert on step 1 buys time to prevent steps 2 and 3.
- **`skipFinalSnapshot=true` + `deleteAutomatedBackups=true` is never a legitimate production operation** — treat it as an unconditional P1.
- **Least privilege on `rds:Delete*` is the highest-leverage control**: in this chain, a role with these permissions was assumable from a pipeline principal. Segmenting backup-service identity from data-service identity eliminates the lateral move.
- **Cross-region snapshot copies are the last line of defense** — they must be out of reach of the identity that manages the source region.
# IR Playbook: ATOMIC-ec2-deregister-ami — AWS EC2 AMI Data Destruction

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data Destruction — EC2 AMI/Snapshot Wipeout |
| Threat Actor | ATOMIC-ec2-deregister-ami (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 — Data Destruction |
| Affected Services | EC2 (AMI, EBS Snapshot), STS, IAM |

---

## 1. Preparation

### Prerequisites

- **CloudTrail** enabled in all regions with management events captured (read + write), delivered to an immutable S3 bucket or CloudWatch Logs.
- **AWS Config** enabled with the `ec2:ami` resource type recorded; drift notifications to SNS.
- **AWS Security Hub** enabled with the AWS Foundational Security Best Practices standard active.
- **EC2 Image Builder** or equivalent golden AMI pipeline with versioned snapshots tagged consistently (e.g., `MayaTrail=true`, `Environment=production`).
- **AMI deregistration protection** (`EnableImageDeregistrationProtection`) enabled by default on all production AMIs via SCP or Config remediation rule.
- **Least-privilege IAM**: no production role should hold `ec2:DeregisterImage`, `ec2:DeleteSnapshot`, or `ec2:DisableImageDeregistrationProtection` unless explicitly required for image management workflows.
- **Backup snapshots** stored in a separate account (cross-account snapshot copies) so destruction in one account does not eliminate recovery options.
- **Runbook access**: this playbook stored in an incident management system accessible without AWS Console access (in case credentials are revoked during response).

### Recommended Preventive Controls

| Control | Mechanism |
|---------|-----------|
| Block DeregisterImage on tagged AMIs | SCP: Deny `ec2:DeregisterImage` where `ec2:ResourceTag/Environment` is `production` |
| Require MFA for destructive EC2 ops | IAM condition: `aws:MultiFactorAuthPresent: true` on `DeregisterImage`, `DeleteSnapshot` |
| Alert on deregistration protection disable | EventBridge rule → SNS on `DisableImageDeregistrationProtection` |
| Immutable snapshots | EBS snapshot lock (compliance mode) on all golden image backing snapshots |

---

## 2. Identification

### Detection Triggers

#### HIGH-CONFIDENCE — Any of these events is a confirmed incident

| Audit Event | Source | Signal |
|-------------|--------|--------|
| `DeregisterImage` | `ec2.amazonaws.com` | AMI permanently removed; cannot be undone |
| `DeleteSnapshot` | `ec2.amazonaws.com` | Backing block-device data destroyed |
| `DisableImageDeregistrationProtection` | `ec2.amazonaws.com` | Attacker clearing protection before destruction |

#### MEDIUM-CONFIDENCE — Investigate further before escalating

| Audit Event | Source | Signal |
|-------------|--------|--------|
| `AssumeRole` (unexpected principal → image-management role) | `sts.amazonaws.com` | Credential theft/misuse before destructive chain |
| `DescribeImages` with tag filter `MayaTrail=true` | `ec2.amazonaws.com` | Reconnaissance of target AMIs |
| Burst of EC2 Describe* calls from a single assumed-role session | `ec2.amazonaws.com` | Pre-destruction enumeration pattern |

---

### Key Investigation Queries

#### 2.1 — Find all DeregisterImage events in the last 7 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeregisterImage \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,User:Username,ImageId:CloudTrailEvent}' \
  --output table
```

#### 2.2 — Find all DeleteSnapshot events in the last 7 days

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteSnapshot \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].{Time:EventTime,User:Username,SnapshotId:CloudTrailEvent}' \
  --output table
```

#### 2.3 — Find DisableImageDeregistrationProtection events (protection clearance)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DisableImageDeregistrationProtection \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, detail: (.CloudTrailEvent | fromjson | .requestParameters)}'
```

#### 2.4 — Find the AssumeRole that started the attack chain (look for victim role)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | select(.CloudTrailEvent | fromjson | .requestParameters.roleArn | test("deregister|ec2|image")) | {time: .EventTime, actor: .Username, role: (.CloudTrailEvent | fromjson | .requestParameters.roleArn), session: (.CloudTrailEvent | fromjson | .requestParameters.roleSessionName)}'
```

#### 2.5 — Correlate full attack session by source IP

```bash
# Replace <SOURCE_IP> with the IP found in step 2.3/2.4 events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeregisterImage \
  --output json | jq -r '.Events[].CloudTrailEvent | fromjson | select(.sourceIPAddress == "<SOURCE_IP>") | {time: .eventTime, action: .eventName, user: .userIdentity.arn, resource: .requestParameters}'
```

#### 2.6 — Check which AMIs were deregistered (get AMI IDs from CloudTrail)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeregisterImage \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq -r '.Events[].CloudTrailEvent | fromjson | {time: .eventTime, ami: .requestParameters.imageId, actor: .userIdentity.arn}'
```

#### 2.7 — Check if destroyed snapshots had cross-account copies (recovery assessment)

```bash
# For each snapshot ID found in DeleteSnapshot events:
aws ec2 describe-snapshots \
  --snapshot-ids snap-<ID> \
  --query 'Snapshots[*].{Id:SnapshotId,State:State,Description:Description,Tags:Tags}' 2>/dev/null || echo "Snapshot no longer exists — confirm via AWS Config history"
```

#### 2.8 — Query AWS Config for historical AMI resource state

```bash
# Check Config timeline for a specific AMI before it was deregistered
aws configservice get-resource-config-history \
  --resource-type AWS::EC2::AMI \
  --resource-id ami-<ID> \
  --limit 5 \
  --output json | jq '.configurationItems[] | {time: .configurationItemCaptureTime, state: .configurationItemStatus, config: .configuration | fromjson | {name: .name, state: .state, snapshotId: .blockDeviceMappings[].ebs.snapshotId}}'
```

#### 2.9 — Security Hub finding check for EC2 AMI controls

```bash
aws securityhub get-findings \
  --filters '{"ProductFields":[{"Key":"aws/securityhub/FindingId","Value":"*DeregisterImage*","Comparison":"CONTAINS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id,Time:CreatedAt}' \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Identify and disable the IAM role used in the attack

```bash
# Disable the victim role by attaching a deny-all inline policy
aws iam put-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name EMERGENCY-DENY-ALL \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]
  }'
```

#### 3.2 — Revoke all active STS sessions for the compromised role

```bash
# Update the role's trust policy to deny all new AssumeRole calls
aws iam update-assume-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*"}]
  }'

# Revoke all active sessions by setting a policy with a past date condition
aws iam put-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name REVOKE-ALL-SESSIONS \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
      \"Effect\":\"Deny\",
      \"Action\":\"*\",
      \"Resource\":\"*\",
      \"Condition\":{\"DateLessThan\":{\"aws:TokenIssueTime\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}}
    }]
  }"
```

#### 3.3 — If an IAM user's long-term key was the initiating principal, deactivate it immediately

```bash
# Find the key used (from CloudTrail accessKeyId field in step 2.4 output)
aws iam update-access-key \
  --user-name <COMPROMISED_USER> \
  --access-key-id AKIA<ID> \
  --status Inactive
```

#### 3.4 — Block the source IP at the network perimeter if identified

```bash
# Create a NACL deny rule for the attacking IP (replace subnet/nacl IDs)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-<ID> \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block <ATTACKER_IP>/32 \
  --ingress

aws ec2 create-network-acl-entry \
  --network-acl-id acl-<ID> \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block <ATTACKER_IP>/32 \
  --egress
```

#### 3.5 — Protect all remaining production AMIs with deregistration protection immediately

```bash
# Find all production AMIs still registered and enable protection
for ami_id in $(aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:Environment,Values=production" \
  --query 'Images[*].ImageId' \
  --output text); do
  echo "Protecting $ami_id"
  aws ec2 enable-image-deregistration-protection \
    --image-id "$ami_id"
done
```

#### 3.6 — Lock remaining production EBS snapshots (prevents deletion)

```bash
# Apply compliance lock on all production snapshots (cannot be deleted until lock expires)
for snap_id in $(aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=tag:Environment,Values=production" \
  --query 'Snapshots[*].SnapshotId' \
  --output text); do
  echo "Locking snapshot $snap_id"
  aws ec2 lock-snapshot \
    --snapshot-id "$snap_id" \
    --lock-mode compliance \
    --lock-duration-days 7
done
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Delete the emergency deny policies and properly re-scope the victim role

```bash
# Remove the emergency deny policies added during containment
aws iam delete-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name EMERGENCY-DENY-ALL

aws iam delete-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name REVOKE-ALL-SESSIONS

# Restore a corrected trust policy (restrict to authorized principals only)
aws iam update-assume-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"ec2.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }'
```

#### 4.2 — Audit all IAM permissions that grant destructive EC2 image/snapshot actions

```bash
# Simulate which principals can call DeregisterImage
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<ACCOUNT_ID>:role/atomic-ec2-deregister-ami-victim-role \
  --action-names ec2:DeregisterImage ec2:DeleteSnapshot ec2:DisableImageDeregistrationProtection \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}'

# List all roles/users with DeregisterImage permissions via inline/attached policies
aws iam get-account-authorization-details \
  --filter Role \
  --output json | jq '.RoleDetailList[] | select(.RolePolicyList[].PolicyDocument.Statement[]?.Action | tostring | test("DeregisterImage|DeleteSnapshot")) | .RoleName'
```

#### 4.3 — Remove DeregisterImage/DeleteSnapshot from any overprivileged policies

```bash
# Get the policy version in use
aws iam get-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name <POLICY_NAME> \
  --output json | jq '.PolicyDocument'

# After editing, put the corrected policy
aws iam put-role-policy \
  --role-name atomic-ec2-deregister-ami-victim-role \
  --policy-name <POLICY_NAME> \
  --policy-document file://corrected_policy.json
```

#### 4.4 — Delete the compromised user's old access key and rotate to new

```bash
# Delete the inactive compromised key
aws iam delete-access-key \
  --user-name <COMPROMISED_USER> \
  --access-key-id AKIA<OLD_ID>

# Create a new key
aws iam create-access-key \
  --user-name <COMPROMISED_USER>
```

#### 4.5 — Check for any additional backdoor resources created during the session

```bash
# Check for IAM resources created by the attacker session
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=atomic-ec2-deregister-ami \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | select(.EventName | test("Create|Put|Attach|Add")) | {time: .EventTime, action: .EventName, detail: (.CloudTrailEvent | fromjson | .requestParameters)}'
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Assess recovery options for destroyed AMIs

```bash
# Check AWS Backup for any AMI recovery points
aws backup list-recovery-points-by-resource \
  --resource-arn arn:aws:ec2:<REGION>:<ACCOUNT>:image/ami-<ID> \
  --query 'RecoveryPoints[*].{Id:RecoveryPointArn,Status:Status,Created:CreationDate}' \
  --output table

# Check for cross-account snapshot copies in backup account
aws ec2 describe-snapshots \
  --owner-ids <BACKUP_ACCOUNT_ID> \
  --filters "Name=description,Values=*<ORIGINAL_SNAPSHOT_ID>*" \
  --query 'Snapshots[*].{Id:SnapshotId,Description:Description,Created:StartTime}' \
  --output table
```

#### 5.2 — Restore AMI from cross-account snapshot copy (if available)

```bash
# In the backup account: share the snapshot with the production account
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-<BACKUP_ID> \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids <PRODUCTION_ACCOUNT_ID> \
  --profile backup-account

# In the production account: register a new AMI from the recovered snapshot
aws ec2 register-image \
  --name "golden-ami-restored-$(date +%Y%m%d)" \
  --description "Restored from backup after T1485 incident" \
  --architecture x86_64 \
  --root-device-name /dev/xvda \
  --block-device-mappings "[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"SnapshotId\":\"snap-<BACKUP_ID>\",\"VolumeType\":\"gp3\"}}]" \
  --virtualization-type hvm \
  --ena-support

# Re-enable deregistration protection on the restored AMI
aws ec2 enable-image-deregistration-protection \
  --image-id ami-<NEW_ID>

# Re-tag with production labels
aws ec2 create-tags \
  --resources ami-<NEW_ID> \
  --tags Key=Environment,Value=production Key=MayaTrail,Value=true Key=RestoredFrom,Value=incident-<DATE>
```

#### 5.3 — Rebuild AMI from source if no backup snapshot exists

```bash
# Trigger EC2 Image Builder pipeline to rebuild golden AMI from patched source
aws imagebuilder start-image-pipeline-execution \
  --image-pipeline-arn arn:aws:imagebuilder:<REGION>:<ACCOUNT>:image-pipeline/<PIPELINE_NAME>
```

#### 5.4 — Re-enable security services if they were impaired during the attack

```bash
# Verify GuardDuty is active
aws guardduty list-detectors --query 'DetectorIds' --output text | \
  xargs -I{} aws guardduty get-detector --detector-id {} \
  --query '{Status:Status,Updated:UpdatedAt}'

# Verify AWS Config recorder is running
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[*].{Name:name,Recording:recording,LastStatus:lastStatus}'

# Verify Security Hub is enabled
aws securityhub describe-hub --query '{HubArn:HubArn,AutoEnableControls:AutoEnableControls}'
```

#### 5.5 — Verify no orphaned snapshots remain from deregistered AMIs

```bash
# List snapshots that are no longer referenced by any AMI (potential orphans)
# Cross-reference snapshot IDs from CloudTrail DeleteSnapshot events against current inventory
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=tag:Environment,Values=production" \
  --query 'Snapshots[*].{Id:SnapshotId,Description:Description,Tags:Tags,Created:StartTime}' \
  --output table
```

#### 5.6 — Validate AMI protection is restored across all production images

```bash
# Confirm all production AMIs have deregistration protection enabled
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:Environment,Values=production" \
  --query 'Images[*].{Id:ImageId,Name:Name,Protected:DeregistrationProtection.Status,State:State}' \
  --output table
```

#### 5.7 — Apply SCP to prevent future T1485 against production AMIs

```bash
# Create an SCP to block DeregisterImage on tagged production resources
# Apply via AWS Organizations
aws organizations create-policy \
  --name "DenyProductionAMIDestruction" \
  --type SERVICE_CONTROL_POLICY \
  --description "Blocks DeregisterImage and DeleteSnapshot on production-tagged resources" \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyDeregisterProductionAMI",
      "Effect":"Deny",
      "Action":["ec2:DeregisterImage","ec2:DisableImageDeregistrationProtection","ec2:DeleteSnapshot"],
      "Resource":"*",
      "Condition":{"StringEquals":{"ec2:ResourceTag/Environment":"production"}}
    }]
  }'
```

---

## 6. Lessons Learned

### Post-Incident Review Checklist

| Finding | Gap | Guardrail |
|---------|-----|-----------|
| Deregistration protection was disabled without alert | No real-time alert on `DisableImageDeregistrationProtection` | EventBridge rule: any `DisableImageDeregistrationProtection` → PagerDuty P1 |
| Victim role had `ec2:DeregisterImage` and `ec2:DeleteSnapshot` | Overpermissive role policy; no MFA condition on destructive EC2 actions | Attach SCP requiring `aws:MultiFactorAuthPresent` for all image/snapshot destroy actions |
| No cross-account backup snapshots existed | AMI backing snapshots stored only in production account | AWS Backup cross-account copy policy: daily snapshot copies to isolated backup account |
| AssumeRole event was not alerted on | Role assumption anomaly not monitored | GuardDuty Findings: `PrivilegeEscalation:IAMUser/AnomalousBehavior` + custom EventBridge rule on AssumeRole with unusual `roleSessionName` pattern |
| EBS snapshots were not immutably locked | No snapshot lock on production backing snapshots | EC2 Snapshot Lock (compliance mode) applied via Config remediation on all `Environment=production` snapshots |
| Destroyed AMIs had no Config configuration history beyond 90 days | Short Config retention | Set Config delivery channel S3 retention to 7 years for compliance; enable longer-term history for critical resource types |

### Timeline Summary

1. **AssumeRole** — Attacker assumed victim IAM role with session name `atomic-ec2-deregister-ami`.
2. **DescribeImages** — Enumerated AMIs tagged `MayaTrail=true` to identify targets and their backing snapshot IDs.
3. **DisableImageDeregistrationProtection** (x2) — Cleared deregistration protection on both golden AMI and backup bait AMI.
4. **DeregisterImage** (x2) — Permanently deregistered both AMIs; new instance launches from these images are now impossible.
5. **DeleteSnapshot** — Destroyed the shared EBS snapshot backing both deregistered AMIs, eliminating block-device recovery without external backup.

### Key Takeaways

- **Protection + monitoring alone is insufficient** — deregistration protection is a single-call bypass (`DisableImageDeregistrationProtection`). Alert on the bypass, not just on `DeregisterImage`.
- **Assume production backup storage will be targeted** — AMIs named `prod-database-backup` were specifically targeted. Cross-account copies are mandatory.
- **STS session chaining creates attribution gaps** — the initiating principal's identity may differ from the resource-acting identity. Always correlate `AssumeRole` → downstream EC2 events by `sessionContext.sourceIdentity` and `requestParameters.roleSessionName` in CloudTrail.
- **Recovery without cross-account snapshots requires full rebuild** — EBS Snapshot Lock in compliance mode on all golden image snapshots is the minimum viable recovery guardrail for this threat.
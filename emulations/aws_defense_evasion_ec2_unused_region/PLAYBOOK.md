# IR Playbook: ATOMIC-ec2-unused-region — AWS T1535 Unused/Unsupported Cloud Regions

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense Evasion via Unused Cloud Region Foothold |
| Threat Actor | ATOMIC-ec2-unused-region (technique emulation profile) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Defense Evasion (TA0005) |
| MITRE Techniques | T1535 — Unused/Unsupported Cloud Regions |

---

## 1. Preparation

### What should be in place before this incident

- **CloudTrail**: Organization-level or account-level trail with `IncludeGlobalServiceEvents=true` and `IsMultiRegionTrail=true` enabled, delivering to a protected S3 bucket with log file validation.
- **GuardDuty**: Detectors active in ALL enabled regions, ideally via delegated admin with auto-enable for member accounts. eu-north-1 and other opt-in-not-required regions included.
- **AWS Config**: Multi-region recorder capturing EC2 instance configuration changes.
- **Security Hub**: Aggregation region configured, GuardDuty findings flowing in.
- **SCP baseline**: `account:EnableRegion` restricted to cloud-platform team roles only.
- **Alerting**: CloudWatch Metric Filter or EventBridge rule forwarding high-signal CloudTrail events (`RunInstances`, `AssumeRole`, `EnableRegion`) to SIEM/alerting pipeline.
- **IAM baseline**: Attacker-reachable roles audited; cross-account trust policies reviewed quarterly.
- **Runbook pre-auth**: IR team has pre-authorized `ec2:TerminateInstances`, `iam:AttachRolePolicy` (deny), and `sts:AssumeRole` in break-glass accounts.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — events that always indicate active T1535 tradecraft

| Audit Event | EventSource | Why High-Confidence | Notes |
|---|---|---|---|
| `RunInstances` | `ec2.amazonaws.com` | EC2 launch in an unused or non-home region from an assumed-role session | Filter: `awsRegion` != account's primary region |
| `EnableRegion` | `account.amazonaws.com` | Attacker probing to unlock a new region — fires even on `errorCode=AccessDenied` | Do NOT filter on `errorCode IS NULL` |
| `ListDetectors` across N regions | `guardduty.amazonaws.com` | Programmatic GD coverage sweep; no human needs this pattern | >3 distinct regions in a 5-min window |
| `DescribeRegions` with `AllRegions=True` | `ec2.amazonaws.com` | Enumerating opt-in regions; legitimate callers rarely pass `AllRegions=True` | Check `requestParameters.allRegions=true` |
| `AssumeRole` followed by cross-region EC2 calls | `sts.amazonaws.com` | Role assumed then immediately used in a non-primary region | Correlate `userIdentity.arn` across events |

#### MEDIUM-CONFIDENCE — events that may indicate reconnaissance

| Audit Event | EventSource | Why Medium-Confidence | Notes |
|---|---|---|---|
| `DescribeTrails` with `IncludeShadowTrails=true` | `cloudtrail.amazonaws.com` | Trail coverage mapping; could be legitimate admin work | Escalate if paired with ListDetectors sweep |
| `DescribeImages` in non-primary region | `ec2.amazonaws.com` | AMI lookup prior to launch in an unused region | Check `awsRegion` against account's active regions |
| `GetCallerIdentity` immediately after `AssumeRole` | `sts.amazonaws.com` | Session validation pattern common in attack scripts | Low signal alone; strong in conjunction |
| `TerminateInstances` in non-primary region | `ec2.amazonaws.com` | Cleanup of a covert instance; may indicate completed operation | Check if instance was short-lived (<30 min) |

---

### Key Investigation Queries

#### Find the initial role assumption

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "2026-10-10T00:00:00Z" \
  --end-time "2026-10-10T23:59:59Z" \
  --region us-east-1 \
  --query 'Events[?contains(CloudTrailEvent, `AtomicT1535`) || contains(CloudTrailEvent, `attacker`)].[EventTime,Username,CloudTrailEvent]' \
  --output json
```

#### Find any EnableRegion attempts (including denied)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=EnableRegion \
  --region us-east-1 \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' \
  --output json
```

#### Find DescribeRegions calls with AllRegions flag

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeRegions \
  --region us-east-1 \
  --query 'Events[?contains(CloudTrailEvent, `allRegions`)].[EventTime,Username,CloudTrailEvent]' \
  --output json
```

#### Sweep for ListDetectors across all regions (run from a loop)

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "=== $region ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListDetectors \
    --region "$region" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" \
    --query 'Events[].[EventTime,Username]' \
    --output text 2>/dev/null
done
```

#### Find RunInstances in eu-north-1 specifically

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --region eu-north-1 \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' \
  --output json
```

#### Identify all EC2 instances launched by the suspect role in eu-north-1

```bash
aws ec2 describe-instances \
  --region eu-north-1 \
  --filters "Name=tag:emulation,Values=T1535" "Name=tag:MayaTrail,Values=true" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,LaunchTime,Tags]' \
  --output table
```

#### Pull the full activity timeline for the suspected IAM role ARN

```bash
# Replace ROLE_ARN with the suspected attacker role ARN
ROLE_ARN="arn:aws:iam::ACCOUNT_ID:role/ATTACKER_ROLE_NAME"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(basename $ROLE_ARN)" \
  --region us-east-1 \
  --query 'Events[].[EventTime,EventName,AwsRegion,CloudTrailEvent]' \
  --output json
```

#### Check GuardDuty detector coverage gaps across regions

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  result=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text 2>/dev/null)
  if [ -z "$result" ]; then
    echo "NO DETECTOR: $region"
  else
    echo "Covered: $region -> $result"
  fi
done
```

#### Look for short-lived instances (launched and terminated within 30 min) in eu-north-1

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances \
  --region eu-north-1 \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' \
  --output json
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 1. Revoke all active sessions for the compromised attacker role

```bash
# Attach an inline deny-all policy to immediately invalidate all existing sessions
ROLE_NAME="ATTACKER_ROLE_NAME"  # substitute real role name

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EmergencyRevoke-$(date +%Y%m%d%H%M%S)" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "DateLessThan": {"aws:TokenIssueTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}
        }
      }
    ]
  }'
```

#### 2. Terminate any running instances in eu-north-1 launched by the attacker

```bash
# List suspect instances
SUSPECT_INSTANCES=$(aws ec2 describe-instances \
  --region eu-north-1 \
  --filters "Name=instance-state-name,Values=running,pending,stopping" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)

# Review before terminating
echo "Instances to terminate: $SUSPECT_INSTANCES"

# Terminate after review
if [ -n "$SUSPECT_INSTANCES" ]; then
  aws ec2 terminate-instances --region eu-north-1 --instance-ids $SUSPECT_INSTANCES
fi
```

#### 3. Block the role from making further cross-region EC2 calls via SCP (if AWS Organizations)

```bash
# Draft SCP — apply to the affected OU after review
cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEC2UnusedRegions",
      "Effect": "Deny",
      "Action": ["ec2:RunInstances"],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
        }
      }
    }
  ]
}
EOF
# Apply via:
# aws organizations create-policy --type SERVICE_CONTROL_POLICY --name EmergencyEC2RegionLock ...
# aws organizations attach-policy --policy-id <id> --target-id <ou-id>
```

#### 4. Enable GuardDuty in eu-north-1 immediately to close the coverage gap

```bash
# Enable detector in eu-north-1
aws guardduty create-detector \
  --region eu-north-1 \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

# Verify
aws guardduty list-detectors --region eu-north-1
```

#### 5. Lock down the role's trust policy to prevent re-assumption

```bash
ROLE_NAME="ATTACKER_ROLE_NAME"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Replace trust policy with a deny-all trust (no principals can assume it)
aws iam update-assume-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": {"AWS": "arn:aws:iam::'"$ACCOUNT_ID"':root"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete or disable the attacker role entirely

```bash
ROLE_NAME="ATTACKER_ROLE_NAME"

# Remove all inline policies
for policy in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output text); do
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$policy"
  echo "Deleted inline policy: $policy"
done

# Detach all managed policies
for policy_arn in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[].PolicyArn' --output text); do
  aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$policy_arn"
  echo "Detached managed policy: $policy_arn"
done

# Delete the role (only after verifying it is not used by legitimate workloads)
aws iam delete-role --role-name "$ROLE_NAME"
echo "Role $ROLE_NAME deleted"
```

#### Terminate any lingering instances in eu-north-1 (catch missed cleanup)

```bash
# Catch any instances not yet terminated
aws ec2 describe-instances \
  --region eu-north-1 \
  --filters "Name=instance-state-name,Values=running,pending,stopped,stopping" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,LaunchTime]' \
  --output table

# Terminate survivors
aws ec2 terminate-instances \
  --region eu-north-1 \
  --instance-ids $(aws ec2 describe-instances \
    --region eu-north-1 \
    --filters "Name=instance-state-name,Values=running,pending,stopped,stopping" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text)
```

#### Delete any VPC resources provisioned in eu-north-1 as part of the attack infra

```bash
# List VPCs not tagged as legitimate
aws ec2 describe-vpcs --region eu-north-1 \
  --query 'Vpcs[?Tags[?Key==`MayaTrail`]].[VpcId,Tags]' \
  --output table

# Security groups, subnets, and VPCs to be deleted after instance termination:
# aws ec2 delete-security-group --region eu-north-1 --group-id <sg-id>
# aws ec2 delete-subnet --region eu-north-1 --subnet-id <subnet-id>
# aws ec2 delete-vpc --region eu-north-1 --vpc-id <vpc-id>
```

#### Audit all CloudTrail events from the attacker session for lateral actions

```bash
# Check if the attacker session performed any IAM writes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="AtomicT1535EC2UnusedRegion" \
  --region us-east-1 \
  --query 'Events[?contains(CloudTrailEvent, `iam`) || contains(CloudTrailEvent, `sts`)].[EventTime,EventName,CloudTrailEvent]' \
  --output json
```

---

## 5. Recovery

### Restore Clean State

#### Re-enable GuardDuty across all enabled regions (close coverage gaps permanently)

```bash
for region in $(aws ec2 describe-regions --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output text); do
  existing=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ -z "$existing" ] || [ "$existing" = "None" ]; then
    echo "Creating GuardDuty detector in $region..."
    aws guardduty create-detector --region "$region" --enable --finding-publishing-frequency FIFTEEN_MINUTES
  else
    echo "GuardDuty already active in $region: $existing"
  fi
done
```

#### Verify CloudTrail multi-region coverage

```bash
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --region us-east-1 \
  --query 'trailList[*].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,HomeRegion,S3BucketName]' \
  --output table
```

#### Remove the emergency revoke inline policy once the role is gone or re-provisioned clean

```bash
# Only if the role is being kept and re-scoped (not deleted)
aws iam delete-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "EmergencyRevoke-TIMESTAMP"
```

#### Confirm no instances remain in eu-north-1

```bash
aws ec2 describe-instances \
  --region eu-north-1 \
  --filters "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]' \
  --output text
# Expected output: (empty)
```

#### Harden `account:EnableRegion` via SCP if not already locked

```bash
# Verify the SCP restricting EnableRegion is attached
aws organizations list-policies-for-target \
  --filter SERVICE_CONTROL_POLICY \
  --target-id $(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text) \
  --query 'Policies[].{Name:Name,Id:Id}' \
  --output table

# Check for EnableRegion deny in the active SCPs:
aws organizations describe-policy --policy-id <SCP_ID> \
  --query 'Policy.Content' --output text | python -m json.tool | grep -A5 EnableRegion
```

#### Run post-incident GuardDuty sample findings to validate detector health

```bash
DETECTOR_ID=$(aws guardduty list-detectors --region eu-north-1 --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings \
  --region eu-north-1 \
  --detector-id "$DETECTOR_ID" \
  --finding-types "UnauthorizedAccess:EC2/TorIPCaller"
```

---

## 6. Lessons Learned

### What would have prevented or accelerated detection of this incident

| Gap Exploited | Guardrail |
|---|---|
| GuardDuty not enabled in eu-north-1 | Enforce GuardDuty auto-enable for all regions via AWS Organizations delegated admin; alert on any detector with `status=DISABLED` |
| No alerting on `RunInstances` in non-primary regions | EventBridge rule: `source=aws.ec2, detail-type=AWS API Call via CloudTrail, detail.eventName=RunInstances` filtered to `awsRegion NOT IN [primary regions]` |
| `EnableRegion` attempts went unalerted | CloudWatch Metric Filter or SIEM rule: `eventName=EnableRegion` fires on both success AND `errorCode=AccessDenied` — do not gate on errorCode being absent |
| `DescribeRegions AllRegions=True` not baselined | Add to anomaly/UBA baseline; flag programmatic callers that pass `allRegions=true` |
| Role's trust policy allowed broad self-account assumption | Least-privilege trust policies: restrict `sts:AssumeRole` by `aws:PrincipalArn` condition and require `sts:ExternalId` for non-workload roles |
| No multi-region CloudTrail trail | Ensure trail `IsMultiRegionTrail=true`; audit with AWS Config rule `cloud-trail-enabled` |
| No SCP blocking `account:EnableRegion` pre-incident | Proactive SCP: deny `account:EnableRegion` for all principals except `cloud-platform-*` roles |

### Timeline reconstruction commands (post-incident)

```bash
# Full attacker session timeline, all regions, sorted by time
for region in us-east-1 eu-north-1 us-west-2; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue="AtomicT1535EC2UnusedRegion" \
    --region "$region" \
    --query 'Events[].[EventTime,EventName,AwsRegion]' \
    --output text 2>/dev/null
done | sort -k1
```

### Detection rule references

- **GuardDuty finding**: `Stealth:EC2/NoGuardDutyDetector` (fires if instances run in regions without a detector — custom rule needed if using Security Hub CSPM)
- **CloudWatch Logs Insights** (if CloudTrail -> CWL):

```
fields @timestamp, eventName, awsRegion, userIdentity.arn, errorCode
| filter eventName in ["RunInstances","EnableRegion","ListDetectors","DescribeRegions"]
| sort @timestamp desc
| limit 200
```

- **Sigma rule hint** for `EnableRegion AccessDenied` (do not filter errorCode):

```yaml
# Key: errorCode field must be checked as PRESENT with value AccessDenied,
# not as ABSENT (which would miss this specific T1535 IoC)
detection:
  selection:
    eventSource: account.amazonaws.com
    eventName: EnableRegion
  condition: selection
  # note: fires on both success and AccessDenied — both are high-signal
```
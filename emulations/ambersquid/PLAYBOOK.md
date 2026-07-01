# IR Playbook: AMBERSQUID — AWS Cryptomining Campaign

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Cryptomining / Resource Hijacking |
| Threat Actor | AMBERSQUID |
| Attribution | Indonesia (financial motivation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Resource Development, Execution, Persistence, Discovery, Defense Evasion, Impact |
| MITRE Techniques | T1583.001, T1608.001, T1204.003, T1078.004, T1136.003, T1098.001, T1059.009, T1525, T1580, T1610, T1578.002, T1070, T1496 |

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail enabled, delivering to S3 with MFA delete and object versioning
- CloudTrail log file validation enabled
- GuardDuty enabled in all regions with ECS Protection and S3 Protection enabled
- AWS Config enabled with conformance pack for CIS AWS Foundations Benchmark
- Security Hub enabled with AWS Foundational Security Best Practices standard
- VPC Flow Logs enabled on all VPCs, delivered to CloudWatch Logs or S3
- ECS Container Insights enabled

**Alerting (must be pre-configured)**
- CloudWatch alarm on `CloudTrail:StopLogging` metric filter — this fires BEFORE the API call completes
- GuardDuty findings SNS → PagerDuty/Slack integration
- AWS Budgets anomaly alert for compute spend spike (>200% of baseline)
- EventBridge rule on `iam:CreateRole` + `iam:AttachRolePolicy` with `AdministratorAccess` policy ARN

**Response Tooling**
- AWS CLI v2 configured with break-glass responder credentials (separate from victim user)
- `jq` installed for JSON parsing in response scripts
- IAM runbook with role isolation procedures
- CloudTrail log S3 bucket with S3 Object Lock (WORM) on at least 30-day retention

**Known IOC Baselines**
- Maintain a list of legitimate IAM roles — flag any role named `AWSCodeCommit-Role`, `sugo-role`, `ecsTaskExecutionRole` not in baseline
- Inventory legitimate Amplify apps, CodeBuild projects, SageMaker notebooks per account

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `cloudtrail:StopLogging` called from non-console session | CloudTrail / CloudWatch Alarm | T1070 |
| P0 | `iam:AttachRolePolicy` with `AdministratorAccess` attached to attacker-created role | CloudTrail | T1136.003 |
| P0 | GuardDuty: `Stealth:IAMUser/CloudTrailLoggingDisabled` | GuardDuty | T1070 |
| P1 | `iam:CreateRole` naming `AWSCodeCommit-Role`, `sugo-role`, or `ecsTaskExecutionRole` from IAM user session | CloudTrail | T1136.003 |
| P1 | `sts:AssumeRole` to `ecsTaskExecutionRole` (or `sugo-role`) within seconds of `iam:CreateRole` | CloudTrail | T1098.001 |
| P1 | `s3:GetObject` on `terraform.tfstate` key from non-pipeline principal | CloudTrail | T1580 |
| P1 | `secretsmanager:GetSecretValue` on `prod/database/master_credentials` from non-application principal | CloudTrail | T1580 |
| P1 | ECS task definition registered with `executionRoleArn` bearing `AdministratorAccess` | CloudTrail | T1610 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `amplify:CreateApp` with CodeCommit source from non-console IAM user | CloudTrail | T1059.009 |
| P2 | `codebuild:CreateProject` targeting internal CodeCommit repo from non-console session | CloudTrail | T1059.009 |
| P2 | `sagemaker:CreateNotebookInstance` with external role ARN | CloudTrail | T1059.009 |
| P2 | Burst of `iam:ListRoles` + `iam:ListUsers` + `iam:GetAccountSummary` within 60 seconds | CloudTrail | T1580 |
| P2 | `s3:ListBuckets` immediately followed by `s3:GetObject` on infrastructure buckets | CloudTrail | T1580 |
| P2 | `ecs:RegisterTaskDefinition` with `WALLET` or `POOL` environment variable names | CloudTrail | T1610 |
| P2 | AWS Budget anomaly: >300% compute spend spike in ECS, SageMaker, CodeBuild line items | AWS Budgets | T1496 |
| P3 | GuardDuty: `CryptoCurrency:EC2/BitcoinTool.B!DNS` or `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | GuardDuty | T1496 |
| P3 | Outbound VPC Flow Logs to ports 3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560 | VPC Flow Logs | T1496 |

---

### Key Investigation Queries

#### Query 1 — Confirm CloudTrail StopLogging event

```bash
# Look back 2 hours for StopLogging (adjust --start-time as needed)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,SourceIP:CloudTrailEvent}' \
  --output table

# Full event JSON for forensic detail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '.'
```

#### Query 2 — Identify attacker IAM roles created

```bash
# Find CreateRole events for known AMBERSQUID role names
for ROLE in "AWSCodeCommit-Role" "sugo-role" "ecsTaskExecutionRole"; do
  echo "=== Searching for CreateRole: $ROLE ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE" \
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region us-east-1 \
    --query 'Events[*].CloudTrailEvent' \
    --output text | jq -r '. | {time: .eventTime, user: .userIdentity.arn, event: .eventName, role: .requestParameters.roleName}'
done

# List all IAM roles created in last 24h regardless of name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '. | {time: .eventTime, caller: .userIdentity.arn, roleName: .requestParameters.roleName}'
```

#### Query 3 — Map the AssumeRole credential chain

```bash
# Find all AssumeRole calls in last 4h — reveals the role-hopping credential chain
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].CloudTrailEvent' \
  --output text | jq -r '. | {time: .eventTime, caller: .userIdentity.arn, roleArn: .requestParameters.roleArn, sessionName: .requestParameters.roleSessionName, sourceIP: .sourceIPAddress}'
```

#### Query 4 — Identify miner infrastructure provisioned

```bash
# Amplify app creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateApp \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output text --query 'Events[*].CloudTrailEvent' | jq -r '.'

# CodeBuild project creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateProject \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output text --query 'Events[*].CloudTrailEvent' | jq -r '.'

# SageMaker notebook creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateNotebookInstance \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output text --query 'Events[*].CloudTrailEvent' | jq -r '.'

# ECS task definitions with miner indicators
aws ecs list-task-definitions --region us-east-1 --output text | grep -E "miner|task1?$"
aws ecs list-clusters --region us-east-1 --output json | jq -r '.clusterArns[]' | grep -E "miner|task"
```

#### Query 5 — Canary access confirmation (terraform.tfstate / secrets)

```bash
# S3 GetObject on terraform state
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output text --query 'Events[*].CloudTrailEvent' | \
  jq -r 'select(.requestParameters.key | test("terraform.tfstate")) | {time: .eventTime, caller: .userIdentity.arn, bucket: .requestParameters.bucketName, key: .requestParameters.key, sourceIP: .sourceIPAddress}'

# SecretsManager GetSecretValue on canary
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '4 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output text --query 'Events[*].CloudTrailEvent' | \
  jq -r '{time: .eventTime, caller: .userIdentity.arn, secretId: .requestParameters.secretId, sourceIP: .sourceIPAddress}'
```

#### Query 6 — Multi-region sweep (AMBERSQUID operates across 16 regions)

```bash
# Get all enabled regions
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

# Check for miner resources in all regions
for REGION in $REGIONS; do
  echo "=== $REGION ==="
  
  # ECS clusters
  aws ecs list-clusters --region "$REGION" --query 'clusterArns' --output text 2>/dev/null | grep -E "miner|task" && echo "  [!] ECS cluster found in $REGION"
  
  # SageMaker notebooks
  aws sagemaker list-notebook-instances --region "$REGION" --query 'NotebookInstances[*].NotebookInstanceName' --output text 2>/dev/null | grep -E "miner|note" && echo "  [!] SageMaker notebook found in $REGION"
  
  # Amplify apps
  aws amplify list-apps --region "$REGION" --query 'apps[*].name' --output text 2>/dev/null | grep -E "miner" && echo "  [!] Amplify app found in $REGION"
  
  # Auto Scaling groups named task or task1
  aws autoscaling describe-auto-scaling-groups --region "$REGION" --query 'AutoScalingGroups[?contains(AutoScalingGroupName, `task`)].AutoScalingGroupName' --output text 2>/dev/null
done
```

#### Query 7 — Enumerate VPC Flow Logs for mining pool connections

```bash
# Query CloudWatch Logs for outbound connections to known mining ports
LOG_GROUP="/vpc-flow-logs"  # adjust to your log group name
START=$(date -u -d '2 hours ago' +%s)000

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --start-time "$START" \
  --filter-pattern "[version, account, eni, source, destination, srcport, destport IN [3333,4444,5555,7777,8888,9999,14444,45560], protocol, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]" \
  --query 'events[*].message' \
  --output text 2>/dev/null | head -50
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Re-enable CloudTrail if disabled (DO THIS FIRST)

```bash
TRAIL_NAME="ambersquid-cloudtrail"   # substitute your trail name/ARN
REGION="us-east-1"

# Re-enable logging
aws cloudtrail start-logging --name "$TRAIL_NAME" --region "$REGION"

# Verify logging is active
aws cloudtrail get-trail-status --name "$TRAIL_NAME" --region "$REGION" \
  --query '{IsLogging:IsLogging, LatestDeliveryTime:LatestDeliveryTime}'
```

#### Step 2 — Disable the compromised victim IAM user access key

```bash
VICTIM_USER="<victim-iam-username>"   # from GetCallerIdentity in CloudTrail
REGION="us-east-1"

# List all keys for the victim user
aws iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'

# Disable the compromised key (do NOT delete yet — preserve forensic evidence)
COMPROMISED_KEY_ID="<key-id-from-above>"
aws iam update-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID" \
  --status Inactive

# Verify key is disabled
aws iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}'
```

#### Step 3 — Revoke all active STS sessions derived from the victim key

```bash
# Deny all current sessions for the victim user by attaching an inline deny policy
# This invalidates all STS tokens (codecommit_role_session, sugo_role_session, ecs_exec_role_session)
# even though they were obtained before the key was disabled

VICTIM_USER="<victim-iam-username>"

aws iam put-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'

echo "[OK] Session revocation policy applied to $VICTIM_USER"
```

#### Step 4 — Stop active ECS tasks running miner containers

```bash
REGION="us-east-1"

# Stop tasks in victim cluster
for CLUSTER in ambersquid-ecs-cluster miner-cluster; do
  echo "=== Stopping tasks in $CLUSTER ==="
  TASKS=$(aws ecs list-tasks --cluster "$CLUSTER" --region "$REGION" \
    --query 'taskArns[]' --output text 2>/dev/null)
  
  for TASK_ARN in $TASKS; do
    echo "  Stopping task: $TASK_ARN"
    aws ecs stop-task \
      --cluster "$CLUSTER" \
      --task "$TASK_ARN" \
      --reason "INCIDENT-RESPONSE: AMBERSQUID cryptominer containment" \
      --region "$REGION"
  done
done
```

#### Step 5 — Isolate attacker-created IAM roles (deny all access)

```bash
# Attach deny-all policy to each attacker role to neutralize live sessions
# (STS tokens from AssumeRole remain valid for their TTL unless permissions are revoked at the role)

DENY_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*"
  }]
}'

for ROLE in "AWSCodeCommit-Role" "sugo-role" "ecsTaskExecutionRole"; do
  echo "=== Isolating role: $ROLE ==="
  # Check if role exists first
  aws iam get-role --role-name "$ROLE" --query 'Role.RoleName' --output text 2>/dev/null || \
    { echo "  Role $ROLE not found — skipping"; continue; }
  
  aws iam put-role-policy \
    --role-name "$ROLE" \
    --policy-name "EmergencyDenyAll" \
    --policy-document "$DENY_POLICY"
  echo "  [OK] Deny-all policy applied to $ROLE"
done
```

#### Step 6 — Stop SageMaker notebook to halt compute charges

```bash
REGION="us-east-1"
NOTEBOOK_NAME="miner-notebook"

# Check notebook state
aws sagemaker describe-notebook-instance \
  --notebook-instance-name "$NOTEBOOK_NAME" \
  --region "$REGION" \
  --query '{Name:NotebookInstanceName, Status:NotebookInstanceStatus, InstanceType:InstanceType}' 2>/dev/null

# Stop if running or pending
aws sagemaker stop-notebook-instance \
  --notebook-instance-name "$NOTEBOOK_NAME" \
  --region "$REGION" 2>/dev/null && echo "[OK] Stop issued for $NOTEBOOK_NAME"

# Also check across all regions
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)
for REGION in $REGIONS; do
  NOTEBOOKS=$(aws sagemaker list-notebook-instances --region "$REGION" \
    --query 'NotebookInstances[?NotebookInstanceStatus!=`Stopped`].NotebookInstanceName' \
    --output text 2>/dev/null)
  for NB in $NOTEBOOKS; do
    echo "[!] Stopping notebook $NB in $REGION"
    aws sagemaker stop-notebook-instance --notebook-instance-name "$NB" --region "$REGION"
  done
done
```

#### Step 7 — Delete attacker Amplify and CodeBuild resources

```bash
REGION="us-east-1"

# Delete Amplify app named miner-app
MINER_APP_ID=$(aws amplify list-apps --region "$REGION" \
  --query "apps[?name=='miner-app'].appId" --output text 2>/dev/null)

if [ -n "$MINER_APP_ID" ]; then
  aws amplify delete-app --app-id "$MINER_APP_ID" --region "$REGION"
  echo "[OK] Deleted Amplify app miner-app ($MINER_APP_ID)"
fi

# Delete CodeBuild project
aws codebuild delete-project --name "miner-build-small" --region "$REGION" 2>/dev/null && \
  echo "[OK] Deleted CodeBuild project miner-build-small"
```

---

## 4. Eradication

### Remove Attacker Access

#### Remove attacker-created IAM roles

```bash
# Full cleanup: detach all policies then delete each role

for ROLE in "AWSCodeCommit-Role" "sugo-role" "ecsTaskExecutionRole"; do
  echo "=== Cleaning up role: $ROLE ==="

  # Check existence
  aws iam get-role --role-name "$ROLE" --query 'Role.RoleName' --output text 2>/dev/null || \
    { echo "  Role not found"; continue; }

  # Remove inline policies first
  INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE" \
    --query 'PolicyNames[]' --output text 2>/dev/null)
  for POLICY_NAME in $INLINE_POLICIES; do
    aws iam delete-role-policy --role-name "$ROLE" --policy-name "$POLICY_NAME"
    echo "  [OK] Deleted inline policy: $POLICY_NAME"
  done

  # Detach managed policies
  ATTACHED=$(aws iam list-attached-role-policies --role-name "$ROLE" \
    --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null)
  for POLICY_ARN in $ATTACHED; do
    aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$POLICY_ARN"
    echo "  [OK] Detached: $POLICY_ARN"
  done

  # Delete the role
  aws iam delete-role --role-name "$ROLE"
  echo "  [OK] Deleted role: $ROLE"
done
```

#### Rotate victim user credentials

```bash
VICTIM_USER="<victim-iam-username>"

# Delete the compromised key (now safe to delete since key is already Inactive from containment step)
aws iam delete-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"

# Issue new access key for legitimate owner (or disable entirely if service account)
aws iam create-access-key --user-name "$VICTIM_USER" \
  --query 'AccessKey.{AccessKeyId:AccessKeyId,SecretAccessKey:SecretAccessKey}'

# Remove emergency session-revocation inline policy once new key is in place
aws iam delete-user-policy \
  --user-name "$VICTIM_USER" \
  --policy-name "EmergencyRevokeSessions"
```

#### Delete attacker ECS cluster and task definitions

```bash
REGION="us-east-1"

# Deregister all revisions of attacker task definitions
for TD_FAMILY in "miner-task" "miner-fargate-task"; do
  TD_ARNS=$(aws ecs list-task-definitions \
    --family-prefix "$TD_FAMILY" \
    --region "$REGION" \
    --query 'taskDefinitionArns[]' --output text 2>/dev/null)
  for ARN in $TD_ARNS; do
    aws ecs deregister-task-definition --task-definition "$ARN" --region "$REGION"
    echo "[OK] Deregistered: $ARN"
  done
done

# Delete attacker-created ECS cluster (confirm no Pulumi-managed resources share this name)
aws ecs delete-cluster --cluster "miner-cluster" --region "$REGION" 2>/dev/null && \
  echo "[OK] Deleted ECS cluster miner-cluster"
```

#### Delete attacker CodeCommit repo (us-west-2)

```bash
# The Pulumi-managed repo in us-east-1 stays; delete the attacker-created one in us-west-2
aws codecommit delete-repository \
  --repository-name "test" \
  --region "us-west-2" 2>/dev/null && \
  echo "[OK] Deleted CodeCommit repo 'test' in us-west-2"
```

#### Delete SageMaker notebook after Stopped state

```bash
REGION="us-east-1"
NOTEBOOK_NAME="miner-notebook"

# Wait for Stopped state before deleting
echo "Waiting for $NOTEBOOK_NAME to reach Stopped state..."
aws sagemaker wait notebook-instance-stopped \
  --notebook-instance-name "$NOTEBOOK_NAME" \
  --region "$REGION" 2>/dev/null

aws sagemaker delete-notebook-instance \
  --notebook-instance-name "$NOTEBOOK_NAME" \
  --region "$REGION" 2>/dev/null && \
  echo "[OK] Deleted SageMaker notebook $NOTEBOOK_NAME"
```

#### Audit and remove any Auto Scaling groups named task or task1

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  for ASG_NAME in "task" "task1"; do
    ASG=$(aws autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "$ASG_NAME" \
      --region "$REGION" \
      --query 'AutoScalingGroups[0].AutoScalingGroupName' \
      --output text 2>/dev/null)
    if [ "$ASG" != "None" ] && [ -n "$ASG" ]; then
      echo "[!] Found ASG $ASG_NAME in $REGION — deleting"
      aws autoscaling delete-auto-scaling-group \
        --auto-scaling-group-name "$ASG_NAME" \
        --force-delete \
        --region "$REGION"
    fi
  done
done
```

#### Restore deleted CloudTrail log objects (S3 versioning)

```bash
TRAIL_BUCKET="ambersquid-cloudtrail-logs-<account-id>"   # substitute account ID
PREFIX="AWSLogs/<account-id>/CloudTrail/us-east-1/"

# List deleted objects (delete markers) in the CloudTrail prefix
aws s3api list-object-versions \
  --bucket "$TRAIL_BUCKET" \
  --prefix "$PREFIX" \
  --query 'DeleteMarkers[*].{Key:Key,VersionId:VersionId}' \
  --output table

# Restore by removing delete markers — repeat for each key/versionId listed above
# (loop example):
aws s3api list-object-versions \
  --bucket "$TRAIL_BUCKET" \
  --prefix "$PREFIX" \
  --query 'DeleteMarkers[*].[Key,VersionId]' \
  --output text | while IFS=$'\t' read -r KEY VERSION_ID; do
    aws s3api delete-object \
      --bucket "$TRAIL_BUCKET" \
      --key "$KEY" \
      --version-id "$VERSION_ID"
    echo "[OK] Restored: $KEY"
  done
```

---

## 5. Recovery

### Restore Clean State

#### Verify CloudTrail is healthy

```bash
TRAIL_NAME="ambersquid-cloudtrail"

aws cloudtrail get-trail-status --name "$TRAIL_NAME" \
  --query '{IsLogging:IsLogging, LatestDeliveryError:LatestDeliveryError, LatestCloudWatchLogsDeliveryError:LatestCloudWatchLogsDeliveryError}'

# Validate log file integrity for the last 24 hours
aws cloudtrail validate-logs \
  --trail-arn "$(aws cloudtrail describe-trails --query "trailList[?Name=='$TRAIL_NAME'].TrailARN" --output text)" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
```

#### Verify no attacker roles remain

```bash
# Confirm all three attacker roles are gone
for ROLE in "AWSCodeCommit-Role" "sugo-role" "ecsTaskExecutionRole"; do
  RESULT=$(aws iam get-role --role-name "$ROLE" 2>&1)
  if echo "$RESULT" | grep -q "NoSuchEntity"; then
    echo "[OK] Role $ROLE confirmed deleted"
  else
    echo "[FAIL] Role $ROLE still exists or error: $RESULT"
  fi
done
```

#### Verify no miner compute is running

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

echo "=== Checking for residual miner compute ==="
for REGION in $REGIONS; do
  # ECS tasks
  for CLUSTER in ambersquid-ecs-cluster miner-cluster; do
    COUNT=$(aws ecs list-tasks --cluster "$CLUSTER" --region "$REGION" \
      --query 'length(taskArns)' --output text 2>/dev/null)
    [ "$COUNT" != "0" ] && [ -n "$COUNT" ] && echo "[!] ECS tasks still running in $CLUSTER / $REGION: $COUNT"
  done

  # SageMaker (non-stopped)
  aws sagemaker list-notebook-instances --region "$REGION" \
    --status-equals InService \
    --query 'NotebookInstances[*].NotebookInstanceName' \
    --output text 2>/dev/null | grep -E "miner|note" && \
    echo "[!] SageMaker notebook still running in $REGION"
done

echo "[OK] Miner compute sweep complete"
```

#### Verify GuardDuty is enabled in all regions

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
  STATUS=$(aws guardduty list-detectors --region "$REGION" \
    --query 'DetectorIds[0]' --output text 2>/dev/null)
  if [ -z "$STATUS" ] || [ "$STATUS" == "None" ]; then
    echo "[!] GuardDuty NOT enabled in $REGION"
  fi
done
```

#### Verify Security Hub findings are cleared or tracked

```bash
# List open critical findings related to this incident
aws securityhub get-findings \
  --filters '{
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --region us-east-1 \
  --query 'Findings[*].{Id:Id,Title:Title,Resource:Resources[0].Id,UpdatedAt:UpdatedAt}' \
  --output table
```

#### Issue new legitimate credentials and validate

```bash
VICTIM_USER="<victim-iam-username>"

# Confirm new key created and working
NEW_KEY=$(aws iam list-access-keys --user-name "$VICTIM_USER" \
  --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
echo "[OK] Active key for $VICTIM_USER: $NEW_KEY"

# Force password reset if console user
aws iam update-login-profile \
  --user-name "$VICTIM_USER" \
  --password-reset-required 2>/dev/null && echo "[OK] Password reset required for $VICTIM_USER"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| IAM user static key leaked via container env var injection | Missing Secrets Manager / IAM Roles for ECS tasks anywhere — long-lived static keys in ECS task definitions violates least-privilege |
| Attacker created role with AdministratorAccess | No SCP blocking `iam:AttachRolePolicy` with AWS-managed admin policies from non-root principals |
| CloudTrail successfully stopped | No SCP or IAM condition blocking `cloudtrail:StopLogging` for non-break-glass roles |
| Multi-service miner deployment (Amplify, CodeBuild, SageMaker) undetected until CloudTrail disabled | No AWS Budgets anomaly alert pre-configured; no EventBridge rule on compute service bursts |

### Recommended Guardrails

**Service Control Policies (SCPs) — apply at OU level**

```json
// SCP 1: Block CloudTrail tampering
{
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/BreakGlassAdmin",
        "arn:aws:iam::*:role/SecurityResponseRole"
      ]
    }
  }
}

// SCP 2: Block AdministratorAccess attachment by non-admin principals
{
  "Effect": "Deny",
  "Action": "iam:AttachRolePolicy",
  "Resource": "*",
  "Condition": {
    "ArnEquals": {
      "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  }
}
```

**Prevent long-lived static keys in ECS containers**
- Require ECS tasks to use IAM task roles (`taskRoleArn`) — deny `ecs:RegisterTaskDefinition` where environment variables match `^AWS_ACCESS_KEY_ID$` or `^AWS_SECRET_ACCESS_KEY$` via SCP

**Least-privilege IAM baseline**
- Victim user should have had `iam:CreateRole` and `iam:AttachRolePolicy` scoped to specific path prefixes only
- SageMaker, Amplify, and CodeBuild creation should be restricted to known CI/CD principals via SCP

**Detection improvements**
- Add EventBridge rule: `iam:AttachRolePolicy` with `AdministratorAccess` → SNS → PagerDuty (P0)
- Add EventBridge rule: `sagemaker:CreateNotebookInstance` from non-CI principal → SNS (P1)
- Pre-configure AWS Budgets alert: >$50/day anomaly on SageMaker, CodeBuild, ECS, Amplify line items
- Enable GuardDuty ECS Runtime Monitoring — detects miner process launch inside container at data plane level, independent of control plane CloudTrail

### Known AMBERSQUID IOCs for Threat Intel Feeds

| Type | Value |
|------|-------|
| Domain | `master.d19tgz4vpyd5.amplifyapp.com` |
| IAM role name | `AWSCodeCommit-Role` |
| IAM role name | `sugo-role` |
| IAM role name | `ecsTaskExecutionRole` (attacker-created with AdministratorAccess) |
| ASG name | `task`, `task1` |
| Tool | SRBMiner-MULTI (UPX-packed) |
| Crypto wallet (ZEPHYR) | `ZEPHYR2vyrpcg2e2sJaA88EM6aGaLCBdiYfiHffrs5b3Fa4p1qpoEPH4UabmhJr5YYF7CxJykLTJmESQWaB9ARNuhb6jvptapVq3v` |
| Crypto wallet (TRX) | `TFrQ7u9spKk8MBgX6Bze3oxPbs3Yh1tAsq` |
| Mining pools | `2miners`, `c3pool`, `nanopool` |
| Mining ports | 3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560 |
| Deployment scripts | `entrypoint.sh`, `amplify-role.sh`, `ecs.sh`, `note.sh`, `scale.sh`, `delete.sh`, `stoptrigger.sh` |
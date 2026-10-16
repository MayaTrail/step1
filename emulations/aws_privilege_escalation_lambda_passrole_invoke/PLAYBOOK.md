# IR Playbook: ATOMIC-lambda-passrole-invoke — AWS Lambda PassRole Privilege Escalation

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Privilege Escalation via Serverless Execution (iam:PassRole + Lambda) |
| Threat Actor | ATOMIC-lambda-passrole-invoke (Technique Emulation) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Discovery, Privilege Escalation, Execution, Collection, Defense Evasion |
| MITRE Technique | T1648 - Serverless Execution |
| Attack Duration | Under 60 seconds (create -> invoke -> delete lifecycle) |

---

## 1. Preparation

### Pre-requisites Before This Incident
The following controls must be in place to detect and respond to this attack pattern:

**Logging & Visibility**
- CloudTrail management events enabled in all regions (covers CreateFunction, DeleteFunction, ListRoles, ListFunctions, ListSecrets)
- CloudTrail data events enabled for Secrets Manager (`secretsmanager.amazonaws.com` data event selector — captures GetSecretValue attributed to Lambda execution role sessions)
- CloudWatch Logs Insights enabled; Lambda function log groups indexed
- AWS Config enabled with Lambda function configuration change rule (`lambda-function-settings-check`)
- GuardDuty enabled (detects `PrivilegeEscalation:IAMUser/AdministrativePermissions` and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` related patterns)

**Alerting Baselines**
- Alert on `iam:PassRole` used in conjunction with `lambda:CreateFunction` from the same IAM principal within a 5-minute window
- Alert on Lambda functions with a lifecycle under 120 seconds (create -> delete)
- Alert on `secretsmanager:GetSecretValue` from a Lambda execution role session where the caller is not the expected application role
- SIEM correlation rule: `CreateFunction` + `Invoke` + `DeleteFunction` from same source identity within 60s

**IR Tooling**
- AWS CLI configured with read-only IR role (`SecurityAuditRole`) in incident response account
- Access to CloudTrail Lake or Athena table over S3-backed CloudTrail logs
- Runbook access to IAM key revocation procedure

---

## 2. Identification

### Detection Triggers (Prioritized)

**HIGH-CONFIDENCE — events that ALWAYS indicate compromise**

| Event Name | Event Source | Significance |
|---|---|---|
| `CreateFunction20150331` | `lambda.amazonaws.com` | New Lambda created; check `requestParameters.role` — if it differs from the calling principal's own roles, PassRole was used |
| `DeleteFunction20150331` | `lambda.amazonaws.com` | Lambda deleted within seconds/minutes of creation — attacker cleanup pattern |
| `GetSecretValue` | `secretsmanager.amazonaws.com` | Called by a Lambda execution role session that has no prior access history to that secret |

**MEDIUM-CONFIDENCE — may indicate reconnaissance or early-stage compromise**

| Event Name | Event Source | Significance |
|---|---|---|
| `ListFunctions20150331` | `lambda.amazonaws.com` | Lambda enumeration from an IAM identity not normally associated with Lambda management |
| `ListRoles` | `iam.amazonaws.com` | IAM role enumeration; look for subsequent `GetRole` calls targeting specific role names |
| `GetRole` | `iam.amazonaws.com` | Role detail lookup following `ListRoles` — attacker confirming passable role ARN |
| `ListSecrets` | `secretsmanager.amazonaws.com` | Secrets Manager enumeration from non-application IAM identity |
| `GetCallerIdentity` | `sts.amazonaws.com` | Session identity verification — attackers call this to confirm credential validity after obtaining stolen keys |

---

### Key Investigation Queries

#### Step 1: Identify the Incident Window — Find the PassRole+CreateFunction Event

```bash
# Find CreateFunction events where the execution role differs from the caller's role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction20150331 \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq '
    .Events[] |
    {
      EventTime: .EventTime,
      UserIdentity: (.CloudTrailEvent | fromjson | .userIdentity),
      FunctionName: (.CloudTrailEvent | fromjson | .requestParameters.functionName),
      ExecutionRole: (.CloudTrailEvent | fromjson | .requestParameters.role),
      SourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)
    }
  '
```

#### Step 2: Correlate the Full Attack Chain — All Events from Suspect Principal

```bash
# Replace PRINCIPAL_ARN with the ARN from the CreateFunction event above
PRINCIPAL_ARN="arn:aws:iam::ACCOUNT_ID:role/atomic-lambda-passrole-invoke-victim-role"
INCIDENT_START="2026-10-11T00:00:00Z"
INCIDENT_END="2026-10-11T23:59:59Z"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo $PRINCIPAL_ARN | awk -F'/' '{print $NF}')" \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --output json | jq -r '.Events[] | "\(.EventTime) \(.EventName) \(.Resources[0].ResourceName // "N/A")"' | sort
```

#### Step 3: Confirm PassRole — Check the Execution Role on the Created Function

```bash
# If the Lambda function still exists, inspect its configuration
FUNCTION_NAME="atomic-passrole-exfil"
REGION="us-east-1"

aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query '{Role: Role, FunctionName: FunctionName, LastModified: LastModified, State: State}' \
  --output json
```

#### Step 4: Confirm Secret Exfiltration — GetSecretValue from Lambda Execution Role

```bash
# Look for GetSecretValue attributed to the target execution role (not the victim role)
# This event appears with the Lambda role as the principal, not the attacker's IAM identity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --output json | jq '
    .Events[] |
    {
      EventTime: .EventTime,
      CallerArn: (.CloudTrailEvent | fromjson | .userIdentity.arn),
      SessionIssuer: (.CloudTrailEvent | fromjson | .userIdentity.sessionContext.sessionIssuer.arn),
      SecretId: (.CloudTrailEvent | fromjson | .requestParameters.secretId),
      SourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)
    }
  '
```

#### Step 5: Check Lambda Short-Lifecycle Pattern — Create Then Delete Within 60s

```bash
# Find DeleteFunction events for the suspected function name
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteFunction20150331 \
  --start-time "$INCIDENT_START" \
  --end-time "$INCIDENT_END" \
  --output json | jq '
    .Events[] |
    select((.CloudTrailEvent | fromjson | .requestParameters.functionName) == "atomic-passrole-exfil") |
    {
      EventTime: .EventTime,
      FunctionName: (.CloudTrailEvent | fromjson | .requestParameters.functionName),
      CallerArn: (.CloudTrailEvent | fromjson | .userIdentity.arn)
    }
  '
```

#### Step 6: Enumerate All IAM Actions from the Victim Role in the Window

```bash
# Confirm full reconnaissance sequence: GetCallerIdentity, ListFunctions, ListRoles, GetRole, ListSecrets
for EVENT in GetCallerIdentity ListFunctions20150331 ListRoles GetRole ListSecrets CreateFunction20150331 DeleteFunction20150331; do
  echo "=== $EVENT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVENT" \
    --start-time "$INCIDENT_START" \
    --end-time "$INCIDENT_END" \
    --output json | jq -r '.Events[] | "\(.EventTime) \(.SourceIPAddress) \(.Username)"'
done
```

#### Step 7: Check CloudWatch Logs for Lambda Execution Evidence

```bash
# Lambda execution logs persist even after function deletion (log group survives)
LOG_GROUP="/aws/lambda/atomic-passrole-exfil"
REGION="us-east-1"

aws logs describe-log-groups \
  --log-group-name-prefix "/aws/lambda/atomic-passrole-exfil" \
  --region "$REGION"

# If log group exists, retrieve execution log
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --region "$REGION" \
  --start-time $(($(date +%s%3N) - 86400000)) \
  --output json | jq -r '.events[].message'
```

#### Step 8: Validate Victim Role Permissions — Confirm PassRole Scope

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"
TARGET_ROLE="atomic-lambda-passrole-invoke-target-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Confirm victim role policy grants iam:PassRole to target role
aws iam list-role-policies \
  --role-name "$VICTIM_ROLE" \
  --output json

# Retrieve inline policy details
aws iam get-role-policy \
  --role-name "$VICTIM_ROLE" \
  --policy-name "$(aws iam list-role-policies --role-name $VICTIM_ROLE --query PolicyNames[0] --output text)" \
  --output json | jq '.PolicyDocument'

# Confirm target role's trust policy — what services/roles can assume it
aws iam get-role \
  --role-name "$TARGET_ROLE" \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

#### Action 1: Identify and Revoke the Compromised Victim Role Credentials

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# List all access keys associated with the victim IAM user (if static keys are from an IAM user)
# First, determine if the credentials belong to an IAM user or instance profile
aws iam list-users --output json | jq -r '.Users[].UserName' | while read USER; do
  KEYS=$(aws iam list-access-keys --user-name "$USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
  if [ -n "$KEYS" ]; then
    echo "User: $USER Keys: $KEYS"
  fi
done

# Deactivate the specific compromised access key (replace KEY_ID with identified key)
COMPROMISED_KEY_ID="AKIAIOSFODNN7EXAMPLE"
VICTIM_USER="victim-user-name"

aws iam update-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID" \
  --status Inactive

# Confirm deactivation
aws iam list-access-keys \
  --user-name "$VICTIM_USER" \
  --output json | jq '.AccessKeyMetadata[] | {KeyId: .AccessKeyId, Status: .Status}'
```

#### Action 2: Revoke All Active Sessions for the Victim Role

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"

# Attach a deny-all policy to revoke all existing sessions for the role
# This denies all actions for sessions issued before now
cat > /tmp/revoke-sessions-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "REPLACE_WITH_CURRENT_TIMESTAMP"
        }
      }
    }
  ]
}
EOF

# Set the timestamp to now (ISO 8601)
REVOKE_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
sed -i "s/REPLACE_WITH_CURRENT_TIMESTAMP/$REVOKE_TIME/" /tmp/revoke-sessions-policy.json

aws iam put-role-policy \
  --role-name "$VICTIM_ROLE" \
  --policy-name "RevokeActiveSessions-$(date +%Y%m%d%H%M%S)" \
  --policy-document file:///tmp/revoke-sessions-policy.json

echo "All sessions for $VICTIM_ROLE issued before $REVOKE_TIME have been revoked"
```

#### Action 3: Delete the Attacker-Created Lambda Function (If Still Present)

```bash
FUNCTION_NAME="atomic-passrole-exfil"
REGION="us-east-1"

# Check if function still exists
aws lambda get-function \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" 2>/dev/null && echo "Function exists - proceeding with deletion" || echo "Function already deleted"

# Delete the function
aws lambda delete-function \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION"

echo "Attacker Lambda function deleted"
```

#### Action 4: Isolate the Target Role — Prevent Lambda Service from Assuming It

```bash
TARGET_ROLE="atomic-lambda-passrole-invoke-target-role"

# Overwrite the trust policy to remove lambda.amazonaws.com as a trusted principal
# This prevents any future Lambda from assuming this role
cat > /tmp/isolated-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document file:///tmp/isolated-trust-policy.json

echo "Target role trust policy updated - Lambda service can no longer assume this role"
```

#### Action 5: Tag the Victim Role for Incident Tracking

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"
INCIDENT_ID="INC-$(date +%Y%m%d)-passrole-001"

aws iam tag-role \
  --role-name "$VICTIM_ROLE" \
  --tags Key=IncidentId,Value="$INCIDENT_ID" Key=ContainedAt,Value="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" Key=Status,Value=Contained
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1: Delete the Compromised Access Key Permanently

```bash
VICTIM_USER="victim-user-name"
COMPROMISED_KEY_ID="AKIAIOSFODNN7EXAMPLE"

# Permanently delete the key (after confirming deactivation in containment)
aws iam delete-access-key \
  --user-name "$VICTIM_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"

echo "Access key $COMPROMISED_KEY_ID permanently deleted"

# Verify no remaining keys for this user
aws iam list-access-keys \
  --user-name "$VICTIM_USER" \
  --output json
```

#### Step 2: Delete Lambda Execution Log Group (Remove Exfiltrated Secret Evidence Trail)

```bash
# Note: Preserve log group as evidence BEFORE deletion — export first
LOG_GROUP="/aws/lambda/atomic-passrole-exfil"
REGION="us-east-1"
EVIDENCE_BUCKET="your-security-evidence-bucket"

# Export logs to S3 for evidence preservation before eradication
aws logs create-export-task \
  --task-name "IR-evidence-$(date +%Y%m%d)" \
  --log-group-name "$LOG_GROUP" \
  --from $(($(date +%s%3N) - 86400000)) \
  --to $(date +%s%3N) \
  --destination "$EVIDENCE_BUCKET" \
  --destination-prefix "incident-evidence/lambda-passrole-$(date +%Y%m%d)/" \
  --region "$REGION"

# After evidence is preserved, delete the log group
aws logs delete-log-group \
  --log-group-name "$LOG_GROUP" \
  --region "$REGION"
```

#### Step 3: Rotate the Canary Secret Value

```bash
SECRET_NAME="atomic-lambda-passrole-invoke-canary-secret"
REGION="us-east-1"

# Rotate the secret value — the attacker retrieved the current value via the Lambda
aws secretsmanager rotate-secret \
  --secret-id "$SECRET_NAME" \
  --region "$REGION"

# Or manually set a new value
aws secretsmanager put-secret-value \
  --secret-id "$SECRET_NAME" \
  --secret-string '{"rotated": true, "rotated_at": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"}' \
  --region "$REGION"

echo "Canary secret rotated - old value is now invalid"
```

#### Step 4: Audit All Lambda Functions Created in the Incident Window

```bash
REGION="us-east-1"
INCIDENT_START="2026-10-11T00:00:00Z"
INCIDENT_END="2026-10-11T23:59:59Z"

# List all currently deployed Lambda functions and check creation dates
aws lambda list-functions \
  --region "$REGION" \
  --output json | jq --arg start "$INCIDENT_START" '
    .Functions[] |
    select(.LastModified >= $start) |
    {FunctionName: .FunctionName, Role: .Role, LastModified: .LastModified}
  '

# Review any unexpected functions — delete if attacker-created artifacts remain
# aws lambda delete-function --function-name <SUSPICIOUS_FUNCTION> --region $REGION
```

#### Step 5: Verify the Victim Role Permissions Are Scoped Correctly

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"

# Simulate privilege escalation path — confirm PassRole is properly scoped
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/$VICTIM_ROLE" \
  --action-names "iam:PassRole" \
  --resource-arns "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/*" \
  --output json | jq '.EvaluationResults[] | {Action: .EvalActionName, Resource: .EvalResourceName, Decision: .EvalDecision}'
```

---

## 5. Recovery

### Restore Clean State

#### Step 1: Restore the Target Role Trust Policy to Original State

```bash
TARGET_ROLE="atomic-lambda-passrole-invoke-target-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Restore original trust policy allowing only expected services/principals
cat > /tmp/restored-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "$ACCOUNT_ID"
        }
      }
    }
  ]
}
EOF

# Apply only after verifying the PassRole victim role is locked down
aws iam update-assume-role-policy \
  --role-name "$TARGET_ROLE" \
  --policy-document file:///tmp/restored-trust-policy.json

echo "Target role trust policy restored with source account condition"
```

#### Step 2: Remove the Session-Revocation Deny Policy from the Victim Role

```bash
VICTIM_ROLE="atomic-lambda-passrole-invoke-victim-role"

# List inline policies (the revoke-sessions policy added during containment)
aws iam list-role-policies \
  --role-name "$VICTIM_ROLE" \
  --output json

# Remove the temporary revocation policy (replace policy name with actual)
REVOKE_POLICY_NAME="RevokeActiveSessions-20261011120000"  # use actual timestamp from containment step
aws iam delete-role-policy \
  --role-name "$VICTIM_ROLE" \
  --policy-name "$REVOKE_POLICY_NAME"
```

#### Step 3: Issue New Access Credentials for the Victim Role's Legitimate Owner

```bash
VICTIM_USER="victim-user-name"

# Create a fresh access key for the legitimate owner
aws iam create-access-key \
  --user-name "$VICTIM_USER" \
  --output json | jq '{AccessKeyId: .AccessKey.AccessKeyId, SecretAccessKey: .AccessKey.SecretAccessKey, Status: .AccessKey.Status}'

# Deliver new credentials through secure channel (not shown here — follow your org's key distribution procedure)
```

#### Step 4: Verify No Persistent Lambda Backdoors Remain

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TARGET_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/atomic-lambda-passrole-invoke-target-role"
REGION="us-east-1"

# Check all Lambda functions — none should be using the target role as execution role
aws lambda list-functions \
  --region "$REGION" \
  --output json | jq --arg role "$TARGET_ROLE_ARN" '
    .Functions[] |
    select(.Role == $role) |
    {FunctionName: .FunctionName, Role: .Role, LastModified: .LastModified}
  '

echo "If any functions appear above, they must be reviewed and deleted — none should be using the target role"
```

#### Step 5: Verify GuardDuty and AWS Config Are Active and Unimpaired

```bash
REGION="us-east-1"

# Confirm GuardDuty detector is active
aws guardduty list-detectors --region "$REGION" --output json | jq '.DetectorIds[]' | while read DETECTOR_ID; do
  DETECTOR_ID=$(echo $DETECTOR_ID | tr -d '"')
  aws guardduty get-detector --detector-id "$DETECTOR_ID" --region "$REGION" \
    --query '{Status: Status, FindingPublishingFrequency: FindingPublishingFrequency}' --output json
done

# Confirm CloudTrail is logging
aws cloudtrail get-trail-status \
  --name "$(aws cloudtrail list-trails --query 'Trails[0].Name' --output text)" \
  --query '{IsLogging: IsLogging, LatestDeliveryTime: LatestDeliveryTime}' \
  --output json

# Confirm AWS Config recorder is active
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Name: name, Recording: recording, LastStatus: lastStatus}' \
  --output json
```

#### Step 6: Verify Secrets Manager Access — Confirm Secret is Not Still Accessible by Attacker

```bash
SECRET_NAME="atomic-lambda-passrole-invoke-canary-secret"
REGION="us-east-1"

# Review resource-based policy on the secret
aws secretsmanager get-resource-policy \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --output json 2>/dev/null || echo "No resource policy on secret (access controlled by IAM only)"

# List recent access events (last 24h) to confirm no ongoing access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$SECRET_NAME" \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --output json | jq -r '.Events[] | "\(.EventTime) \(.EventName) \(.Username)"'
```

---

## 6. Lessons Learned

### What This Attack Exploited

| Root Cause | Guardrail to Add |
|---|---|
| IAM user with static long-lived access keys | Eliminate static keys; use IAM Roles Anywhere, EC2 instance profiles, or short-lived STS tokens exclusively |
| `iam:PassRole` scoped to a single role but that role was over-privileged | Apply least-privilege on the **target role** — scope its Secrets Manager permissions to specific secret ARNs only |
| No alert on `CreateFunction` + `PassRole` within a single session | Add SIEM/EventBridge rule correlating these two API calls from the same `userIdentity.arn` within 5 minutes |
| Lambda function lifecycle anomaly not baselined | Establish CloudWatch metric filter for Lambda functions deleted within 120 seconds of creation |
| Secrets Manager data events not enabled | Enable CloudTrail data events for `secretsmanager.amazonaws.com` — management events alone miss `GetSecretValue` |
| No canary-token alerting on the secret | Add a Lambda trigger on `GetSecretValue` for this secret to page the security team immediately |

### Detective Controls to Implement

```bash
# Create EventBridge rule to catch PassRole+CreateFunction pattern
aws events put-rule \
  --name "DetectLambdaPassRoleEscalation" \
  --event-pattern '{
    "source": ["aws.lambda"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["CreateFunction20150331"],
      "requestParameters": {
        "role": [{"prefix": "arn:aws:iam::"}]
      }
    }
  }' \
  --state ENABLED \
  --description "Alert on Lambda function creation where execution role may be passed via iam:PassRole"

# Create CloudWatch metric filter for short-lived Lambda functions
aws logs put-metric-filter \
  --log-group-name "aws-cloudtrail-logs" \
  --filter-name "LambdaCreateDeleteWithin60s" \
  --filter-pattern '{ ($.eventName = "CreateFunction20150331") || ($.eventName = "DeleteFunction20150331") }' \
  --metric-transformations \
    metricName=LambdaLifecycleEvents,metricNamespace=SecurityMetrics,metricValue=1
```

### Preventive Controls to Implement

```bash
# SCP to require iam:PassRole targets be tagged with approved tag
# Add to AWS Organizations SCP:
cat << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireApprovedRoleTagForPassRole",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "iam:ResourceTag/approved-for-lambda": "true"
        }
      }
    }
  ]
}
EOF

# Enable AWS Config rule for Lambda function public access
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "lambda-function-public-access-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
    }
  }'
```

### Key Timeline Indicators for Future Detection

| Time Offset | Event | Detection Value |
|---|---|---|
| T+0s | `GetCallerIdentity` from victim role static key | Low — but establishes session start |
| T+5-30s | `ListFunctions`, `ListRoles`, `GetRole`, `ListSecrets` | Medium — enumeration burst from non-Lambda-owning identity |
| T+30-45s | `CreateFunction20150331` with cross-role `role` parameter | **HIGH** — PassRole privilege escalation |
| T+45-55s | `GetSecretValue` attributed to Lambda execution role session | **HIGH** — confirms exfiltration via serverless proxy |
| T+55-60s | `DeleteFunction20150331` within 60s of creation | **HIGH** — attacker cleanup, short-lifecycle anomaly |
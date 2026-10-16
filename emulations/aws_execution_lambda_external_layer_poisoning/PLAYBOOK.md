# IR Playbook: ATOMIC-lambda-external-layer-poisoning — AWS Lambda Supply Chain Injection

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Software Supply Chain Compromise — Lambda Layer Injection |
| Threat Actor | ATOMIC-lambda-external-layer-poisoning (technique emulation) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Initial Access |
| MITRE Technique | T1195.002 — Compromise Software Supply Chain |
| Attack Surface | Lambda Layer management APIs (control plane) + Lambda execution (data plane) |

---

## 1. Preparation

### Prerequisites for effective detection
- **CloudTrail management events** must be enabled in every region (default ON — verify with `aws cloudtrail get-trail-status`).
- **CloudTrail Lambda data events** must be explicitly enabled for `lambda.amazonaws.com` (Invoke operations are NOT captured without this).
- **CloudWatch Logs retention** set to ≥ 90 days for all Lambda log groups under `/aws/lambda/`.
- **GuardDuty** enabled with Lambda Protection feature ON (`aws guardduty list-detectors` → `aws guardduty get-detector --detector-id <id>`).
- **Baseline identity mapping**: Know which IAM principals (roles/users) are the authoritative publishers for each Lambda layer — typically a CI/CD role or a specific deployment role. Document this in a CMDB or tag the layers at publish time.
- **Tag Lambda layers and functions** with `DeployedBy`, `Pipeline`, and `Repo` tags to make principal-mismatch anomalies visible.

### Runbook trigger conditions
Open this playbook when any of the following fire:
- SIEM alert: `UpdateFunctionConfiguration` with a `Layers` field change from an unexpected principal.
- GuardDuty finding: `Lambda:Execution/SuspiciousCode`.
- CloudWatch Logs Insights alert: string `LAYER_POISONED` found in any Lambda log group.
- Peer-reviewed anomaly: `PublishLayerVersion` called by a role that is not the registered CI/CD identity for that layer name.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE indicators — always indicate suspicious activity

| Audit Event | eventSource | What it means | CloudTrail field to check |
|---|---|---|---|
| `UpdateFunctionConfiguration20150331v2` | `lambda.amazonaws.com` | Layer list on a function was modified | `requestParameters.layers[]` changed from known-good ARN to new ARN |
| `PublishLayerVersion20181031` | `lambda.amazonaws.com` | New layer version published — check if principal matches authoritative deployer | `userIdentity.arn` vs. registered CI/CD role |
| `GetFunction20150331v2` | `lambda.amazonaws.com` | Function config read by non-application role — likely reconnaissance | `userIdentity.arn` is not the application or CI/CD identity |

#### MEDIUM-CONFIDENCE indicators — investigate in context

| Audit Event | eventSource | What it means |
|---|---|---|
| `Invoke` (data event) | `lambda.amazonaws.com` | Invocation by attacker role rather than expected event source (requires data events enabled) |
| `LAYER_POISONED` string in CloudWatch Logs | N/A | Execution of injected module code confirmed |
| `ENV_KEYS` list in Lambda log output | N/A | Injected code enumerated environment variable names on import |

---

### Key Investigation Queries

#### Step 1 — Confirm the UpdateFunctionConfiguration event and capture the injected layer ARN

```bash
# Look back 7 days; narrow time window once you have the approximate incident time
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionConfiguration20150331v2 \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,User:Username,Detail:CloudTrailEvent}' \
  --output json | jq '.[] | {Time: .Time, User: .User, Func: (.Detail | fromjson | .requestParameters.functionName), Layers: (.Detail | fromjson | .requestParameters.layers), Principal: (.Detail | fromjson | .userIdentity.arn)}'
```

#### Step 2 — Find the PublishLayerVersion call for the injected layer

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PublishLayerVersion20181031 \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].CloudTrailEvent' \
  --output json \
  | jq '.[] | fromjson | {Time: .eventTime, Principal: .userIdentity.arn, LayerName: .requestParameters.layerName, LayerArn: .responseElements.layerVersionArn}'
```

#### Step 3 — Find the GetFunction reconnaissance call (baseline read)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFunction20150331v2 \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].CloudTrailEvent' \
  --output json \
  | jq '.[] | fromjson | {Time: .eventTime, Principal: .userIdentity.arn, Function: .requestParameters.functionName}'
```

#### Step 4 — Search CloudWatch Logs for the LAYER_POISONED execution marker

```bash
# Replace LOG_GROUP with the actual function log group name
LOG_GROUP="/aws/lambda/atomic-lambda-external-layer-poisoning-victim-function"

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --filter-pattern "LAYER_POISONED" \
  --start-time $(( $(date -u +%s) - 604800 ))000 \
  --query 'events[*].{timestamp:timestamp,message:message}' \
  --output table
```

#### Step 5 — Search for ENV_KEYS enumeration in logs (data exfil indicator)

```bash
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --filter-pattern "ENV_KEYS" \
  --start-time $(( $(date -u +%s) - 604800 ))000 \
  --query 'events[*].{timestamp:timestamp,message:message}' \
  --output json
```

#### Step 6 — Get current layer configuration of the victim function

```bash
FUNCTION_NAME="atomic-lambda-external-layer-poisoning-victim-function"
REGION="us-east-1"   # adjust to your region

aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query '{FunctionName:FunctionName, Runtime:Runtime, LastModified:LastModified, Layers:Layers, Role:Role}' \
  --output json
```

#### Step 7 — List ALL versions of the poisoned layer to map the attacker's publish history

```bash
LAYER_NAME="atomic-lambda-external-layer-poisoning-common-deps"   # adjust if different

aws lambda list-layer-versions \
  --layer-name "$LAYER_NAME" \
  --region "$REGION" \
  --query 'LayerVersions[*].{Version:Version,CreatedDate:CreatedDate,Arn:LayerVersionArn}' \
  --output table
```

#### Step 8 — Enumerate all functions that reference any version of the poisoned layer

```bash
# Find all Lambda functions that have this layer attached
aws lambda list-functions \
  --region "$REGION" \
  --query "Functions[?Layers[?contains(Arn, '$LAYER_NAME')]].{Name:FunctionName,Runtime:Runtime,LastModified:LastModified,Layers:Layers}" \
  --output json
```

#### Step 9 — Identify the attacker role and enumerate its recent activity

```bash
# Pull attacker role ARN from UpdateFunctionConfiguration event, then query all its events
ATTACKER_ROLE_ARN="arn:aws:iam::<ACCOUNT_ID>:assumed-role/<ROLE_NAME>/<SESSION_NAME>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="<SESSION_NAME>" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[*].{Time:EventTime,Event:EventName,Resource:Resources}' \
  --output table
```

#### Step 10 — Check if Lambda data events are enabled (confirms Invoke visibility)

```bash
aws cloudtrail get-event-selectors \
  --trail-name "$(aws cloudtrail describe-trails --query 'trailList[0].Name' --output text)" \
  --query 'EventSelectors[*].{DataResources:DataResources,ReadWriteType:ReadWriteType}' \
  --output json
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Action 1 — Revoke the attacker role's ability to make further Lambda changes

```bash
# Detach all inline and managed policies from the attacker role
ATTACKER_ROLE="<ATTACKER_ROLE_NAME>"

# List and detach managed policies
aws iam list-attached-role-policies --role-name "$ATTACKER_ROLE" \
  --query 'AttachedPolicies[*].PolicyArn' --output text \
  | tr '\t' '\n' \
  | xargs -I{} aws iam detach-role-policy --role-name "$ATTACKER_ROLE" --policy-arn {}

# List and delete inline policies
aws iam list-role-policies --role-name "$ATTACKER_ROLE" \
  --query 'PolicyNames[*]' --output text \
  | tr '\t' '\n' \
  | xargs -I{} aws iam delete-role-policy --role-name "$ATTACKER_ROLE" --policy-name {}
```

#### Action 2 — Deny the attacker role entirely with an inline deny-all policy

```bash
aws iam put-role-policy \
  --role-name "$ATTACKER_ROLE" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*"
    }]
  }'
```

#### Action 3 — Revoke all active sessions for the attacker role

```bash
# This revokes all sessions assumed before NOW by updating the role's policy timestamp
aws iam put-role-policy \
  --role-name "$ATTACKER_ROLE" \
  --policy-name "INCIDENT-RESPONSE-REVOKE-SESSIONS" \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
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

#### Action 4 — Restore the victim Lambda function to the known-good layer version

```bash
# Replace KNOWN_GOOD_LAYER_ARN with the ARN captured from GetFunction in the audit trail
# (the layer ARN present BEFORE UpdateFunctionConfiguration was called)
KNOWN_GOOD_LAYER_ARN="arn:aws:lambda:<REGION>:<ACCOUNT_ID>:layer:<LAYER_NAME>:<BASELINE_VERSION>"

aws lambda update-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --layers "$KNOWN_GOOD_LAYER_ARN"

# Wait for the update to complete before validating
aws lambda wait function-updated \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION"

echo "Verify restored configuration:"
aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query 'Layers' \
  --output json
```

#### Action 5 — Throttle or disable the victim Lambda function to prevent further poisoned execution

```bash
# Throttle to 0 concurrent executions (immediate, reversible)
aws lambda put-function-concurrency \
  --function-name "$FUNCTION_NAME" \
  --reserved-concurrent-executions 0 \
  --region "$REGION"
```

---

## 4. Eradication

### Remove Attacker Access

#### Step 1 — Delete the poisoned layer version(s)

```bash
# Identify all attacker-published versions (from PublishLayerVersion CloudTrail event)
POISONED_VERSION="<VERSION_NUMBER_FROM_CLOUDTRAIL>"

aws lambda delete-layer-version \
  --layer-name "$LAYER_NAME" \
  --version-number "$POISONED_VERSION" \
  --region "$REGION"
```

#### Step 2 — Confirm no other functions are using the poisoned layer

```bash
# Check all functions across the account for the poisoned layer ARN
POISONED_LAYER_ARN="arn:aws:lambda:<REGION>:<ACCOUNT_ID>:layer:$LAYER_NAME:$POISONED_VERSION"

aws lambda list-functions --region "$REGION" \
  --query "Functions[?Layers[?Arn=='$POISONED_LAYER_ARN']].FunctionName" \
  --output table
```

#### Step 3 — Rotate credentials for any IAM identity that assumed the attacker role

```bash
# If the attacker role was assumed via an IAM user's access key, rotate that key
IAM_USER="<USER_WHO_ASSUMED_ATTACKER_ROLE>"

# Create new access key
aws iam create-access-key --user-name "$IAM_USER"

# Deactivate old key (get old key ID from CloudTrail AssumeRole event)
OLD_KEY_ID="<KEY_ID_FROM_CLOUDTRAIL>"
aws iam update-access-key \
  --user-name "$IAM_USER" \
  --access-key-id "$OLD_KEY_ID" \
  --status Inactive

# After confirming new key works, delete the old one
aws iam delete-access-key \
  --user-name "$IAM_USER" \
  --access-key-id "$OLD_KEY_ID"
```

#### Step 4 — Audit the attacker role trust policy for persistence mechanisms

```bash
aws iam get-role \
  --role-name "$ATTACKER_ROLE" \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json

# Also check if any other roles have unexpected trust relationships to the attacker role
aws iam list-roles \
  --query "Roles[?contains(AssumeRolePolicyDocument, '$ATTACKER_ROLE')].{Name:RoleName,Arn:Arn}" \
  --output table
```

#### Step 5 — Check CloudWatch Logs for additional exfiltration beyond env key names

```bash
# Look for any HTTP calls, DNS lookups, or data written to external destinations
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --filter-pattern "ERROR" \
  --start-time $(( $(date -u +%s) - 604800 ))000 \
  --output json

# Check for any urllib, requests, boto3 calls to non-AWS endpoints in the log output
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --filter-pattern "http" \
  --start-time $(( $(date -u +%s) - 604800 ))000 \
  --output json
```

#### Step 6 — Verify function environment variables were not exfiltrated

```bash
# List the current env var KEYS (not values) to compare against what appeared in logs
aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query 'Environment.Variables' \
  --output json | jq 'keys'

# If any env vars contain secrets (DB passwords, API keys), rotate them now
# Cross-reference key names against what appeared in the ENV_KEYS CloudWatch log line
```

---

## 5. Recovery

### Restore Clean State

#### Step 1 — Re-enable the victim Lambda function's concurrency

```bash
# After confirming the known-good layer is in place
aws lambda delete-function-concurrency \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION"

# Confirm function is healthy
aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/invoke-response.json \
  && cat /tmp/invoke-response.json
```

#### Step 2 — Verify the restored layer is the expected known-good version

```bash
aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --query '{Layers:Layers, LastModified:LastModified, LastUpdateStatus:LastUpdateStatus}' \
  --output json
```

#### Step 3 — Confirm the LAYER_POISONED marker no longer appears in new invocations

```bash
# Invoke the function and check logs
aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --log-type Tail \
  /tmp/recovery-test.json \
  | jq -r '.LogResult' | base64 -d

# Also check CloudWatch directly for any new LAYER_POISONED occurrences
aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --filter-pattern "LAYER_POISONED" \
  --start-time $(( $(date -u +%s) - 300 ))000 \
  --output json
```

#### Step 4 — Enable Lambda data event logging if it was absent during the incident

```bash
TRAIL_NAME="$(aws cloudtrail describe-trails --query 'trailList[0].Name' --output text)"

aws cloudtrail put-event-selectors \
  --trail-name "$TRAIL_NAME" \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::Lambda::Function",
          "Values": ["arn:aws:lambda"]
        }
      ]
    }
  ]'
```

#### Step 5 — Harden the attacker role with a scoped permission boundary going forward

```bash
# Create a boundary policy that prevents Lambda layer publishing and function config changes
aws iam create-policy \
  --policy-name "lambda-layer-publish-boundary" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":[
        "lambda:PublishLayerVersion",
        "lambda:UpdateFunctionConfiguration",
        "lambda:AddLayerVersionPermission"
      ],
      "Resource":"*"
    }]
  }'

# Apply as permission boundary to restrict the role further
aws iam put-role-permissions-boundary \
  --role-name "$ATTACKER_ROLE" \
  --permissions-boundary "arn:aws:iam::<ACCOUNT_ID>:policy/lambda-layer-publish-boundary"
```

#### Step 6 — Tag the restored function and layer with a recovery audit marker

```bash
aws lambda tag-resource \
  --resource "arn:aws:lambda:$REGION:<ACCOUNT_ID>:function:$FUNCTION_NAME" \
  --tags "IncidentRestored=$(date -u +%Y-%m-%dT%H:%M:%SZ),RestoredLayer=$KNOWN_GOOD_LAYER_ARN"
```

---

## 6. Lessons Learned

### What would have prevented or limited this incident

| Gap | Guardrail |
|---|---|
| Attacker role had `lambda:PublishLayerVersion` + `lambda:UpdateFunctionConfiguration` — broad Lambda permissions | Apply least-privilege: CI/CD role gets these; all other roles are explicitly denied via SCP or permission boundary |
| `UpdateFunctionConfiguration` with a `Layers` change from an unexpected principal was not alerted on | Create a CloudWatch Events rule or EventBridge rule that triggers on `UpdateFunctionConfiguration` and compares `userIdentity.arn` against an allowed-deployers list |
| Lambda data events were not enabled — Invoke by attacker role was not captured | Enable Lambda data events in CloudTrail for all production functions (additional cost, but required for full Invoke attribution) |
| No SIEM rule for layer ARN owner mismatch | Parse `PublishLayerVersion` events and alert when the publisher ARN differs from the registered layer owner stored in CMDB |
| LAYER_POISONED marker in logs was not monitored | Deploy a CloudWatch Logs metric filter on `/aws/lambda/` log groups matching `LAYER_POISONED` and tie it to a CloudWatch Alarm → SNS |
| GuardDuty Lambda Protection may not have been enabled | Verify `aws guardduty get-detector` shows `lambdaNetworkLogs: ENABLED`; enable Lambda Protection feature if not already active |
| No tagging of layers with authoritative publisher identity | Enforce a `PublishedBy` tag via SCP on `lambda:PublishLayerVersion`; alert on layer versions missing this tag |
| No integrity check on layer contents before function update | Integrate layer hash verification into the CI/CD pipeline: compare SHA256 of layer zip at deploy time against a trusted baseline stored in SSM Parameter Store |

### Detection coverage summary

| Technique step | Covered without data events | Covered with data events |
|---|---|---|
| GetFunction reconnaissance | Yes (management event) | Yes |
| PublishLayerVersion (attacker publishes poisoned layer) | Yes (management event) | Yes |
| UpdateFunctionConfiguration (inject layer) | Yes (management event — PRIMARY IoC) | Yes |
| Lambda Invoke (trigger execution) | No | Yes |
| LAYER_POISONED in CloudWatch Logs | Yes (log filter independent of CloudTrail) | Yes |
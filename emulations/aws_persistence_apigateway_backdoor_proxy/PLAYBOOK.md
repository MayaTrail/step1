# IR Playbook: ATOMIC-apigateway-backdoor-proxy — AWS API Gateway Backdoor Route Injection

## Classification

| Field | Value |
|-------|-------|
| Incident Type | API Gateway Backdoor / Unauthorized Route Injection |
| Threat Actor | ATOMIC-apigateway-backdoor-proxy (technique emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Initial Access (TA0001), Discovery (TA0007), Persistence (TA0003), Defense Evasion (TA0005) |
| MITRE Technique | T1190 — Exploit Public-Facing Application |
| Primary Signal | PutMethod with authorizationType=NONE on a new API Gateway resource created outside CI/CD |

---

## 1. Preparation

### Pre-requisites for Effective Response

**Logging and Visibility**
- CloudTrail management events enabled in all regions (must capture `apigateway.amazonaws.com` and `lambda.amazonaws.com` events)
- CloudTrail S3 bucket with at least 90-day retention; log file integrity validation enabled
- AWS Config recorder enabled; rules for detecting unauthorized API Gateway deployments
- GuardDuty enabled with a current findings baseline

**Baselines Required**
- Approved CI/CD pipeline principal ARNs documented (the IAM roles/users that legitimately deploy API Gateway changes)
- Baseline snapshot of all API Gateway REST APIs: resources, methods, integrations, and authorization types per resource — exportable as Swagger/OpenAPI from the console or via `aws apigateway get-export`
- Lambda resource policies for all functions integrated with API Gateway — snapshot stored in SIEM or S3
- List of approved Lambda integrations per API ID (ARN → API ID mapping)

**Runbook Assumptions**
- Responder has `ReadOnlyAccess` + `cloudtrail:LookupEvents` + `apigateway:GET*` + `lambda:GetPolicy` + ability to call `aws sts assume-role` into a break-glass incident response role
- AWS CLI v2 configured with MFA-protected credentials; `AWS_DEFAULT_REGION` set
- `jq` available for JSON parsing

**Recommended Alerting (if not already in place)**
- Security Hub custom insight: `PutMethod` events where `requestParameters.authorizationType == "NONE"` from a non-pipeline principal
- EventBridge rule: API Gateway `CreateDeployment` not from an approved pipeline role ARN → SNS page

---

## 2. Identification

### Detection Triggers (Prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise or Requires Immediate Investigation

| Event | EventSource | Signal |
|-------|-------------|--------|
| `PutMethod` with `authorizationType=NONE` | `apigateway.amazonaws.com` | Unauthenticated route added to a production API |
| `CreateResource` on a live REST API by a non-pipeline principal | `apigateway.amazonaws.com` | New path injected outside deployment workflow |
| `PutIntegration` by a non-pipeline principal | `apigateway.amazonaws.com` | New Lambda or HTTP backend wired to a route outside deployment |
| `CreateDeployment` to `prod` stage by a non-pipeline principal | `apigateway.amazonaws.com` | Backdoor activated in production |
| `AddPermission20150331v2` on a Lambda not in integration baseline | `lambda.amazonaws.com` | Lambda resource policy modified outside deployment pipeline |
| `AssumeRole` for a DevOps/infrastructure role from a non-CI/CD principal | `sts.amazonaws.com` | Credential misuse or initial access pivot |

#### MEDIUM-CONFIDENCE — Investigate in Context

| Event | EventSource | Signal |
|-------|-------------|--------|
| `GetResources` on a production REST API by an unusual principal | `apigateway.amazonaws.com` | Attacker reconnaissance of existing API structure |
| `GetCallerIdentity` immediately after `AssumeRole` | `sts.amazonaws.com` | Session validity probe — common attacker pattern |
| `DeleteResource` on a REST API by a non-pipeline principal | `apigateway.amazonaws.com` | Could be cleanup/defense evasion after backdoor use |
| `RemovePermission` on a Lambda | `lambda.amazonaws.com` | Cleanup of injected resource policy — defense evasion |
| Rapid sequence of `CreateResource → PutMethod → PutIntegration → CreateDeployment` within minutes | `apigateway.amazonaws.com` | GuardDuty anomalous call pattern; matches this TTPs sequence exactly |

---

### Key Investigation Queries

#### Step 0 — Establish Time Window and Suspect Principal

```bash
# Look up recent API Gateway write events in the last 24 hours
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=apigateway.amazonaws.com \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?contains(`["CreateResource","PutMethod","PutIntegration","CreateDeployment","DeleteResource"]`, EventName)].[EventTime,EventName,Username,CloudTrailEvent]' \
  --output table
```

```bash
# Look up Lambda permission changes in the same window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=lambda.amazonaws.com \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?EventName==`AddPermission20150331v2` || EventName==`RemovePermission20150331v2`].[EventTime,EventName,Username,CloudTrailEvent]' \
  --output table
```

#### Step 1 — Identify the Assuming Principal and Source IP

```bash
# Find all AssumeRole calls in the last 24 hours; look for non-pipeline principals assuming infrastructure roles
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].[EventTime, Username, CloudTrailEvent]' \
  --output text | grep -i "devops\|apigateway\|infra\|pipeline"
```

```bash
# Decode the specific AssumeRole event to get source IP, MFA status, and role ARN
# Replace EVENT_ID with the relevant CloudTrail event ID
aws cloudtrail get-event \
  --event-id EVENT_ID \
  --query 'Event.CloudTrailEvent' --output text | jq '{
    eventTime,
    userAgent,
    sourceIPAddress,
    userIdentity,
    requestParameters: .requestParameters.roleArn,
    responseElements: .responseElements.assumedRoleUser
  }'
```

#### Step 2 — Reconstruct the Attack Sequence on the Victim API

```bash
# Set the API ID from your API Gateway console or discovery step below
VICTIM_API_ID=$(aws apigateway get-rest-apis \
  --query 'items[?name!=`null`].[id,name]' \
  --output text | grep -i "victim\|prod\|app" | awk '{print $1}')

echo "Victim API ID: $VICTIM_API_ID"
```

```bash
# Enumerate current resources — compare against baseline to find injected routes
aws apigateway get-resources \
  --rest-api-id "$VICTIM_API_ID" \
  --query 'items[*].{id:id,path:path,methods:keys(resourceMethods)}' \
  --output table
```

```bash
# Check for any resource with no authorization on its methods (the PutMethod NONE signal)
aws apigateway get-resources \
  --rest-api-id "$VICTIM_API_ID" \
  --embed methods \
  --query 'items[*].{path:path,methods:resourceMethods}' \
  --output json | jq '
    .[] | select(.methods != null) |
    .path as $path |
    .methods | to_entries[] |
    select(.value.authorizationType == "NONE") |
    {path: $path, httpMethod: .key, authorizationType: .value.authorizationType}
  '
```

```bash
# For each suspicious resource, check integration target (look for non-baseline Lambda ARNs)
SUSPECT_RESOURCE_ID="<resource_id_from_above>"
aws apigateway get-integration \
  --rest-api-id "$VICTIM_API_ID" \
  --resource-id "$SUSPECT_RESOURCE_ID" \
  --http-method GET \
  --query '{type:type,uri:uri,integrationHttpMethod:httpMethod}'
```

#### Step 3 — Investigate the Backdoor Lambda

```bash
# Get the Lambda resource policy — look for statements added by a non-deployment principal
# Replace BACKDOOR_LAMBDA with the function name extracted from the integration URI
BACKDOOR_LAMBDA="internal-health-check"

aws lambda get-policy \
  --function-name "$BACKDOOR_LAMBDA" \
  --query 'Policy' --output text | jq '.Statement[] | {
    Sid,
    Effect,
    Principal,
    Action,
    Resource,
    Condition
  }'
```

```bash
# Check Lambda configuration for any unusual env vars, layers, or VPC config
aws lambda get-function-configuration \
  --function-name "$BACKDOOR_LAMBDA" \
  --query '{
    FunctionName: FunctionName,
    Runtime: Runtime,
    Handler: Handler,
    Role: Role,
    LastModified: LastModified,
    Environment: Environment,
    Layers: Layers,
    VpcConfig: VpcConfig
  }'
```

```bash
# Review recent Lambda invocations via CloudWatch Logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/$BACKDOOR_LAMBDA" \
  --start-time $(date -d '24 hours ago' +%s000) \
  --query 'events[*].{timestamp:timestamp,message:message}' \
  --output table
```

#### Step 4 — Check API Gateway Deployment History

```bash
# List deployments on the prod stage to see when unauthorized CreateDeployment fired
aws apigateway get-deployments \
  --rest-api-id "$VICTIM_API_ID" \
  --query 'items[*].{id:id,createdDate:createdDate,description:description}' \
  --output table
```

```bash
# Get stage variables and active deployment ID for the prod stage
aws apigateway get-stage \
  --rest-api-id "$VICTIM_API_ID" \
  --stage-name prod \
  --query '{deploymentId:deploymentId,lastUpdatedDate:lastUpdatedDate,stageName:stageName,accessLogSettings:accessLogSettings}'
```

#### Step 5 — Scope the Blast Radius (Additional APIs)

```bash
# Check whether the same principal hit other APIs
SUSPECT_PRINCIPAL="arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/SESSION_NAME"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$SUSPECT_PRINCIPAL" \
  --start-time $(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].[EventTime,EventName,EventSource,CloudTrailEvent]' \
  --output table
```

---

## 3. Containment

### Immediate Actions — First 15 Minutes

#### 3.1 — Revoke the Compromised Session

```bash
# Identify the assumed role session name from CloudTrail; deny all sessions for that role immediately
COMPROMISED_ROLE_NAME="<role-name-from-cloudtrail>"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Attach an inline deny policy to the IAM role to immediately invalidate all existing sessions
aws iam put-role-policy \
  --role-name "$COMPROMISED_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL-$(date +%Y%m%d%H%M%S)" \
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

```bash
# Verify the inline policy was applied
aws iam get-role-policy \
  --role-name "$COMPROMISED_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL-$(date +%Y%m%d%H%M%S)"
```

#### 3.2 — Remove the Backdoor Route (If Still Present)

```bash
# Check whether the backdoor resource still exists
aws apigateway get-resources \
  --rest-api-id "$VICTIM_API_ID" \
  --query 'items[?path==`/health-check-v2`].{id:id,path:path}' \
  --output table
```

```bash
# If present, delete the backdoor resource (cascades to methods and integrations)
BACKDOOR_RESOURCE_ID="<resource_id_of_health-check-v2>"

aws apigateway delete-resource \
  --rest-api-id "$VICTIM_API_ID" \
  --resource-id "$BACKDOOR_RESOURCE_ID"
```

```bash
# Redeploy prod stage to make the deletion live
aws apigateway create-deployment \
  --rest-api-id "$VICTIM_API_ID" \
  --stage-name prod \
  --description "IR containment: remove backdoor route $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

#### 3.3 — Revoke Backdoor Lambda Resource Policy Statement

```bash
# Remove the unauthorized resource policy statement from the backdoor Lambda
# Statement SID is typically set by the attacker; discover it first
aws lambda get-policy \
  --function-name "$BACKDOOR_LAMBDA" \
  --query 'Policy' --output text | jq -r '.Statement[].Sid'
```

```bash
# Remove the specific statement (replace SID with value from above)
POLICY_SID="<statement-sid-from-above>"

aws lambda remove-permission \
  --function-name "$BACKDOOR_LAMBDA" \
  --statement-id "$POLICY_SID"
```

```bash
# Confirm policy is clean
aws lambda get-policy \
  --function-name "$BACKDOOR_LAMBDA" \
  --query 'Policy' --output text | jq '.Statement | length'
```

#### 3.4 — Lock Down the Compromised IAM Role

```bash
# Remove excessive API Gateway permissions from the role's inline/managed policies
# First: review current permissions
aws iam list-role-policies --role-name "$COMPROMISED_ROLE_NAME"
aws iam list-attached-role-policies --role-name "$COMPROMISED_ROLE_NAME"
```

```bash
# If the role was over-permissioned on apigateway:* — remove or restrict the policy
# Option A: Remove the specific inline policy granting apigateway:*
aws iam delete-role-policy \
  --role-name "$COMPROMISED_ROLE_NAME" \
  --policy-name "<over-permissioned-policy-name>"
```

```bash
# Option B: Detach the managed policy (if using a managed policy)
aws iam detach-role-policy \
  --role-name "$COMPROMISED_ROLE_NAME" \
  --policy-arn "arn:aws:iam::$ACCOUNT_ID:policy/<policy-name>"
```

#### 3.5 — Verify the prod Stage is Clean

```bash
# Confirm only expected routes remain after containment
aws apigateway get-resources \
  --rest-api-id "$VICTIM_API_ID" \
  --embed methods \
  --query 'items[*].{path:path,methods:keys(resourceMethods)}' \
  --output table
```

```bash
# Export current API definition as Swagger for audit trail
aws apigateway get-export \
  --rest-api-id "$VICTIM_API_ID" \
  --stage-name prod \
  --export-type swagger \
  --accepts application/json \
  --query 'body' \
  --output text > /tmp/api-post-containment-$(date +%Y%m%d%H%M%S).json
```

---

## 4. Eradication

### Remove All Attacker Artifacts

#### 4.1 — Audit All API Gateway APIs for Additional Backdoors

```bash
# Get all REST API IDs in the account for this region
aws apigateway get-rest-apis \
  --query 'items[*].{id:id,name:name,createdDate:createdDate}' \
  --output table
```

```bash
# For each API, check for any method with authorizationType=NONE on non-root resources
for API_ID in $(aws apigateway get-rest-apis --query 'items[*].id' --output text); do
  echo "=== Checking API: $API_ID ==="
  aws apigateway get-resources \
    --rest-api-id "$API_ID" \
    --embed methods \
    --query 'items[?path!=`/`].{path:path,methods:resourceMethods}' \
    --output json 2>/dev/null | jq --arg api "$API_ID" '
      .[] | select(.methods != null) |
      .path as $path |
      .methods | to_entries[] |
      select(.value.authorizationType == "NONE") |
      {api: $api, path: $path, httpMethod: .key}
    '
done
```

#### 4.2 — Audit All Lambda Resource Policies for Unauthorized Statements

```bash
# List all Lambda functions and check resource policies for API Gateway invoke grants
# added by non-deployment principals
for FN in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  POLICY=$(aws lambda get-policy --function-name "$FN" --query 'Policy' --output text 2>/dev/null)
  if [ -n "$POLICY" ]; then
    SUSPICIOUS=$(echo "$POLICY" | jq -r '.Statement[] | select(.Principal.Service == "apigateway.amazonaws.com") | .Sid')
    if [ -n "$SUSPICIOUS" ]; then
      echo "Lambda $FN has API Gateway invoke policy SIDs: $SUSPICIOUS"
    fi
  fi
done
```

#### 4.3 — Remove the Emergency Deny Policy After Role Remediation

```bash
# Only after the role's excessive permissions have been scoped down:
aws iam delete-role-policy \
  --role-name "$COMPROMISED_ROLE_NAME" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL-<timestamp>"
```

#### 4.4 — Rotate Credentials If Source Credentials Were Long-Term Keys

```bash
# If the initial AssumeRole was made with long-term IAM access keys (not a role session),
# identify the access key from CloudTrail userIdentity.accessKeyId and deactivate it
COMPROMISED_KEY_ID="<access-key-id-from-cloudtrail>"
COMPROMISED_USER="<iam-username>"

aws iam update-access-key \
  --user-name "$COMPROMISED_USER" \
  --access-key-id "$COMPROMISED_KEY_ID" \
  --status Inactive
```

```bash
# Then rotate: create a new key, distribute to legitimate owner, delete the compromised one
aws iam create-access-key --user-name "$COMPROMISED_USER"
# (securely deliver new key to the legitimate user)
aws iam delete-access-key \
  --user-name "$COMPROMISED_USER" \
  --access-key-id "$COMPROMISED_KEY_ID"
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Verify API Definition Matches Approved Baseline

```bash
# Export current prod stage API definition
aws apigateway get-export \
  --rest-api-id "$VICTIM_API_ID" \
  --stage-name prod \
  --export-type swagger \
  --accepts application/json \
  --query 'body' \
  --output text > /tmp/api-recovery-state.json

# Diff against the last approved deployment export stored in your artifact repository
# diff /path/to/approved-baseline.json /tmp/api-recovery-state.json
```

#### 5.2 — Re-enable GuardDuty and Verify Findings

```bash
# Confirm GuardDuty detector is active
aws guardduty list-detectors --query 'DetectorIds' --output text | \
  xargs -I{} aws guardduty get-detector --detector-id {} \
  --query '{DetectorId:DetectorId,Status:Status,UpdatedAt:UpdatedAt}'
```

```bash
# List any findings from the incident window
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "GreaterThanOrEqual": '"$(date -d '48 hours ago' +%s000)"'
      }
    }
  }' \
  --query 'FindingIds' --output text | \
  xargs aws guardduty get-findings \
    --detector-id "$DETECTOR_ID" \
    --finding-ids \
  --query 'Findings[*].{Type:Type,Severity:Severity,Title:Title,UpdatedAt:UpdatedAt}' \
  --output table
```

#### 5.3 — Verify AWS Config Compliance

```bash
# Run a compliance evaluation for API Gateway-related Config rules
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT \
  --query 'ComplianceByConfigRules[?contains(ConfigRuleName, `apigateway`) || contains(ConfigRuleName, `lambda`)].{Rule:ConfigRuleName,Compliance:Compliance.ComplianceType}' \
  --output table
```

#### 5.4 — Enforce Least-Privilege on the DevOps Role

```bash
# Replace the apigateway:* wildcard with scoped actions and explicit resource constraints
# Generate a policy with least-privilege using IAM Access Analyzer (if available)
aws accessanalyzer validate-policy \
  --policy-type IDENTITY_POLICY \
  --policy-document file://proposed-scoped-policy.json \
  --query 'findings[*].{findingType:findingType,message:findingDetails}' \
  --output table
```

#### 5.5 — Re-deploy from Source of Truth (CI/CD)

```bash
# Trigger a clean deployment from the approved pipeline to re-establish the known-good state
# (Commands are pipeline-specific — use your CodePipeline, Jenkins, or GitHub Actions trigger)

# If using CodePipeline:
aws codepipeline start-pipeline-execution \
  --name "<your-pipeline-name>" \
  --query 'pipelineExecutionId'
```

```bash
# Monitor the pipeline execution until success
aws codepipeline get-pipeline-execution \
  --pipeline-name "<your-pipeline-name>" \
  --pipeline-execution-id "<execution-id>" \
  --query 'pipelineExecution.status'
```

---

## 6. Lessons Learned

### Root Causes and Guardrails

| Finding | Remediation |
|---------|-------------|
| DevOps IAM role had `apigateway:*` scoped to API ARN prefix, enabling full resource/method management | Replace with scoped actions: `apigateway:GET*` for operations, restrict write actions (`CreateResource`, `PutMethod`, `PutIntegration`, `CreateDeployment`) to pipeline execution role only |
| DevOps role had `lambda:AddPermission` / `lambda:RemovePermission` — allows modifying resource policies on arbitrary Lambdas | Restrict to `lambda:InvokeFunction` for the specific Lambda ARNs required; remove permission management rights from human-assumable roles |
| No detection for `PutMethod` with `authorizationType=NONE` on existing production APIs | Add Security Hub custom insight or EventBridge rule: `apigateway.amazonaws.com` source + `PutMethod` + `requestParameters.authorizationType == "NONE"` → page on-call |
| No baseline comparison for API Gateway deployments to prod | Store `aws apigateway get-export` output as an artifact on each successful CI/CD pipeline run; compare in post-deployment lint step |
| `CreateDeployment` to a production stage not gated to pipeline role only | Add an SCP (if using AWS Organizations) or permission boundary restricting `apigateway:CreateDeployment` to the CI/CD pipeline role ARN |
| GuardDuty did not alert on the rapid `CreateResource → PutMethod → PutIntegration → CreateDeployment` sequence | Enable GuardDuty API call anomaly detection; add a custom CloudWatch metric filter for this 4-event sequence within a 5-minute window from the same principal |
| No Lambda resource policy change alerting | EventBridge rule: `lambda.amazonaws.com` source + `AddPermission20150331v2` event by a non-pipeline principal → immediate alert |

### Detection Engineering Artifacts

**EventBridge Rule — Unauthenticated API Gateway Route Added**
```json
{
  "source": ["aws.apigateway"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["PutMethod"],
    "requestParameters": {
      "authorizationType": ["NONE"]
    }
  }
}
```

**CloudWatch Metric Filter — Backdoor Deployment Sequence**
```
{ ($.eventSource = "apigateway.amazonaws.com") && ($.eventName = "CreateResource" || $.eventName = "PutMethod" || $.eventName = "PutIntegration" || $.eventName = "CreateDeployment") }
```
Alert threshold: 4 events within 300 seconds from the same `userIdentity.arn`.

**SCP — Restrict API Gateway Deployments to Pipeline Role**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAPIGatewayDeploymentOutsidePipeline",
    "Effect": "Deny",
    "Action": [
      "apigateway:CreateDeployment",
      "apigateway:CreateResource",
      "apigateway:PutMethod",
      "apigateway:PutIntegration"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotLike": {
        "aws:PrincipalArn": [
          "arn:aws:iam::*:role/cicd-deploy-role",
          "arn:aws:iam::*:role/ir-breakglass-role"
        ]
      }
    }
  }]
}
```
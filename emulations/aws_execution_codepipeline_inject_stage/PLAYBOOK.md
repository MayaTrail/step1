# IR Playbook: ATOMIC-codepipeline-inject-stage — AWS CodePipeline Supply Chain Compromise

## Classification
| Field | Value |
|-------|-------|
| Incident Type | Supply Chain Compromise — CI/CD Pipeline Stage Injection |
| Threat Actor | ATOMIC-codepipeline-inject-stage (technique emulation; real-world analogue: UNC3944, Scattered Spider CI/CD abuse) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Initial Access |
| MITRE Techniques | T1195 — Supply Chain Compromise |
| Key AWS Services | AWS CodePipeline, AWS STS, AWS IAM, AWS CloudTrail, AWS CodeBuild, AWS Secrets Manager |

---

## 1. Preparation
**What should be in place before this incident.**

| Control | Implementation |
|---------|---------------|
| CloudTrail data events | Enable management + data events in all regions; centralize to immutable S3 bucket with Object Lock |
| EventBridge rule | Alert on `codepipeline.amazonaws.com` `UpdatePipeline` events from non-pipeline-service principals |
| IAM least-privilege for CICD roles | CICD service account roles should have `sts:AssumeRole` blocked from human admin principals in trust policy |
| CodePipeline change detection | AWS Config rule `codepipeline-deployment-count-check`; Security Hub FSBP CodePipeline controls |
| Secrets Manager canary | `prod/database/master_credentials` should be a canary secret with GuardDuty monitored access |
| SIEM alerting | Pre-built detection for `UpdatePipeline` calls where `userIdentity.type` != `Service` and `userIdentity.invokedBy` != `codepipeline.amazonaws.com` |
| Pipeline definition baseline | Store hashed pipeline definitions in S3 or Config; diff alerts on stage count changes |
| Incident response runbook | This playbook, tested quarterly via purple team exercise |

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — Any of these alone indicates active attack or compromise:**

| Audit Event | eventSource | Condition that makes it HIGH-confidence |
|-------------|-------------|----------------------------------------|
| `AssumeRole` | `sts.amazonaws.com` | `requestParameters.roleArn` contains a CICD service account role AND `userIdentity.type` = `IAMUser` or `AssumedRole` (not CodePipeline service) |
| `UpdatePipeline` | `codepipeline.amazonaws.com` | `userIdentity.sessionContext.sessionIssuer.userName` matches CICD victim role AND calling identity is NOT `codepipeline.amazonaws.com` |
| `UpdatePipeline` | `codepipeline.amazonaws.com` | Stage count increases then decreases within a short window (injection + restoration pattern) |
| `GetPipeline` | `codepipeline.amazonaws.com` | Called by an assumed-role session from a non-pipeline principal, especially at off-hours |

**MEDIUM-CONFIDENCE — Require correlation or additional context:**

| Audit Event | eventSource | Why Medium |
|-------------|-------------|------------|
| `GetCallerIdentity` | `sts.amazonaws.com` | Common recon step; elevated signal when preceded by `AssumeRole` into CICD role |
| `GetSecretValue` on canary secret | `secretsmanager.amazonaws.com` | Only HIGH if called from CodeBuild session associated with injected stage |
| `StartPipelineExecution` | `codepipeline.amazonaws.com` | Could be legitimate; HIGH only if triggered immediately after `UpdatePipeline` with stage injection |

---

### Key Investigation Queries

**Step 1 — Find all `AssumeRole` calls into CICD service account roles (last 90 days):**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query "Events[?contains(CloudTrailEvent, 'codepipeline')].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | {time: .[0], user: .[1], event: (.[2] | fromjson | {roleArn: .requestParameters.roleArn, sessionName: .requestParameters.roleSessionName, sourceIP: .sourceIPAddress, userAgent: .userAgent})}'
```

**Step 2 — Find all `UpdatePipeline` events NOT from the CodePipeline service itself:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdatePipeline \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query "Events[].[EventTime,Username,CloudTrailEvent]" \
  --output json | jq '.[] | select((.[2] | fromjson | .userIdentity.invokedBy) != "codepipeline.amazonaws.com") | {time: .[0], user: .[1], event: (.[2] | fromjson | {pipeline: .requestParameters.pipeline.name, stageCount: (.requestParameters.pipeline.stages | length), sourceIP: .sourceIPAddress, sessionIssuer: .userIdentity.sessionContext.sessionIssuer.userName})}'
```

**Step 3 — Enumerate all `GetPipeline` calls from non-service principals:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetPipeline \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, detail: (.CloudTrailEvent | fromjson | {pipeline: .requestParameters.name, userType: .userIdentity.type, arn: .userIdentity.arn, sourceIP: .sourceIPAddress})}'
```

**Step 4 — Reconstruct the attack session from a known compromised role ARN:**
```bash
# Replace <VICTIM_ROLE_NAME> with actual role name (e.g., codepipeline-inject-stage-victim-role)
VICTIM_ROLE="<VICTIM_ROLE_NAME>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$VICTIM_ROLE" \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events | sort_by(.EventTime) | .[] | {time: .EventTime, event: .EventName, detail: (.CloudTrailEvent | fromjson | {sourceIP: .sourceIPAddress, userAgent: .userAgent, sessionName: .userIdentity.sessionContext.sessionIssuer.userName})}'
```

**Step 5 — Check if the injected pipeline executed (CodeBuild ran the AttackerStage):**
```bash
# Find CodeBuild build history for any builds that ran with an anomalous trigger context
aws codebuild list-builds-for-project \
  --project-name <CODEBUILID_PROJECT_NAME> \
  --sort-order DESCENDING \
  --query 'ids[:20]' \
  --output json | xargs -I{} aws codebuild batch-get-builds --ids {} \
  --query 'builds[] | {id: id, startTime: startTime, initiator: initiator, source: source.location, buildStatus: buildStatus}'
```

**Step 6 — Check current pipeline definition for any residual injected stages:**
```bash
aws codepipeline get-pipeline \
  --name <PIPELINE_NAME> \
  --query 'pipeline.stages[*].{name: name, actionCount: length(actions)}' \
  --output table
```

**Step 7 — Audit who can assume the CICD victim role (trust policy review):**
```bash
aws iam get-role \
  --role-name <VICTIM_ROLE_NAME> \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json | jq .
```

**Step 8 — Check Secrets Manager access logs for canary secret:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, detail: (.CloudTrailEvent | fromjson | {secretId: .requestParameters.secretId, sourceIP: .sourceIPAddress, arn: .userIdentity.arn})} | select(.detail.secretId | test("prod/database/master_credentials"; "i"))'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Action 1 — Revoke all active sessions from the compromised CICD role (deny-all inline policy):**
```bash
# Attach a deny-all policy to immediately invalidate all existing sessions
aws iam put-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name EMERGENCY-REVOKE-ALL-SESSIONS \
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

**Action 2 — Lock down the CICD role trust policy to block human principal assumption:**
```bash
# Replace account root trust with explicit CodePipeline service-only trust
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws iam update-assume-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "codepipeline.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

**Action 3 — Snapshot and verify current pipeline state (determine if AttackerStage persists):**
```bash
# Capture pipeline snapshot for forensic record
aws codepipeline get-pipeline \
  --name <PIPELINE_NAME> \
  --output json > pipeline-forensic-snapshot-$(date +%Y%m%d-%H%M%S).json

# Count stages and list their names
aws codepipeline get-pipeline \
  --name <PIPELINE_NAME> \
  --query 'pipeline.stages[*].name' \
  --output table
```

**Action 4 — Stop any in-flight pipeline executions:**
```bash
# List running executions
aws codepipeline list-pipeline-executions \
  --pipeline-name <PIPELINE_NAME> \
  --query "pipelineExecutionSummaries[?status=='InProgress'].[pipelineExecutionId]" \
  --output text | while read exec_id; do
    echo "Stopping execution: $exec_id"
    aws codepipeline stop-pipeline-execution \
      --pipeline-name <PIPELINE_NAME> \
      --pipeline-execution-id "$exec_id" \
      --abandon \
      --reason "SECURITY INCIDENT - Potential supply chain compromise, stopping all in-progress executions"
done
```

**Action 5 — Disable the pipeline to prevent execution during investigation:**
```bash
# Disable the source trigger to prevent auto-execution
aws codepipeline disable-stage-transition \
  --pipeline-name <PIPELINE_NAME> \
  --stage-name Source \
  --transition-type Inbound \
  --reason "SECURITY HOLD: Pipeline under investigation for stage injection (IR-$(date +%Y%m%d))"
```

**Action 6 — Identify the admin user who triggered the AssumeRole and assess scope of compromise:**
```bash
# Find which admin principal assumed the CICD role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | (.CloudTrailEvent | fromjson) | select(.requestParameters.roleArn | test("<VICTIM_ROLE_NAME>")) | {time: .eventTime, callerArn: .userIdentity.arn, sourceIP: .sourceIPAddress, userAgent: .userAgent}'
```

**Action 7 — If the originating admin user is compromised, deactivate their access key:**
```bash
# Identify and disable the access key used in the attack
COMPROMISED_USER="<ADMIN_USERNAME>"
aws iam list-access-keys --user-name "$COMPROMISED_USER" \
  --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' \
  --output table

# Deactivate the suspected compromised key
aws iam update-access-key \
  --user-name "$COMPROMISED_USER" \
  --access-key-id <COMPROMISED_KEY_ID> \
  --status Inactive
```

---

## 4. Eradication

### Remove Attacker Access

**Step 1 — Remove the injected stage if still present in pipeline definition:**
```bash
# Export current pipeline
aws codepipeline get-pipeline --name <PIPELINE_NAME> --output json > /tmp/pipeline-current.json

# Manually edit to remove AttackerStage (or use jq):
cat /tmp/pipeline-current.json | jq 'del(.metadata) | .pipeline.stages |= map(select(.name != "AttackerStage"))' > /tmp/pipeline-clean.json

# Verify stage count and names before applying
jq '.pipeline.stages[*].name' /tmp/pipeline-clean.json

# Apply clean pipeline definition
aws codepipeline update-pipeline --cli-input-json file:///tmp/pipeline-clean.json
```

**Step 2 — Remove the emergency deny-all policy (after trust policy is hardened):**
```bash
aws iam delete-role-policy \
  --role-name <VICTIM_ROLE_NAME> \
  --policy-name EMERGENCY-REVOKE-ALL-SESSIONS
```

**Step 3 — Rotate all credentials associated with the compromised admin user:**
```bash
COMPROMISED_USER="<ADMIN_USERNAME>"

# Delete compromised access keys
aws iam list-access-keys --user-name "$COMPROMISED_USER" \
  --query 'AccessKeyMetadata[*].AccessKeyId' --output text | \
  xargs -n1 -I{} aws iam delete-access-key --user-name "$COMPROMISED_USER" --access-key-id {}

# Force password reset
aws iam update-login-profile \
  --user-name "$COMPROMISED_USER" \
  --password-reset-required

# Revoke all MFA sessions
aws iam deactivate-mfa-device \
  --user-name "$COMPROMISED_USER" \
  --serial-number $(aws iam list-mfa-devices --user-name "$COMPROMISED_USER" \
    --query 'MFADevices[0].SerialNumber' --output text)
```

**Step 4 — Audit and tighten CodeBuild project IAM role to remove over-permissioned Secrets Manager access:**
```bash
# Find the CodeBuild service role
PROJECT_NAME="<CODEBUILID_PROJECT_NAME>"
CB_ROLE=$(aws codebuild batch-get-projects --names "$PROJECT_NAME" \
  --query 'projects[0].serviceRole' --output text)

# List policies attached to the CodeBuild role
aws iam list-attached-role-policies --role-name "$(basename $CB_ROLE)" --output table
aws iam list-role-policies --role-name "$(basename $CB_ROLE)" --output table

# Review and remove secretsmanager:GetSecretValue if not required by legitimate builds
# Example: remove an inline policy granting access to canary secret
aws iam delete-role-policy \
  --role-name "$(basename $CB_ROLE)" \
  --policy-name <POLICY_GRANTING_SECRETS_ACCESS>
```

**Step 5 — Rotate the canary secret to invalidate any value that may have been read:**
```bash
aws secretsmanager rotate-secret \
  --secret-id prod/database/master_credentials \
  --force-delete-without-recovery
```

**Step 6 — Audit all other pipelines for similar stage injections:**
```bash
# List all pipelines in the account
aws codepipeline list-pipelines --query 'pipelines[*].name' --output text | \
  tr '\t' '\n' | while read pipeline; do
    echo "=== $pipeline ==="
    aws codepipeline get-pipeline --name "$pipeline" \
      --query 'pipeline.stages[*].{name: name, provider: actions[0].actionTypeId.provider}' \
      --output table
done
```

---

## 5. Recovery

### Restore Clean State

**Step 1 — Re-enable pipeline transitions after verification:**
```bash
aws codepipeline enable-stage-transition \
  --pipeline-name <PIPELINE_NAME> \
  --stage-name Source \
  --transition-type Inbound
```

**Step 2 — Validate pipeline definition matches pre-attack baseline:**
```bash
# Compare current pipeline against known-good baseline (stored in S3 or Config)
aws codepipeline get-pipeline --name <PIPELINE_NAME> \
  | jq 'del(.metadata) | .pipeline.stages[*].name'

# Cross-check with AWS Config recorded pipeline state
aws configservice get-resource-config-history \
  --resource-type AWS::CodePipeline::Pipeline \
  --resource-id <PIPELINE_NAME> \
  --limit 5 \
  --query 'configurationItems[*].{captureTime: configurationItemCaptureTime, status: configurationItemStatus}' \
  --output table
```

**Step 3 — Re-run a clean pipeline execution to validate build integrity:**
```bash
aws codepipeline start-pipeline-execution \
  --name <PIPELINE_NAME> \
  --query 'pipelineExecutionId'

# Monitor execution progress
aws codepipeline list-pipeline-executions \
  --pipeline-name <PIPELINE_NAME> \
  --query 'pipelineExecutionSummaries[0].{status: status, startTime: startTime, execId: pipelineExecutionId}' \
  --output table
```

**Step 4 — Re-issue credentials for the admin user under controlled conditions:**
```bash
COMPROMISED_USER="<ADMIN_USERNAME>"

# Create new access key (share via secure channel only)
aws iam create-access-key --user-name "$COMPROMISED_USER" \
  --query 'AccessKey.{KeyId: AccessKeyId, Secret: SecretAccessKey}'

# Re-enroll MFA
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name "${COMPROMISED_USER}-recovery-mfa" \
  --outfile /tmp/mfa-qr.png \
  --bootstrap-method QRCodePNG
```

**Step 5 — Verify GuardDuty findings generated by the attack were reviewed and closed:**
```bash
# List GuardDuty findings related to the incident timeframe
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "GreaterThanOrEqual": '"$(date -d '7 days ago' +%s000)"'
      },
      "service.action.awsApiCallAction.serviceName": {
        "Eq": ["codepipeline.amazonaws.com", "sts.amazonaws.com"]
      }
    }
  }' \
  --output json | jq '.FindingIds[]'
```

**Step 6 — Enable enhanced monitoring going forward:**
```bash
# Create EventBridge rule to alert on future UpdatePipeline from non-service principals
aws events put-rule \
  --name "DetectCodePipelineStageInjection" \
  --event-pattern '{
    "source": ["aws.codepipeline"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["codepipeline.amazonaws.com"],
      "eventName": ["UpdatePipeline"],
      "userIdentity": {
        "type": ["IAMUser", "AssumedRole"]
      }
    }
  }' \
  --state ENABLED \
  --description "Alert when UpdatePipeline is called by human identity (not CodePipeline service)"
```

---

## 6. Lessons Learned

### Root Cause
The CICD service account role (`codepipeline-inject-stage-victim-role`) had a trust policy allowing `sts:AssumeRole` from the account root principal (`arn:aws:iam::<ACCOUNT_ID>:root`), meaning any admin-level user in the account could impersonate the CICD service identity and make CodePipeline API calls as if they were the pipeline service.

### What Would Have Prevented This

| Guardrail | Preventive Value |
|-----------|-----------------|
| **CICD role trust policy: service-only** | Trust `codepipeline.amazonaws.com` exclusively; use `aws:SourceArn` condition to pin to specific pipeline ARN |
| **SCP: Deny `sts:AssumeRole` on CICD roles from human principals** | Block admin-level assumption at the org level: `Deny sts:AssumeRole where aws:PrincipalTag/Role != cicd-service` |
| **CodePipeline mutation alert (EventBridge)** | Real-time alert on `UpdatePipeline` from any non-service caller; <5 min detection |
| **Pipeline definition checksumming (AWS Config)** | Config rule that diffs stage count/names on every `UpdatePipeline`; auto-remediation option |
| **CodeBuild role least-privilege** | `secretsmanager:GetSecretValue` on canary secret should not be reachable from a build project used in developer pipelines |
| **Canary secret GuardDuty monitoring** | `prod/database/master_credentials` should trigger GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` on anomalous access |
| **MFA for admin IAM users** | Reduces initial admin credential compromise blast radius |

### Key Forensic Artifacts to Preserve
- CloudTrail events for `AssumeRole`, `GetCallerIdentity`, `GetPipeline`, `UpdatePipeline` from the incident window (export to S3)
- Pipeline definition snapshot at time of injection (`GetPipeline` response)
- CodeBuild build logs for any builds that executed during the `AttackerStage` window
- VPC flow logs and source IP for the attack session

### Attacker Tradecraft Notes
The attack used a **double `UpdatePipeline`** pattern — injection followed immediately by restoration — to minimize dwell time of the malicious stage in the pipeline definition. Defenders should alert on **stage count changes that revert within a short window** (e.g., within 10 minutes), not just on net additions. The restoration event does not erase the `GetPipeline` + first `UpdatePipeline` evidence from CloudTrail.
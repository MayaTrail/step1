# IR Playbook: ATOMIC-sqs-open-queue-policy — AWS SQS

## Classification
| Field | Value |
|-------|-------|
| Incident Type | SQS Resource Policy Manipulation — Public Queue Exposure |
| Threat Actor | ATOMIC-sqs-open-queue-policy |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 — Account Manipulation |
| Detection Sources | CloudTrail management events, CloudWatch Logs |

---

## 1. Preparation

### Prerequisites
- CloudTrail management events enabled in all regions with S3 delivery and CloudWatch Logs integration
- AWS Config rule `sqs-queue-publicly-accessible` (or equivalent) enabled
- GuardDuty enabled — detects `Policy:S3/BucketPublicAccessGranted` pattern (analogous SQS alerts if SQS protection enabled)
- EventBridge rule alerting on `sqs:SetQueueAttributes` events where policy contains `"Principal": "*"`
- IAM least-privilege enforced — victim role should not have `sqs:SetQueueAttributes` in production
- Runbook access to Pulumi stack outputs for victim credential identification
- On-call access to the AWS account with `sqs:SetQueueAttributes`, `sqs:GetQueueAttributes`, `iam:DeleteAccessKey`, `iam:GetAccessKeyLastUsed`

### Key Assets to Protect
- SQS queue: `orders-ingest-prod` and any other queues with business-critical data
- IAM credentials surfaced as Pulumi stack outputs (victim_access_key_id, victim_secret_access_key)

---

## 2. Identification

### Detection Triggers (prioritized)

**HIGH-CONFIDENCE — always indicates compromise or attempted policy manipulation:**

| Audit Event | eventSource | Why High-Confidence |
|---|---|---|
| `SetQueueAttributes` with `Policy` containing `"Principal":"*"` | `sqs.amazonaws.com` | Wildcard principal on a resource policy grants public access — no legitimate use case in production |
| `SetQueueAttributes` from an unexpected IAM principal (e.g., a seeded/victim key) | `sqs.amazonaws.com` | Credential misuse; victim identity should not modify queue policies |
| `ListQueues` followed by `GetQueueAttributes` followed by `SetQueueAttributes` in rapid succession from same identity | `sqs.amazonaws.com` | Recon-then-inject pattern characteristic of this technique |

**MEDIUM-CONFIDENCE — may indicate compromise; investigate further:**

| Audit Event | eventSource | Why Medium-Confidence |
|---|---|---|
| `ListQueues` from an IAM principal that does not normally enumerate queues | `sqs.amazonaws.com` | Reconnaissance; alone is not definitive |
| `GetQueueAttributes` requesting `QueueArn` attribute from a non-automation principal | `sqs.amazonaws.com` | ARN harvesting prior to policy injection |
| `SetQueueAttributes` clearing the `Policy` attribute (empty string) | `sqs.amazonaws.com` | Cleanup after injection — may indicate attacker cover-up |

---

### Key Investigation Queries

#### 1. Find all `SetQueueAttributes` events in the last 24 hours
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SetQueueAttributes \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,User:Username,Source:CloudTrailEvent}' \
  --output json
```

#### 2. Find `SetQueueAttributes` events on the specific queue
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=orders-ingest-prod \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | jq '.Events[] | select(.CloudTrailEvent | fromjson | .eventName == "SetQueueAttributes")'
```

#### 3. Correlate all API calls from the victim access key (replace KEY_ID)
```bash
VICTIM_KEY_ID="AKIA..."   # from Pulumi stack output or CloudTrail userIdentity

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="${VICTIM_KEY_ID}" \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --query 'Events[*].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \
  --output json | jq '.[] | {Time,Event,IP: (.IP | fromjson | .sourceIPAddress)}'
```

#### 4. Check the current queue policy for wildcard principals (live state)
```bash
QUEUE_URL=$(aws sqs get-queue-url \
  --queue-name orders-ingest-prod \
  --region us-east-1 \
  --query 'QueueUrl' --output text)

aws sqs get-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attribute-names Policy \
  --region us-east-1 \
  --query 'Attributes.Policy' --output text | python3 -m json.tool
```

#### 5. Check for wildcard principal in the active policy (automated detection)
```bash
aws sqs get-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attribute-names Policy \
  --region us-east-1 \
  --query 'Attributes.Policy' \
  --output text | python3 -c "
import sys, json
policy_str = sys.stdin.read().strip()
if not policy_str or policy_str == 'None':
    print('[OK] No resource policy attached')
    exit(0)
policy = json.loads(policy_str)
for stmt in policy.get('Statement', []):
    p = stmt.get('Principal', {})
    if p == '*' or p == {'AWS': '*'} or (isinstance(p, dict) and '*' in p.get('AWS', [])):
        print('[ALERT] WILDCARD PRINCIPAL DETECTED in statement:', json.dumps(stmt, indent=2))
    else:
        print('[OK] Statement principal:', p)
"
```

#### 6. Search CloudWatch Logs for injection event (if log group configured)
```bash
aws logs filter-log-events \
  --log-group-name "emulation-log-group" \
  --filter-pattern "SetQueueAttributes" \
  --start-time $(python3 -c "import time; print(int((time.time() - 3600) * 1000))") \
  --region us-east-1 \
  --query 'events[*].message' \
  --output text
```

#### 7. Identify the source IP and user-agent from the injection event
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SetQueueAttributes \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | {
    time: .eventTime,
    user: .userIdentity.arn,
    accessKeyId: .userIdentity.accessKeyId,
    sourceIP: .sourceIPAddress,
    userAgent: .userAgent,
    requestParams: .requestParameters
  }'
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — Disable the compromised access key immediately
```bash
VICTIM_KEY_ID="AKIA..."   # from CloudTrail userIdentity.accessKeyId
VICTIM_USERNAME="..."     # from CloudTrail userIdentity.userName or arn

aws iam update-access-key \
  --access-key-id "${VICTIM_KEY_ID}" \
  --status Inactive \
  --user-name "${VICTIM_USERNAME}" \
  --region us-east-1

# Confirm it is disabled
aws iam list-access-keys \
  --user-name "${VICTIM_USERNAME}" \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId,Status:Status}' \
  --output table
```

#### Step 2 — Remove the wildcard policy from the queue (if still present)
```bash
QUEUE_URL=$(aws sqs get-queue-url \
  --queue-name orders-ingest-prod \
  --region us-east-1 \
  --query 'QueueUrl' --output text)

aws sqs set-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attributes Policy="" \
  --region us-east-1

echo "Policy removed. Verifying..."
aws sqs get-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attribute-names Policy \
  --region us-east-1 \
  --query 'Attributes' \
  --output json
```

#### Step 3 — Confirm no messages were exfiltrated during the open-policy window
```bash
# Review approximate message count delta — if ReceiveMessage was called, messages may be drained
aws sqs get-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attribute-names ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible,LastModifiedTimestamp \
  --region us-east-1

# Check CloudTrail for ReceiveMessage or DeleteMessage events during the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ReceiveMessage \
  --start-time "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | jq '.Events[].CloudTrailEvent | fromjson | select(.requestParameters.queueUrl | test("orders-ingest-prod"))'
```

#### Step 4 — Enumerate all other queues the victim credential touched
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="${VICTIM_KEY_ID}" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 \
  --output json | jq '[.Events[].CloudTrailEvent | fromjson | .requestParameters.queueUrl // empty] | unique'
```

#### Step 5 — Audit all queues for open policies (sweep)
```bash
# List all SQS queues and check each for wildcard principals
aws sqs list-queues --region us-east-1 --query 'QueueUrls[]' --output text | tr '\t' '\n' | while read -r url; do
  policy=$(aws sqs get-queue-attributes \
    --queue-url "$url" \
    --attribute-names Policy \
    --region us-east-1 \
    --query 'Attributes.Policy' --output text 2>/dev/null)
  if echo "$policy" | grep -q '"Principal":"\*"\|"Principal":{"AWS":"\*"}'; then
    echo "[ALERT] Open policy on: $url"
    echo "$policy" | python3 -m json.tool
  fi
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the compromised access key (after confirming no legitimate use)
```bash
aws iam delete-access-key \
  --access-key-id "${VICTIM_KEY_ID}" \
  --user-name "${VICTIM_USERNAME}" \
  --region us-east-1

# Confirm deletion
aws iam list-access-keys \
  --user-name "${VICTIM_USERNAME}" \
  --output table
```

#### Issue new credentials for the victim user if needed for legitimate use
```bash
aws iam create-access-key \
  --user-name "${VICTIM_USERNAME}" \
  --query 'AccessKey.{AccessKeyId:AccessKeyId,SecretAccessKey:SecretAccessKey}' \
  --output json
# Store immediately in Secrets Manager or SSM Parameter Store — do not log to terminal
```

#### Verify the queue policy is clean and matches the expected baseline
```bash
aws sqs get-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attribute-names All \
  --region us-east-1 \
  --output json
# Policy attribute should be absent or match the pre-incident expected value
```

#### Audit IAM permissions for the victim role — confirm sqs:SetQueueAttributes should not be granted
```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):user/${VICTIM_USERNAME}" \
  --action-names sqs:SetQueueAttributes \
  --resource-arns "${QUEUE_ARN}" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}' \
  --output table
```

#### Remove `sqs:SetQueueAttributes` from the victim IAM user/role policy if over-provisioned
```bash
# First identify which policy grants the permission
aws iam list-attached-user-policies --user-name "${VICTIM_USERNAME}" --output table
aws iam list-user-policies --user-name "${VICTIM_USERNAME}" --output table

# If inline policy — remove the SetQueueAttributes action
# aws iam put-user-policy --user-name "${VICTIM_USERNAME}" --policy-name <name> --policy-document '<revised-policy>'

# If managed policy — detach and replace with a scoped-down version
# aws iam detach-user-policy --user-name "${VICTIM_USERNAME}" --policy-arn <arn>
```

---

## 5. Recovery

### Restore Clean State

#### Re-apply the intended queue policy (if a known-good policy existed pre-incident)
```bash
# Replace with the organization's known-good policy document
INTENDED_POLICY=$(cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": []
}
EOF
)

# Only apply a policy if one existed before — otherwise leave absent
# aws sqs set-queue-attributes \
#   --queue-url "${QUEUE_URL}" \
#   --attributes "Policy=${INTENDED_POLICY}" \
#   --region us-east-1
```

#### Verify queue is operational — send and receive a test message
```bash
RECEIPT=$(aws sqs send-message \
  --queue-url "${QUEUE_URL}" \
  --message-body '{"test": "recovery-probe"}' \
  --region us-east-1 \
  --query 'MessageId' --output text)
echo "Test message sent: ${RECEIPT}"

aws sqs receive-message \
  --queue-url "${QUEUE_URL}" \
  --max-number-of-messages 1 \
  --region us-east-1 \
  --query 'Messages[0].Body' --output text
```

#### Confirm GuardDuty is active and ingesting SQS-related events
```bash
aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[]' --output text | while read -r did; do
  aws guardduty get-detector --detector-id "$did" --region us-east-1 \
    --query '{Status:Status,FindingFrequency:FindingPublishingFrequency}' --output table
done
```

#### Enable AWS Config rule to continuously monitor SQS queue policies
```bash
# Check if the sqs-queue-publicly-accessible managed rule is active
aws configservice describe-config-rules \
  --config-rule-names sqs-queue-publicly-accessible \
  --region us-east-1 \
  --query 'ConfigRules[*].{Name:ConfigRuleName,State:ConfigRuleState}' \
  --output table 2>/dev/null || echo "Rule not found — create it:"

# Create the rule if absent
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "sqs-queue-publicly-accessible",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "SQS_QUEUE_PUBLICLY_ACCESSIBLE"
    }
  }' \
  --region us-east-1
```

#### Set up an EventBridge rule to alert on future SetQueueAttributes events (hardening)
```bash
aws events put-rule \
  --name "DetectSQSPolicyInjection" \
  --event-pattern '{
    "source": ["aws.sqs"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["SetQueueAttributes"],
      "requestParameters": {
        "attributes": {
          "Policy": [{"exists": true}]
        }
      }
    }
  }' \
  --state ENABLED \
  --region us-east-1
# Then attach a target (SNS topic, Lambda, etc.) via aws events put-targets
```

---

## 6. Lessons Learned

### What Happened
A victim IAM access key (seeded via Pulumi stack outputs) was used to enumerate SQS queues (`ListQueues`), resolve the `orders-ingest-prod` queue ARN (`GetQueueAttributes`), and inject a wildcard resource policy (`SetQueueAttributes` with `"Principal": "*"`). The policy granted `SendMessage`, `ReceiveMessage`, `DeleteMessage`, and `GetQueueAttributes` to any principal, publicly exposing the queue. The attacker verified the policy was live, then removed it to cover tracks.

### Root Cause
| Factor | Finding |
|---|---|
| Credential exposure | IAM access keys exported as Pulumi stack outputs — plaintext in state file |
| Over-provisioned permissions | Victim role granted `sqs:SetQueueAttributes` — unnecessary for the role's function |
| Missing detective control | No EventBridge/Config rule alerting on wildcard SQS policy injection |
| Missing preventive control | No SCP or resource-based deny blocking `sqs:SetQueueAttributes` from non-admin principals |

### Guardrails to Implement
1. **Never export plaintext IAM keys as Pulumi stack outputs** — use `Output.secret()` and store in Secrets Manager; reference via SSM Parameter Store in downstream consumers.
2. **SCP to deny `sqs:SetQueueAttributes` except from trusted automation roles** — apply at OU level.
3. **AWS Config rule `SQS_QUEUE_PUBLICLY_ACCESSIBLE`** — continuous evaluation with auto-remediation Lambda to remove wildcard policies.
4. **EventBridge alert on `SetQueueAttributes` where policy contains wildcard principal** — page on-call within seconds.
5. **IAM Access Analyzer** — enable with SQS support to surface public queue policies automatically.
6. **Rotate all credentials exported in Pulumi stack outputs** — treat them as compromised by default; scope victim roles to only the specific SQS actions required (`sqs:SendMessage` for producers, never `sqs:SetQueueAttributes`).

### Detection Gap Assessment
| Gap | Recommendation |
|---|---|
| No real-time alert on wildcard policy injection | EventBridge rule + SNS paging (see Recovery step above) |
| CloudTrail lookup-events has 90-second delay | Pre-index CloudTrail events into CloudWatch Logs Insights for sub-minute queries |
| Cleanup event (`SetQueueAttributes` with empty policy) is indistinguishable from a benign rotation | Correlate with preceding wildcard-injection event within the same session; alert on the pair |
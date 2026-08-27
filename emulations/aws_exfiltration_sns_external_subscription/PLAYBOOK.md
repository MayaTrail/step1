# IR Playbook: ATOMIC-SNS-External-Subscription — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Data Exfiltration via SNS Subscription Hijacking |
| Threat Actor | ATOMIC-sns-external-subscription (Technique Emulation) |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Exfiltration |
| MITRE Techniques | T1567 — Exfiltration Over Web Service |
| Detection Window | Steps 1–3 visible in CloudTrail; Steps 4–5 data-plane only |

---

## 1. Preparation

### Pre-requisites (must exist before this incident)

**CloudTrail**
- Multi-region trail enabled with S3 delivery and CloudWatch Logs integration.
- Management events (Read + Write) captured for `sts.amazonaws.com` and `sns.amazonaws.com`.
- SNS data-plane logging is **off by default** — Publish and ReceiveMessage are invisible without explicit opt-in. Enable delivery-status logging per topic if SNS data-plane visibility is required.

**GuardDuty**
- Detector enabled in all regions; finding type `Policy:IAMUser/RootCredentialUsage` and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` should be baselined.
- GuardDuty does not natively detect SNS over-subscription — this is a gap to address in Lessons Learned.

**AWS Config**
- Rule `sns-encrypted-kms` active.
- Custom Config rule or Security Hub control verifying no SNS topic has cross-account or public subscriptions.

**Baseline documentation**
- Inventory of all SNS topics and their expected subscriber endpoints (protocol + ARN).
- Inventory of IAM roles with `sns:Subscribe`, their expected callers, and expected subscription targets.

**Alerting**
- CloudWatch metric filter on CloudTrail log group for `eventName = Subscribe AND eventSource = sns.amazonaws.com` — alert threshold: any event where `subscriptionProtocol` is `http`, `https`, `email`, `email-json`, or any ARN not in the known-good inventory.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — always indicates compromise or requires immediate investigation

| # | Audit Event | eventSource | Indicator |
|---|-------------|-------------|-----------|
| 1 | `Subscribe` | `sns.amazonaws.com` | Endpoint ARN/protocol not in approved subscriber inventory, especially external HTTPS, email, or cross-account SQS |
| 2 | `AssumeRole` | `sts.amazonaws.com` | Victim role assumed by an unexpected principal (e.g., attack execution identity, EC2 instance outside normal use) |
| 3 | `ListTopics` | `sns.amazonaws.com` | Broad topic enumeration from an assumed-role session rather than a service principal |

#### MEDIUM-CONFIDENCE — warrants investigation; may have benign explanation

| # | Audit Event | eventSource | Indicator |
|---|-------------|-------------|-----------|
| 4 | `ListSubscriptionsByTopic` | `sns.amazonaws.com` | Attacker validating their subscription registered correctly |
| 5 | `ReceiveMessage` | `sqs.amazonaws.com` | SQS queue polled by a role session outside expected consumers (data-plane; only visible if SQS access logging enabled) |
| 6 | `GetQueueAttributes` | `sqs.amazonaws.com` | Attacker reconnaissance on sink queue capacity/visibility timeout |

---

### Key Investigation Queries

#### 2.1 — Find all AssumeRole events for the victim role (last 24 h)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query "Events[?contains(CloudTrailEvent, 'atomic-sns-external-subscription-victim-role')].[EventTime,Username,CloudTrailEvent]" \
  --output table
```

#### 2.2 — Find all SNS Subscribe events (last 24 h)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Subscribe \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json | \
  jq '.Events[] | {time: .EventTime, user: .Username, event: (.CloudTrailEvent | fromjson | {principal: .userIdentity.arn, topic: .requestParameters.topicArn, protocol: .requestParameters.protocol, endpoint: .requestParameters.endpoint, subscriptionArn: .responseElements.subscriptionArn})}'
```

#### 2.3 — Find SNS ListTopics enumeration from assumed-role sessions

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListTopics \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --output json | \
  jq '.Events[] | select((.CloudTrailEvent | fromjson | .userIdentity.type) == "AssumedRole") | {time: .EventTime, role: (.CloudTrailEvent | fromjson | .userIdentity.sessionContext.sessionIssuer.arn), session: (.CloudTrailEvent | fromjson | .userIdentity.sessionContext.sessionIssuer.userName), sourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress)}'
```

#### 2.4 — Enumerate current subscriptions on all topics (live state)

```bash
# List all topics
aws sns list-topics --region us-east-1 --query 'Topics[*].TopicArn' --output text | \
  tr '\t' '\n' | while read -r arn; do
    echo "=== $arn ==="
    aws sns list-subscriptions-by-topic --topic-arn "$arn" --region us-east-1 \
      --query 'Subscriptions[*].{Protocol:Protocol,Endpoint:Endpoint,Status:SubscriptionArn}' \
      --output table
  done
```

#### 2.5 — Identify unexpected SQS queue subscribed to SNS (cross-account check)

```bash
TOPIC_ARN="<target-topic-arn>"
aws sns list-subscriptions-by-topic \
  --topic-arn "$TOPIC_ARN" \
  --region us-east-1 \
  --output json | \
  jq '.Subscriptions[] | select(.Protocol == "sqs" or .Protocol == "https" or .Protocol == "email") | {protocol: .Protocol, endpoint: .Endpoint, subscriptionArn: .SubscriptionArn}'
```

#### 2.6 — Check SQS queue policy for unexpected principals (if sink queue identified)

```bash
SQS_URL="<sink-queue-url>"
aws sqs get-queue-attributes \
  --queue-url "$SQS_URL" \
  --attribute-names Policy \
  --region us-east-1 \
  --query 'Attributes.Policy' --output text | jq .
```

#### 2.7 — Correlate AssumeRole session to all subsequent API calls (session tracking)

```bash
# Extract the role session name from the AssumeRole event, then search for it
SESSION_NAME="atomic-sns-exfil-session"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION_NAME" \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --region us-east-1 \
  --query "Events[*].{Time:EventTime,Event:EventName,Source:EventSource}" \
  --output table
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Unsubscribe the attacker-registered endpoint

```bash
# Obtain the SubscriptionArn from 2.4 or 2.2 above, then:
SUBSCRIPTION_ARN="<arn:aws:sns:REGION:ACCOUNT:topic-name:subscription-uuid>"
aws sns unsubscribe \
  --subscription-arn "$SUBSCRIPTION_ARN" \
  --region us-east-1
echo "Unsubscribed: $SUBSCRIPTION_ARN"
```

#### 3.2 — Revoke the victim role's active STS sessions (deny all)

There is no direct `revoke-session` API. The fastest containment is attaching an explicit deny policy to the role. This invalidates all active sessions immediately.

```bash
ROLE_NAME="atomic-sns-external-subscription-victim-role"

# Create inline deny-all policy
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "INCIDENT-CONTAINMENT-DenyAll" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
        }
      }
    }]
  }'
echo "Deny-all inline policy applied to $ROLE_NAME"
```

#### 3.3 — Block the source IP (if identified from CloudTrail sourceIPAddress)

```bash
# If attacker IP is known, block at the WAF or NACl level
ATTACKER_IP="<x.x.x.x>"
VPC_ID="<vpc-id>"

# Option A: VPC Network ACL deny rule (lowest-level block)
NACL_ID=$(aws ec2 describe-network-acls \
  --filters Name=vpc-id,Values="$VPC_ID" \
  --query 'NetworkAcls[0].NetworkAclId' \
  --output text)

aws ec2 create-network-acl-entry \
  --network-acl-id "$NACL_ID" \
  --rule-number 1 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block "${ATTACKER_IP}/32" \
  --ingress
echo "NACL deny rule created for $ATTACKER_IP"
```

#### 3.4 — Disable the SQS sink queue (prevent further message reads)

```bash
SQS_URL="<sink-queue-url>"
# Set receive-message-wait-time to 0 and visibility timeout to max — deny effective access
# Fastest approach: lock down the queue policy to deny all actions
aws sqs set-queue-attributes \
  --queue-url "$SQS_URL" \
  --attributes '{
    "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"sqs:*\",\"Resource\":\"*\"}]}"
  }' \
  --region us-east-1
echo "SQS queue policy locked down"
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Remove the attacker-registered SNS subscription (if still present after 3.1)

```bash
# Verify no stale subscriptions remain
aws sns list-subscriptions --region us-east-1 --output json | \
  jq '.Subscriptions[] | select(.TopicArn | contains("atomic-sns-external-subscription"))'
```

#### 4.2 — Remove the containment deny policy and apply least-privilege correction

```bash
ROLE_NAME="atomic-sns-external-subscription-victim-role"

# Remove the emergency deny policy
aws iam delete-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "INCIDENT-CONTAINMENT-DenyAll"

# Review current attached policies
aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output table
aws iam list-role-policies --role-name "$ROLE_NAME" --output table

# Detach or replace the over-permissioned policy with a least-privilege replacement
# (policy name will vary — substitute the actual policy ARN from the list above)
OVER_PERMISSIONED_POLICY_ARN="<arn:aws:iam::ACCOUNT:policy/over-permissioned-policy>"
aws iam detach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "$OVER_PERMISSIONED_POLICY_ARN"
echo "Over-permissioned policy detached"
```

#### 4.3 — Purge any messages delivered to the SQS sink during the dwell window

```bash
SQS_URL="<sink-queue-url>"
aws sqs purge-queue \
  --queue-url "$SQS_URL" \
  --region us-east-1
echo "SQS sink queue purged"
```

#### 4.4 — Rotate any secrets or credentials that transited the topic

If the SNS topic carried application secrets, rotate them now:

```bash
# Example: rotate a Secrets Manager secret that was published to the topic
SECRET_ID="<secret-name-or-arn>"
aws secretsmanager rotate-secret \
  --secret-id "$SECRET_ID" \
  --region us-east-1
```

#### 4.5 — Audit all other SNS topics for unauthorized subscriptions

```bash
# Comprehensive sweep across all topics in the region
aws sns list-topics --region us-east-1 --output json | \
  jq -r '.Topics[].TopicArn' | while read -r topic; do
    SUBS=$(aws sns list-subscriptions-by-topic \
      --topic-arn "$topic" \
      --region us-east-1 \
      --output json | \
      jq '[.Subscriptions[] | select(.Protocol == "https" or .Protocol == "email" or .Protocol == "email-json" or .Protocol == "http")]')
    COUNT=$(echo "$SUBS" | jq 'length')
    if [ "$COUNT" -gt "0" ]; then
      echo "SUSPICIOUS TOPIC: $topic"
      echo "$SUBS" | jq .
    fi
  done
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Re-enable the victim role with a corrected least-privilege policy

```bash
# Apply new least-privilege policy permitting only the specific topic and action required
ROLE_NAME="atomic-sns-external-subscription-victim-role"
TOPIC_ARN="<arn:aws:sns:REGION:ACCOUNT:atomic-sns-external-subscription-topic>"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "LeastPrivilege-SNS-ReadOnly" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Allow\",
        \"Action\": [\"sns:ListTopics\", \"sns:GetTopicAttributes\"],
        \"Resource\": \"*\"
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": [\"sns:Publish\"],
        \"Resource\": \"$TOPIC_ARN\"
      }
    ]
  }"
echo "Least-privilege policy applied to $ROLE_NAME"
```

Note: `sns:Subscribe` is removed from the corrected policy. If the role legitimately needs to create subscriptions, scope it with a condition key on the target topic ARN.

#### 5.2 — Restore the SQS queue policy to the legitimate application policy

```bash
SQS_URL="<sink-queue-url>"
# Replace with the application's production policy (from runbook or IaC source of truth)
aws sqs set-queue-attributes \
  --queue-url "$SQS_URL" \
  --attributes '{"Policy": "<legitimate-policy-json>"}' \
  --region us-east-1
```

#### 5.3 — Verify no unauthorized subscriptions remain (post-eradication confirmation)

```bash
TOPIC_ARN="<arn:aws:sns:REGION:ACCOUNT:atomic-sns-external-subscription-topic>"
aws sns list-subscriptions-by-topic \
  --topic-arn "$TOPIC_ARN" \
  --region us-east-1 \
  --output table
```

Expected output: only legitimate application subscriber ARNs; no SQS queues outside the account's known infrastructure.

#### 5.4 — Verify GuardDuty detector is active and findings are processed

```bash
DETECTOR_ID=$(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text)
aws guardduty get-detector \
  --detector-id "$DETECTOR_ID" \
  --region us-east-1 \
  --query '{Status: Status, UpdatedAt: UpdatedAt, ServiceRole: ServiceRole}'
```

#### 5.5 — Enable SNS delivery-status logging on the topic (close the data-plane blind spot)

```bash
TOPIC_ARN="<arn:aws:sns:REGION:ACCOUNT:atomic-sns-external-subscription-topic>"
LOG_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/SNSDeliveryLoggingRole"  # must exist with CloudWatch write perms

aws sns set-topic-attributes \
  --topic-arn "$TOPIC_ARN" \
  --attribute-name SQSSuccessFeedbackRoleArn \
  --attribute-value "$LOG_ROLE_ARN"

aws sns set-topic-attributes \
  --topic-arn "$TOPIC_ARN" \
  --attribute-name SQSSuccessFeedbackSampleRate \
  --attribute-value "100"
echo "SNS delivery-status logging enabled for SQS protocol at 100% sample rate"
```

#### 5.6 — Confirm CloudTrail is delivering and no gap exists in the trail

```bash
TRAIL_NAME="<your-trail-name>"
aws cloudtrail get-trail-status \
  --name "$TRAIL_NAME" \
  --region us-east-1 \
  --query '{IsLogging: IsLogging, LatestDeliveryTime: LatestDeliveryTime, LatestDeliveryError: LatestDeliveryError}'
```

---

## 6. Lessons Learned

### Root Cause

The victim IAM role `atomic-sns-external-subscription-victim-role` was granted `sns:Subscribe` without a resource condition scoping it to a specific topic ARN or requiring a condition on `sns:Protocol`. This allowed any caller that could assume the role to register arbitrary external endpoints — including attacker-controlled HTTPS or email addresses — as topic subscribers.

### What Would Have Prevented This

| Guardrail | Implementation |
|-----------|----------------|
| **Remove `sns:Subscribe` from broad roles** | Scope `sns:Subscribe` with `Condition: {StringEquals: {"sns:Protocol": "sqs"}}` **and** `Resource` pinned to specific topic ARNs |
| **SCP deny on unrecognized protocols** | AWS Organizations SCP: `Deny sns:Subscribe` where `sns:Protocol` is `http`, `https`, `email`, `email-json` account-wide, with exception for approved CI/CD roles |
| **CloudWatch alert on SNS Subscribe** | Metric filter on CloudTrail → alert within 5 minutes of any `Subscribe` event; page on-call |
| **SNS topic resource policy** | Add a topic-level `Deny` on `sns:Subscribe` for any principal not in the approved subscriber list |
| **Inventory-driven subscription drift detection** | Daily `list-subscriptions-by-topic` sweep comparing against IaC-declared subscription inventory; alert on delta |
| **SNS data-plane logging** | Enable `SQSSuccessFeedbackRoleArn` per topic so `Publish` and delivery events are captured in CloudWatch Logs |
| **GuardDuty custom threat intel** | Upload known-bad SQS queue ARNs or IP ranges as custom threat intel sets; GuardDuty has no native SNS subscription finding type |

### Detection Gap

Steps 4 (`sns:Publish`) and 5 (`sqs:ReceiveMessage`) are **entirely invisible in CloudTrail** because they are data-plane API calls. An attacker who remains solely in the data plane after registering their subscription cannot be detected through CloudTrail alone. Mandatory SNS delivery-status logging and SQS access logging must be enabled to close this gap.

### MITRE Coverage Mapping

| Attack Step | MITRE ID | Detected By | Prevented By |
|-------------|----------|-------------|--------------|
| AssumeRole on victim role | T1078.004 | CloudTrail `AssumeRole` alert | Restrict who can assume the role (trust policy) |
| ListTopics enumeration | T1526 | CloudTrail `ListTopics` alert on AssumedRole sessions | Deny `sns:ListTopics` on broad roles |
| SNS Subscribe (exfil channel setup) | T1567 | CloudTrail `Subscribe` alert — HIGH confidence | SCP deny on unrecognized protocols; topic resource policy |
| SNS Publish (data exfil) | T1567 | SNS delivery-status logs only | KMS encryption on topic + key policy restricting encrypt/decrypt |
| SQS ReceiveMessage (confirmation) | T1567 | SQS access logs only | SQS queue resource policy denying unexpected principals |
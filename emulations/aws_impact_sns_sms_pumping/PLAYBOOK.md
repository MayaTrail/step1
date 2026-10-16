# IR Playbook: ATOMIC-sns-sms-pumping — AWS SNS SMS Pumping

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Cloud Resource Hijacking — SMS Pumping |
| Threat Actor | ATOMIC-sns-sms-pumping (technique emulation; maps to real-world SMS toll-fraud actors) |
| Platform | aws |
| Severity | High |
| MITRE Tactics | Resource Hijacking |
| MITRE Techniques | T1496.003 — Resource Hijacking: SMS Pumping |
| Data Sources | CloudTrail (Management + Data Events), SNS SMS Delivery Logs, AWS Cost & Billing |

---

## 1. Preparation

### What must be in place before this incident can be detected

| Control | Purpose |
|---------|---------|
| CloudTrail multi-region trail, management events ON | Captures all SNS control-plane calls including `GetSMSAttributes`, `SetSMSAttributes`, `GetSMSSandboxAccountStatus` |
| CloudTrail data events for SNS | Captures individual `sns:Publish` calls (phone-number destination, not just topic ARN) |
| SNS SMS Delivery Logs shipped to CloudWatch Logs | Provides per-message delivery status independent of CloudTrail; catches burst volume anomalies |
| AWS Budgets / Cost anomaly alert on SNS SMS spend | First-warning signal before CloudTrail analysis is even initiated |
| GuardDuty enabled (all detectors) | May surface `ResourceHijacking` finding on unusual SNS Publish volume |
| IAM deny policies on `sns:SetSMSAttributes` for unprivileged roles | Forces AccessDenied events — these must NOT be filtered out of detections |
| SNS SMS sandbox enabled on non-production accounts | Hard blocks real-number delivery; prevents billing exposure during emulation |

```bash
# Verify CloudTrail trail is logging SNS management events
aws cloudtrail get-trail-status --name <trail-name>
aws cloudtrail get-event-selectors --trail-name <trail-name>

# Verify SNS SMS delivery logs are configured
aws sns get-sms-attributes --attributes DefaultSMSType MonthlySpendLimit DeliveryStatusSuccessSamplingRate

# Check sandbox status
aws sns get-sms-sandbox-account-status

# Verify budget alert exists for SNS spend
aws budgets describe-budgets --account-id $(aws sts get-caller-identity --query Account --output text)
```

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Indicates active SMS pumping or reconnaissance

| Audit Event | EventSource | Why High Confidence |
|-------------|-------------|---------------------|
| `GetSMSAttributes` | sns.amazonaws.com | Adversary reads spend limits before launching burst; rarely called by automation |
| `GetSMSSandboxAccountStatus` | sns.amazonaws.com | Explicit sandbox probe — no legitimate use outside security tooling or onboarding |
| `SetSMSAttributes` (errorCode: AccessDenied) | sns.amazonaws.com | Spend-limit escalation attempt; must not be filtered on `errorCode IS NULL` |
| Burst of `Publish` calls with `PhoneNumber` destination | sns.amazonaws.com | Direct-to-phone publishing anomalous for most accounts that use topic ARNs |
| `Publish` calls to 555-01xx / fictional number range | sns.amazonaws.com | Indicators from this emulation; real campaigns use real numbers |
| `AssumeRole` with session name `sns-sms-pumping*` | sts.amazonaws.com | Session naming pattern from this emulation run |

#### MEDIUM-CONFIDENCE — Warrants investigation, not conclusive

| Audit Event | EventSource | Why Medium |
|-------------|-------------|------------|
| `AssumeRole` by unexpected principal into SNS-capable role | sts.amazonaws.com | Could be legitimate CI/CD; correlate with subsequent SNS calls |
| Spike in `sns:Publish` call volume vs. 30-day baseline | sns.amazonaws.com | Volume alone; need destination type to confirm phone targeting |
| SNS SMS delivery failures spike in CloudWatch | SNS Delivery Logs | Could be legitimate misconfiguration; correlate with `GetSMSSandboxAccountStatus` |
| Cost anomaly alert on SNS spend | AWS Billing | Late indicator; confirms impact but precedes detailed investigation |

---

### Key Investigation Queries

#### Step 1 — Identify the initial role assumption

```bash
# Find AssumeRole events into SNS-capable roles in the last 24 hours
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --query "Events[*].{Time:EventTime,User:Username,Event:CloudTrailEvent}" \
  --output table

# Filter for session names matching known pumping patterns
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | \
  python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    rss = ct.get('requestParameters',{}).get('roleSessionName','')
    if 'sms' in rss.lower() or 'pump' in rss.lower() or 'sns' in rss.lower():
        print(ct['eventTime'], ct['userIdentity'].get('arn',''), rss)
"
```

#### Step 2 — Identify SNS reconnaissance calls

```bash
# GetSMSAttributes - spend limit reconnaissance
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSMSAttributes \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username, event: (.CloudTrailEvent | fromjson | {actor: .userIdentity.arn, sourceIP: .sourceIPAddress})}'

# GetSMSSandboxAccountStatus - sandbox probe
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSMSSandboxAccountStatus \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {time: .EventTime, user: .Username}'
```

#### Step 3 — Find spend-limit escalation attempts (including AccessDenied)

```bash
# CRITICAL: SetSMSAttributes including AccessDenied - must NOT filter on errorCode
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SetSMSAttributes \
  --start-time $(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-48H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {
    time: .EventTime,
    user: .Username,
    errorCode: (.CloudTrailEvent | fromjson | .errorCode // "SUCCESS"),
    sourceIP: (.CloudTrailEvent | fromjson | .sourceIPAddress),
    actor: (.CloudTrailEvent | fromjson | .userIdentity.arn)
  }'
```

#### Step 4 — Identify the Publish burst to phone numbers

```bash
# SNS Publish calls - look for PhoneNumber destination (not topic ARN)
# Note: requires data events enabled on CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Publish \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | python3 -c "
import json, sys
events = json.load(sys.stdin)['Events']
phone_publishes = []
for e in events:
    ct = json.loads(e['CloudTrailEvent'])
    params = ct.get('requestParameters', {})
    dest = params.get('phoneNumber', params.get('topicArn', ''))
    if dest.startswith('+') or (params.get('phoneNumber')):
        phone_publishes.append({
            'time': ct['eventTime'],
            'actor': ct['userIdentity'].get('arn',''),
            'phone': dest,
            'smsType': params.get('messageAttributes',{}).get('AWS.SNS.SMS.SMSType',{}).get('stringValue',''),
            'sourceIP': ct.get('sourceIPAddress','')
        })
print(json.dumps(phone_publishes, indent=2))
print(f'Total phone-number Publish calls: {len(phone_publishes)}')
"

# Check SNS SMS delivery logs in CloudWatch for burst volume
aws logs filter-log-events \
  --log-group-name "sns/us-east-1/<account-id>/DirectPublishToPhoneNumber" \
  --start-time $(date -d '2 hours ago' +%s%3N 2>/dev/null || python3 -c "import time; print(int((time.time()-7200)*1000))") \
  --filter-pattern "{ $.status = FAILED }" \
  --query "events[*].{time:timestamp,msg:message}" \
  --output table
```

#### Step 5 — Correlate full attack chain for a single actor

```bash
# Correlate all SNS-related events from the suspected actor ARN
ACTOR_ARN="arn:aws:sts::<account-id>:assumed-role/attacker-role/sns-sms-pumping-emulation"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="${ACTOR_ARN}" \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ) \
  --output json | jq '.Events[] | {
    time: .EventTime,
    event: .EventName,
    source: .EventSource,
    error: (.CloudTrailEvent | fromjson | .errorCode // null)
  }' | jq -s 'sort_by(.time)'
```

#### Step 6 — Check current SNS spend and limits

```bash
# Current SMS spend attributes
aws sns get-sms-attributes

# Check if spend limit was actually modified (compare against baseline)
aws sns get-sms-attributes --query 'attributes.MonthlySpendLimit'

# Cost explorer - SNS charges in current month
aws ce get-cost-and-usage \
  --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Simple Notification Service"]}}' \
  --metrics "UnblendedCost" \
  --group-by Type=DIMENSION,Key=USAGE_TYPE
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### 3.1 — Revoke the attacker role session

```bash
# Identify the attacker role ARN
ATTACKER_ROLE="arn:aws:iam::<account-id>:role/attacker-role"

# Add an inline deny policy to the role to invalidate all active sessions immediately
# (IAM policy changes take effect within ~1 minute for new API calls)
aws iam put-role-policy \
  --role-name attacker-role \
  --policy-name EMERGENCY-DENY-ALL \
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

# Verify the inline deny is attached
aws iam list-role-policies --role-name attacker-role
```

#### 3.2 — Isolate the compromised IAM principal that assumed the role

```bash
# Identify what principal called AssumeRole (from CloudTrail above)
# If it was an IAM user - disable their access keys
VICTIM_USER="<iam-username-from-investigation>"

# List and disable all access keys
aws iam list-access-keys --user-name "${VICTIM_USER}" --output table
aws iam update-access-key \
  --user-name "${VICTIM_USER}" \
  --access-key-id <KEY-ID> \
  --status Inactive

# If it was an IAM role - disable the role itself
aws iam update-role \
  --role-name <source-role> \
  --description "DISABLED PENDING INCIDENT REVIEW - $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Attach a deny-all inline policy to block further use
aws iam put-role-policy \
  --role-name <source-role> \
  --policy-name EMERGENCY-DENY-ALL \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

#### 3.3 — Stop outbound SMS (if sandbox is NOT active)

```bash
# Check if account is in sandbox
aws sns get-sms-sandbox-account-status

# If NOT in sandbox and Publish calls were made - set spend limit to $0 immediately
# (Requires sns:SetSMSAttributes permission for the responder)
aws sns set-sms-attributes \
  --attributes MonthlySpendLimit=0

# Verify
aws sns get-sms-attributes --query 'attributes.MonthlySpendLimit'

# Optionally enable SMS sandbox to block all future sends to unverified numbers
# (Cannot be done via CLI on production accounts without AWS Support ticket)
# Open AWS Support ticket: request sandbox re-enablement or spend limit enforcement
```

#### 3.4 — Block the attacker's source IP at the network perimeter

```bash
# Get source IP from CloudTrail investigation (Step 2 above)
ATTACKER_IP="<source-ip-from-cloudtrail>"

# If VPC-based: check if requests came from within VPC or public internet
# For public internet source - consider WAF block or SCPs

# Add to an explicit deny SCP (requires Organizations admin access)
# This is a significant action - confirm with team first
aws organizations create-policy \
  --name "EMERGENCY-BLOCK-${ATTACKER_IP}" \
  --type SERVICE_CONTROL_POLICY \
  --description "Emergency SCP block for incident response" \
  --content "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"IpAddress\": {
          \"aws:SourceIp\": \"${ATTACKER_IP}/32\"
        }
      }
    }]
  }"
```

---

## 4. Eradication

### Remove Attacker Access

#### 4.1 — Audit and remove all backdoor permissions

```bash
# Check the attacker role's full permission set
aws iam get-role --role-name attacker-role
aws iam list-attached-role-policies --role-name attacker-role
aws iam list-role-policies --role-name attacker-role

# Check trust policy for unexpected principals
aws iam get-role --role-name attacker-role --query 'Role.AssumeRolePolicyDocument'

# Review all policies granting sns:Publish to PhoneNumber
aws iam list-policies --scope Local --query 'Policies[*].{Name:PolicyName,Arn:PolicyArn}' --output table

# Simulate what the attacker role could do (policy simulation)
ROLE_ARN="arn:aws:iam::<account-id>:role/attacker-role"
aws iam simulate-principal-policy \
  --policy-source-arn "${ROLE_ARN}" \
  --action-names sns:Publish sns:GetSMSAttributes sns:SetSMSAttributes sns:GetSMSSandboxAccountStatus \
  --resource-arns "*" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}'
```

#### 4.2 — Rotate credentials for all potentially compromised principals

```bash
# If an IAM user's keys were used to assume the attacker role - rotate them
VICTIM_USER="<iam-username>"

# Delete old keys (the ones used in the attack)
aws iam list-access-keys --user-name "${VICTIM_USER}"
aws iam delete-access-key \
  --user-name "${VICTIM_USER}" \
  --access-key-id <COMPROMISED-KEY-ID>

# Create fresh key (and distribute securely)
aws iam create-access-key --user-name "${VICTIM_USER}"

# Force console password reset
aws iam update-login-profile \
  --user-name "${VICTIM_USER}" \
  --password-reset-required
```

#### 4.3 — Remove emergency inline deny policy from the attacker role (after confirming it should be decommissioned or rebuilt)

```bash
# Option A: Delete the role entirely if it was created for the attack
aws iam delete-role-policy --role-name attacker-role --policy-name EMERGENCY-DENY-ALL
aws iam detach-role-policy --role-name attacker-role --policy-arn <arn>
aws iam delete-role --role-name attacker-role

# Option B: Replace the emergency deny with a scoped minimal policy for legitimate use
# (Keep the EMERGENCY-DENY-ALL in place until the role is fully reviewed)
```

#### 4.4 — Clean up any SNS resources created during the attack

```bash
# List any SNS topics that may have been created
aws sns list-topics --output table

# Check for any subscriptions to unexpected phone numbers
aws sns list-subscriptions \
  --query 'Subscriptions[?Protocol==`sms`].{Endpoint:Endpoint,TopicArn:TopicArn,SubscriptionArn:SubscriptionArn}' \
  --output table

# Delete any unexpected SMS subscriptions
aws sns unsubscribe --subscription-arn <subscription-arn>
```

---

## 5. Recovery

### Restore Clean State

#### 5.1 — Re-enable and verify security controls

```bash
# Confirm SNS spend limit is reset to an appropriate value
aws sns set-sms-attributes --attributes MonthlySpendLimit=1  # Set to actual baseline

# Verify IAM deny on attacker role is removed (if role is being retained)
aws iam list-role-policies --role-name attacker-role

# Verify CloudTrail is still active and logging
aws cloudtrail get-trail-status --name <trail-name> --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'

# Verify GuardDuty is active
aws guardduty list-detectors --query 'DetectorIds' --output table
for detector in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  aws guardduty get-detector --detector-id $detector --query '{Status:Status,FindingPublishingFrequency:FindingPublishingFrequency}'
done
```

#### 5.2 — Verify no persistence mechanisms remain

```bash
# Check for any new IAM roles created during the incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time <incident-start-time> \
  --output json | jq '.Events[] | {time:.EventTime, role: (.CloudTrailEvent | fromjson | .requestParameters.roleName)}'

# Check for any new access keys created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time <incident-start-time> \
  --output json | jq '.Events[] | {time:.EventTime, user: (.CloudTrailEvent | fromjson | .requestParameters.userName)}'

# Check for any new SNS subscriptions or topic policy changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Subscribe \
  --start-time <incident-start-time> \
  --output json | jq '.Events[] | {time:.EventTime, protocol: (.CloudTrailEvent | fromjson | .requestParameters.protocol), endpoint: (.CloudTrailEvent | fromjson | .requestParameters.endpoint)}'

# Check Lambda or EventBridge rules that could re-trigger SNS sends
aws events list-rules --query 'Rules[*].{Name:Name,State:State,ScheduleExpression:ScheduleExpression}' --output table
```

#### 5.3 — File cost dispute if real SMS charges were incurred

```bash
# Get exact SNS SMS charges for the incident period
aws ce get-cost-and-usage \
  --time-period Start=<incident-date>,End=<day-after-incident> \
  --granularity DAILY \
  --filter '{"And":[
    {"Dimensions":{"Key":"SERVICE","Values":["Amazon Simple Notification Service"]}},
    {"Dimensions":{"Key":"USAGE_TYPE","Values":["USE1-OutboundSMSMessages","USE1-SMS-Outbound"]}}
  ]}' \
  --metrics "UnblendedCost" "UsageQuantity"

# Open AWS Support case for fraudulent SMS charge reversal
# (Must be done via console or Support API - not CLI-automatable for case creation,
# but use the cost data above as evidence)
aws support create-case \
  --subject "Fraudulent SMS charges - incident response" \
  --service-code "amazon-sns" \
  --severity-code "high" \
  --category-code "general-guidance" \
  --communication-body "Requesting charge reversal for unauthorized SNS SMS sends during security incident on <date>. CloudTrail evidence available."
```

#### 5.4 — Restore victim user credentials and validate

```bash
# Verify new key works correctly
aws sts get-caller-identity  # Run as the restored user

# Confirm the user only has expected permissions post-rotation
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::<account-id>:user/<victim-user>" \
  --action-names sns:Publish sns:SetSMSAttributes \
  --resource-arns "*" \
  --query 'EvaluationResults[*].{Action:EvalActionName,Decision:EvalDecision}'
```

---

## 6. Lessons Learned

### What would have prevented or shortened this incident

| Gap | Guardrail |
|-----|-----------|
| `SetSMSAttributes` AccessDenied events filtered from detections | Detection rules must NOT apply `errorCode IS NULL` filter — denied attempts are high-signal for privilege escalation probing |
| No alert on `GetSMSSandboxAccountStatus` | This call has no legitimate automation use; alert on any call outside known pipeline ARNs |
| No alert on `GetSMSAttributes` from non-automation principals | Baseline legitimate callers and alert on deviations |
| No volume threshold on direct-to-phone `sns:Publish` calls | Set CloudWatch alarm: `>10 Publish calls with PhoneNumber destination in 60 seconds` |
| Monthly spend limit set above $0 in non-production accounts | SCPs should enforce `sns:SetSMSAttributes` only for break-glass principals; non-prod spend limit should be $1 |
| SNS sandbox not enforced on all non-production accounts | Organizational SCP: deny `sns:Publish` to `phoneNumber` unless account is tagged `env=production` |
| No GuardDuty finding for SMS burst | Enable GuardDuty threat intelligence feeds; review `ResourceHijacking` finding type configuration |
| Attacker role had `sns:Publish` at all | Apply least privilege: scope `sns:Publish` to specific topic ARNs, not `Resource: *` |
| No SNS SMS delivery logs in CloudWatch | Require `DeliveryStatusSuccessSamplingRate=100` and `DeliveryStatusIAMRole` in all accounts via Config rule |

### Detection validation notes from emulation

- **Step 4 (`SetSMSAttributes` AccessDenied)** is the most important detection-filter validation signal. A detection that fires only on successful calls will miss spend-limit escalation attempts. Confirm your SIEM/detection query does NOT include `WHERE errorCode IS NULL` or equivalent for this event.
- **Step 3 (`GetSMSSandboxAccountStatus`)** is a nearly zero-false-positive indicator. Any call to this API from a non-onboarding, non-security-tooling principal should be treated as reconnaissance.
- **Step 5 (`Publish` burst)** generates `PhoneNumber` in `requestParameters` — ensure your CloudTrail data-event query projects `requestParameters.phoneNumber` and not just `requestParameters.topicArn` to catch direct-to-phone sends.

### Recommended detection rule (CloudWatch Logs Insights)

```
# Run against CloudTrail log group
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, errorCode,
       requestParameters.phoneNumber, requestParameters.attributes.MonthlySpendLimit
| filter eventSource = "sns.amazonaws.com"
| filter eventName in ["GetSMSAttributes", "GetSMSSandboxAccountStatus", "SetSMSAttributes",
                       "Publish"]
| filter ispresent(requestParameters.phoneNumber) OR eventName in ["GetSMSAttributes",
         "GetSMSSandboxAccountStatus", "SetSMSAttributes"]
| sort @timestamp asc
| limit 500
```

### Recommended CloudWatch alarm for Publish burst

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "SNS-DirectPhonePublish-Burst" \
  --alarm-description "Alert on burst of direct-to-phone SNS Publish calls" \
  --metric-name "NumberOfMessagesSent" \
  --namespace "AWS/SNS" \
  --dimensions Name=TopicName,Value=DirectPublish \
  --statistic Sum \
  --period 60 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions <sns-alert-topic-arn>
```
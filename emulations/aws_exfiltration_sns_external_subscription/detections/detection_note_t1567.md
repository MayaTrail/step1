# Detection Note: T1567 - SNS Publish (Data Plane)

## Technique
SNS Publish - attacker publishes a message to the target SNS topic after registering a malicious
subscription endpoint. The message is delivered to all subscribers, including the newly registered
attacker-controlled SQS queue or external HTTP/email endpoint.

## Audit Visibility
**None by default.** SNS Publish is a data-plane API call. It does NOT appear in CloudTrail
management events unless SNS data-plane logging is explicitly enabled on the topic.

## Why This Matters
The Publish step is the actual data exfiltration moment: sensitive payload flows out of the
account to every registered subscriber. Detecting the Subscribe event (Step 3, control plane)
before a Publish is the preferred prevention-oriented approach.

## Detection Alternatives

### 1. SNS Delivery Status Logging (requires explicit opt-in per topic)
Enable CloudWatch delivery-status logging on the SNS topic (via `sns:SetTopicAttributes`).
This writes per-message delivery records to CloudWatch Logs including:
- Delivery status (SUCCESS / FAILED)
- Subscriber endpoint ARN
- Message size
- Timestamp

Set up a CloudWatch Logs Insights query or metric filter on the topic's delivery log group:

```
fields @timestamp, status, endpointArn, statusCode
| filter status = "SUCCESS"
| filter endpointArn not like /arn:aws:sqs:<TRUSTED_REGION>:<TRUSTED_ACCOUNT_ID>/
| sort @timestamp desc
```

### 2. CloudTrail - SetTopicAttributes / AddPermission Anomaly
An attacker enabling delivery-status logging themselves (to verify delivery) would trigger:
- eventName: SetTopicAttributes
- requestParameters.attributeName: HTTPSuccessFeedbackRoleArn / SQSSuccessFeedbackRoleArn

Alert on unexpected SetTopicAttributes calls from AssumedRole sessions.

### 3. GuardDuty
GuardDuty may surface findings for anomalous SNS activity if the publishing principal
exhibits unusual behavior patterns (new principal, unexpected region, high volume):
- Finding type: SNS/AnonymousAccess (if topic policy allows public access)

### 4. SQS Message Body Forensics (post-breach investigation)
If the SQS sink queue is accessible, inspect message bodies for sensitive field patterns
(PII, secrets keywords, ATOMIC-* test markers). This is a forensic capability, not a
real-time alert.

### 5. AWS Config Rule
Create a custom AWS Config rule that evaluates SNS topic policies and subscriber lists for
external-account SQS ARNs or non-corporate email domains on a continuous basis.

## Recommended Priority
Focus on alerting on the control-plane Subscribe event (sigma_T1567_sns_subscribe.yml) as a
leading indicator before Publish can occur. SNS delivery logging is the secondary layer if
data-in-flight visibility is required.

---

# Detection Note: T1567 - SQS ReceiveMessage (Data Plane)

## Technique
SQS ReceiveMessage - attacker reads back messages from the SQS sink queue to confirm
end-to-end exfiltration delivery. In the emulation this proves SNS->SQS fan-out reached
the attacker-registered endpoint. In a real attack the attacker would poll their
external HTTP endpoint or email inbox; a SQS sink is used here as an in-lab proxy.

## Audit Visibility
**None by default.** SQS ReceiveMessage is a data-plane API call. It does NOT appear in
CloudTrail management events. Data-plane SQS events require explicit enablement.

## Detection Alternatives

### 1. SQS Data-Plane Logging via CloudTrail (requires explicit enablement)
Enable CloudTrail data events for SQS in the account/region. This captures:
- ReceiveMessage
- DeleteMessage
- SendMessage

CloudTrail data events for SQS are charged at additional per-event rates. Once enabled,
the KQL query below surfaces SQS reads by unexpected assumed-role sessions:

```kql
AWSCloudTrail
| where EventName == "ReceiveMessage"
| where EventSource == "sqs.amazonaws.com"
| where UserIdentityType == "AssumedRole"
| where UserIdentityArn !contains ":assumed-role/AWSServiceRole"
| project TimeGenerated, UserIdentityArn, RequestParameters, SourceIpAddress, AWSRegion
| sort by TimeGenerated desc
```

### 2. VPC Flow Logs (if SQS is accessed via VPC endpoint)
If the environment routes SQS traffic through a VPC endpoint, VPC flow logs will show
connection records to the SQS endpoint IP range from the EC2/Lambda instance running
the attack script. This provides network-layer evidence but not API-level granularity.

### 3. SQS Queue Access Policy Audit (preventive)
Use AWS Config managed rule `SQS_QUEUE_ENCRYPTION_ENABLED` as a baseline, and add a custom
Config rule that flags SQS queues whose resource policies allow access from principals
outside a set of approved role ARNs. This detects misconfigured sink queues before exploitation.

### 4. GuardDuty - Anomalous SQS API Behavior
GuardDuty may generate findings for unusual SQS access patterns from new or unexpected
geographic locations when the assumed-role session originates from an atypical source IP.

### 5. CloudWatch Metrics - NumberOfMessagesSent + NumberOfMessagesReceived Delta
Create a CloudWatch alarm on a monitored SQS queue when NumberOfMessagesReceived spikes
without a corresponding internal NumberOfMessagesSent increase (indicating messages arrived
via SNS subscription rather than direct sends from expected producers).

## Recommended Priority
SQS ReceiveMessage detection is low-value in isolation. The highest-value detection is the
upstream control-plane Subscribe event (sigma_T1567_sns_subscribe.yml). If audit depth
covering the full delivery confirmation is required, enable CloudTrail SQS data events on
sensitive queues that should not be readable by assumed-role sessions.

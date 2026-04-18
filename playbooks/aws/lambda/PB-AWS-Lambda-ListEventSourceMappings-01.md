---
id: aws-lambda-listeventsourcemappings
api_call: lambda:ListEventSourceMappings
required_inputs:
  - INCIDENT_START_TIME
  - CALLER_ARN
  - ACCOUNT_ID
  - FUNCTION_NAME
provided_outputs:
  - EVENT_SOURCE_ARNS
  - MAPPING_COUNT
  - SOURCE_IP
---

# Playbook: Lambda ListEventSourceMappings Reconnaissance

## 1. Governance & Metadata

| Field | Value |
|---|---|
| **Playbook Name** | Lambda ListEventSourceMappings Reconnaissance |
| **Playbook ID** | PB-AWS-Lambda-ListEventSourceMappings-01 |
| **Version** | 1.0 |
| **Scenario** | Attacker enumerates Lambda event source mappings to discover data flow architecture (SQS queues, DynamoDB streams, Kinesis streams) that trigger Lambda functions. In SCARLETEEL, this was called from stolen EC2 role credentials to map the serverless data pipeline. |
| **Trigger** | CloudTrail `eventName: ListEventSourceMappings20150331` |
| **MITRE ATT&CK** | T1526 - Cloud Service Discovery |

### Severity Matrix

| Severity | Condition |
|---|---|
| **CRITICAL** | CALLER_ARN is not in the approved IAM roles list AND source IP is outside corporate CIDR blocks AND call count >= 5 distinct functions within 10 minutes |
| **HIGH** | CALLER_ARN is an EC2 instance profile role AND the call originates from a non-management subnet OR call count >= 3 distinct functions within 30 minutes |
| **MEDIUM** | CALLER_ARN is a known service role but the call occurs outside business hours (00:00-06:00 UTC) OR from an unusual AWS region |

### Prerequisites

- CloudTrail logging enabled in target account with management events captured
- Athena table configured for CloudTrail logs
- AWS CLI v2 installed and configured with incident response role
- Access to SecurityHub or equivalent SIEM

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-Technique | Procedure |
|---|---|---|---|
| Discovery | T1526 Cloud Service Discovery | N/A | Enumerate event source mappings to understand Lambda trigger architecture |

### Stakeholders

| Role | Responsibility |
|---|---|
| SOC Analyst (L1) | Initial triage, severity classification, escalation |
| IR Lead (L2) | Containment decisions, investigation coordination |
| Cloud Security Engineer (L3) | Forensic analysis, hardening, root cause analysis |
| Application Owner | Validate legitimate use, approve containment actions |

### SLA

| Severity | Acknowledge | Contain | Resolve |
|---|---|---|---|
| CRITICAL | 15 minutes | 1 hour | 4 hours |
| HIGH | 30 minutes | 2 hours | 8 hours |
| MEDIUM | 2 hours | 8 hours | 24 hours |

### Compliance

- SOC 2 Type II - CC6.1 (Logical Access Controls)
- NIST 800-53 - IR-4 (Incident Handling), IR-6 (Incident Reporting)
- CIS AWS Benchmark - 3.x (Monitoring)

### Related Playbooks

Part of Lambda enumeration chain. See PB-AWS-Lambda-ListFunctions-01, PB-AWS-Lambda-GetFunction-01, and PB-AWS-CAMPAIGN-SCARLETEEL-01 for full context.

---

## 2. Triage & Validation

### Automated Enrichment

**Step 2.1: Retrieve CloudTrail events for the API call**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListEventSourceMappings20150331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --region us-east-1 \
  --output json
```

**Step 2.2: Identify the caller identity and source IP**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<FUNCTION_NAME> \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 20 \
  --region us-east-1 \
  --query 'Events[*].{EventTime:EventTime,Username:Username,SourceIP:CloudTrailEvent}' \
  --output table
```

**Step 2.3: Check if CALLER_ARN is a known/approved role**

```bash
aws iam get-role \
  --role-name "$(echo <CALLER_ARN> | awk -F'/' '{print $NF}')" \
  --query 'Role.{RoleName:RoleName,CreateDate:CreateDate,Description:Description,Tags:Tags}' \
  --output json
```

**Step 2.4: Enumerate what event source mappings currently exist for the function**

```bash
aws lambda list-event-source-mappings \
  --function-name <FUNCTION_NAME> \
  --query 'EventSourceMappings[*].{UUID:UUID,EventSourceArn:EventSourceArn,State:State,BatchSize:BatchSize}' \
  --output table
```

**Step 2.5: Check for other reconnaissance API calls from the same CALLER_ARN in the time window**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(echo <CALLER_ARN> | awk -F'/' '{print $NF}')" \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --query 'Events[*].{EventName:EventName,EventTime:EventTime}' \
  --output table
```

### Decision Gates

| Condition | Action |
|---|---|
| IF CALLER_ARN is an approved automation role AND source IP is within corporate CIDR | THEN close as benign, document in ticket |
| IF CALLER_ARN is an EC2 instance profile AND source IP is an EC2 private IP | THEN escalate to L2, proceed to Section 3 |
| IF CALLER_ARN is unknown or recently created (< 24 hours) | THEN escalate to L2 immediately, treat as CRITICAL |
| IF multiple Lambda functions were enumerated (>= 3) within 10 minutes | THEN escalate to L2, treat as CRITICAL |
| IF call originates from outside known AWS regions | THEN escalate to L2, treat as HIGH |

---

## 3. Containment Strategy

> **Pre-check**: Before executing L2 or L3 actions, verify the target resource does NOT have the `Critical-Production-App` tag.

```bash
aws lambda list-tags \
  --resource <FUNCTION_ARN> \
  --query 'Tags."Critical-Production-App"' \
  --output text
```

| Level | Action | Command | Rollback |
|---|---|---|---|
| **L1** | Revoke active sessions for the compromised role | `aws iam put-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<INCIDENT_START_TIME>"}}}]}'` | `aws iam delete-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy` |
| **L1** | Block source IP in Security Group | `aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr <SOURCE_IP>/32` | `aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr <SOURCE_IP>/32` |
| **L2** | Attach explicit deny policy to the IAM role | `aws iam attach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/IncidentDenyAll` | `aws iam detach-role-policy --role-name <ROLE_NAME> --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/IncidentDenyAll` |
| **L2** | Disable compromised EC2 instance credentials via IMDS | `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-endpoint disabled` | `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-endpoint enabled` |
| **L3** | Isolate EC2 instance to forensic security group | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <FORENSIC_SG_ID>` | `aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <ORIGINAL_SG_ID>` |
| **L3** | Snapshot EBS volume for forensics before termination | `aws ec2 create-snapshot --volume-id <VOLUME_ID> --description "IR-PB-AWS-Lambda-ListEventSourceMappings-01-<INCIDENT_ID>"` | N/A (snapshot is additive) |

---

## 4. Investigation & Forensics

### 4.1 Scope Assessment

Determine the blast radius by answering:

1. How many distinct Lambda functions had their event source mappings enumerated?
2. What event sources (SQS, DynamoDB, Kinesis) were exposed?
3. Did the attacker proceed to invoke or modify any of the discovered functions?
4. Were credentials used to access the event source resources directly?

### 4.2 Athena Query - ListEventSourceMappings Activity

```sql
SELECT
    eventTime,
    userIdentity.arn AS caller_arn,
    userIdentity.principalId AS principal_id,
    sourceIPAddress,
    userAgent,
    requestParameters,
    responseElements,
    errorCode,
    errorMessage,
    awsRegion
FROM cloudtrail_logs
WHERE eventName = 'ListEventSourceMappings20150331'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND recipientAccountId = '<ACCOUNT_ID>'
ORDER BY eventTime ASC;
```

### 4.3 Correlated Activity Query

```sql
SELECT
    eventName,
    eventTime,
    sourceIPAddress,
    userAgent,
    requestParameters
FROM cloudtrail_logs
WHERE userIdentity.arn = '<CALLER_ARN>'
  AND eventTime >= '<INCIDENT_START_TIME>'
  AND eventName IN (
    'ListEventSourceMappings20150331',
    'ListFunctions20150331',
    'GetFunction20150331',
    'GetPolicy20150331',
    'ListTags20170331',
    'ListAliases20150331',
    'Invoke'
  )
ORDER BY eventTime ASC;
```

### 4.4 Evidence Preservation

```bash
# Save CloudTrail events to S3 evidence bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListEventSourceMappings20150331 \
  --start-time "<INCIDENT_START_TIME>" \
  --max-results 50 \
  --output json > /tmp/evidence-listeventsourcemappings-<INCIDENT_ID>.json

aws s3 cp /tmp/evidence-listeventsourcemappings-<INCIDENT_ID>.json \
  s3://<EVIDENCE_BUCKET>/incidents/<INCIDENT_ID>/cloudtrail/listeventsourcemappings.json \
  --sse aws:kms --sse-kms-key-id <EVIDENCE_KMS_KEY_ID>

# Capture current event source mapping state
aws lambda list-event-source-mappings \
  --function-name <FUNCTION_NAME> \
  --output json > /tmp/evidence-current-mappings-<INCIDENT_ID>.json

aws s3 cp /tmp/evidence-current-mappings-<INCIDENT_ID>.json \
  s3://<EVIDENCE_BUCKET>/incidents/<INCIDENT_ID>/lambda/current-event-source-mappings.json \
  --sse aws:kms --sse-kms-key-id <EVIDENCE_KMS_KEY_ID>
```

---

## 5. Recovery & Hardening

### 5.1 Sanitize

- Rotate all credentials associated with CALLER_ARN
- Delete any inline policies added during containment after confirming new policies are in place
- Remove any temporary security group rules

```bash
# Rotate access keys if applicable
aws iam list-access-keys --user-name <IAM_USER_NAME> --output json
aws iam create-access-key --user-name <IAM_USER_NAME>
aws iam delete-access-key --user-name <IAM_USER_NAME> --access-key-id <OLD_ACCESS_KEY_ID>
```

### 5.2 Restore

- Re-enable IMDS on the EC2 instance if it was disabled (only if instance is confirmed clean)
- Restore original security groups after forensic analysis is complete

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-endpoint enabled \
  --http-tokens required

aws ec2 modify-instance-attribute \
  --instance-id <INSTANCE_ID> \
  --groups <ORIGINAL_SG_ID>
```

### 5.3 Harden

- Enforce IMDSv2 on all EC2 instances to prevent SSRF-based credential theft

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

- Deploy CloudWatch metric filter and alarm for `lambda:ListEventSourceMappings` from compute roles (EC2/Lambda). Do NOT block this API via SCP as it is widely used by legitimate infrastructure tooling (Terraform drift detection, AWS Config rules, cost allocation automation).

```bash
aws logs put-metric-filter \
  --log-group-name <CLOUDTRAIL_LOG_GROUP> \
  --filter-name ListEventSourceMappings-FromComputeRoles \
  --filter-pattern '{ ($.eventName = "ListEventSourceMappings20150331") && ($.userIdentity.type = "AssumedRole") }' \
  --metric-transformations metricName=ListEventSourceMappingsFromCompute,metricNamespace=MayaTrail/LambdaRecon,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name ListEventSourceMappings-ComputeRole-Alert \
  --metric-name ListEventSourceMappingsFromCompute \
  --namespace MayaTrail/LambdaRecon \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions <SNS_TOPIC_ARN>
```

- Enable GuardDuty Lambda Protection if not already active

```bash
aws guardduty update-detector \
  --detector-id <DETECTOR_ID> \
  --features '[{"Name":"LAMBDA_NETWORK_LOGS","Status":"ENABLED"}]'
```

### 5.4 Verify

```bash
# Confirm compromised role no longer has active sessions
aws iam get-role-policy --role-name <ROLE_NAME> --policy-name DenyAllPolicy 2>&1 | grep -c "NoSuchEntity"

# Confirm IMDSv2 enforcement
aws ec2 describe-instances \
  --instance-ids <INSTANCE_ID> \
  --query 'Reservations[0].Instances[0].MetadataOptions' \
  --output json

# Confirm GuardDuty Lambda feature is enabled
aws guardduty get-detector \
  --detector-id <DETECTOR_ID> \
  --query 'Features[?Name==`LAMBDA_NETWORK_LOGS`].Status' \
  --output text
```

### 5.5 Post-Mortem

- Document timeline from initial compromise to containment
- Record all event source ARNs that were exposed (EVENT_SOURCE_ARNS)
- Total mapping count discovered by attacker (MAPPING_COUNT)
- Identify gaps in monitoring that allowed reconnaissance to proceed
- Update detection rules with new IOCs (source IPs, user agents)
- Schedule 30-day review of Lambda permissions across the account

---

## Detection Rule (Sigma Format)

```yaml
title: AWS Lambda ListEventSourceMappings Reconnaissance
id: e3a1b2c4-5d6f-7890-abcd-ef1234567890
status: experimental
description: Detects enumeration of Lambda event source mappings, which may indicate reconnaissance of serverless data flow architecture as seen in SCARLETEEL.
references:
  - https://sysdig.com/blog/scarleteel-2-0/
author: MayaTrail
date: 2026/04/05
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: lambda.amazonaws.com
    eventName: ListEventSourceMappings20150331
  filter_approved:
    userIdentity.arn|contains:
      - 'APPROVED_ROLE_1'
      - 'APPROVED_ROLE_2'
  condition: selection and not filter_approved
falsepositives:
  - Legitimate CI/CD pipelines enumerating event source mappings
  - Infrastructure-as-code tools (Terraform, Pulumi, CloudFormation)
  - Authorized monitoring or inventory automation
level: medium
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---|---|---|---|
| Discovery | T1526 | Cloud Service Discovery | Attacker enumerates event source mappings to map Lambda trigger architecture |
| Credential Access | T1552.005 | Cloud Instance Metadata API | Stolen EC2 role credentials used to make the API call |
| Initial Access | T1190 | Exploit Public-Facing Application | SCARLETEEL initial access via vulnerable container |
| Execution | T1648 | Serverless Execution | Understanding event sources enables targeted Lambda invocation |
